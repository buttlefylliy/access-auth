#!/usr/bin/env python3
"""access_auth：用户凭据登记与口令校验。

本文件既是用户注册表的实现，也是命令行入口。命令行从标准输入读取一个
UTF-8 JSON 文档，按顺序执行 operations 数组中的 register / authenticate /
authenticate_stateful 操作，并向标准输出写入紧凑 JSON 结果。
行为契约见 README.md 与 --help。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
import unicodedata

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 200000
SALT_BYTES = 16
SALT_HEX_LENGTH = SALT_BYTES * 2

MAX_INPUT_BYTES = 1024 * 1024  # 1 MiB
MAX_OPERATIONS = 1000
USER_ID_MIN_LENGTH = 1
USER_ID_MAX_LENGTH = 64
PASSWORD_MIN_BYTES = 8
PASSWORD_MAX_BYTES = 128

MAX_NOW = 9007199254740991  # 2**53 - 1
LOCK_SECONDS = 300
MAX_FAILED_ATTEMPTS = 3

EXIT_OK = 0
EXIT_PARAMETER_ERROR = 2
EXIT_VALUE_ERROR = 3
EXIT_DUPLICATE_USER = 4
EXIT_UNKNOWN_USER = 5
EXIT_STATE_ERROR = 6

_OPERATION_REGISTER = "register"
_OPERATION_AUTHENTICATE = "authenticate"
_OPERATION_AUTHENTICATE_STATEFUL = "authenticate_stateful"
_REQUIRED_KEYS = {
    _OPERATION_REGISTER: ("operation", "user_id", "password", "salt"),
    _OPERATION_AUTHENTICATE: ("operation", "user_id", "password"),
    _OPERATION_AUTHENTICATE_STATEFUL: (
        "operation",
        "user_id",
        "password",
        "now",
    ),
}

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class BatchError(Exception):
    """整批校验或执行失败；携带输出所需的 error 对象字段与退出码。"""

    def __init__(self, error_type, operation_index, message, exit_code):
        super().__init__(message)
        self.error_type = error_type
        self.operation_index = operation_index
        self.message = message
        self.exit_code = exit_code


class DuplicateUserError(Exception):
    """登记已存在的用户。"""


class UnknownUserError(Exception):
    """操作引用了未登记的用户。"""


class StateError(Exception):
    """同一用户的 now 早于上次已提交时间。"""


def encode_credential(password, salt):
    """按 pbkdf2_sha256$200000$盐十六进制$摘要十六进制 编码凭据。"""
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS
    )
    return "%s$%d$%s$%s" % (ALGORITHM, ITERATIONS, salt.hex(), digest.hex())


class UserRegistry:
    """内存用户注册表：user_id -> 编码凭据，外加每用户的认证状态。

    不保存明文口令，不落盘，不保留认证历史。认证状态仅含最后一次
    有效 now、失败次数与锁定截止值三个标量。
    """

    def __init__(self):
        self._credentials = {}
        self._states = {}

    def __contains__(self, user_id):
        return user_id in self._credentials

    def copy(self):
        clone = UserRegistry()
        clone._credentials = dict(self._credentials)
        clone._states = {
            user_id: dict(state) for user_id, state in self._states.items()
        }
        return clone

    def register(self, user_id, password, salt):
        """登记用户；salt 为 16 字节。重复登记抛出 DuplicateUserError。"""
        if user_id in self._credentials:
            raise DuplicateUserError(user_id)
        self._credentials[user_id] = encode_credential(password, salt)

    @staticmethod
    def _verify_password(stored, password):
        """对编码凭据执行一次 PBKDF2 校验，返回 True/False。"""
        _algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
        ).hex()
        return hmac.compare_digest(candidate, digest_hex)

    def authenticate(self, user_id, password):
        """校验口令；返回 True/False。未知用户抛出 UnknownUserError。"""
        stored = self._credentials.get(user_id)
        if stored is None:
            raise UnknownUserError(user_id)
        return self._verify_password(stored, password)

    def authenticate_stateful(self, user_id, password, now):
        """带失败计数与临时锁定的口令校验。

        now 为调用方注入的秒数（已校验的整数）。返回
        (accepted, reason, failed_attempts, locked_until)。
        未知用户抛出 UnknownUserError；now 早于该用户上次已提交
        时间抛出 StateError。每次调用至多执行一次 PBKDF2 校验。
        """
        stored = self._credentials.get(user_id)
        if stored is None:
            raise UnknownUserError(user_id)
        state = self._states.get(user_id)
        if state is None:
            state = {
                "last_now": None,
                "failed_attempts": 0,
                "locked_until": None,
            }
            self._states[user_id] = state
        last_now = state["last_now"]
        if last_now is not None and now < last_now:
            raise StateError(user_id)
        state["last_now"] = now
        locked_until = state["locked_until"]
        if locked_until is not None:
            if now < locked_until:
                return (
                    False,
                    "account_locked",
                    state["failed_attempts"],
                    locked_until,
                )
            # 到达截止值：先解锁并清零旧计数，再处理本次口令。
            state["failed_attempts"] = 0
            state["locked_until"] = None
        if self._verify_password(stored, password):
            state["failed_attempts"] = 0
            state["locked_until"] = None
            return True, None, 0, None
        state["failed_attempts"] += 1
        if state["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            state["locked_until"] = now + LOCK_SECONDS
        return (
            False,
            "invalid_password",
            state["failed_attempts"],
            state["locked_until"],
        )


def _is_control_free(value):
    return all(unicodedata.category(ch) != "Cc" for ch in value)


def _validate_string_field(operation, key, index):
    value = operation.get(key)
    if not isinstance(value, str):
        raise BatchError(
            "parameter_error",
            index,
            "field %r must be a string" % key,
            EXIT_PARAMETER_ERROR,
        )
    return value


def _validate_operation(index, operation):
    """校验单个操作，返回 (kind, user_id, password, salt, now)。"""
    if not isinstance(operation, dict):
        raise BatchError(
            "parameter_error",
            index,
            "operation must be a JSON object",
            EXIT_PARAMETER_ERROR,
        )
    kind = operation.get("operation")
    if kind not in _REQUIRED_KEYS:
        raise BatchError(
            "parameter_error",
            index,
            "field 'operation' must be 'register', 'authenticate' "
            "or 'authenticate_stateful'",
            EXIT_PARAMETER_ERROR,
        )
    expected = set(_REQUIRED_KEYS[kind])
    actual = set(operation)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        parts = []
        if missing:
            parts.append("missing field(s): %s" % ", ".join(missing))
        if extra:
            parts.append("unexpected field(s): %s" % ", ".join(extra))
        raise BatchError(
            "parameter_error", index, "; ".join(parts), EXIT_PARAMETER_ERROR
        )

    user_id = _validate_string_field(operation, "user_id", index)
    password = _validate_string_field(operation, "password", index)
    salt = None
    if kind == _OPERATION_REGISTER:
        salt = _validate_string_field(operation, "salt", index)
    now = None
    if kind == _OPERATION_AUTHENTICATE_STATEFUL:
        now = operation.get("now")
        if isinstance(now, bool) or not isinstance(now, int):
            raise BatchError(
                "parameter_error",
                index,
                "field 'now' must be a JSON integer",
                EXIT_PARAMETER_ERROR,
            )

    if not (USER_ID_MIN_LENGTH <= len(user_id) <= USER_ID_MAX_LENGTH):
        raise BatchError(
            "value_error",
            index,
            "user_id must be %d..%d Unicode code points, got %d"
            % (USER_ID_MIN_LENGTH, USER_ID_MAX_LENGTH, len(user_id)),
            EXIT_VALUE_ERROR,
        )
    if not _is_control_free(user_id):
        raise BatchError(
            "value_error",
            index,
            "user_id must not contain control characters",
            EXIT_VALUE_ERROR,
        )
    password_bytes = len(password.encode("utf-8"))
    if not (PASSWORD_MIN_BYTES <= password_bytes <= PASSWORD_MAX_BYTES):
        raise BatchError(
            "value_error",
            index,
            "password must be %d..%d bytes in UTF-8, got %d"
            % (PASSWORD_MIN_BYTES, PASSWORD_MAX_BYTES, password_bytes),
            EXIT_VALUE_ERROR,
        )
    salt_bytes = None
    if kind == _OPERATION_REGISTER:
        if len(salt) != SALT_HEX_LENGTH or any(
            ch not in _HEX_DIGITS for ch in salt
        ):
            raise BatchError(
                "value_error",
                index,
                "salt must be exactly %d hexadecimal characters (%d bytes)"
                % (SALT_HEX_LENGTH, SALT_BYTES),
                EXIT_VALUE_ERROR,
            )
        salt_bytes = bytes.fromhex(salt)
    if kind == _OPERATION_AUTHENTICATE_STATEFUL:
        if now < 0 or now > MAX_NOW:
            raise BatchError(
                "value_error",
                index,
                "now must be in 0..%d, got %d" % (MAX_NOW, now),
                EXIT_VALUE_ERROR,
            )
        if now + LOCK_SECONDS > MAX_NOW:
            raise BatchError(
                "value_error",
                index,
                "now + %d exceeds %d" % (LOCK_SECONDS, MAX_NOW),
                EXIT_VALUE_ERROR,
            )
    return kind, user_id, password, salt_bytes, now


def run_batch(registry, operations):
    """校验并执行整批操作。

    任一操作出错则注册表保持不变并抛出 BatchError；全部成功后一次性提交，
    按操作顺序返回结果列表。
    """
    validated = [
        _validate_operation(index, operation)
        for index, operation in enumerate(operations)
    ]
    working = registry.copy()
    results = []
    for index, (kind, user_id, password, salt, now) in enumerate(validated):
        if kind == _OPERATION_REGISTER:
            try:
                working.register(user_id, password, salt)
            except DuplicateUserError:
                raise BatchError(
                    "duplicate_user",
                    index,
                    "user already registered: %s" % user_id,
                    EXIT_DUPLICATE_USER,
                )
            results.append(
                {
                    "operation": _OPERATION_REGISTER,
                    "user_id": user_id,
                    "status": "registered",
                }
            )
        elif kind == _OPERATION_AUTHENTICATE:
            try:
                accepted = working.authenticate(user_id, password)
            except UnknownUserError:
                raise BatchError(
                    "unknown_user",
                    index,
                    "user not registered: %s" % user_id,
                    EXIT_UNKNOWN_USER,
                )
            result = {
                "operation": _OPERATION_AUTHENTICATE,
                "user_id": user_id,
                "status": "accepted" if accepted else "denied",
            }
            if not accepted:
                result["reason"] = "invalid_password"
            results.append(result)
        else:
            try:
                (
                    accepted,
                    reason,
                    failed_attempts,
                    locked_until,
                ) = working.authenticate_stateful(user_id, password, now)
            except UnknownUserError:
                raise BatchError(
                    "unknown_user",
                    index,
                    "user not registered: %s" % user_id,
                    EXIT_UNKNOWN_USER,
                )
            except StateError:
                raise BatchError(
                    "state_error",
                    index,
                    "now is earlier than the last committed time "
                    "for user: %s" % user_id,
                    EXIT_STATE_ERROR,
                )
            results.append(
                {
                    "operation": _OPERATION_AUTHENTICATE_STATEFUL,
                    "user_id": user_id,
                    "status": "accepted" if accepted else "denied",
                    "reason": reason,
                    "failed_attempts": failed_attempts,
                    "locked_until": locked_until,
                }
            )
    registry._credentials = working._credentials
    registry._states = working._states
    return results


def _reject_constant(value):
    raise ValueError("invalid JSON constant: %s" % value)


def _extract_operations(document):
    if not isinstance(document, dict):
        raise BatchError(
            "parameter_error",
            None,
            "top-level JSON value must be an object",
            EXIT_PARAMETER_ERROR,
        )
    extra = sorted(set(document) - {"operations"})
    if extra:
        raise BatchError(
            "parameter_error",
            None,
            "unexpected top-level field(s): %s" % ", ".join(extra),
            EXIT_PARAMETER_ERROR,
        )
    if "operations" not in document:
        raise BatchError(
            "parameter_error",
            None,
            "missing top-level field: operations",
            EXIT_PARAMETER_ERROR,
        )
    operations = document["operations"]
    if not isinstance(operations, list):
        raise BatchError(
            "parameter_error",
            None,
            "field 'operations' must be an array",
            EXIT_PARAMETER_ERROR,
        )
    if len(operations) > MAX_OPERATIONS:
        raise BatchError(
            "value_error",
            None,
            "batch must contain at most %d operations, got %d"
            % (MAX_OPERATIONS, len(operations)),
            EXIT_VALUE_ERROR,
        )
    return operations


def _serialize(payload):
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _emit_error(error_type, operation_index, message):
    sys.stdout.write(
        _serialize(
            {
                "ok": False,
                "results": None,
                "error": {
                    "type": error_type,
                    "operation_index": operation_index,
                    "message": message,
                },
            }
        )
        + "\n"
    )


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="access_auth.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "从标准输入读取一个 UTF-8 JSON 文档，按顺序执行 operations 数组中的\n"
            "register / authenticate / authenticate_stateful 操作，向标准输出\n"
            "写入紧凑 JSON 结果。\n"
            "整批操作先全部校验，任一错误则注册表保持不变；全部成功后才提交。"
        ),
        epilog=(
            "输入边界:\n"
            "  输入为单个 UTF-8 JSON 文档，上限 1 MiB；每批最多 1000 个操作。\n"
            "  顶层为对象，仅含 \"operations\" 数组；空数组合法，原样返回空结果。\n"
            "字段限制:\n"
            "  user_id: 字符串，1..64 个 Unicode 码点，不含控制字符 (Cc)。\n"
            "  password: 字符串，UTF-8 编码长度 8..128 字节。\n"
            "  salt (仅 register): 恰好 32 个十六进制字符，表示 16 字节。\n"
            "  now (仅 authenticate_stateful): JSON 整数，0..9007199254740991，\n"
            "  且 now + 300 不超过上限；表示调用方注入的秒数，不读系统时间。\n"
            "  字符串按原值处理：不去空白、不改大小写、不做 Unicode 归一化。\n"
            "  操作对象只允许上述字段；凭据编码为\n"
            "  pbkdf2_sha256$200000$盐十六进制$摘要十六进制，输出不含明文口令。\n"
            "锁定语义 (authenticate_stateful):\n"
            "  口令错误计一次失败，第三次失败锁定至 now + 300 秒；锁定期间\n"
            "  返回 denied/account_locked 且不计数，到达截止值自动解锁清零。\n"
            "  同一用户的 now 不得早于上次已提交时间（相等合法）。\n"
            "退出码:\n"
            "  0  成功（含口令校验被拒绝 denied/invalid_password）\n"
            "  2  parameter_error：JSON 语法或字段类型错误\n"
            "  3  value_error：长度、salt 编码、now 范围或批量上限错误\n"
            "  4  duplicate_user：重复登记（不覆盖原凭据）\n"
            "  5  unknown_user：操作引用了未登记的用户\n"
            "  6  state_error：now 早于该用户上次已提交时间"
        ),
    )
    return parser


def main(argv=None):
    _build_parser().parse_args(argv)

    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        _emit_error(
            "value_error",
            None,
            "input exceeds %d bytes (1 MiB)" % MAX_INPUT_BYTES,
        )
        return EXIT_VALUE_ERROR
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        _emit_error("parameter_error", None, "input is not valid UTF-8: %s" % exc)
        return EXIT_PARAMETER_ERROR
    try:
        document = json.loads(text, parse_constant=_reject_constant)
    except ValueError as exc:
        _emit_error("parameter_error", None, "invalid JSON: %s" % exc)
        return EXIT_PARAMETER_ERROR

    registry = UserRegistry()
    try:
        operations = _extract_operations(document)
        results = run_batch(registry, operations)
    except BatchError as err:
        _emit_error(err.error_type, err.operation_index, err.message)
        return err.exit_code

    sys.stdout.write(
        _serialize({"ok": True, "results": results, "error": None}) + "\n"
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
