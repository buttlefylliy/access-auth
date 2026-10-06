#!/usr/bin/env python3
"""access_auth：用户凭据登记与口令校验。

本文件既是用户注册表的实现，也是命令行入口。命令行从标准输入读取一个
UTF-8 JSON 文档，按顺序执行 operations 数组中的 register / authenticate /
authenticate_stateful / authenticate_session / validate_session /
terminate_session 操作，并向标准输出写入紧凑 JSON 结果。
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
SESSION_ID_MIN_LENGTH = 1
SESSION_ID_MAX_LENGTH = 64
LIFETIME_MIN = 1
LIFETIME_MAX = 86400

# authenticate_stateful：调用方注入的秒数上限（2^53 - 1）与锁定时长。
MAX_NOW = 9007199254740991
LOCK_DURATION_SECONDS = 300
MAX_FAILED_ATTEMPTS = 3

EXIT_OK = 0
EXIT_PARAMETER_ERROR = 2
EXIT_VALUE_ERROR = 3
EXIT_DUPLICATE_USER = 4
EXIT_UNKNOWN_USER = 5
EXIT_STATE_ERROR = 6
EXIT_DUPLICATE_SESSION = 7
EXIT_UNKNOWN_SESSION = 8

_OPERATION_REGISTER = "register"
_OPERATION_AUTHENTICATE = "authenticate"
_OPERATION_AUTHENTICATE_STATEFUL = "authenticate_stateful"
_OPERATION_AUTHENTICATE_SESSION = "authenticate_session"
_OPERATION_VALIDATE_SESSION = "validate_session"
_OPERATION_TERMINATE_SESSION = "terminate_session"
_REQUIRED_KEYS = {
    _OPERATION_REGISTER: ("operation", "user_id", "password", "salt"),
    _OPERATION_AUTHENTICATE: ("operation", "user_id", "password"),
    _OPERATION_AUTHENTICATE_STATEFUL: (
        "operation",
        "user_id",
        "password",
        "now",
    ),
    _OPERATION_AUTHENTICATE_SESSION: (
        "operation",
        "user_id",
        "password",
        "session_id",
        "now",
        "lifetime",
    ),
    _OPERATION_VALIDATE_SESSION: (
        "operation",
        "session_id",
        "now",
    ),
    _OPERATION_TERMINATE_SESSION: (
        "operation",
        "session_id",
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


class StateRegressionError(Exception):
    """authenticate_stateful 的 now 早于该用户上次已提交的时间。"""

    def __init__(self, user_id, now, last_now):
        super().__init__(user_id)
        self.user_id = user_id
        self.now = now
        self.last_now = last_now


class DuplicateSessionError(Exception):
    """authenticate_session 使用了仍然存在的 session_id。"""


class UnknownSessionError(Exception):
    """validate_session / terminate_session 引用了不存在的会话。"""


class SessionTimeRegressionError(Exception):
    """会话操作的 now 早于该会话上次已提交的时间。"""

    def __init__(self, session_id, now, last_now):
        super().__init__(session_id)
        self.session_id = session_id
        self.now = now
        self.last_now = last_now


def encode_credential(password, salt):
    """按 pbkdf2_sha256$200000$盐十六进制$摘要十六进制 编码凭据。"""
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS
    )
    return "%s$%d$%s$%s" % (ALGORITHM, ITERATIONS, salt.hex(), digest.hex())


class UserRegistry:
    """内存用户注册表：user_id -> 编码凭据。不保存明文口令，不落盘。

    另为 authenticate_stateful 维护每用户的认证状态
    (last_now, failed_attempts, locked_until)，值为不可变元组，
    不保留认证历史。

    会话仅驻留内存：session_id -> (user_id, expires_at, last_check,
    terminated_at)，其中 last_check 为最近已提交的检查/终止时间（创建时为
    None），terminated_at 为首次终止时间（未终止为 None）。
    会话过期是终态：过期记录保留在表中直至进程结束，重复创建同 id
    仍判为重复，重复校验仍返回 session_expired。会话终止同为终态：
    重复终止幂等返回首次 terminated_at，此后校验一律返回
    session_terminated。
    """

    def __init__(self):
        self._credentials = {}
        self._states = {}
        self._sessions = {}

    def __contains__(self, user_id):
        return user_id in self._credentials

    def copy(self):
        clone = UserRegistry()
        clone._credentials = dict(self._credentials)
        clone._states = dict(self._states)
        clone._sessions = dict(self._sessions)
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

        返回 (status, reason, failed_attempts, locked_until) 并提交该用户的
        新状态（含普通拒绝）。未知用户抛出 UnknownUserError；now 早于该用户
        上次已提交时间时抛出 StateRegressionError，状态不变。
        未锁定的本次请求最多执行一次 PBKDF2 校验。
        """
        stored = self._credentials.get(user_id)
        if stored is None:
            raise UnknownUserError(user_id)
        last_now, failed_attempts, locked_until = self._states.get(
            user_id, (None, 0, None)
        )
        if last_now is not None and now < last_now:
            raise StateRegressionError(user_id, now, last_now)
        if locked_until is not None:
            if now < locked_until:
                # 锁定期间：不增加失败次数，仅推进已提交时间。
                self._states[user_id] = (now, failed_attempts, locked_until)
                return ("denied", "account_locked", failed_attempts, locked_until)
            # 到达截止值：先解锁并清零旧计数，再处理本次口令。
            failed_attempts = 0
            locked_until = None
        if self._verify_password(stored, password):
            self._states[user_id] = (now, 0, None)
            return ("accepted", None, 0, None)
        failed_attempts += 1
        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            locked_until = now + LOCK_DURATION_SECONDS
        self._states[user_id] = (now, failed_attempts, locked_until)
        return ("denied", "invalid_password", failed_attempts, locked_until)

    def authenticate_session(self, user_id, password, session_id, now, lifetime):
        """有状态认证通过后创建确定性会话。

        沿用 authenticate_stateful 的全部凭据校验、时间单调性、失败计数与
        锁定语义；仅在 accepted 时检查 session_id 重复并创建会话，过期时刻为
        now + lifetime，初始检查时间为 None。拒绝时不创建会话。
        未知用户抛出 UnknownUserError；now 回退抛出 StateRegressionError；
        session_id 已存在（含已过期的终态记录）抛出 DuplicateSessionError。
        """
        status, reason, _failed_attempts, _locked_until = (
            self.authenticate_stateful(user_id, password, now)
        )
        if status != "accepted":
            return ("denied", reason, None)
        if session_id in self._sessions:
            raise DuplicateSessionError(session_id)
        expires_at = now + lifetime
        self._sessions[session_id] = (user_id, expires_at, None, None)
        return ("accepted", None, expires_at)

    def validate_session(self, session_id, now):
        """按注入时间校验会话是否仍未过期且未被终止。

        返回 (status, reason, user_id, expires_at) 并提交本次检查时间：
        now 早于该会话最近已提交的时间时抛出 SessionTimeRegressionError，
        状态不变（相等时间允许重复检查）；已终止的会话一律返回
        denied/session_terminated；未终止时 now < expires_at 返回 accepted；
        now >= expires_at 返回 denied/session_expired，过期为终态，过期时刻
        不被刷新，用户认证状态不被触碰。未知会话抛出 UnknownSessionError。
        """
        record = self._sessions.get(session_id)
        if record is None:
            raise UnknownSessionError(session_id)
        user_id, expires_at, last_check, terminated_at = record
        if last_check is not None and now < last_check:
            raise SessionTimeRegressionError(session_id, now, last_check)
        self._sessions[session_id] = (user_id, expires_at, now, terminated_at)
        if terminated_at is not None:
            return ("denied", "session_terminated", user_id, expires_at)
        if now < expires_at:
            return ("accepted", None, user_id, expires_at)
        return ("denied", "session_expired", user_id, expires_at)

    def terminate_session(self, session_id, now):
        """按注入时间主动终止一个有效会话。

        返回 (status, reason, user_id, terminated_at, expires_at) 并提交本次
        时间：now 早于该会话最近已提交的时间时抛出
        SessionTimeRegressionError，状态不变（相等时间允许重复调用）。
        未终止且 now < expires_at：写入终止标记，返回 terminated 与首次
        终止时间 now；已终止：幂等返回首次 terminated_at，不改写终止时间；
        未终止但 now >= expires_at：会话保持过期终态，返回
        denied/session_expired 且 terminated_at 为 None。
        终止不改变用户失败计数、锁定状态或其他会话。
        未知会话抛出 UnknownSessionError。
        """
        record = self._sessions.get(session_id)
        if record is None:
            raise UnknownSessionError(session_id)
        user_id, expires_at, last_check, terminated_at = record
        if last_check is not None and now < last_check:
            raise SessionTimeRegressionError(session_id, now, last_check)
        if terminated_at is not None:
            self._sessions[session_id] = (
                user_id,
                expires_at,
                now,
                terminated_at,
            )
            return ("terminated", None, user_id, terminated_at, expires_at)
        if now >= expires_at:
            self._sessions[session_id] = (user_id, expires_at, now, None)
            return ("denied", "session_expired", user_id, None, expires_at)
        self._sessions[session_id] = (user_id, expires_at, now, now)
        return ("terminated", None, user_id, now, expires_at)


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


def _validate_integer_field(operation, key, index):
    """校验整数字段类型（JSON 布尔不算整数），返回 Python int。"""
    value = operation.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise BatchError(
            "parameter_error",
            index,
            "field %r must be a JSON integer" % key,
            EXIT_PARAMETER_ERROR,
        )
    return value


def _validate_now_type(index, operation):
    """校验 now 字段类型，返回整数值。"""
    return _validate_integer_field(operation, "now", index)


def _validate_now_range(index, now, max_added=LOCK_DURATION_SECONDS):
    """校验 now 的取值范围：0..MAX_NOW 且加上给定上限后不越界。"""
    if not (0 <= now <= MAX_NOW):
        raise BatchError(
            "value_error",
            index,
            "now must be in 0..%d, got %d" % (MAX_NOW, now),
            EXIT_VALUE_ERROR,
        )
    if now + max_added > MAX_NOW:
        raise BatchError(
            "value_error",
            index,
            "now + %d must not exceed %d, got %d"
            % (max_added, MAX_NOW, now),
            EXIT_VALUE_ERROR,
        )


def _validate_operation(index, operation):
    """校验单个操作，返回含规范化字段的字典。"""
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
            "field 'operation' must be 'register', 'authenticate', "
            "'authenticate_stateful', 'authenticate_session', "
            "'validate_session' or 'terminate_session'",
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

    validated = {"kind": kind}
    needs_user = kind in (
        _OPERATION_REGISTER,
        _OPERATION_AUTHENTICATE,
        _OPERATION_AUTHENTICATE_STATEFUL,
        _OPERATION_AUTHENTICATE_SESSION,
    )
    if needs_user:
        user_id = _validate_string_field(operation, "user_id", index)
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
        validated["user_id"] = user_id

    if kind in (
        _OPERATION_REGISTER,
        _OPERATION_AUTHENTICATE,
        _OPERATION_AUTHENTICATE_STATEFUL,
        _OPERATION_AUTHENTICATE_SESSION,
    ):
        password = _validate_string_field(operation, "password", index)
        password_bytes = len(password.encode("utf-8"))
        if not (PASSWORD_MIN_BYTES <= password_bytes <= PASSWORD_MAX_BYTES):
            raise BatchError(
                "value_error",
                index,
                "password must be %d..%d bytes in UTF-8, got %d"
                % (PASSWORD_MIN_BYTES, PASSWORD_MAX_BYTES, password_bytes),
                EXIT_VALUE_ERROR,
            )
        validated["password"] = password

    if kind == _OPERATION_REGISTER:
        salt = _validate_string_field(operation, "salt", index)
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
        validated["salt"] = bytes.fromhex(salt)

    if kind in (
        _OPERATION_AUTHENTICATE_STATEFUL,
        _OPERATION_AUTHENTICATE_SESSION,
        _OPERATION_VALIDATE_SESSION,
        _OPERATION_TERMINATE_SESSION,
    ):
        now = _validate_now_type(index, operation)
        # now 沿用现有限制（0..MAX_NOW 且为锁定时长预留空间）；
        # authenticate_session 额外要求 now+lifetime 不越界，在 lifetime
        # 校验后复查。
        _validate_now_range(index, now, LOCK_DURATION_SECONDS)
        validated["now"] = now

    if kind in (
        _OPERATION_AUTHENTICATE_SESSION,
        _OPERATION_VALIDATE_SESSION,
        _OPERATION_TERMINATE_SESSION,
    ):
        session_id = _validate_string_field(operation, "session_id", index)
        if not (
            SESSION_ID_MIN_LENGTH <= len(session_id) <= SESSION_ID_MAX_LENGTH
        ):
            raise BatchError(
                "value_error",
                index,
                "session_id must be %d..%d Unicode code points, got %d"
                % (
                    SESSION_ID_MIN_LENGTH,
                    SESSION_ID_MAX_LENGTH,
                    len(session_id),
                ),
                EXIT_VALUE_ERROR,
            )
        if not _is_control_free(session_id):
            raise BatchError(
                "value_error",
                index,
                "session_id must not contain control characters",
                EXIT_VALUE_ERROR,
            )
        validated["session_id"] = session_id

    if kind == _OPERATION_AUTHENTICATE_SESSION:
        lifetime = _validate_integer_field(operation, "lifetime", index)
        if not (LIFETIME_MIN <= lifetime <= LIFETIME_MAX):
            raise BatchError(
                "value_error",
                index,
                "lifetime must be %d..%d, got %d"
                % (LIFETIME_MIN, LIFETIME_MAX, lifetime),
                EXIT_VALUE_ERROR,
            )
        _validate_now_range(index, now, lifetime)
        validated["lifetime"] = lifetime

    return validated


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
    for index, op in enumerate(validated):
        kind = op["kind"]
        if kind == _OPERATION_REGISTER:
            user_id = op["user_id"]
            try:
                working.register(user_id, op["password"], op["salt"])
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
            user_id = op["user_id"]
            try:
                accepted = working.authenticate(user_id, op["password"])
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
        elif kind == _OPERATION_AUTHENTICATE_STATEFUL:
            user_id = op["user_id"]
            try:
                status, reason, failed_attempts, locked_until = (
                    working.authenticate_stateful(
                        user_id, op["password"], op["now"]
                    )
                )
            except UnknownUserError:
                raise BatchError(
                    "unknown_user",
                    index,
                    "user not registered: %s" % user_id,
                    EXIT_UNKNOWN_USER,
                )
            except StateRegressionError as exc:
                raise BatchError(
                    "state_error",
                    index,
                    "now %d is before last committed now %d for user: %s"
                    % (exc.now, exc.last_now, exc.user_id),
                    EXIT_STATE_ERROR,
                )
            results.append(
                {
                    "operation": _OPERATION_AUTHENTICATE_STATEFUL,
                    "user_id": user_id,
                    "status": status,
                    "reason": reason,
                    "failed_attempts": failed_attempts,
                    "locked_until": locked_until,
                }
            )
        elif kind == _OPERATION_AUTHENTICATE_SESSION:
            user_id = op["user_id"]
            session_id = op["session_id"]
            try:
                status, reason, expires_at = working.authenticate_session(
                    user_id,
                    op["password"],
                    session_id,
                    op["now"],
                    op["lifetime"],
                )
            except UnknownUserError:
                raise BatchError(
                    "unknown_user",
                    index,
                    "user not registered: %s" % user_id,
                    EXIT_UNKNOWN_USER,
                )
            except StateRegressionError as exc:
                raise BatchError(
                    "state_error",
                    index,
                    "now %d is before last committed now %d for user: %s"
                    % (exc.now, exc.last_now, exc.user_id),
                    EXIT_STATE_ERROR,
                )
            except DuplicateSessionError:
                raise BatchError(
                    "duplicate_session",
                    index,
                    "session already exists: %s" % session_id,
                    EXIT_DUPLICATE_SESSION,
                )
            results.append(
                {
                    "operation": _OPERATION_AUTHENTICATE_SESSION,
                    "user_id": user_id,
                    "session_id": session_id,
                    "status": status,
                    "reason": reason,
                    "expires_at": expires_at,
                }
            )
        elif kind == _OPERATION_VALIDATE_SESSION:
            session_id = op["session_id"]
            try:
                status, reason, session_user_id, expires_at = (
                    working.validate_session(session_id, op["now"])
                )
            except UnknownSessionError:
                raise BatchError(
                    "unknown_session",
                    index,
                    "session not found: %s" % session_id,
                    EXIT_UNKNOWN_SESSION,
                )
            except SessionTimeRegressionError as exc:
                raise BatchError(
                    "state_error",
                    index,
                    "now %d is before last committed now %d for session: %s"
                    % (exc.now, exc.last_now, exc.session_id),
                    EXIT_STATE_ERROR,
                )
            results.append(
                {
                    "operation": _OPERATION_VALIDATE_SESSION,
                    "session_id": session_id,
                    "user_id": session_user_id,
                    "status": status,
                    "reason": reason,
                    "expires_at": expires_at,
                }
            )
        else:
            session_id = op["session_id"]
            try:
                status, reason, session_user_id, terminated_at, expires_at = (
                    working.terminate_session(session_id, op["now"])
                )
            except UnknownSessionError:
                raise BatchError(
                    "unknown_session",
                    index,
                    "session not found: %s" % session_id,
                    EXIT_UNKNOWN_SESSION,
                )
            except SessionTimeRegressionError as exc:
                raise BatchError(
                    "state_error",
                    index,
                    "now %d is before last committed now %d for session: %s"
                    % (exc.now, exc.last_now, exc.session_id),
                    EXIT_STATE_ERROR,
                )
            results.append(
                {
                    "operation": _OPERATION_TERMINATE_SESSION,
                    "session_id": session_id,
                    "user_id": session_user_id,
                    "status": status,
                    "reason": reason,
                    "terminated_at": terminated_at,
                    "expires_at": expires_at,
                }
            )
    registry._credentials = working._credentials
    registry._states = working._states
    registry._sessions = working._sessions
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
            "register / authenticate / authenticate_stateful /\n"
            "authenticate_session / validate_session / terminate_session 操作，\n"
            "向标准输出写入紧凑 JSON 结果。\n"
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
            "  now (有状态操作): 0..9007199254740991 的 JSON 整数，\n"
            "  表示调用方注入的秒数；功能不读取系统时间。\n"
            "  session_id (会话操作): 字符串，1..64 个 Unicode 码点，不含控制字符。\n"
            "  lifetime (仅 authenticate_session): 1..86400 的 JSON 整数秒，\n"
            "  且 now+lifetime 不得超过 9007199254740991。\n"
            "  字符串按原值处理：不去空白、不改大小写、不做 Unicode 归一化。\n"
            "  操作对象只允许上述字段；凭据编码为\n"
            "  pbkdf2_sha256$200000$盐十六进制$摘要十六进制，输出不含明文口令。\n"
            "authenticate_stateful:\n"
            "  每个用户独立保存最后一次已提交 now、失败次数与锁定截止值。\n"
            "  口令错误计一次失败，第三次失败锁定至 now+300；锁定期间返回\n"
            "  denied/account_locked 且不计数；now 到达截止值后先解锁再校验。\n"
            "  口令正确返回 accepted 并清零计数与截止值。同一用户的 now 不得\n"
            "  早于上次已提交时间（相等合法），否则整批 state_error。\n"
            "authenticate_session:\n"
            "  沿用 authenticate_stateful 的凭据校验、时间单调性、失败计数与\n"
            "  锁定语义；accepted 时创建内存会话，expires_at=now+lifetime，\n"
            "  拒绝时不创建会话，expires_at 为 null。session_id 重复（含已过期\n"
            "  的终态会话）整批 duplicate_session。结果键序为 operation、\n"
            "  user_id、session_id、status、reason、expires_at。\n"
            "validate_session:\n"
            "  now 早于该会话最近已提交的时间时整批 state_error（状态不变，\n"
            "  相等时间允许重复检查）；已终止的会话一律返回\n"
            "  denied/session_terminated；未终止时 now 小于 expires_at 返回\n"
            "  accepted，达到或超过返回 denied/session_expired，过期为终态，\n"
            "  不刷新过期时刻，也不改变用户认证状态。未知 session_id 整批\n"
            "  unknown_session。结果键序为 operation、session_id、user_id、\n"
            "  status、reason、expires_at。会话仅驻留当前进程。\n"
            "terminate_session:\n"
            "  按注入时间主动终止有效会话，字段与校验同 validate_session。\n"
            "  now 早于该会话最近已提交的时间时整批 state_error（状态不变，\n"
            "  相等时间允许重复调用）。未终止且 now 小于 expires_at：返回\n"
            "  terminated，terminated_at 为首次终止时间 now；再次终止幂等返回\n"
            "  首次 terminated_at，不改写终止时间；now 达到或超过 expires_at：\n"
            "  会话保持过期终态，返回 denied/session_expired 且 terminated_at\n"
            "  为 null。终止不改变用户失败计数、锁定状态或其他会话。\n"
            "  未知 session_id 整批 unknown_session。结果键序为 operation、\n"
            "  session_id、user_id、status、reason、terminated_at、expires_at。\n"
            "退出码:\n"
            "  0  成功（含 denied/invalid_password、account_locked、\n"
            "      session_expired、session_terminated 与 terminated）\n"
            "  2  parameter_error：JSON 语法或字段类型错误\n"
            "  3  value_error：长度、salt 编码、now/lifetime 范围或批量上限错误\n"
            "  4  duplicate_user：重复登记（不覆盖原凭据）\n"
            "  5  unknown_user：操作引用了未登记的用户\n"
            "  6  state_error：now 早于该用户或会话上次已提交时间\n"
            "  7  duplicate_session：session_id 已存在\n"
            "  8  unknown_session：session_id 不存在"
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
