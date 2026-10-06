#!/usr/bin/env python3
"""access_auth: user credential registry and password verification.

Single-file module and command line entry point. Standard library only,
offline, deterministic: the same initial state and the same input always
produce byte-identical output. No lockout, sessions, admission policy, or
on-disk state — the registry lives in memory for one invocation.

CLI contract (see --help):
  stdin  : one UTF-8 JSON document, at most 1 MiB, with an "operations"
           array of at most 1000 register/authenticate operations.
  stdout : one compact JSON object with fixed keys ok/results/error.
"""

import argparse
import hashlib
import hmac
import json
import sys
import unicodedata

MAX_INPUT_BYTES = 1 << 20  # 1 MiB stdin limit
MAX_OPERATIONS = 1000  # per-batch operation limit
USER_MIN_CODEPOINTS = 1
USER_MAX_CODEPOINTS = 64
PASSWORD_MIN_BYTES = 8
PASSWORD_MAX_BYTES = 128
SALT_HEX_LENGTH = 32  # 16 bytes expressed as hexadecimal
PBKDF2_ALGORITHM = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 200000

EXIT_OK = 0
EXIT_PARAMETER_ERROR = 2
EXIT_VALUE_ERROR = 3
EXIT_DUPLICATE_USER = 4
EXIT_UNKNOWN_USER = 5

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class BatchError(Exception):
    """One batch-level failure; carries the wire error object and exit code."""

    def __init__(self, error_type, operation_index, message, exit_code):
        super().__init__(message)
        self.error_type = error_type
        self.operation_index = operation_index
        self.message = message
        self.exit_code = exit_code

    def error_object(self):
        return {
            "type": self.error_type,
            "operation_index": self.operation_index,
            "message": self.message,
        }


def _parameter_error(operation_index, message):
    return BatchError(
        "parameter_error", operation_index, message, EXIT_PARAMETER_ERROR
    )


def _value_error(operation_index, message):
    return BatchError("value_error", operation_index, message, EXIT_VALUE_ERROR)


def encode_credential(password, salt_hex):
    """Encode a password as pbkdf2_sha256$200000$<salt hex>$<digest hex>."""
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        PBKDF2_ITERATIONS,
    ).hex()
    return "%s$%d$%s$%s" % (PBKDF2_ALGORITHM, PBKDF2_ITERATIONS, salt_hex, digest)


class UserRegistry:
    """In-memory user registry; stores encoded credentials, never plaintext."""

    def __init__(self, credentials=None):
        self._credentials = dict(credentials) if credentials else {}

    def __contains__(self, user):
        return user in self._credentials

    def register(self, user, password, salt_hex):
        """Add a user; raises duplicate_user without overwriting on conflict."""
        if user in self._credentials:
            raise BatchError(
                "duplicate_user", None,
                "user is already registered", EXIT_DUPLICATE_USER,
            )
        self._credentials[user] = encode_credential(password, salt_hex)

    def authenticate(self, user, password):
        """Return True for the correct password, False otherwise.

        Raises unknown_user for unregistered users. The stored digest is
        recomputed from the presented password and compared with
        hmac.compare_digest.
        """
        try:
            stored = self._credentials[user]
        except KeyError:
            raise BatchError(
                "unknown_user", None,
                "user is not registered", EXIT_UNKNOWN_USER,
            )
        _, iterations, salt_hex, digest = stored.split("$")
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
        ).hex()
        return hmac.compare_digest(digest, candidate)


def _validate_user(value, index):
    if not isinstance(value, str):
        raise _parameter_error(index, "user must be a string")
    if not USER_MIN_CODEPOINTS <= len(value) <= USER_MAX_CODEPOINTS:
        raise _value_error(index, "user must be 1..64 Unicode code points")
    if any(unicodedata.category(ch) == "Cc" for ch in value):
        raise _value_error(index, "user must not contain control characters")
    return value


def _validate_password(value, index):
    if not isinstance(value, str):
        raise _parameter_error(index, "password must be a string")
    if not PASSWORD_MIN_BYTES <= len(value.encode("utf-8")) <= PASSWORD_MAX_BYTES:
        raise _value_error(index, "password must be 8..128 bytes in UTF-8")
    return value


def _validate_salt(value, index):
    if not isinstance(value, str):
        raise _parameter_error(index, "salt must be a string")
    if len(value) != SALT_HEX_LENGTH or any(c not in _HEX_DIGITS for c in value):
        raise _value_error(
            index, "salt must be exactly 16 bytes as 32 hexadecimal characters"
        )
    return value


def _validate_operation(operation, index):
    """Check one operation's structure and field values; return a normalized tuple."""
    if not isinstance(operation, dict):
        raise _parameter_error(index, "operation must be an object")
    kind = operation.get("op")
    if kind not in ("register", "authenticate"):
        raise _parameter_error(index, "op must be 'register' or 'authenticate'")
    required = ("user", "password", "salt") if kind == "register" else ("user", "password")
    for field in required:
        if field not in operation:
            raise _parameter_error(index, "missing required field '%s'" % field)
    user = _validate_user(operation["user"], index)
    password = _validate_password(operation["password"], index)
    salt_hex = _validate_salt(operation["salt"], index) if kind == "register" else None
    return kind, user, password, salt_hex


def run_batch(registry, operations):
    """Validate the whole batch, then apply it atomically and return results.

    Every operation is validated first; any failure leaves the registry
    unchanged. Semantics (duplicate_user/unknown_user) are checked against a
    working copy that applies the batch in order, so later operations see
    earlier registrations. Only a fully successful batch is committed.
    """
    if len(operations) > MAX_OPERATIONS:
        raise _value_error(None, "batch exceeds the 1000 operation limit")
    validated = [_validate_operation(op, i) for i, op in enumerate(operations)]
    working = UserRegistry(registry._credentials)
    results = []
    for index, (kind, user, password, salt_hex) in enumerate(validated):
        try:
            if kind == "register":
                working.register(user, password, salt_hex)
                results.append({"status": "registered"})
            elif working.authenticate(user, password):
                results.append({"status": "accepted"})
            else:
                results.append({"status": "denied", "reason": "invalid_password"})
        except BatchError as exc:
            exc.operation_index = index
            raise
    registry._credentials = working._credentials
    return results


def _emit(payload):
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.buffer.write(data.encode("utf-8") + b"\n")


def _emit_error(error):
    _emit({"ok": False, "results": None, "error": error.error_object()})
    return error.exit_code


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="access_auth.py",
        description=(
            "User credential registry and password verification. Reads one "
            "UTF-8 JSON document from standard input and writes one compact "
            "JSON result to standard output. Standard library only, offline, "
            "deterministic; no state is persisted between invocations."
        ),
        epilog=(
            "input boundaries:\n"
            "  stdin is a single UTF-8 JSON document of at most 1 MiB:\n"
            '  {"operations": [<operation>, ...]} with at most 1000 operations.\n'
            "  register:     {\"op\": \"register\", \"user\": u, \"password\": p, \"salt\": s}\n"
            "  authenticate: {\"op\": \"authenticate\", \"user\": u, \"password\": p}\n"
            "\n"
            "field limits (strings are used verbatim; no trimming, case folding,\n"
            "or Unicode normalization is applied):\n"
            "  user      string, 1..64 Unicode code points, no control characters\n"
            "  password  string, 8..128 bytes when encoded as UTF-8\n"
            "  salt      string of exactly 32 hexadecimal characters (16 bytes)\n"
            "\n"
            "the whole batch is validated before any operation takes effect; a\n"
            "failed batch leaves the registry unchanged. Credentials are stored\n"
            "as pbkdf2_sha256$200000$<salt hex>$<digest hex>; plaintext\n"
            "passwords never appear in records or output.\n"
            "\n"
            'output: {"ok": bool, "results": [...] | null, "error": {...} | null}\n'
            "with error keys type/operation_index/message, serialized with\n"
            "ensure_ascii=False and compact separators.\n"
            "\n"
            "exit codes:\n"
            "  0  success (including password denied as invalid_password)\n"
            "  2  parameter_error: JSON syntax or field type errors\n"
            "  3  value_error: length, salt encoding, input size, or batch limit\n"
            "  4  duplicate_user: register of an already registered user\n"
            "  5  unknown_user: authenticate of an unregistered user"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.parse_args(argv)

    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        return _emit_error(_value_error(None, "input exceeds the 1 MiB limit"))
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _emit_error(_parameter_error(None, "input is not valid UTF-8"))
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        return _emit_error(_parameter_error(None, "invalid JSON: %s" % exc))
    if not isinstance(document, dict) or not isinstance(
        document.get("operations"), list
    ):
        return _emit_error(
            _parameter_error(
                None, "document must be an object with an 'operations' array"
            )
        )

    registry = UserRegistry()
    try:
        results = run_batch(registry, document["operations"])
    except BatchError as exc:
        return _emit_error(exc)
    _emit({"ok": True, "results": results, "error": None})
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
