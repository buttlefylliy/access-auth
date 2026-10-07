#!/usr/bin/env python3
"""access_auth：用户凭据登记与口令校验。

本文件既是用户注册表的实现，也是命令行入口。命令行从标准输入读取一个
UTF-8 JSON 文档，按顺序执行 operations 数组中的 register /
replace_credential / authenticate /
authenticate_stateful / unlock_account / authenticate_session /
validate_session / terminate_session / set_session_limit /
set_admission_policy / set_admission_default /
set_admission_overrides / check_admission /
set_session_idle_timeout / list_authentication_events /
list_accounting_events / list_admission_events /
record_accounting_interim /
reauthenticate_session / get_account_status / get_session_status /
report_session_disconnect 操作，
并向标准输出写入紧凑 JSON 结果。
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
MAX_SESSIONS_MIN = 0
MAX_SESSIONS_MAX = 64
PORT_ID_MIN_LENGTH = 1
PORT_ID_MAX_LENGTH = 64
VLAN_ID_MIN = 1
VLAN_ID_MAX = 4094
MAX_POLICY_RULES = 64
MAX_OVERRIDE_RULES = 64
IDLE_TIMEOUT_MIN = 0
IDLE_TIMEOUT_MAX = 86400
MAX_ACCOUNTING_INTERIM_EVENTS = 64

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
_OPERATION_REPLACE_CREDENTIAL = "replace_credential"
_OPERATION_AUTHENTICATE = "authenticate"
_OPERATION_AUTHENTICATE_STATEFUL = "authenticate_stateful"
_OPERATION_UNLOCK_ACCOUNT = "unlock_account"
_OPERATION_AUTHENTICATE_SESSION = "authenticate_session"
_OPERATION_VALIDATE_SESSION = "validate_session"
_OPERATION_TERMINATE_SESSION = "terminate_session"
_OPERATION_SET_SESSION_LIMIT = "set_session_limit"
_OPERATION_SET_ADMISSION_POLICY = "set_admission_policy"
_OPERATION_SET_ADMISSION_DEFAULT = "set_admission_default"
_OPERATION_SET_ADMISSION_OVERRIDES = "set_admission_overrides"
_OPERATION_CHECK_ADMISSION = "check_admission"
_OPERATION_SET_SESSION_IDLE_TIMEOUT = "set_session_idle_timeout"
_OPERATION_LIST_AUTHENTICATION_EVENTS = "list_authentication_events"
_OPERATION_LIST_ACCOUNTING_EVENTS = "list_accounting_events"
_OPERATION_LIST_ADMISSION_EVENTS = "list_admission_events"
_OPERATION_RECORD_ACCOUNTING_INTERIM = "record_accounting_interim"
_OPERATION_REAUTHENTICATE_SESSION = "reauthenticate_session"
_OPERATION_GET_ACCOUNT_STATUS = "get_account_status"
_OPERATION_GET_SESSION_STATUS = "get_session_status"
_OPERATION_REPORT_SESSION_DISCONNECT = "report_session_disconnect"
_REQUIRED_KEYS = {
    _OPERATION_REGISTER: ("operation", "user_id", "password", "salt"),
    _OPERATION_REPLACE_CREDENTIAL: ("operation", "user_id", "password", "salt"),
    _OPERATION_AUTHENTICATE: ("operation", "user_id", "password"),
    _OPERATION_AUTHENTICATE_STATEFUL: (
        "operation",
        "user_id",
        "password",
        "now",
    ),
    _OPERATION_UNLOCK_ACCOUNT: (
        "operation",
        "user_id",
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
    _OPERATION_SET_SESSION_LIMIT: (
        "operation",
        "user_id",
        "max_sessions",
    ),
    _OPERATION_SET_ADMISSION_POLICY: (
        "operation",
        "user_id",
        "rules",
    ),
    _OPERATION_SET_ADMISSION_DEFAULT: (
        "operation",
        "user_id",
        "default_action",
    ),
    _OPERATION_SET_ADMISSION_OVERRIDES: (
        "operation",
        "user_id",
        "rules",
    ),
    _OPERATION_CHECK_ADMISSION: (
        "operation",
        "session_id",
        "now",
        "port_id",
        "vlan_id",
    ),
    _OPERATION_SET_SESSION_IDLE_TIMEOUT: (
        "operation",
        "user_id",
        "idle_timeout",
    ),
    _OPERATION_LIST_AUTHENTICATION_EVENTS: (
        "operation",
        "user_id",
    ),
    _OPERATION_LIST_ACCOUNTING_EVENTS: (
        "operation",
        "session_id",
    ),
    _OPERATION_LIST_ADMISSION_EVENTS: (
        "operation",
        "session_id",
    ),
    _OPERATION_RECORD_ACCOUNTING_INTERIM: (
        "operation",
        "session_id",
        "now",
    ),
    _OPERATION_REAUTHENTICATE_SESSION: (
        "operation",
        "source_session_id",
        "session_id",
        "password",
        "now",
        "lifetime",
    ),
    _OPERATION_GET_ACCOUNT_STATUS: (
        "operation",
        "user_id",
        "now",
    ),
    _OPERATION_GET_SESSION_STATUS: (
        "operation",
        "session_id",
        "now",
    ),
    _OPERATION_REPORT_SESSION_DISCONNECT: (
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
    """validate_session 引用了不存在的会话。"""


class SessionTimeRegressionError(Exception):
    """validate_session 的 now 早于该会话上次已提交的检查时间。"""

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

    unlock_account 对已登记用户执行确定性的人工解锁：服从该用户既有的
    时间单调规则（now 早于最近已提交认证状态时间时抛出
    StateRegressionError，相等允许），随后无条件将 failed_attempts
    归零、locked_until 置为 None，并把 now 记为最近已提交的认证状态
    时间；无论调用前处于锁定、只有累计失败、锁定已自然到期还是干净
    状态，都提交同一个幂等状态 (now, 0, None)。人工解锁不校验口令、
    不修改编码凭据，也不产生认证或计费事件；解锁后的新失败从一次
    重新累计。未知用户抛出 UnknownUserError。

    会话仅驻留内存：session_id -> (user_id, expires_at, last_check,
    terminated_at, idle_timeout, last_activity, idle_expired,
    disconnected_at)，其中
    last_check 为最近已提交的检查/终止时间（创建时为 None），terminated_at
    为首次终止时间（未终止为 None）；idle_timeout 为创建时快照的用户空闲
    超时（0 表示关闭），last_activity 为最近活动时间（创建时为创建 now，
    仅 validate_session / check_admission 对仍有效会话完成判定后刷新），
    idle_expired 为空闲过期终态标志，disconnected_at 为首次异常断线时间
    （未断线为 None）。
    会话过期与终止都是终态：记录保留在表中直至进程结束，重复创建同 id
    仍判为重复，过期后重复校验仍返回 session_expired，终止后校验一律
    返回 session_terminated，重复终止幂等返回首次 terminated_at。
    空闲过期同样是终态：命中后两个检查入口一律返回 session_idle_expired，
    terminate_session 也返回该原因且 terminated_at 为 null。
    异常断线也是终态：report_session_disconnect 对仍有效会话记录首次
    disconnected_at 并追加一条 reason 为 session_disconnected 的 stop
    计费事件；此后 validate_session、check_admission、terminate_session
    与 record_accounting_interim 一律返回 denied/session_disconnected，
    不刷新活动时间、不追加 interim，并发计数排除该会话；重复报告幂等
    返回首次 disconnected_at，不重复追加事件。

    另维护每用户并发会话上限 _session_limits（user_id -> int）；未配置的
    用户不限并发。上限只约束 authenticate_session 创建新会话：在本次
    now 下未终止且 now 小于 expires_at 的会话计入并发，已过期会话保留
    记录但不计入；达到上限时拒绝创建，既有会话不被终止。

    另维护每用户准入策略 _admission_policies
    （user_id -> frozenset[(port_id, vlan_id)]）与每用户默认准入动作
    _admission_defaults（user_id -> "allow"/"deny"，每用户至多一个）。
    两者均未配置的用户默认拒绝准入（policy_not_configured）；只配置默认
    动作也视为策略已配置，默认动作适用于所有合法端口和 VLAN。精确规则
    命中时默认动作不生效；未命中时按默认动作 allow 放行、deny 拒绝
    （policy_denied）。策略与默认动作只影响 check_admission 的判定，
    不影响凭据、认证状态、已有会话与并发限额。

    另维护每用户有序覆盖规则 _admission_overrides
    （user_id -> tuple[(port_id, vlan_id, action)]，port_id/vlan_id
    为 None 表示该维度通配，action 为 "allow"/"deny"）。check_admission
    在会话有效性判定后、精确规则与默认动作之前按数组顺序采用首条匹配的
    覆盖规则；未配置或空数组（已清除）时不影响原有精确规则、默认动作与
    拒绝原因语义。覆盖规则只影响 check_admission 的判定，不产生认证或
    计费事件，也不改变会话时间语义。

    另维护每用户空闲超时 _idle_timeouts（user_id -> int，秒）；
    未配置或配置为 0 均表示关闭空闲超时。配置只在创建会话时快照进会话
    记录，已有会话沿用创建时的配置；lifetime 仍是不可延长的硬期限。

    另维护每用户认证事件轨迹 _auth_events
    （user_id -> list[(source, now, status, reason, session_id)]），
    仅记录已作为普通结果提交的 authenticate_stateful 与
    authenticate_session 尝试；无状态 authenticate 不产生事件。每个用户的
    事件按提交顺序从 1 连续编号，事件不含口令、盐、编码凭据或摘要。轨迹随
    整批副本一起提交或回滚；只读查询 list_authentication_events 不追加事件。

    另维护每会话计费轨迹 _accounting_events
    （session_id -> list[(event_type, now, reason)]）：
    authenticate_session 成功创建会话时追加且仅追加一条 ("start", now, None)，
    时间取该请求显式传入的 now；口令拒绝、账户锁定、并发上限拒绝与整批异常
    均不产生开始事件。validate_session、check_admission、terminate_session
    或 record_accounting_interim 首次将已有会话判为终态时追加且仅追加一条
    stop 事件：主动终止取首次
    terminated_at、reason 为 session_terminated；首次观察到硬过期取触发结果
    的 now、reason 为 session_expired；首次观察到空闲过期取触发结果的 now、
    reason 为 session_idle_expired。重复校验、重复终止或从另一入口再次观察
    同一终态不改写也不追加；尚未被这些入口观察到的超时不出现在轨迹中。
    record_accounting_interim 对仍有效的会话追加 ("interim", now, None)，
    时间取该请求显式传入的 now，每个会话最多保存 64 条 interim；同一会话
    以相同 now 重复提交时返回原编号、不重复追加。每个会话的 sequence 从 1
    连续递增，正常轨迹为一条 start、至多 64 条 interim 与至多一条 stop。
    轨迹随整批副本一起提交或回滚；只读查询 list_accounting_events 不追加
    事件、不推进任何时间。

    另维护每会话准入判定事件轨迹 _admission_events
    （session_id -> list[(now, port_id, vlan_id, status, reason)]）：
    每次 check_admission 完成普通业务判定并提交状态（接受、策略拒绝、默认
    拒绝及会话终态拒绝）后追加且仅追加一条，记录请求显式传入的 now、
    port_id、vlan_id 与对外返回的 status、reason；相同 now 的重复请求是
    两次独立判定，形成两条事件。未知会话、时间回退与字段/取值校验失败不
    留下事件，批次后续失败时新增事件随整批副本一起回滚。追加事件不额外
    改变会话时间、终态、认证状态、准入策略或计费轨迹，事件不含凭据材料。
    每个会话的 sequence 从 1 连续递增，受每批最多 MAX_OPERATIONS 个操作
    限制，每个会话每批至多产生 MAX_OPERATIONS 条事件。只读查询
    list_admission_events 不追加事件、不推进任何时间。

    reauthenticate_session 凭终态源会话的归属与口令创建替代会话：源会话
    仍有效时返回 denied/session_active（不校验口令、不刷新活动时间、不
    修改源会话、不记事件）；源会话已终止、已硬过期、已空闲过期、已异常
    断线或本次
    首次达到超时时，首次观察到超时只追加一条 stop 计费事件，源会话记录
    与终态原因不变，随后按 authenticate_stateful 语义校验所属用户口令，
    口令正确后检查新 session_id 重复与并发上限，通过则以
    expires_at = now + lifetime 创建新会话（快照当前空闲超时配置）并
    追加一条 start 事件；进入再次认证或并发上限判定的普通结果追加
    source 为 reauthenticate_session、携带新 session_id 的认证事件。

    get_account_status 为只读查询：按注入 now 报告该用户的锁定/解锁
    状态、失败计数、锁定截止值与最近已提交认证状态时间，服从该用户既有的
    时间单调规则；不改写认证状态、不推进已提交时间、不触碰会话，也不追加
    认证或计费事件。

    get_session_status 为只读查询：按注入 now 报告该会话的状态，服从该
    会话既有的时间单调规则（now 早于最近已提交时间抛出
    SessionTimeRegressionError，相等允许）。按既有优先级判定：主动终止
    标记存在时返回 terminated/session_terminated；已为空闲过期终态时
    返回 expired/session_idle_expired；已异常断线时返回
    disconnected/session_disconnected 并公开 disconnected_at；否则
    now 达到 expires_at 时返回 expired/session_expired；硬期限未到但
    空闲超时启用且 now 达到
    last_activity + idle_timeout 时返回 expired/session_idle_expired；
    其余返回 active、reason 为 None。即使 now 达到硬期限或空闲期限，也
    不写入终态、不推进会话最近已提交时间、不刷新 last_activity，也不追加
    认证或计费事件；不影响并发计数、准入策略、凭据与账户锁定。
    """

    def __init__(self):
        self._credentials = {}
        self._states = {}
        self._sessions = {}
        self._session_limits = {}
        self._admission_policies = {}
        self._admission_defaults = {}
        self._admission_overrides = {}
        self._idle_timeouts = {}
        self._auth_events = {}
        self._accounting_events = {}
        self._admission_events = {}

    def __contains__(self, user_id):
        return user_id in self._credentials

    def copy(self):
        clone = UserRegistry()
        clone._credentials = dict(self._credentials)
        clone._states = dict(self._states)
        clone._sessions = dict(self._sessions)
        clone._session_limits = dict(self._session_limits)
        clone._admission_policies = dict(self._admission_policies)
        clone._admission_defaults = dict(self._admission_defaults)
        clone._admission_overrides = dict(self._admission_overrides)
        clone._idle_timeouts = dict(self._idle_timeouts)
        clone._auth_events = {
            user_id: list(events)
            for user_id, events in self._auth_events.items()
        }
        clone._accounting_events = {
            session_id: list(events)
            for session_id, events in self._accounting_events.items()
        }
        clone._admission_events = {
            session_id: list(events)
            for session_id, events in self._admission_events.items()
        }
        return clone

    def append_authentication_event(
        self, user_id, source, now, status, reason, session_id
    ):
        """为用户追加一条已提交的认证事件（按调用顺序连续编号）。"""
        self._auth_events.setdefault(user_id, []).append(
            (source, now, status, reason, session_id)
        )

    def list_authentication_events(self, user_id):
        """返回该用户认证轨迹的只读副本（按提交顺序）。

        轨迹中的每条记录为
        (source, now, status, reason, session_id)，编号由调用方按
        1 起始的位置派生。不修改任何状态。未知用户抛出 UnknownUserError。
        """
        if user_id not in self._credentials:
            raise UnknownUserError(user_id)
        return list(self._auth_events.get(user_id, ()))

    def _record_accounting_stop(self, session_id, now, reason):
        """在会话首次被判为终态时追加 stop 计费事件。

        每个会话至多一条 stop：已存在 stop 事件时不改写、不追加，
        重复观察同一终态幂等。
        """
        events = self._accounting_events.get(session_id)
        if events is None:
            return
        for event_type, _event_now, _event_reason in events:
            if event_type == "stop":
                return
        events.append(("stop", now, reason))

    def list_accounting_events(self, session_id):
        """返回 (user_id, 该会话计费轨迹的只读副本)（按提交顺序）。

        轨迹中的每条记录为 (event_type, now, reason)，为一条 start、
        至多 64 条 interim 与至多一条 stop 的提交序列，编号由调用方按
        1 起始的位置派生。不修改任何状态。未知会话抛出 UnknownSessionError。
        """
        record = self._sessions.get(session_id)
        if record is None:
            raise UnknownSessionError(session_id)
        return record[0], list(self._accounting_events.get(session_id, ()))

    def append_admission_event(
        self, session_id, now, port_id, vlan_id, status, reason
    ):
        """为会话追加一条已提交的准入判定事件（按调用顺序连续编号）。

        仅在 check_admission 完成普通业务判定后由调用方追加；事件记录请求
        显式传入的 now、port_id、vlan_id 与对外返回的 status、reason，不含
        凭据材料，也不额外改变任何会话或策略状态。
        """
        self._admission_events.setdefault(session_id, []).append(
            (now, port_id, vlan_id, status, reason)
        )

    def list_admission_events(self, session_id):
        """返回 (user_id, 该会话准入判定轨迹的只读副本)（按提交顺序）。

        轨迹中的每条记录为 (now, port_id, vlan_id, status, reason)，编号由
        调用方按 1 起始的位置派生。不修改任何状态、不推进任何时间。
        未知会话抛出 UnknownSessionError。
        """
        record = self._sessions.get(session_id)
        if record is None:
            raise UnknownSessionError(session_id)
        return record[0], list(self._admission_events.get(session_id, ()))

    def register(self, user_id, password, salt):
        """登记用户；salt 为 16 字节。重复登记抛出 DuplicateUserError。"""
        if user_id in self._credentials:
            raise DuplicateUserError(user_id)
        self._credentials[user_id] = encode_credential(password, salt)

    def replace_credential(self, user_id, password, salt):
        """完整替换已登记用户的编码凭据；salt 为 16 字节。

        只更新编码凭据：不改变失败次数、锁定截止值、最近认证时间、既有
        会话及其超时、并发上限、准入策略、默认动作、覆盖规则与空闲超时
        配置，也不产生认证、准入或计费事件；相同 user_id、password、salt
        的重复提交写入相同的编码凭据，无额外状态变化。未知用户抛出
        UnknownUserError。
        """
        if user_id not in self._credentials:
            raise UnknownUserError(user_id)
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

    def unlock_account(self, user_id, now):
        """对已登记用户执行确定性的人工解锁。

        将该用户状态无条件提交为 (now, 0, None)：failed_attempts 归零、
        locked_until 置为 None，并把 now 记为最近已提交的认证状态时间。
        无论调用前处于锁定、只有累计失败、锁定已自然到期还是干净状态，
        结果相同且以相同 now 重复提交逐字节一致。服从该用户既有的时间
        单调规则：now 早于最近已提交认证状态时间时抛出
        StateRegressionError，状态不变（相等时间允许执行）。
        不校验口令、不修改编码凭据，也不产生认证或计费事件。
        未知用户抛出 UnknownUserError。
        """
        if user_id not in self._credentials:
            raise UnknownUserError(user_id)
        last_now, _failed_attempts, _locked_until = self._states.get(
            user_id, (None, 0, None)
        )
        if last_now is not None and now < last_now:
            raise StateRegressionError(user_id, now, last_now)
        self._states[user_id] = (now, 0, None)

    def get_account_status(self, user_id, now):
        """只读查询已登记用户的认证状态，不提交任何状态变化。

        返回 (status, failed_attempts, locked_until, last_authentication_at)，
        其中 last_authentication_at 为该用户最近一次已提交认证状态操作的
        now（从未进行有状态认证或人工解锁时为 None）。保存的 locked_until
        非空且 now 小于该值时返回 ("locked", 当前失败计数, 原锁定截止值)；
        now 已达到或超过该值时按既有自动到期语义报告
        ("unlocked", 0, None)，但不改写保存的状态；其余未锁定情况返回
        ("unlocked", 当前失败计数, None)。服从该用户既有的时间单调规则：
        now 早于最近已提交认证状态时间时抛出 StateRegressionError（相等
        允许）。不推进 last_now、不改变失败计数或锁定值、不创建/刷新/终止
        会话，也不追加认证或计费事件。未知用户抛出 UnknownUserError。
        """
        if user_id not in self._credentials:
            raise UnknownUserError(user_id)
        last_now, failed_attempts, locked_until = self._states.get(
            user_id, (None, 0, None)
        )
        if last_now is not None and now < last_now:
            raise StateRegressionError(user_id, now, last_now)
        if locked_until is not None:
            if now < locked_until:
                return ("locked", failed_attempts, locked_until, last_now)
            # 锁定已自然到期：按自动到期语义报告，但不提交状态变化。
            return ("unlocked", 0, None, last_now)
        return ("unlocked", failed_attempts, None, last_now)

    def authenticate_session(self, user_id, password, session_id, now, lifetime):
        """有状态认证通过后创建确定性会话。

        沿用 authenticate_stateful 的全部凭据校验、时间单调性、失败计数与
        锁定语义；仅在 accepted 时检查 session_id 重复并创建会话，过期时刻为
        now + lifetime，初始检查时间为 None。拒绝时不创建会话。
        未知用户抛出 UnknownUserError；now 回退抛出 StateRegressionError；
        session_id 已存在（含已过期的终态记录）抛出 DuplicateSessionError。

        若该用户已配置并发上限，则在口令被接受且 session_id 未使用后检查
        容量：本次 now 下属于该用户、未终止且 now 小于 expires_at 的会话
        计入并发（已过期会话保留记录但不计入）；已达到空闲期限（含已置
        空闲终态）或已异常断线的会话同样不计入，计数不刷新任何会话的
        活动时间。
        活动数达到上限时返回
        denied/session_limit_reached、expires_at 为 None，不创建会话，
        正确口令清零失败计数的效果仍提交。降低上限不终止已有会话。

        创建会话时快照该用户当前的空闲超时配置（未配置或 0 表示关闭），
        并以创建 now 作为首次活动时间；此后该用户的配置变更不影响此会话。
        """
        status, reason, _failed_attempts, _locked_until = (
            self.authenticate_stateful(user_id, password, now)
        )
        if status != "accepted":
            return ("denied", reason, None)
        if session_id in self._sessions:
            raise DuplicateSessionError(session_id)
        limit = self._session_limits.get(user_id)
        if limit is not None:
            active = 0
            for (
                session_user_id,
                expires_at,
                _last_check,
                terminated_at,
                idle_timeout,
                last_activity,
                idle_expired,
                disconnected_at,
            ) in self._sessions.values():
                if (
                    session_user_id != user_id
                    or terminated_at is not None
                    or disconnected_at is not None
                    or now >= expires_at
                    or idle_expired
                    or (
                        idle_timeout
                        and now >= last_activity + idle_timeout
                    )
                ):
                    continue
                active += 1
            if active >= limit:
                return ("denied", "session_limit_reached", None)
        expires_at = now + lifetime
        idle_timeout = self._idle_timeouts.get(user_id, 0)
        self._sessions[session_id] = (
            user_id,
            expires_at,
            None,
            None,
            idle_timeout,
            now,
            False,
            None,
        )
        # 成功创建会话：追加且仅追加一条 start 计费事件，时间取请求 now。
        self._accounting_events[session_id] = [("start", now, None)]
        return ("accepted", None, expires_at)

    def reauthenticate_session(
        self, source_session_id, session_id, password, now, lifetime
    ):
        """凭终态源会话的归属与口令创建替代会话。

        返回 (status, reason, user_id, expires_at)。先按既有优先级判定源
        会话：未知源会话抛出 UnknownSessionError；now 早于源会话最近已
        提交时间抛出 SessionTimeRegressionError，状态不变。源会话在 now
        下仍有效（未终止、未达硬期限、未达空闲期限、未异常断线）时返回
        denied/session_active：不校验口令、不刷新活动时间、不修改源会话，
        也不产生任何事件。源会话已主动终止、已硬过期、已空闲过期、已异常
        断线或本次
        首次达到超时（先硬期限后空闲期限）时，首次观察到超时只追加一条
        stop 计费事件（幂等，时间取本次 now），源会话记录与终态原因不变；
        随后按 authenticate_stateful 的失败计数、锁定与解锁语义校验所属
        用户口令（now 早于该用户最近已提交认证时间抛出
        StateRegressionError），口令错误返回 denied/invalid_password，
        锁定期间返回 denied/account_locked。口令正确后新 session_id 已
        存在（含终态记录）抛出 DuplicateSessionError；再按
        authenticate_session 的既有规则检查并发上限，达到上限返回
        denied/session_limit_reached、expires_at 为 None；否则以
        expires_at = now + lifetime 创建新会话，快照该用户当前空闲超时
        配置，并追加且仅追加一条 start 计费事件。除 session_active 外的
        普通结果由调用方追加 source 为 reauthenticate_session、携带新
        session_id 的认证事件。
        """
        record = self._sessions.get(source_session_id)
        if record is None:
            raise UnknownSessionError(source_session_id)
        (
            user_id,
            expires_at,
            last_check,
            terminated_at,
            idle_timeout,
            last_activity,
            idle_expired,
            disconnected_at,
        ) = record
        if last_check is not None and now < last_check:
            raise SessionTimeRegressionError(source_session_id, now, last_check)
        if terminated_at is None and not idle_expired and disconnected_at is None:
            if now >= expires_at:
                # 首次观察到硬过期：只追加一条 stop，源会话记录不变。
                self._record_accounting_stop(
                    source_session_id, now, "session_expired"
                )
            elif self._idle_expired_now(idle_timeout, last_activity, now):
                # 首次观察到空闲过期：只追加一条 stop，源会话记录不变。
                self._record_accounting_stop(
                    source_session_id, now, "session_idle_expired"
                )
            else:
                # 源会话仍有效：不校验口令、不刷新活动时间、不记事件。
                return ("denied", "session_active", user_id, None)
        status, reason, _failed_attempts, _locked_until = (
            self.authenticate_stateful(user_id, password, now)
        )
        if status != "accepted":
            return ("denied", reason, user_id, None)
        if session_id in self._sessions:
            raise DuplicateSessionError(session_id)
        limit = self._session_limits.get(user_id)
        if limit is not None:
            active = 0
            for (
                session_user_id,
                session_expires_at,
                _last_check,
                session_terminated_at,
                session_idle_timeout,
                session_last_activity,
                session_idle_expired,
                session_disconnected_at,
            ) in self._sessions.values():
                if (
                    session_user_id != user_id
                    or session_terminated_at is not None
                    or session_disconnected_at is not None
                    or now >= session_expires_at
                    or session_idle_expired
                    or (
                        session_idle_timeout
                        and now >= session_last_activity + session_idle_timeout
                    )
                ):
                    continue
                active += 1
            if active >= limit:
                return ("denied", "session_limit_reached", user_id, None)
        new_expires_at = now + lifetime
        new_idle_timeout = self._idle_timeouts.get(user_id, 0)
        self._sessions[session_id] = (
            user_id,
            new_expires_at,
            None,
            None,
            new_idle_timeout,
            now,
            False,
            None,
        )
        # 成功创建替代会话：追加且仅追加一条 start 计费事件，时间取请求 now。
        self._accounting_events[session_id] = [("start", now, None)]
        return ("accepted", None, user_id, new_expires_at)

    def set_session_limit(self, user_id, max_sessions):
        """为已登记用户设置并发会话上限；重复设置相同值幂等，新值覆盖旧值。

        未配置的用户不限并发。上限只约束新会话创建，不终止已有会话。
        未知用户抛出 UnknownUserError。
        """
        if user_id not in self._credentials:
            raise UnknownUserError(user_id)
        self._session_limits[user_id] = max_sessions

    def set_admission_policy(self, user_id, rules):
        """为已登记用户设置准入策略；rules 为 (port_id, vlan_id) 对的序列。

        重复提交相同策略幂等，提交不同策略完整替换旧值；空策略合法，表示
        拒绝一切准入。只替换精确规则，保留已配置的默认准入动作；不影响
        凭据、认证状态、已有会话与并发限额。未知用户抛出 UnknownUserError。
        """
        if user_id not in self._credentials:
            raise UnknownUserError(user_id)
        self._admission_policies[user_id] = frozenset(rules)

    def set_admission_default(self, user_id, default_action):
        """为已登记用户设置默认准入动作（"allow" 或 "deny"）。

        重复设置相同值幂等，新值覆盖旧值；每用户至多保存一个默认动作。
        默认动作只影响 check_admission 对未命中精确规则时的判定，不改写
        精确规则、凭据、认证状态、已有会话、并发限额或超时配置。
        未知用户抛出 UnknownUserError。
        """
        if user_id not in self._credentials:
            raise UnknownUserError(user_id)
        self._admission_defaults[user_id] = default_action

    def set_admission_overrides(self, user_id, rules):
        """为已登记用户设置有序准入覆盖规则。

        rules 为 (port_id, vlan_id, action) 三元组的序列，port_id/vlan_id
        为 None 表示该维度通配，action 为 "allow"/"deny"。新数组完整替换
        旧值并保留顺序，重复提交相同内容幂等，空数组表示清除。覆盖规则在
        check_admission 的会话有效性判定后、精确规则与默认动作之前按顺序
        采用首条匹配项；不改写精确规则、默认动作、凭据、认证状态、已有
        会话、并发限额或超时配置，也不产生认证或计费事件。
        未知用户抛出 UnknownUserError。
        """
        if user_id not in self._credentials:
            raise UnknownUserError(user_id)
        self._admission_overrides[user_id] = tuple(rules)

    def set_session_idle_timeout(self, user_id, idle_timeout):
        """为已登记用户设置会话空闲超时（秒）；0 表示关闭。

        重复设置相同值幂等，新值覆盖旧值但只作用于此后创建的会话，
        已有会话沿用创建时快照的配置。未知用户抛出 UnknownUserError。
        """
        if user_id not in self._credentials:
            raise UnknownUserError(user_id)
        self._idle_timeouts[user_id] = idle_timeout

    @staticmethod
    def _idle_expired_now(idle_timeout, last_activity, now):
        """判断启用空闲超时的会话在本次 now 下是否达到空闲期限。"""
        return bool(idle_timeout) and now >= last_activity + idle_timeout

    def check_admission(self, session_id, now, port_id, vlan_id):
        """按注入时间检查会话是否仍有效，并按所属用户策略判定端口准入。

        返回 (status, reason, user_id) 并提交本次检查时间；会话状态与
        时间单调语义同 validate_session：now 早于该会话最近已提交的检查
        时间时抛出 SessionTimeRegressionError，状态不变；已终止的会话
        一律返回 denied/session_terminated；已处于空闲过期终态的会话一律
        返回 denied/session_idle_expired；已异常断线的会话一律返回
        denied/session_disconnected；否则先判断 now >= expires_at
        返回 denied/session_expired，再判断启用了空闲超时的会话
        now >= last_activity + idle_timeout，命中则置空闲过期终态并返回
        denied/session_idle_expired。仍有效的会话先按所属用户的有序覆盖
        规则判定：按配置顺序采用首条 port_id 与 vlan_id 均匹配（null 为
        该维度通配）的规则，allow 返回 accepted、deny 返回
        denied/policy_denied；未命中覆盖规则时按所属用户策略精确匹配
        (port_id, vlan_id)：命中返回 accepted；未命中时若该用户配置了默认
        准入动作，allow 返回 accepted、deny 返回 denied/policy_denied；
        精确规则与默认动作均未配置返回 denied/policy_not_configured；
        已配置精确规则（含空集）但未配置默认动作且未命中返回
        denied/policy_denied；这些判定都以本次 now 刷新最近活动时间
        （策略拒绝也算活动）。异常、时间回退、硬过期与空闲过期均不刷新。
        每次完成普通业务判定（接受、策略拒绝、默认拒绝或会话终态拒绝）后
        由调用方为该会话追加一条准入判定事件；未知会话或时间回退抛出异常，
        不留下事件。
        未知会话抛出 UnknownSessionError。
        """
        record = self._sessions.get(session_id)
        if record is None:
            raise UnknownSessionError(session_id)
        (
            user_id,
            expires_at,
            last_check,
            terminated_at,
            idle_timeout,
            last_activity,
            idle_expired,
            disconnected_at,
        ) = record
        if last_check is not None and now < last_check:
            raise SessionTimeRegressionError(session_id, now, last_check)
        if terminated_at is not None:
            self._sessions[session_id] = (
                user_id, expires_at, now, terminated_at,
                idle_timeout, last_activity, idle_expired, disconnected_at,
            )
            return ("denied", "session_terminated", user_id)
        if idle_expired:
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, True, None,
            )
            return ("denied", "session_idle_expired", user_id)
        if disconnected_at is not None:
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, False, disconnected_at,
            )
            return ("denied", "session_disconnected", user_id)
        if now >= expires_at:
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, False, None,
            )
            self._record_accounting_stop(session_id, now, "session_expired")
            return ("denied", "session_expired", user_id)
        if self._idle_expired_now(idle_timeout, last_activity, now):
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, True, None,
            )
            self._record_accounting_stop(
                session_id, now, "session_idle_expired"
            )
            return ("denied", "session_idle_expired", user_id)
        # 会话仍有效：提交检查时间并刷新最近活动时间。
        self._sessions[session_id] = (
            user_id, expires_at, now, None, idle_timeout, now, False, None,
        )
        # 有序覆盖规则优先于精确规则与默认动作：按顺序采用首条匹配项。
        for rule_port_id, rule_vlan_id, rule_action in (
            self._admission_overrides.get(user_id, ())
        ):
            if (
                rule_port_id is None or rule_port_id == port_id
            ) and (
                rule_vlan_id is None or rule_vlan_id == vlan_id
            ):
                if rule_action == "allow":
                    return ("accepted", None, user_id)
                return ("denied", "policy_denied", user_id)
        policy = self._admission_policies.get(user_id)
        if policy is not None and (port_id, vlan_id) in policy:
            return ("accepted", None, user_id)
        default_action = self._admission_defaults.get(user_id)
        if default_action is not None:
            if default_action == "allow":
                return ("accepted", None, user_id)
            return ("denied", "policy_denied", user_id)
        if policy is None:
            return ("denied", "policy_not_configured", user_id)
        return ("denied", "policy_denied", user_id)

    def validate_session(self, session_id, now):
        """按注入时间校验会话是否仍未过期、未终止。

        返回 (status, reason, user_id, expires_at) 并提交本次检查时间：
        now 早于该会话最近已提交的检查时间时抛出 SessionTimeRegressionError，
        状态不变（相等时间允许重复检查）；已终止的会话一律返回
        denied/session_terminated；已处于空闲过期终态的会话一律返回
        denied/session_idle_expired；已异常断线的会话一律返回
        denied/session_disconnected；否则先判断硬期限：now >= expires_at
        返回 denied/session_expired，过期为终态，过期时刻不被刷新；
        再判断启用了空闲超时的会话 now >= last_activity + idle_timeout，
        命中则置空闲过期终态并返回 denied/session_idle_expired；
        否则返回 accepted 并以本次 now 刷新最近活动时间。异常、时间回退、
        硬过期与空闲过期均不刷新活动时间；用户认证状态不被触碰。
        未知会话抛出 UnknownSessionError。
        """
        record = self._sessions.get(session_id)
        if record is None:
            raise UnknownSessionError(session_id)
        (
            user_id,
            expires_at,
            last_check,
            terminated_at,
            idle_timeout,
            last_activity,
            idle_expired,
            disconnected_at,
        ) = record
        if last_check is not None and now < last_check:
            raise SessionTimeRegressionError(session_id, now, last_check)
        if terminated_at is not None:
            self._sessions[session_id] = (
                user_id, expires_at, now, terminated_at,
                idle_timeout, last_activity, idle_expired, disconnected_at,
            )
            return ("denied", "session_terminated", user_id, expires_at)
        if idle_expired:
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, True, None,
            )
            return ("denied", "session_idle_expired", user_id, expires_at)
        if disconnected_at is not None:
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, False, disconnected_at,
            )
            return ("denied", "session_disconnected", user_id, expires_at)
        if now >= expires_at:
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, False, None,
            )
            self._record_accounting_stop(session_id, now, "session_expired")
            return ("denied", "session_expired", user_id, expires_at)
        if self._idle_expired_now(idle_timeout, last_activity, now):
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, True, None,
            )
            self._record_accounting_stop(
                session_id, now, "session_idle_expired"
            )
            return ("denied", "session_idle_expired", user_id, expires_at)
        # 会话仍有效：提交检查时间并刷新最近活动时间。
        self._sessions[session_id] = (
            user_id, expires_at, now, None, idle_timeout, now, False, None,
        )
        return ("accepted", None, user_id, expires_at)

    def terminate_session(self, session_id, now):
        """按注入时间主动终止有效会话。

        返回 (status, reason, user_id, terminated_at, expires_at) 并提交本次
        时间：now 早于该会话最近已提交的时间时抛出
        SessionTimeRegressionError，状态不变（相等时间允许重复调用）；
        已终止的会话幂等返回首次 terminated_at，不改写终止时间；
        已处于空闲过期终态的会话返回 denied/session_idle_expired 且
        terminated_at 为 null；已异常断线的会话返回
        denied/session_disconnected 且 terminated_at 为 null；
        now >= expires_at 时会话保持过期终态，返回
        denied/session_expired、terminated_at 为 null，不留下终止标记；
        启用了空闲超时的会话 now >= last_activity + idle_timeout 时置空闲
        过期终态，返回 denied/session_idle_expired、terminated_at 为 null；
        否则记录 terminated_at=now 并返回 terminated。终止不刷新活动时间，
        不改变用户失败计数、锁定状态或其他会话。
        未知会话抛出 UnknownSessionError。
        """
        record = self._sessions.get(session_id)
        if record is None:
            raise UnknownSessionError(session_id)
        (
            user_id,
            expires_at,
            last_check,
            terminated_at,
            idle_timeout,
            last_activity,
            idle_expired,
            disconnected_at,
        ) = record
        if last_check is not None and now < last_check:
            raise SessionTimeRegressionError(session_id, now, last_check)
        if terminated_at is not None:
            self._sessions[session_id] = (
                user_id, expires_at, now, terminated_at,
                idle_timeout, last_activity, idle_expired, disconnected_at,
            )
            return ("terminated", None, user_id, terminated_at, expires_at)
        if idle_expired:
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, True, None,
            )
            return (
                "denied", "session_idle_expired", user_id, None, expires_at,
            )
        if disconnected_at is not None:
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, False, disconnected_at,
            )
            return (
                "denied", "session_disconnected", user_id, None, expires_at,
            )
        if now >= expires_at:
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, False, None,
            )
            self._record_accounting_stop(session_id, now, "session_expired")
            return ("denied", "session_expired", user_id, None, expires_at)
        if self._idle_expired_now(idle_timeout, last_activity, now):
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, True, None,
            )
            self._record_accounting_stop(
                session_id, now, "session_idle_expired"
            )
            return (
                "denied", "session_idle_expired", user_id, None, expires_at,
            )
        self._sessions[session_id] = (
            user_id, expires_at, now, now, idle_timeout, last_activity,
            False, None,
        )
        self._record_accounting_stop(session_id, now, "session_terminated")
        return ("terminated", None, user_id, now, expires_at)

    def report_session_disconnect(self, session_id, now):
        """按注入时间把有效会话标记为异常断线（终态）。

        返回 (status, reason, user_id, disconnected_at, expires_at) 并提交
        本次时间：now 早于该会话最近已提交的时间时抛出
        SessionTimeRegressionError，状态不变（相等时间允许重复调用）；
        未知会话抛出 UnknownSessionError。保持既有终态优先级：已主动终止、
        已空闲过期，或本次 now 已达到硬期限或空闲期限时，不写断线标记，
        分别返回 denied/session_terminated、denied/session_idle_expired
        或 denied/session_expired（disconnected_at 为 None），首次观察到
        超时仍只追加一条 stop 计费事件。会话仍有效时记录首次
        disconnected_at=now，返回 disconnected、reason 为 None，并追加
        一条时间为 now、reason 为 session_disconnected 的 stop 计费事件；
        重复报告已断线会话时保留首次 disconnected_at，幂等返回且不重复
        追加事件。断线不刷新活动时间，不改变用户认证状态或其他会话。
        """
        record = self._sessions.get(session_id)
        if record is None:
            raise UnknownSessionError(session_id)
        (
            user_id,
            expires_at,
            last_check,
            terminated_at,
            idle_timeout,
            last_activity,
            idle_expired,
            disconnected_at,
        ) = record
        if last_check is not None and now < last_check:
            raise SessionTimeRegressionError(session_id, now, last_check)
        if terminated_at is not None:
            self._sessions[session_id] = (
                user_id, expires_at, now, terminated_at,
                idle_timeout, last_activity, idle_expired, disconnected_at,
            )
            return ("denied", "session_terminated", user_id, None, expires_at)
        if idle_expired:
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, True, None,
            )
            return (
                "denied", "session_idle_expired", user_id, None, expires_at,
            )
        if disconnected_at is not None:
            # 重复报告：保留首次断线时间，不重复追加 stop 事件。
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, False, disconnected_at,
            )
            return ("disconnected", None, user_id, disconnected_at, expires_at)
        if now >= expires_at:
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, False, None,
            )
            self._record_accounting_stop(session_id, now, "session_expired")
            return ("denied", "session_expired", user_id, None, expires_at)
        if self._idle_expired_now(idle_timeout, last_activity, now):
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, True, None,
            )
            self._record_accounting_stop(
                session_id, now, "session_idle_expired"
            )
            return (
                "denied", "session_idle_expired", user_id, None, expires_at,
            )
        # 会话仍有效：记录首次断线时间并追加一条 stop 计费事件。
        self._sessions[session_id] = (
            user_id, expires_at, now, None, idle_timeout, last_activity,
            False, now,
        )
        self._record_accounting_stop(session_id, now, "session_disconnected")
        return ("disconnected", None, user_id, now, expires_at)

    def record_accounting_interim(self, session_id, now):
        """按注入时间为有效会话写入一条中间计费点。

        返回 (status, reason, user_id, sequence)：now 早于该会话最近已提交
        时间时抛出 SessionTimeRegressionError，轨迹与时间状态不变；未知会话
        抛出 UnknownSessionError。已主动终止、已空闲过期、已异常断线或已
        硬过期的会话不
        追加 interim，分别返回 denied/session_terminated、
        denied/session_idle_expired、denied/session_disconnected 或
        denied/session_expired，sequence 为
        None；本次首次观察到硬过期或空闲过期时仍只追加一条 stop，时间取本次
        now。活动会话提交成功时追加 ("interim", now, None) 并返回新事件
        编号；同一会话以相同 now 重复提交时返回原编号、不重复追加。每个会话
        最多保存 64 条 interim，达到上限后返回
        denied/accounting_interim_limit_reached、sequence 为 None，轨迹不变。
        中间计费只推进会话最近已提交时间，不刷新活动时间，不延长空闲或硬
        期限，也不改变认证、准入与并发上限状态。
        """
        record = self._sessions.get(session_id)
        if record is None:
            raise UnknownSessionError(session_id)
        (
            user_id,
            expires_at,
            last_check,
            terminated_at,
            idle_timeout,
            last_activity,
            idle_expired,
            disconnected_at,
        ) = record
        if last_check is not None and now < last_check:
            raise SessionTimeRegressionError(session_id, now, last_check)
        if terminated_at is not None:
            self._sessions[session_id] = (
                user_id, expires_at, now, terminated_at,
                idle_timeout, last_activity, idle_expired, disconnected_at,
            )
            return ("denied", "session_terminated", user_id, None)
        if idle_expired:
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, True, None,
            )
            return ("denied", "session_idle_expired", user_id, None)
        if disconnected_at is not None:
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, False, disconnected_at,
            )
            return ("denied", "session_disconnected", user_id, None)
        if now >= expires_at:
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, False, None,
            )
            self._record_accounting_stop(session_id, now, "session_expired")
            return ("denied", "session_expired", user_id, None)
        if self._idle_expired_now(idle_timeout, last_activity, now):
            self._sessions[session_id] = (
                user_id, expires_at, now, None,
                idle_timeout, last_activity, True, None,
            )
            self._record_accounting_stop(
                session_id, now, "session_idle_expired"
            )
            return ("denied", "session_idle_expired", user_id, None)
        # 会话仍有效：只推进最近已提交时间，不刷新最近活动时间。
        self._sessions[session_id] = (
            user_id, expires_at, now, None,
            idle_timeout, last_activity, False, None,
        )
        events = self._accounting_events[session_id]
        if events and events[-1][0] == "interim" and events[-1][1] == now:
            # 相同 now 的重复提交：幂等返回原编号，不重复追加。
            return ("recorded", None, user_id, len(events))
        interim_count = 0
        for event_type, _event_now, _event_reason in events:
            if event_type == "interim":
                interim_count += 1
        if interim_count >= MAX_ACCOUNTING_INTERIM_EVENTS:
            return (
                "denied", "accounting_interim_limit_reached", user_id, None,
            )
        events.append(("interim", now, None))
        return ("recorded", None, user_id, len(events))

    def get_session_status(self, session_id, now):
        """只读查询会话状态，不提交任何状态变化。

        返回 (status, reason, user_id, expires_at, terminated_at,
        idle_timeout, last_activity_at, disconnected_at)。未知会话抛出
        UnknownSessionError；
        now 早于该会话最近已提交时间时抛出 SessionTimeRegressionError
        （相等允许），状态不变。按既有优先级判定：主动终止标记存在时返回
        terminated/session_terminated；已处于空闲过期终态时返回
        expired/session_idle_expired；已异常断线时返回
        disconnected/session_disconnected；否则 now 达到 expires_at 时返回
        expired/session_expired；硬期限未到但空闲超时启用且 now 达到
        last_activity + idle_timeout 时返回 expired/session_idle_expired；
        其余返回 active、reason 为 None。未主动终止时 terminated_at 为
        None，未异常断线时 disconnected_at 为 None，空闲超时关闭时
        idle_timeout 为 0，时间值取自保存状态。
        查询不写入终态、不推进最近已提交时间、不刷新活动时间，也不追加
        认证或计费事件；即使 now 达到硬期限或空闲期限，后续校验、终止、
        计费中间点与再认证仍按既有语义首次提交终态。
        """
        record = self._sessions.get(session_id)
        if record is None:
            raise UnknownSessionError(session_id)
        (
            user_id,
            expires_at,
            last_check,
            terminated_at,
            idle_timeout,
            last_activity,
            idle_expired,
            disconnected_at,
        ) = record
        if last_check is not None and now < last_check:
            raise SessionTimeRegressionError(session_id, now, last_check)
        if terminated_at is not None:
            return (
                "terminated",
                "session_terminated",
                user_id,
                expires_at,
                terminated_at,
                idle_timeout,
                last_activity,
                disconnected_at,
            )
        if idle_expired:
            return (
                "expired",
                "session_idle_expired",
                user_id,
                expires_at,
                None,
                idle_timeout,
                last_activity,
                None,
            )
        if disconnected_at is not None:
            return (
                "disconnected",
                "session_disconnected",
                user_id,
                expires_at,
                None,
                idle_timeout,
                last_activity,
                disconnected_at,
            )
        if now >= expires_at:
            return (
                "expired",
                "session_expired",
                user_id,
                expires_at,
                None,
                idle_timeout,
                last_activity,
                None,
            )
        if self._idle_expired_now(idle_timeout, last_activity, now):
            return (
                "expired",
                "session_idle_expired",
                user_id,
                expires_at,
                None,
                idle_timeout,
                last_activity,
                None,
            )
        return (
            "active",
            None,
            user_id,
            expires_at,
            None,
            idle_timeout,
            last_activity,
            None,
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


def _validate_port_id(operation, key, index):
    """校验 port_id 字段：字符串类型、长度与不含控制字符。"""
    port_id = _validate_string_field(operation, key, index)
    if not (PORT_ID_MIN_LENGTH <= len(port_id) <= PORT_ID_MAX_LENGTH):
        raise BatchError(
            "value_error",
            index,
            "port_id must be %d..%d Unicode code points, got %d"
            % (PORT_ID_MIN_LENGTH, PORT_ID_MAX_LENGTH, len(port_id)),
            EXIT_VALUE_ERROR,
        )
    if not _is_control_free(port_id):
        raise BatchError(
            "value_error",
            index,
            "port_id must not contain control characters",
            EXIT_VALUE_ERROR,
        )
    return port_id


def _validate_vlan_id(operation, key, index):
    """校验 vlan_id 字段：JSON 整数类型与取值范围。"""
    vlan_id = _validate_integer_field(operation, key, index)
    if not (VLAN_ID_MIN <= vlan_id <= VLAN_ID_MAX):
        raise BatchError(
            "value_error",
            index,
            "vlan_id must be %d..%d, got %d"
            % (VLAN_ID_MIN, VLAN_ID_MAX, vlan_id),
            EXIT_VALUE_ERROR,
        )
    return vlan_id


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
            "field 'operation' must be 'register', 'replace_credential', "
            "'authenticate', "
            "'authenticate_stateful', 'unlock_account', "
            "'authenticate_session', "
            "'validate_session', 'terminate_session', 'set_session_limit', "
            "'set_admission_policy', 'set_admission_default', "
            "'set_admission_overrides', 'check_admission', "
            "'set_session_idle_timeout', "
            "'list_authentication_events', 'list_accounting_events', "
            "'list_admission_events', "
            "'record_accounting_interim', 'reauthenticate_session', "
            "'get_account_status', 'get_session_status' or "
            "'report_session_disconnect'",
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
        _OPERATION_REPLACE_CREDENTIAL,
        _OPERATION_AUTHENTICATE,
        _OPERATION_AUTHENTICATE_STATEFUL,
        _OPERATION_UNLOCK_ACCOUNT,
        _OPERATION_AUTHENTICATE_SESSION,
        _OPERATION_SET_SESSION_LIMIT,
        _OPERATION_SET_ADMISSION_POLICY,
        _OPERATION_SET_ADMISSION_DEFAULT,
        _OPERATION_SET_ADMISSION_OVERRIDES,
        _OPERATION_SET_SESSION_IDLE_TIMEOUT,
        _OPERATION_LIST_AUTHENTICATION_EVENTS,
        _OPERATION_GET_ACCOUNT_STATUS,
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
        _OPERATION_REPLACE_CREDENTIAL,
        _OPERATION_AUTHENTICATE,
        _OPERATION_AUTHENTICATE_STATEFUL,
        _OPERATION_AUTHENTICATE_SESSION,
        _OPERATION_REAUTHENTICATE_SESSION,
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

    if kind in (_OPERATION_REGISTER, _OPERATION_REPLACE_CREDENTIAL):
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
        _OPERATION_UNLOCK_ACCOUNT,
        _OPERATION_AUTHENTICATE_SESSION,
        _OPERATION_VALIDATE_SESSION,
        _OPERATION_TERMINATE_SESSION,
        _OPERATION_CHECK_ADMISSION,
        _OPERATION_RECORD_ACCOUNTING_INTERIM,
        _OPERATION_REAUTHENTICATE_SESSION,
        _OPERATION_GET_ACCOUNT_STATUS,
        _OPERATION_GET_SESSION_STATUS,
        _OPERATION_REPORT_SESSION_DISCONNECT,
    ):
        now = _validate_now_type(index, operation)
        # now 沿用现有限制（0..MAX_NOW 且为锁定时长预留空间）；
        # authenticate_session 与 reauthenticate_session 额外要求
        # now+lifetime 不越界，在 lifetime 校验后复查。
        _validate_now_range(index, now, LOCK_DURATION_SECONDS)
        validated["now"] = now

    if kind in (
        _OPERATION_AUTHENTICATE_SESSION,
        _OPERATION_VALIDATE_SESSION,
        _OPERATION_TERMINATE_SESSION,
        _OPERATION_CHECK_ADMISSION,
        _OPERATION_LIST_ACCOUNTING_EVENTS,
        _OPERATION_LIST_ADMISSION_EVENTS,
        _OPERATION_RECORD_ACCOUNTING_INTERIM,
        _OPERATION_REAUTHENTICATE_SESSION,
        _OPERATION_GET_SESSION_STATUS,
        _OPERATION_REPORT_SESSION_DISCONNECT,
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

    if kind == _OPERATION_REAUTHENTICATE_SESSION:
        source_session_id = _validate_string_field(
            operation, "source_session_id", index
        )
        if not (
            SESSION_ID_MIN_LENGTH
            <= len(source_session_id)
            <= SESSION_ID_MAX_LENGTH
        ):
            raise BatchError(
                "value_error",
                index,
                "source_session_id must be %d..%d Unicode code points, got %d"
                % (
                    SESSION_ID_MIN_LENGTH,
                    SESSION_ID_MAX_LENGTH,
                    len(source_session_id),
                ),
                EXIT_VALUE_ERROR,
            )
        if not _is_control_free(source_session_id):
            raise BatchError(
                "value_error",
                index,
                "source_session_id must not contain control characters",
                EXIT_VALUE_ERROR,
            )
        validated["source_session_id"] = source_session_id

    if kind in (
        _OPERATION_AUTHENTICATE_SESSION,
        _OPERATION_REAUTHENTICATE_SESSION,
    ):
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

    if kind == _OPERATION_SET_SESSION_LIMIT:
        max_sessions = _validate_integer_field(
            operation, "max_sessions", index
        )
        if not (MAX_SESSIONS_MIN <= max_sessions <= MAX_SESSIONS_MAX):
            raise BatchError(
                "value_error",
                index,
                "max_sessions must be %d..%d, got %d"
                % (MAX_SESSIONS_MIN, MAX_SESSIONS_MAX, max_sessions),
                EXIT_VALUE_ERROR,
            )
        validated["max_sessions"] = max_sessions

    if kind == _OPERATION_SET_SESSION_IDLE_TIMEOUT:
        idle_timeout = _validate_integer_field(
            operation, "idle_timeout", index
        )
        if not (IDLE_TIMEOUT_MIN <= idle_timeout <= IDLE_TIMEOUT_MAX):
            raise BatchError(
                "value_error",
                index,
                "idle_timeout must be %d..%d, got %d"
                % (IDLE_TIMEOUT_MIN, IDLE_TIMEOUT_MAX, idle_timeout),
                EXIT_VALUE_ERROR,
            )
        validated["idle_timeout"] = idle_timeout

    if kind == _OPERATION_SET_ADMISSION_POLICY:
        rules = operation.get("rules")
        if not isinstance(rules, list):
            raise BatchError(
                "parameter_error",
                index,
                "field 'rules' must be an array",
                EXIT_PARAMETER_ERROR,
            )
        # 先完成全部结构/类型校验（parameter_error），再做取值校验
        # （value_error），保证错误分型与字段顺序无关。
        for rule_index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise BatchError(
                    "parameter_error",
                    index,
                    "rules[%d] must be a JSON object" % rule_index,
                    EXIT_PARAMETER_ERROR,
                )
            if set(rule) != {"port_id", "vlan_id"}:
                raise BatchError(
                    "parameter_error",
                    index,
                    "rules[%d] must contain exactly 'port_id' and 'vlan_id'"
                    % rule_index,
                    EXIT_PARAMETER_ERROR,
                )
            if not isinstance(rule["port_id"], str):
                raise BatchError(
                    "parameter_error",
                    index,
                    "rules[%d].port_id must be a string" % rule_index,
                    EXIT_PARAMETER_ERROR,
                )
            vlan_id = rule["vlan_id"]
            if isinstance(vlan_id, bool) or not isinstance(vlan_id, int):
                raise BatchError(
                    "parameter_error",
                    index,
                    "rules[%d].vlan_id must be a JSON integer" % rule_index,
                    EXIT_PARAMETER_ERROR,
                )
        if len(rules) > MAX_POLICY_RULES:
            raise BatchError(
                "value_error",
                index,
                "rules must contain at most %d entries, got %d"
                % (MAX_POLICY_RULES, len(rules)),
                EXIT_VALUE_ERROR,
            )
        pairs = []
        for rule_index, rule in enumerate(rules):
            pairs.append(
                (
                    _validate_port_id(rule, "port_id", index),
                    _validate_vlan_id(rule, "vlan_id", index),
                )
            )
        if len(set(pairs)) != len(pairs):
            raise BatchError(
                "value_error",
                index,
                "rules must not contain duplicate (port_id, vlan_id) pairs",
                EXIT_VALUE_ERROR,
            )
        validated["rules"] = pairs

    if kind == _OPERATION_SET_ADMISSION_DEFAULT:
        default_action = _validate_string_field(
            operation, "default_action", index
        )
        if default_action not in ("allow", "deny"):
            raise BatchError(
                "value_error",
                index,
                "default_action must be 'allow' or 'deny', got %r"
                % default_action,
                EXIT_VALUE_ERROR,
            )
        validated["default_action"] = default_action

    if kind == _OPERATION_SET_ADMISSION_OVERRIDES:
        rules = operation.get("rules")
        if not isinstance(rules, list):
            raise BatchError(
                "parameter_error",
                index,
                "field 'rules' must be an array",
                EXIT_PARAMETER_ERROR,
            )
        # 先完成全部结构/类型校验（parameter_error），再做取值校验
        # （value_error），保证错误分型与字段顺序无关。
        for rule_index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise BatchError(
                    "parameter_error",
                    index,
                    "rules[%d] must be a JSON object" % rule_index,
                    EXIT_PARAMETER_ERROR,
                )
            if set(rule) != {"port_id", "vlan_id", "action"}:
                raise BatchError(
                    "parameter_error",
                    index,
                    "rules[%d] must contain exactly 'port_id', 'vlan_id' "
                    "and 'action'" % rule_index,
                    EXIT_PARAMETER_ERROR,
                )
            port_id = rule["port_id"]
            if port_id is not None and not isinstance(port_id, str):
                raise BatchError(
                    "parameter_error",
                    index,
                    "rules[%d].port_id must be a string or null" % rule_index,
                    EXIT_PARAMETER_ERROR,
                )
            vlan_id = rule["vlan_id"]
            if vlan_id is not None and (
                isinstance(vlan_id, bool) or not isinstance(vlan_id, int)
            ):
                raise BatchError(
                    "parameter_error",
                    index,
                    "rules[%d].vlan_id must be a JSON integer or null"
                    % rule_index,
                    EXIT_PARAMETER_ERROR,
                )
            if not isinstance(rule["action"], str):
                raise BatchError(
                    "parameter_error",
                    index,
                    "rules[%d].action must be a string" % rule_index,
                    EXIT_PARAMETER_ERROR,
                )
        if len(rules) > MAX_OVERRIDE_RULES:
            raise BatchError(
                "value_error",
                index,
                "rules must contain at most %d entries, got %d"
                % (MAX_OVERRIDE_RULES, len(rules)),
                EXIT_VALUE_ERROR,
            )
        triples = []
        for rule in rules:
            port_id = rule["port_id"]
            if port_id is not None:
                _validate_port_id(rule, "port_id", index)
            vlan_id = rule["vlan_id"]
            if vlan_id is not None:
                _validate_vlan_id(rule, "vlan_id", index)
            action = rule["action"]
            if action not in ("allow", "deny"):
                raise BatchError(
                    "value_error",
                    index,
                    "action must be 'allow' or 'deny', got %r" % action,
                    EXIT_VALUE_ERROR,
                )
            triples.append((port_id, vlan_id, action))
        validated["rules"] = triples

    if kind == _OPERATION_CHECK_ADMISSION:
        validated["port_id"] = _validate_port_id(operation, "port_id", index)
        validated["vlan_id"] = _validate_vlan_id(operation, "vlan_id", index)

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
        elif kind == _OPERATION_REPLACE_CREDENTIAL:
            user_id = op["user_id"]
            try:
                working.replace_credential(
                    user_id, op["password"], op["salt"]
                )
            except UnknownUserError:
                raise BatchError(
                    "unknown_user",
                    index,
                    "user not registered: %s" % user_id,
                    EXIT_UNKNOWN_USER,
                )
            # 凭据替换不视为认证：不改变认证状态、会话与策略，也不产生
            # 认证、准入或计费事件；相同输入重复提交写入相同编码凭据。
            results.append(
                {
                    "operation": _OPERATION_REPLACE_CREDENTIAL,
                    "user_id": user_id,
                    "status": "updated",
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
            working.append_authentication_event(
                user_id,
                _OPERATION_AUTHENTICATE_STATEFUL,
                op["now"],
                status,
                reason,
                None,
            )
        elif kind == _OPERATION_UNLOCK_ACCOUNT:
            user_id = op["user_id"]
            try:
                working.unlock_account(user_id, op["now"])
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
            # 人工解锁不校验口令、不产生认证或计费事件；所有起始状态
            # （锁定、累计失败、锁定已自然到期、干净状态）均返回同一结果。
            results.append(
                {
                    "operation": _OPERATION_UNLOCK_ACCOUNT,
                    "user_id": user_id,
                    "status": "unlocked",
                    "reason": None,
                    "failed_attempts": 0,
                    "locked_until": None,
                }
            )
        elif kind == _OPERATION_GET_ACCOUNT_STATUS:
            user_id = op["user_id"]
            try:
                status, failed_attempts, locked_until, last_now = (
                    working.get_account_status(user_id, op["now"])
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
            # 只读：不改写认证状态、不推进 last_now、不触碰会话，也不追加
            # 认证或计费事件；在副本上查询，批次失败时整体回滚。
            results.append(
                {
                    "operation": _OPERATION_GET_ACCOUNT_STATUS,
                    "user_id": user_id,
                    "status": status,
                    "failed_attempts": failed_attempts,
                    "locked_until": locked_until,
                    "last_authentication_at": last_now,
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
            # 接受、口令拒绝、锁定与达到并发上限都记录请求中的 session_id；
            # 重复 session_id 在上方作为整批异常抛出，不会到达这里。
            working.append_authentication_event(
                user_id,
                _OPERATION_AUTHENTICATE_SESSION,
                op["now"],
                status,
                reason,
                session_id,
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
        elif kind == _OPERATION_SET_SESSION_LIMIT:
            user_id = op["user_id"]
            try:
                working.set_session_limit(user_id, op["max_sessions"])
            except UnknownUserError:
                raise BatchError(
                    "unknown_user",
                    index,
                    "user not registered: %s" % user_id,
                    EXIT_UNKNOWN_USER,
                )
            results.append(
                {
                    "operation": _OPERATION_SET_SESSION_LIMIT,
                    "user_id": user_id,
                    "status": "configured",
                    "max_sessions": op["max_sessions"],
                }
            )
        elif kind == _OPERATION_SET_ADMISSION_POLICY:
            user_id = op["user_id"]
            try:
                working.set_admission_policy(user_id, op["rules"])
            except UnknownUserError:
                raise BatchError(
                    "unknown_user",
                    index,
                    "user not registered: %s" % user_id,
                    EXIT_UNKNOWN_USER,
                )
            results.append(
                {
                    "operation": _OPERATION_SET_ADMISSION_POLICY,
                    "user_id": user_id,
                    "status": "configured",
                    "rule_count": len(op["rules"]),
                }
            )
        elif kind == _OPERATION_SET_ADMISSION_DEFAULT:
            user_id = op["user_id"]
            try:
                working.set_admission_default(user_id, op["default_action"])
            except UnknownUserError:
                raise BatchError(
                    "unknown_user",
                    index,
                    "user not registered: %s" % user_id,
                    EXIT_UNKNOWN_USER,
                )
            results.append(
                {
                    "operation": _OPERATION_SET_ADMISSION_DEFAULT,
                    "user_id": user_id,
                    "status": "configured",
                    "default_action": op["default_action"],
                }
            )
        elif kind == _OPERATION_SET_ADMISSION_OVERRIDES:
            user_id = op["user_id"]
            try:
                working.set_admission_overrides(user_id, op["rules"])
            except UnknownUserError:
                raise BatchError(
                    "unknown_user",
                    index,
                    "user not registered: %s" % user_id,
                    EXIT_UNKNOWN_USER,
                )
            results.append(
                {
                    "operation": _OPERATION_SET_ADMISSION_OVERRIDES,
                    "user_id": user_id,
                    "status": "configured",
                    "rule_count": len(op["rules"]),
                }
            )
        elif kind == _OPERATION_SET_SESSION_IDLE_TIMEOUT:
            user_id = op["user_id"]
            try:
                working.set_session_idle_timeout(
                    user_id, op["idle_timeout"]
                )
            except UnknownUserError:
                raise BatchError(
                    "unknown_user",
                    index,
                    "user not registered: %s" % user_id,
                    EXIT_UNKNOWN_USER,
                )
            results.append(
                {
                    "operation": _OPERATION_SET_SESSION_IDLE_TIMEOUT,
                    "user_id": user_id,
                    "status": "configured",
                    "idle_timeout": op["idle_timeout"],
                }
            )
        elif kind == _OPERATION_CHECK_ADMISSION:
            session_id = op["session_id"]
            try:
                status, reason, session_user_id = working.check_admission(
                    session_id, op["now"], op["port_id"], op["vlan_id"]
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
                    "operation": _OPERATION_CHECK_ADMISSION,
                    "session_id": session_id,
                    "user_id": session_user_id,
                    "port_id": op["port_id"],
                    "vlan_id": op["vlan_id"],
                    "status": status,
                    "reason": reason,
                }
            )
            # 接受、策略拒绝、默认拒绝与会话终态拒绝都是已提交的普通判定，
            # 一律如实追加一条事件；未知会话与时间回退在上方作为整批异常
            # 抛出，不会到达这里。
            working.append_admission_event(
                session_id,
                op["now"],
                op["port_id"],
                op["vlan_id"],
                status,
                reason,
            )
        elif kind == _OPERATION_LIST_ADMISSION_EVENTS:
            session_id = op["session_id"]
            try:
                session_user_id, events = working.list_admission_events(
                    session_id
                )
            except UnknownSessionError:
                raise BatchError(
                    "unknown_session",
                    index,
                    "session not found: %s" % session_id,
                    EXIT_UNKNOWN_SESSION,
                )
            # 只读：不推进任何时间、不改变状态、不追加事件；在副本上查询
            # 即可反映本批先前已提交的事件，批次失败时整体回滚。
            results.append(
                {
                    "operation": _OPERATION_LIST_ADMISSION_EVENTS,
                    "session_id": session_id,
                    "user_id": session_user_id,
                    "status": "reported",
                    "event_count": len(events),
                    "events": [
                        {
                            "sequence": sequence,
                            "now": now,
                            "port_id": port_id,
                            "vlan_id": vlan_id,
                            "status": status,
                            "reason": reason,
                        }
                        for sequence, (
                            now,
                            port_id,
                            vlan_id,
                            status,
                            reason,
                        ) in enumerate(events, start=1)
                    ],
                }
            )
        elif kind == _OPERATION_LIST_AUTHENTICATION_EVENTS:
            user_id = op["user_id"]
            try:
                events = working.list_authentication_events(user_id)
            except UnknownUserError:
                raise BatchError(
                    "unknown_user",
                    index,
                    "user not registered: %s" % user_id,
                    EXIT_UNKNOWN_USER,
                )
            # 只读：不推进任何时间、不改变状态、不追加事件；在副本上查询
            # 即可反映本批先前已提交的事件，批次失败时整体回滚。
            results.append(
                {
                    "operation": _OPERATION_LIST_AUTHENTICATION_EVENTS,
                    "user_id": user_id,
                    "status": "reported",
                    "event_count": len(events),
                    "events": [
                        {
                            "sequence": sequence,
                            "source": source,
                            "now": now,
                            "status": status,
                            "reason": reason,
                            "session_id": session_id,
                        }
                        for sequence, (
                            source,
                            now,
                            status,
                            reason,
                            session_id,
                        ) in enumerate(events, start=1)
                    ],
                }
            )
        elif kind == _OPERATION_LIST_ACCOUNTING_EVENTS:
            session_id = op["session_id"]
            try:
                session_user_id, events = working.list_accounting_events(
                    session_id
                )
            except UnknownSessionError:
                raise BatchError(
                    "unknown_session",
                    index,
                    "session not found: %s" % session_id,
                    EXIT_UNKNOWN_SESSION,
                )
            # 只读：不推进任何时间、不改变状态、不追加事件；在副本上查询
            # 即可反映本批先前已提交的事件，批次失败时整体回滚。
            results.append(
                {
                    "operation": _OPERATION_LIST_ACCOUNTING_EVENTS,
                    "session_id": session_id,
                    "user_id": session_user_id,
                    "status": "reported",
                    "event_count": len(events),
                    "events": [
                        {
                            "sequence": sequence,
                            "event_type": event_type,
                            "now": now,
                            "reason": reason,
                        }
                        for sequence, (event_type, now, reason) in enumerate(
                            events, start=1
                        )
                    ],
                }
            )
        elif kind == _OPERATION_RECORD_ACCOUNTING_INTERIM:
            session_id = op["session_id"]
            try:
                status, reason, session_user_id, sequence = (
                    working.record_accounting_interim(session_id, op["now"])
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
                    "operation": _OPERATION_RECORD_ACCOUNTING_INTERIM,
                    "session_id": session_id,
                    "user_id": session_user_id,
                    "status": status,
                    "reason": reason,
                    "sequence": sequence,
                }
            )
        elif kind == _OPERATION_REAUTHENTICATE_SESSION:
            source_session_id = op["source_session_id"]
            session_id = op["session_id"]
            try:
                status, reason, session_user_id, expires_at = (
                    working.reauthenticate_session(
                        source_session_id,
                        session_id,
                        op["password"],
                        op["now"],
                        op["lifetime"],
                    )
                )
            except UnknownSessionError:
                raise BatchError(
                    "unknown_session",
                    index,
                    "session not found: %s" % source_session_id,
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
                    "operation": _OPERATION_REAUTHENTICATE_SESSION,
                    "source_session_id": source_session_id,
                    "session_id": session_id,
                    "user_id": session_user_id,
                    "status": status,
                    "reason": reason,
                    "expires_at": expires_at,
                }
            )
            # session_active 未进入再次认证，不记事件；进入再次认证或并发
            # 上限判定的普通结果（接受、口令拒绝、锁定、并发上限）都记录
            # source 为 reauthenticate_session、携带新 session_id 的事件。
            if reason != "session_active":
                working.append_authentication_event(
                    session_user_id,
                    _OPERATION_REAUTHENTICATE_SESSION,
                    op["now"],
                    status,
                    reason,
                    session_id,
                )
        elif kind == _OPERATION_GET_SESSION_STATUS:
            session_id = op["session_id"]
            try:
                (
                    status,
                    reason,
                    session_user_id,
                    expires_at,
                    terminated_at,
                    idle_timeout,
                    last_activity_at,
                    disconnected_at,
                ) = working.get_session_status(session_id, op["now"])
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
            # 只读：不写入终态、不推进会话时间、不刷新活动时间，也不追加
            # 认证或计费事件；在副本上查询，批次失败时整体回滚。
            results.append(
                {
                    "operation": _OPERATION_GET_SESSION_STATUS,
                    "session_id": session_id,
                    "user_id": session_user_id,
                    "status": status,
                    "reason": reason,
                    "expires_at": expires_at,
                    "terminated_at": terminated_at,
                    "idle_timeout": idle_timeout,
                    "last_activity_at": last_activity_at,
                    "disconnected_at": disconnected_at,
                }
            )
        elif kind == _OPERATION_REPORT_SESSION_DISCONNECT:
            session_id = op["session_id"]
            try:
                (
                    status,
                    reason,
                    session_user_id,
                    disconnected_at,
                    expires_at,
                ) = working.report_session_disconnect(session_id, op["now"])
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
                    "operation": _OPERATION_REPORT_SESSION_DISCONNECT,
                    "session_id": session_id,
                    "user_id": session_user_id,
                    "status": status,
                    "reason": reason,
                    "disconnected_at": disconnected_at,
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
    registry._session_limits = working._session_limits
    registry._admission_policies = working._admission_policies
    registry._admission_defaults = working._admission_defaults
    registry._admission_overrides = working._admission_overrides
    registry._idle_timeouts = working._idle_timeouts
    registry._auth_events = working._auth_events
    registry._accounting_events = working._accounting_events
    registry._admission_events = working._admission_events
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
            "register / replace_credential / authenticate / authenticate_stateful /\n"
            "unlock_account / authenticate_session / validate_session /\n"
            "terminate_session / set_session_limit / set_admission_policy /\n"
            "set_admission_default / set_admission_overrides /\n"
            "check_admission / set_session_idle_timeout /\n"
            "list_authentication_events / list_accounting_events /\n"
            "list_admission_events /\n"
            "record_accounting_interim / reauthenticate_session /\n"
            "get_account_status / get_session_status /\n"
            "report_session_disconnect 操作，\n"
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
            "  salt (仅 register 与 replace_credential): 恰好 32 个十六进制字符，\n"
            "  表示 16 字节。\n"
            "  now (有状态操作): 0..9007199254740991 的 JSON 整数，\n"
            "  表示调用方注入的秒数；功能不读取系统时间。\n"
            "  session_id (会话操作): 字符串，1..64 个 Unicode 码点，不含控制字符。\n"
            "  lifetime (仅 authenticate_session): 1..86400 的 JSON 整数秒，\n"
            "  且 now+lifetime 不得超过 9007199254740991。\n"
            "  max_sessions (仅 set_session_limit): 0..64 的 JSON 整数。\n"
            "  idle_timeout (仅 set_session_idle_timeout): 0..86400 的 JSON 整数秒，\n"
            "  0 表示关闭空闲超时。\n"
            "  port_id (准入操作): 字符串，1..64 个 Unicode 码点，不含控制字符。\n"
            "  vlan_id (准入操作): 1..4094 的 JSON 整数。\n"
            "  rules (仅 set_admission_policy): 最多 64 项的 JSON 数组，每项为仅含\n"
            "  port_id 与 vlan_id 的对象；(port_id, vlan_id) 匹配对不得重复，\n"
            "  顺序不影响策略语义。\n"
            "  default_action (仅 set_admission_default): 字符串 'allow' 或 'deny'。\n"
            "  rules (仅 set_admission_overrides): 最多 64 项的 JSON 数组，每项为\n"
            "  仅含 port_id、vlan_id 与 action 的对象；port_id 为 null 或同上的\n"
            "  端口标识，vlan_id 为 null 或 1..4094 的 JSON 整数，null 表示该维度\n"
            "  通配；action 为字符串 'allow' 或 'deny'。\n"
            "  字符串按原值处理：不去空白、不改大小写、不做 Unicode 归一化。\n"
            "  操作对象只允许上述字段；凭据编码为\n"
            "  pbkdf2_sha256$200000$盐十六进制$摘要十六进制，输出不含明文口令。\n"
            "replace_credential:\n"
            "  确定性替换一个已登记用户的口令与盐，接收 operation、user_id、\n"
            "  password、salt，字段约束同 register；不重新登记用户。成功时完整\n"
            "  替换该用户的编码凭据，后续所有认证入口只接受新口令；相同 user_id、\n"
            "  password、salt 的重复提交返回逐字节相同结果且无额外状态变化。\n"
            "  凭据替换不视为认证，也不等同于人工解锁：不改变失败次数、\n"
            "  locked_until、最近认证时间、现有会话及其超时、并发上限、准入\n"
            "  策略、默认动作与覆盖规则，也不产生认证、准入或计费事件；已锁定\n"
            "  账户更新后仍保持原锁定状态。未知 user_id 整批 unknown_user\n"
            "  （退出码 5）。结果固定键序为 operation、user_id、status，\n"
            "  status 为 updated。\n"
            "authenticate_stateful:\n"
            "  每个用户独立保存最后一次已提交 now、失败次数与锁定截止值。\n"
            "  口令错误计一次失败，第三次失败锁定至 now+300；锁定期间返回\n"
            "  denied/account_locked 且不计数；now 到达截止值后先解锁再校验。\n"
            "  口令正确返回 accepted 并清零计数与截止值。同一用户的 now 不得\n"
            "  早于上次已提交时间（相等合法），否则整批 state_error。\n"
            "unlock_account:\n"
            "  对已登记用户执行确定性的人工解锁，接收 user_id 与 now，字段约束\n"
            "  同 authenticate_stateful（now 显式注入，不读取系统时间），不校验\n"
            "  口令。now 早于该用户最近已提交认证状态时间时整批 state_error\n"
            "  （退出码 6，状态不变，相等时间允许）；未知用户整批 unknown_user\n"
            "  （退出码 5）。成功后 failed_attempts 归零、locked_until 置为\n"
            "  null，并把 now 记为最近已提交认证状态时间；无论调用前处于锁定、\n"
            "  只有累计失败、锁定已自然到期还是干净状态，都返回同一个幂等结果，\n"
            "  以相同 now 重复提交逐字节一致。人工解锁不修改编码凭据、不影响\n"
            "  无状态 authenticate、既有会话及其超时、并发限额与准入策略，也不\n"
            "  产生认证或计费事件；解锁后的新失败从一次重新累计，原有的自动到期\n"
            "  解锁、锁定期间拒绝与成功认证清零语义保持不变。结果固定键序为\n"
            "  operation、user_id、status、reason、failed_attempts、\n"
            "  locked_until；status 为 unlocked，reason 与 locked_until 为 null，\n"
            "  failed_attempts 为 0。\n"
            "authenticate_session:\n"
            "  沿用 authenticate_stateful 的凭据校验、时间单调性、失败计数与\n"
            "  锁定语义；accepted 时创建内存会话，expires_at=now+lifetime，\n"
            "  拒绝时不创建会话，expires_at 为 null。session_id 重复（含已过期\n"
            "  的终态会话）整批 duplicate_session。若该用户已通过\n"
            "  set_session_limit 配置并发上限，则在口令被接受且 session_id\n"
            "  未使用后检查容量：本次 now 下属于该用户、未终止且 now 小于\n"
            "  expires_at 的会话计入并发（已过期会话保留记录但不计入）；\n"
            "  活动数达到上限时返回 denied/session_limit_reached、expires_at\n"
            "  为 null，不创建会话，正确口令清零失败计数的效果仍提交。\n"
            "  已达到空闲期限的会话不计入并发，计数不刷新活动时间。创建会话时\n"
            "  快照该用户当前的空闲超时配置（未配置或 0 表示关闭），并以创建\n"
            "  now 作为首次活动时间；lifetime 仍是不可延长的硬期限。\n"
            "  结果键序为 operation、user_id、session_id、status、reason、\n"
            "  expires_at。\n"
            "validate_session:\n"
            "  now 早于该会话最近已提交的检查时间时整批 state_error（状态不变，\n"
            "  相等时间允许重复检查）；已终止的会话一律返回\n"
            "  denied/session_terminated；已处于空闲过期终态的会话一律返回\n"
            "  denied/session_idle_expired；否则先判断硬期限：now 达到或超过\n"
            "  expires_at 返回 denied/session_expired，过期为终态，不刷新过期\n"
            "  时刻；再判断启用了空闲超时的会话 now 是否达到\n"
            "  最近活动时间+idle_timeout，命中则置空闲过期终态并返回\n"
            "  denied/session_idle_expired；否则返回 accepted 并以本次 now\n"
            "  刷新最近活动时间。异常、时间回退、硬过期与空闲过期均不刷新\n"
            "  活动时间，也不改变用户认证状态。未知 session_id 整批\n"
            "  unknown_session。\n"
            "  结果键序为 operation、session_id、user_id、status、reason、\n"
            "  expires_at。会话仅驻留当前进程。\n"
            "terminate_session:\n"
            "  主动终止有效会话，字段与校验规则同 validate_session。\n"
            "  now 早于该会话最近已提交的时间时整批 state_error（状态不变，\n"
            "  相等时间允许重复调用）；已终止的会话幂等返回首次 terminated_at；\n"
            "  已处于空闲过期终态的会话返回 denied/session_idle_expired 且\n"
            "  terminated_at 为 null；now 达到或超过 expires_at 时会话保持过期\n"
            "  终态，返回 denied/session_expired 且 terminated_at 为 null；\n"
            "  启用了空闲超时的会话 now 达到 最近活动时间+idle_timeout 时置空闲\n"
            "  过期终态，返回 denied/session_idle_expired 且 terminated_at 为\n"
            "  null；否则记录 terminated_at=now 并返回 terminated、reason 为 null。\n"
            "  终止不刷新活动时间。\n"
            "  终止不改变用户失败计数、锁定状态或其他会话；未知 session_id\n"
            "  整批 unknown_session。结果键序为 operation、session_id、user_id、\n"
            "  status、reason、terminated_at、expires_at。\n"
            "set_session_limit:\n"
            "  为已登记用户设置进程内并发会话上限，接收 user_id 与 max_sessions\n"
            "  （0..64 的 JSON 整数）。未配置的用户默认不限并发；重复提交相同值\n"
            "  结果不变，提交新值覆盖旧值。上限只在 authenticate_session 创建\n"
            "  新会话时生效：在本次 now 下属于该用户、未主动终止且 now 小于\n"
            "  expires_at 的会话计入并发，已过期会话保留记录但不计入；达到上限\n"
            "  时拒绝新会话（denied/session_limit_reached），不终止已有会话，\n"
            "  降低上限亦然，直至活动数低于上限。引用未知用户整批 unknown_user。\n"
            "  结果键序为 operation、user_id、status、max_sessions，status 为\n"
            "  configured。\n"
            "set_admission_policy:\n"
            "  为已登记用户设置准入策略，接收 user_id 与 rules。rules 是最多 64 项\n"
            "  的 JSON 数组，每项为仅含 port_id 与 vlan_id 的对象；port_id 为\n"
            "  1..64 个无控制字符 (Cc) 的 Unicode 码点，vlan_id 为 1..4094 的\n"
            "  JSON 整数；(port_id, vlan_id) 匹配对不得重复，顺序不影响策略语义。\n"
            "  未配置或空策略均默认拒绝准入。重复提交相同策略幂等，提交不同策略\n"
            "  完整替换旧值；只替换精确规则，保留已配置的默认准入动作；不影响\n"
            "  凭据、认证状态、已有会话与并发限额。引用未知\n"
            "  用户整批 unknown_user。结果键序为 operation、user_id、status、\n"
            "  rule_count，status 为 configured。\n"
            "set_admission_default:\n"
            "  为已登记用户设置默认准入动作，接收 user_id 与 default_action\n"
            "  （字符串 'allow' 或 'deny'）。重复设置相同值幂等，新值覆盖旧值；\n"
            "  每用户至多保存一个默认动作。默认动作只影响 check_admission 对未命中\n"
            "  精确规则时的判定，适用于所有合法端口和 VLAN；只配置默认动作而没有\n"
            "  精确规则也视为策略已配置。设置默认动作不改写精确规则、凭据、认证\n"
            "  状态、已有会话、并发限额或超时配置；已有活动会话在下一次\n"
            "  check_admission 时使用新值。引用未知用户整批 unknown_user。\n"
            "  结果键序为 operation、user_id、status、default_action，status 为\n"
            "  configured。\n"
            "set_admission_overrides:\n"
            "  为已登记用户配置有序准入覆盖规则，接收 user_id 与 rules。rules 是\n"
            "  最多 64 项的 JSON 数组，每项为仅含 port_id、vlan_id 与 action 的\n"
            "  对象；port_id 为 null 或 1..64 个无控制字符 (Cc) 的 Unicode 码点，\n"
            "  vlan_id 为 null 或 1..4094 的 JSON 整数，null 表示该维度通配；\n"
            "  action 为字符串 'allow' 或 'deny'。check_admission 在会话有效性\n"
            "  判定后、精确规则与默认动作之前按数组顺序采用首条匹配的覆盖规则：\n"
            "  allow 返回 accepted 且 reason 为 null，deny 返回\n"
            "  denied/policy_denied；未命中则继续精确规则与默认动作判定。新数组\n"
            "  完整替换旧值并保留顺序，重复提交相同内容幂等，空数组表示清除。\n"
            "  覆盖规则只影响 check_admission 的判定，不改写精确规则、默认动作、\n"
            "  凭据、认证状态、已有会话、并发限额或超时配置，不改变终止、硬过期\n"
            "  与空闲过期的优先级及活动时间刷新规则，也不产生认证或计费事件。\n"
            "  引用未知用户整批 unknown_user。结果键序为 operation、user_id、\n"
            "  status、rule_count，status 为 configured。\n"
            "check_admission:\n"
            "  按注入时间检查会话有效性并按所属用户策略判定端口准入，接收\n"
            "  session_id、now、port_id、vlan_id，字段约束同上。会话状态与时间\n"
            "  单调语义同 validate_session：now 早于该会话最近已提交的检查时间\n"
            "  整批 state_error（状态不变，相等时间允许重复检查）；未知\n"
            "  session_id 整批 unknown_session。已终止的会话返回\n"
            "  denied/session_terminated；已处于空闲过期终态的会话返回\n"
            "  denied/session_idle_expired；已过期的会话返回 denied/session_expired；\n"
            "  启用了空闲超时的会话 now 达到 最近活动时间+idle_timeout 时置空闲\n"
            "  过期终态并返回 denied/session_idle_expired；仍有效的会话先按所属\n"
            "  用户的有序覆盖规则（见 set_admission_overrides）采用首条匹配项，\n"
            "  未命中时按所属用户策略精确匹配 (port_id, vlan_id)：命中返回\n"
            "  accepted 且 reason 为 null；未命中时若该用户配置了默认准入动作，\n"
            "  allow 返回 accepted 且 reason 为 null，deny 返回\n"
            "  denied/policy_denied；精确规则与默认动作均未配置返回\n"
            "  denied/policy_not_configured；已配置精确规则（含空集）但未配置默认\n"
            "  动作且未命中返回 denied/policy_denied。对仍有效会话的判定（含策略\n"
            "  拒绝）以本次 now\n"
            "  刷新最近活动时间；异常、时间回退、硬过期与空闲过期均不刷新。\n"
            "  正常判定均提交本次会话检查时间，异常则整批\n"
            "  回滚。结果键序为 operation、session_id、user_id、port_id、\n"
            "  vlan_id、status、reason。\n"
            "set_session_idle_timeout:\n"
            "  为已登记用户设置会话空闲超时，接收 user_id 与 idle_timeout\n"
            "  （0..86400 的 JSON 整数秒，0 表示关闭；未配置等同关闭）。重复设置\n"
            "  相同值幂等，新值覆盖旧值但只作用于此后创建的会话，已有会话沿用\n"
            "  创建时快照的配置。启用后，新会话以创建 now 作为首次活动时间；\n"
            "  validate_session 与 check_admission 对仍有效会话完成判定后以本次\n"
            "  now 刷新最近活动时间（策略拒绝也算活动）；异常、时间回退、硬过期、\n"
            "  空闲过期与整批失败均不刷新。三个会话入口保留主动终止或空闲过期\n"
            "  终态，否则先判断 now 是否达到 expires_at（不可延长的硬期限），再\n"
            "  判断是否达到 最近活动时间+idle_timeout；命中空闲期限返回\n"
            "  denied/session_idle_expired 并成为不可恢复终态，terminate_session\n"
            "  也返回该原因且 terminated_at 为 null。并发计数排除已达到空闲期限\n"
            "  的会话且不刷新活动时间。引用未知用户整批 unknown_user。结果键序为\n"
            "  operation、user_id、status、idle_timeout，status 为 configured。\n"
            "list_authentication_events:\n"
            "  为已登记用户返回本进程当前批次内已提交的认证轨迹，仅接收\n"
            "  operation 与 user_id。轨迹只覆盖 authenticate_stateful 与\n"
            "  authenticate_session（无状态 authenticate 不产生事件），每个有状态\n"
            "  认证操作在得到普通业务结果（接受、口令拒绝、锁定、并发上限）后\n"
            "  至多追加一条；导致整批失败的异常（时间回退、重复 session_id、\n"
            "  未知用户等）不留下事件，批次后续失败时先前新增事件一并回滚。\n"
            "  事件按该用户提交顺序从 1 连续编号，键序为 sequence、source、now、\n"
            "  status、reason、session_id；source 为触发操作名，now 为显式输入值，\n"
            "  status 与 reason 等于该操作的对外结果，authenticate_stateful 的\n"
            "  session_id 为 null，authenticate_session 一律记录请求中的\n"
            "  session_id。查询为只读：重复查询返回逐字节相同内容，不推进认证\n"
            "  时间、会话检查时间或活动时间，也不生成事件；无事件时返回空数组\n"
            "  和 0。事件不含口令、盐、编码凭据或摘要。引用未知用户整批\n"
            "  unknown_user。结果键序为 operation、user_id、status、event_count、\n"
            "  events，status 为 reported。\n"
            "list_accounting_events:\n"
            "  为指定 session_id 返回本进程当前批次内已提交的计费开始、中间与\n"
            "  停止事件，仅接收 operation 与 session_id。authenticate_session\n"
            "  成功创建会话时\n"
            "  产生且仅产生一条 start 事件，时间取该请求显式传入的 now；口令拒绝、\n"
            "  账户锁定、并发上限拒绝与整批异常均不产生开始事件。validate_session、\n"
            "  check_admission、terminate_session 或 record_accounting_interim\n"
            "  首次将已有会话判为终态时追加\n"
            "  且仅追加一条 stop 事件：主动终止取首次 terminated_at、reason 为\n"
            "  session_terminated；首次观察到硬过期取触发结果的 now、reason 为\n"
            "  session_expired；首次观察到空闲过期取触发结果的 now、reason 为\n"
            "  session_idle_expired。重复校验、重复终止或从另一入口再次观察同一\n"
            "  终态不改写也不追加；尚未被这些入口观察到的超时不出现在轨迹中。\n"
            "  record_accounting_interim 对仍有效的会话追加 interim 事件，时间取\n"
            "  该请求显式传入的 now，每个会话最多保存 64 条 interim。每个会话的\n"
            "  sequence 从 1 连续递增，正常轨迹为一条 start、至多 64 条 interim\n"
            "  与至多一条 stop。查询只读：不推进用户或会话时间，也不生成事件；\n"
            "  事件不含口令、\n"
            "  盐或编码凭据。未知 session_id 整批 unknown_session（退出码 8）；\n"
            "  字段缺失、多余或类型错误仍为 parameter_error。结果固定键序为\n"
            "  operation、session_id、user_id、status、event_count、events，\n"
            "  status 为 reported；events 按 sequence 升序，每项固定键序为\n"
            "  sequence、event_type、now、reason。\n"
            "list_admission_events:\n"
            "  为指定 session_id 返回本进程当前批次内已提交的准入判定轨迹，\n"
            "  仅接收 operation 与 session_id。每次 check_admission 完成普通\n"
            "  业务判定（接受、策略拒绝、默认拒绝或会话终态拒绝）并提交状态后\n"
            "  追加且仅追加一条事件，内容依次为从 1 连续递增的 sequence、请求\n"
            "  显式传入的 now、port_id、vlan_id、对外返回的 status 与 reason；\n"
            "  相同 now 的重复请求是两次独立判定，形成两条连续事件。未知会话、\n"
            "  时间回退与字段/取值校验失败不留下事件；本批后续操作失败时新增\n"
            "  事件随其他状态一起回滚。记录事件不额外改变会话时间、终态、认证\n"
            "  状态、策略或计费轨迹，事件不含凭据材料。查询只读：不推进时间、\n"
            "  不刷新活动，也不产生事件，重复查询逐字节一致；events 按\n"
            "  sequence 升序，无事件时返回空数组和 event_count 0，每项固定键序\n"
            "  为 sequence、now、port_id、vlan_id、status、reason。受每批最多\n"
            "  1000 个操作限制，每个会话每批至多产生并返回 1000 条事件。未知\n"
            "  session_id 整批 unknown_session（退出码 8）；字段缺失、多余或\n"
            "  类型错误仍为 parameter_error，取值错误为 value_error。结果固定\n"
            "  键序为 operation、session_id、user_id、status、event_count、\n"
            "  events，status 为 reported。\n"
            "record_accounting_interim:\n"
            "  为有效会话写入一条中间计费点，仅接收 operation、session_id 与 now，\n"
            "  字段约束同其他会话入口，时间只取显式输入。未知 session_id 整批\n"
            "  unknown_session（退出码 8）；now 早于该会话最近已提交时间时整批\n"
            "  state_error（退出码 6）；两种异常均不改变轨迹或时间状态。提交前\n"
            "  按现有优先级判断终态与超时：已主动终止、已空闲过期或已硬过期时\n"
            "  不追加 interim，分别返回 denied/session_terminated、\n"
            "  denied/session_idle_expired 或 denied/session_expired，sequence\n"
            "  为 null；本次首次观察到硬过期或空闲过期时仍只追加一条 stop，时间\n"
            "  取本次 now。活动会话提交成功时 status 为 recorded、reason 为 null、\n"
            "  sequence 为新事件编号；同一会话以相同 now 重复提交时返回原\n"
            "  sequence，不重复追加。每个会话最多保存 64 条 interim，达到上限后\n"
            "  返回 denied/accounting_interim_limit_reached、sequence 为 null，\n"
            "  轨迹不变。中间计费只推进会话最近已提交时间，不刷新活动时间，不\n"
            "  延长空闲或硬期限，也不改变认证、准入与并发上限状态。结果固定键序\n"
            "  为 operation、session_id、user_id、status、reason、sequence。\n"
            "reauthenticate_session:\n"
            "  凭终态源会话的归属与口令创建替代会话，接收 operation、\n"
            "  source_session_id、session_id、password、now、lifetime；字段约束\n"
            "  同 authenticate_session（source_session_id 同 session_id 规则），\n"
            "  now 须显式注入，不读取系统时间。先按既有优先级判定源会话：未知\n"
            "  源会话整批 unknown_session（退出码 8）；now 早于源会话最近已提交\n"
            "  时间或该用户最近已提交认证时间整批 state_error（退出码 6）。源会话\n"
            "  在 now 下仍有效（未终止、未达硬期限、未达空闲期限、未异常\n"
            "  断线）时返回\n"
            "  denied/session_active、expires_at 为 null：不校验口令、不刷新活动\n"
            "  时间、不修改源会话、不记事件。源会话已主动终止、已硬过期、已空闲\n"
            "  过期、已异常断线或本次首次达到超时（先硬期限后空闲期限）时，首次\n"
            "  观察到超时只\n"
            "  追加一条 stop 计费事件（时间取本次 now），源会话记录与终态原因\n"
            "  不变；随后按 authenticate_stateful 的失败计数、锁定与解锁语义校验\n"
            "  所属用户口令：口令错误返回 denied/invalid_password，锁定期间返回\n"
            "  denied/account_locked。口令正确后新 session_id 已存在（含终态\n"
            "  记录）整批 duplicate_session（退出码 7）；再按既有规则检查并发\n"
            "  上限，达到上限返回 denied/session_limit_reached、expires_at 为\n"
            "  null；否则创建新会话，expires_at = now + lifetime，快照当前空闲\n"
            "  超时配置，追加且仅追加一条 start 计费事件。进入再次认证或并发上限\n"
            "  判定（即除 session_active 与整批异常外的普通结果）时，认证轨迹\n"
            "  追加 source 为 reauthenticate_session、携带新 session_id 的一条\n"
            "  事件。结果固定键序为 operation、source_session_id、session_id、\n"
            "  user_id、status、reason、expires_at；成功时 status 为 accepted、\n"
            "  reason 为 null、expires_at 为新过期时刻，拒绝时 expires_at 为\n"
            "  null。\n"
            "get_account_status:\n"
            "  只读查询已登记用户的认证状态，仅接收 operation、user_id 与 now，\n"
            "  字段约束同 authenticate_stateful（now 显式注入，不读取系统\n"
            "  时间）。保存的 locked_until 非空且 now 小于该值时 status 为\n"
            "  locked，原样返回失败计数与锁定截止值；now 已达到或超过该值时按\n"
            "  既有自动到期语义报告 status 为 unlocked、failed_attempts 为 0、\n"
            "  locked_until 为 null；其余未锁定状态也报告 unlocked，并返回当前\n"
            "  累计失败次数和 null。last_authentication_at 为该用户最近一次已\n"
            "  提交认证状态操作的 now，从未进行有状态认证或人工解锁时为 null。\n"
            "  查询不改写认证状态、不推进 last_authentication_at，不创建、刷新\n"
            "  或终止会话，也不追加认证及计费事件；观察到锁定到期后，后续认证仍\n"
            "  由原入口按既有规则提交实际状态变化。now 早于该用户最近已提交认证\n"
            "  状态时间时整批 state_error（退出码 6，相等时间允许）；未知\n"
            "  user_id 整批 unknown_user（退出码 5）。结果固定键序为\n"
            "  operation、user_id、status、failed_attempts、locked_until、\n"
            "  last_authentication_at。\n"
            "get_session_status:\n"
            "  只读查询会话状态，仅接收 operation、session_id 与 now，字段约束\n"
            "  同其他会话入口（now 显式注入，不读取系统时间）。按既有优先级\n"
            "  判定：主动终止标记存在时返回 terminated/session_terminated；\n"
            "  已处于空闲过期终态时返回 expired/session_idle_expired；已异常\n"
            "  断线时返回 disconnected/session_disconnected；否则\n"
            "  now 达到 expires_at 时返回 expired/session_expired；硬期限未到\n"
            "  但空闲超时启用且 now 达到 最近活动时间+idle_timeout 时返回\n"
            "  expired/session_idle_expired；其余返回 active、reason 为 null。\n"
            "  未主动终止时 terminated_at 为 null，空闲超时关闭时 idle_timeout\n"
            "  为 0，时间值取自保存状态。查询不写入终态、不推进会话最近已提交\n"
            "  时间、不刷新活动时间，也不追加认证或计费事件；即使 now 达到硬\n"
            "  期限或空闲期限，后续校验、准入检查、终止、计费中间点与再认证仍\n"
            "  按既有语义首次提交终态。now 早于该会话最近已提交时间时整批\n"
            "  state_error（退出码 6，相等时间允许）；未知 session_id 整批\n"
            "  unknown_session（退出码 8）。结果固定键序为 operation、\n"
            "  session_id、user_id、status、reason、expires_at、terminated_at、\n"
            "  idle_timeout、last_activity_at、disconnected_at。\n"
            "report_session_disconnect:\n"
            "  把有效会话标记为异常断线（终态），仅接收 operation、session_id\n"
            "  与 now，字段约束同其他会话入口，时间只取显式输入。未知\n"
            "  session_id 整批 unknown_session（退出码 8）；now 早于该会话最近\n"
            "  已提交时间时整批 state_error（退出码 6，相等时间允许）。保持既有\n"
            "  终态优先级：已主动终止、已空闲过期，或本次 now 已达到硬期限或\n"
            "  空闲期限时，不写断线标记，分别返回 denied/session_terminated、\n"
            "  denied/session_idle_expired 或 denied/session_expired，\n"
            "  disconnected_at 为 null，首次观察到超时仍只追加一条 stop 计费\n"
            "  事件。会话仍有效时记录首次 disconnected_at=now，返回\n"
            "  disconnected、reason 为 null，并追加一条时间为 now、reason 为\n"
            "  session_disconnected 的 stop 计费事件；重复报告已断线会话时保留\n"
            "  首次 disconnected_at，幂等返回且不重复追加事件。断线后\n"
            "  validate_session、check_admission、terminate_session 与\n"
            "  record_accounting_interim 均返回 denied/session_disconnected，\n"
            "  不刷新活动时间、不追加 interim；get_session_status 返回\n"
            "  disconnected/session_disconnected 并公开 disconnected_at；并发\n"
            "  计数排除该会话；reauthenticate_session 可将已断线会话作为终态\n"
            "  源会话创建替代会话。结果固定键序为 operation、session_id、\n"
            "  user_id、status、reason、disconnected_at、expires_at。\n"
            "退出码:\n"
            "  0  成功（含 denied/invalid_password、account_locked、\n"
            "      session_expired、session_idle_expired、session_terminated、\n"
            "      session_limit_reached、accounting_interim_limit_reached、\n"
            "      session_active、session_disconnected、\n"
            "      policy_not_configured、policy_denied 与终止\n"
            "      结果）\n"
            "  2  parameter_error：JSON 语法或字段类型错误\n"
            "  3  value_error：长度、salt 编码、now/lifetime 范围、规则数量、\n"
            "      重复匹配对或批量上限错误\n"
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
