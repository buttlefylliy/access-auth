#!/usr/bin/env python3
"""端到端验证 authenticate_session / validate_session 行为契约。"""

import json
import subprocess
import sys

PATH = "access_auth.py"
SALT = "00" * 16
PW = "correct horse"
PWB = "wrong horse!"

passed = 0
failed = 0


def run(ops):
    payload = json.dumps({"operations": ops}, ensure_ascii=False).encode("utf-8")
    proc = subprocess.run(
        [sys.executable, PATH],
        input=payload,
        capture_output=True,
    )
    out = proc.stdout.decode("utf-8")
    doc = json.loads(out) if out else None
    return proc.returncode, out, doc


def reg(uid="alice", pw=PW, salt=SALT):
    return {"operation": "register", "user_id": uid, "password": pw, "salt": salt}


def asess(uid, sid, now, lifetime, pw=PW):
    return {
        "operation": "authenticate_session",
        "user_id": uid,
        "password": pw,
        "session_id": sid,
        "now": now,
        "lifetime": lifetime,
    }


def vsess(sid, now):
    return {"operation": "validate_session", "session_id": sid, "now": now}


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print("FAIL:", name, detail)


# 1. 成功创建 + 键序/紧凑输出
code, raw, doc = run([reg(), asess("alice", "s1", 100, 60)])
check("create ok exit", code == 0, code)
r = doc["results"][1]
check(
    "create raw key order",
    '{"operation":"authenticate_session","user_id":"alice",'
    '"session_id":"s1","status":"accepted","reason":null,"expires_at":160}'
    in raw,
    raw,
)
check("create expires_at", r["expires_at"] == 160, r)

# 2. 批内校验：有效期内 accepted（同批 register+create+validate）
code, raw, doc = run([reg(), asess("alice", "s1", 100, 60), vsess("s1", 159)])
check("valid accepted exit", code == 0, code)
r = doc["results"][2]
check(
    "validate raw key order",
    raw.split("\n")[0].endswith(
        '{"operation":"validate_session","session_id":"s1","user_id":"alice",'
        '"status":"accepted","reason":null,"expires_at":160}'
    )
    or '"operation":"validate_session","session_id":"s1","user_id":"alice",'
    '"status":"accepted","reason":null,"expires_at":160}' in raw,
    raw,
)
check("valid accepted status", r["status"] == "accepted" and r["user_id"] == "alice", r)

# 3. now == expires_at-1 accepted；now == expires_at 过期（终态）
code, _, doc = run(
    [
        reg(),
        asess("alice", "s1", 100, 60),
        vsess("s1", 159),
        vsess("s1", 160),
        vsess("s1", 1000),
    ]
)
check("boundary exit", code == 0, code)
sts = [x["status"] for x in doc["results"][2:]]
rs = [x.get("reason") for x in doc["results"][2:]]
check("boundary statuses", sts == ["accepted", "denied", "denied"], sts)
check("boundary reasons", rs == [None, "session_expired", "session_expired"], rs)
# 过期结果退出码仍是 0 且 expires_at 不变
check("expiry commits", doc["results"][3]["expires_at"] == 160, doc["results"][3])

# 4. 相等时间允许重复检查
code, _, doc = run(
    [reg(), asess("alice", "s1", 100, 500), vsess("s1", 120), vsess("s1", 120)]
)
check("equal now exit", code == 0, code)
check("equal now both accepted", all(x["status"] == "accepted" for x in doc["results"][2:]), doc)

# 5. validate now 回退 -> state_error(6)，整批回滚
code, raw, doc = run(
    [
        reg(),
        asess("alice", "s1", 100, 500),
        vsess("s1", 200),
        asess("alice", "s2", 50, 10),  # 用户 now 回退，也应 state_error
    ]
)
check("session regression exit", code == 6, code)
check("session regression type", doc["error"]["type"] == "state_error", doc)

# validate 自身的时间回退
code, _, doc = run(
    [reg(), asess("alice", "s1", 100, 500), vsess("s1", 200), vsess("s1", 199)]
)
check("validate regression exit", code == 6, (code, doc))
check("validate regression index", doc["error"]["operation_index"] == 3, doc)

# 回滚：state_error 批次中的创建不生效 —— 新进程空注册表，无法跨批；
# 改为批内前置已提交批次不受影响需多进程，这里验证同批失败后整体无输出结果
check("rollback no results", doc["results"] is None, doc)

# 6. 拒绝（错误口令）不创建会话：同会话 id 随后可成功创建
code, _, doc = run(
    [
        reg(),
        asess("alice", "s1", 100, 60, pw=PWB),
        asess("alice", "s1", 100, 60),
        vsess("s1", 110),
    ]
)
check("denied no session exit", code == 0, code)
r0 = doc["results"][1]
check(
    "denied shape",
    r0["status"] == "denied"
    and r0["reason"] == "invalid_password"
    and r0["expires_at"] is None
    and r0["session_id"] == "s1",
    r0,
)
check("reuse after denied", doc["results"][2]["status"] == "accepted", doc["results"][2])
check("validate reused", doc["results"][3]["status"] == "accepted", doc["results"][3])

# 7. 锁定语义沿用：三次错误后 authenticate_session 也 account_locked
code, _, doc = run(
    [
        reg(),
        asess("alice", "a", 0, 60, pw=PWB),
        asess("alice", "b", 1, 60, pw=PWB),
        asess("alice", "c", 2, 60, pw=PWB),
        asess("alice", "d", 100, 60),
    ]
)
check("locked exit", code == 0, code)
# 第三次失败当次仍为 invalid_password，但锁定截止值已置为 302
check("third denial sets lock", doc["results"][3]["reason"] == "invalid_password", doc["results"][3])
check(
    "locked no session",
    doc["results"][4]["status"] == "denied"
    and doc["results"][4]["reason"] == "account_locked"
    and doc["results"][4]["expires_at"] is None,
    doc["results"][4],
)
# 到点解锁（now=302 >= 302 截止）
code, _, doc = run(
    [
        reg(),
        asess("alice", "a", 0, 60, pw=PWB),
        asess("alice", "b", 1, 60, pw=PWB),
        asess("alice", "c", 2, 60, pw=PWB),
        asess("alice", "d", 302, 60),
    ]
)
check("unlock at deadline", doc["results"][4]["status"] == "accepted", doc["results"][4])

# 8. 重复 session_id -> duplicate_session(7)，且整批回滚
code, _, doc = run(
    [reg(), asess("alice", "s1", 0, 60), asess("alice", "s1", 0, 60)]
)
check("dup session exit", code == 7, code)
check("dup session type", doc["error"]["type"] == "duplicate_session", doc)
check("dup session index", doc["error"]["operation_index"] == 2, doc)

# 9. 未知 session_id -> unknown_session(8)
code, _, doc = run([reg(), vsess("nope", 0)])
check("unknown session exit", code == 8, code)
check("unknown session type", doc["error"]["type"] == "unknown_session", doc)

# authenticate_session 未知用户 -> unknown_user(5)
code, _, doc = run([asess("ghost", "s1", 0, 60)])
check("session unknown user", code == 5 and doc["error"]["type"] == "unknown_user", (code, doc))

# 10. 参数/范围校验
def expect_error(name, ops, exit_code, etype):
    code, _, doc = run(ops)
    check(name, code == exit_code and doc["error"]["type"] == etype, (code, doc))

base = [reg()]
expect_error("missing lifetime", base + [
    {"operation": "authenticate_session", "user_id": "alice", "password": PW,
     "session_id": "s", "now": 0}], 2, "parameter_error")
expect_error("extra field", base + [
    {"operation": "authenticate_session", "user_id": "alice", "password": PW,
     "session_id": "s", "now": 0, "lifetime": 1, "x": 1}], 2, "parameter_error")
expect_error("validate extra field", base + [
    {"operation": "validate_session", "session_id": "s", "now": 0, "x": 1}],
    2, "parameter_error")
expect_error("lifetime string", base + [asess("alice", "s", 0, "10")],
    2, "parameter_error")
expect_error("lifetime bool", base + [asess("alice", "s", 0, True)],
    2, "parameter_error")
expect_error("now float", base + [asess("alice", "s", 1.5, 10)],
    2, "parameter_error")
expect_error("validate now string", base + [vsess("s", "0")],
    2, "parameter_error")
expect_error("session_id empty", base + [asess("alice", "", 0, 10)],
    3, "value_error")
expect_error("session_id control char", base + [asess("alice", "a\tb", 0, 10)],
    3, "value_error")
expect_error("session_id too long", base + [asess("alice", "x" * 65, 0, 10)],
    3, "value_error")
expect_error("lifetime zero", base + [asess("alice", "s", 0, 0)],
    3, "value_error")
expect_error("lifetime 86401", base + [asess("alice", "s", 0, 86401)],
    3, "value_error")
expect_error("lifetime ok boundary", base + [asess("alice", "s", 0, 86400)],
    0, None) if False else None
code, _, doc = run(base + [asess("alice", "s", 0, 86400)])
check("lifetime 86400 ok", code == 0 and doc["results"][1]["expires_at"] == 86400, (code, doc))
expect_error("now+lifetime overflow",
    base + [asess("alice", "s", 9007199254740991, 1)], 3, "value_error")
expect_error("now negative (session)", base + [asess("alice", "s", -1, 1)],
    3, "value_error")
expect_error("now too big (validate)", base + [vsess("s", 9007199254740992)],
    3, "value_error")
expect_error("now+300 overflow still enforced",
    base + [asess("alice", "s", 9007199254740990, 1)], 3, "value_error")

# 11. 静态整批校验：后置参数错误导致前置 register 也不提交（同批回滚语义）
expect_error("static validation first",
    [reg("a"), reg("b", pw="short")], 3, "value_error")

# 12. 确定性：相同输入两次运行逐字节一致
payload = json.dumps(
    {"operations": [reg(), asess("alice", "s1", 100, 60), vsess("s1", 120)]},
    ensure_ascii=False,
).encode("utf-8")
o1 = subprocess.run([sys.executable, PATH], input=payload, capture_output=True).stdout
o2 = subprocess.run([sys.executable, PATH], input=payload, capture_output=True).stdout
check("deterministic bytes", o1 == o2, (o1, o2))

# 13. validate 不刷新 expires_at / 不改变用户锁定状态：
# 成功建会话后制造 2 次失败（未锁），中间插入 validate，
# 第 3 次失败仍应锁定，证明 validate 未触碰用户计数。
code, _, doc = run(
    [
        reg("bob"),
        asess("bob", "s1", 2, 1000),
        {"operation": "authenticate_stateful", "user_id": "bob",
         "password": PWB, "now": 501},
        {"operation": "authenticate_stateful", "user_id": "bob",
         "password": PWB, "now": 502},
        vsess("s1", 503),
        {"operation": "authenticate_stateful", "user_id": "bob",
         "password": PWB, "now": 504},
        {"operation": "authenticate_stateful", "user_id": "bob",
         "password": PW, "now": 505},
    ]
)
check("validation preserves user state exit", code == 0, code)
check("session created", doc["results"][1]["status"] == "accepted", doc["results"][1])
check("validate mid-flight accepted",
      doc["results"][4]["status"] == "accepted", doc["results"][4])
# 第 3 次失败当次置锁定截止值；紧接的正确口令请求被 account_locked 拒绝，
# 证明 validate 未清零失败计数。
check("third fail sets lock (state preserved across validate)",
      doc["results"][5]["reason"] == "invalid_password"
      and doc["results"][5]["locked_until"] == 804, doc["results"][5])
check("next request account_locked",
      doc["results"][6]["reason"] == "account_locked", doc["results"][6])
# validate 返回的 expires_at 始终是建会话时的 1002，未被刷新
check("expires_at never refreshed",
      doc["results"][4]["expires_at"] == 1002, doc["results"][4])

# 14. 64 码点 Unicode（含非 Cc）合法；emoji 按码点计数
sid = "会" * 64
code, _, doc = run(base + [asess("alice", sid, 0, 10), vsess(sid, 5)])
check("unicode 64 codepoints", code == 0 and doc["results"][2]["status"] == "accepted", code)

# 15. 既有操作未受影响：stateful 结果键序
payload = json.dumps({"operations": [
    reg(), {"operation": "authenticate_stateful", "user_id": "alice",
            "password": PW, "now": 0}]}).encode()
proc = subprocess.run([sys.executable, PATH], input=payload, capture_output=True)
check("legacy key order", proc.returncode == 0 and proc.stdout.decode().endswith(
    '{"operation":"authenticate_stateful","user_id":"alice","status":"accepted",'
    '"reason":null,"failed_attempts":0,"locked_until":null}],"error":null}\n'
), proc.stdout)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
