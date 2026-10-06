# access-auth

接入认证与准入控制（凭据、锁定、会话、准入判定）。

## 约束

* 仅使用 Python 标准库，不联网，不依赖第三方包。
* 行为必须确定：相同输入多次运行产生逐字节一致的输出；时间相关行为由显式注入的时钟驱动，不读墙上时钟。
* 所有结论可由公开接口与落盘产物独立验收。

## 公开入口

* 入口文件：`access_auth.py` 
* 命令行：`python access_auth.py --help` 
* 使用说明与行为契约以本文件为准；入口的签名、键序与既有语义在迭代中保持兼容。

## 状态

仓库初始为空，功能按增量需求持续构建。

## 操作

* `register`：登记用户（user_id、password、salt），重复登记报 `duplicate_user`（退出码 4）。
* `authenticate`：无状态口令校验，返回 accepted 或 denied/invalid_password。
* `authenticate_stateful`：带失败计数与临时锁定的口令校验。额外接收 `now`
  （0..9007199254740991 的 JSON 整数，调用方注入的秒数；不读取系统时间）。
  每个用户独立保存最后一次已提交 `now`、失败次数与锁定截止值，不保留认证历史。
  * 口令正确：accepted，清零失败次数与锁定截止值。
  * 口令错误：denied/invalid_password，失败次数加一；第三次失败锁定至 `now+300`。
  * 锁定期间（`now` 小于截止值）：denied/account_locked，不增加次数；
    `now` 到达截止值时先解锁并清零旧计数，再处理本次口令。
  * 同一用户的 `now` 不得早于上次已提交时间（相等合法），否则整批
    `state_error`（退出码 6）。
  * 结果键序固定为 operation、user_id、status、reason、failed_attempts、
    locked_until；成功时 reason 为 null，未锁定时 locked_until 为 null。
* `authenticate_session`：有状态认证通过后创建确定性会话。接收 user_id、
  password、session_id、`now`、`lifetime`，沿用 `authenticate_stateful` 的
  凭据校验、用户时间单调性、失败计数与锁定语义。
  * 凭据通过：accepted，创建内存会话，`expires_at = now + lifetime`；
    拒绝（invalid_password、account_locked）时不创建会话，`expires_at` 为 null。
  * `session_id`：1..64 个无控制字符 (Cc) 的 Unicode 码点；`lifetime`：
    1..86400 的 JSON 整数秒，且 `now+lifetime` 不得超过 9007199254740991。
  * session_id 重复（含已过期的终态会话）整批 `duplicate_session`（退出码 7）。
  * 若该用户已配置并发上限（见 `set_session_limit`），在口令被接受且
    session_id 未使用后检查容量：本次 `now` 下属于该用户、未终止且
    `now < expires_at` 的会话计入并发（已过期会话保留记录但不计入）；
    活动数达到上限时返回 denied/session_limit_reached、`expires_at` 为 null，
    不创建会话，正确口令清零失败计数的效果仍提交。
  * 结果键序固定为 operation、user_id、session_id、status、reason、expires_at。
* `validate_session`：按注入时间校验会话，接收 session_id、`now`。
  * 会话保存最近已提交的检查时间；`now` 早于该值整批 `state_error`（退出码 6），
    状态不变；相等时间允许重复检查。
  * 已终止的会话一律 denied/session_terminated；否则 `now < expires_at`：
    accepted；`now >= expires_at`：denied/session_expired，过期为终态。
    检查不刷新过期时刻，也不改变用户认证状态，时间只取自输入。
  * 未知 session_id 整批 `unknown_session`（退出码 8）。
  * 结果键序固定为 operation、session_id、user_id、status、reason、expires_at。
* `terminate_session`：按注入时间主动终止有效会话，接收 session_id、`now`，
  字段校验与 `validate_session` 相同，遵循同一会话时间单调规则。
  * 终止成功：status 为 terminated、reason 为 null、terminated_at 为首次
    终止时间、expires_at 为原过期时刻；不改变用户失败计数、锁定状态或其他会话。
  * `now >= expires_at`：会话保持过期终态，返回 denied/session_expired、
    terminated_at 为 null，不留下终止标记。
  * 已终止的会话重复终止幂等返回首次 terminated_at，不改写终止时间；
    此后 `validate_session` 无论是否达到原过期时间都返回
    denied/session_terminated。
  * 未知 session_id 整批 `unknown_session`（退出码 8）。
  * 结果键序固定为 operation、session_id、user_id、status、reason、
    terminated_at、expires_at。
* `set_session_limit`：为已登记用户设置进程内并发会话上限，接收 user_id、
  `max_sessions`（0..64 的 JSON 整数）。
  * 未配置的用户默认不限并发；重复提交相同值结果不变，提交新值覆盖旧值。
  * 上限只在 `authenticate_session` 创建新会话时生效：在本次 `now` 下属于
    该用户、未主动终止且 `now < expires_at` 的会话计入并发，已过期会话保留
    记录但不计入；达到上限时拒绝新会话（denied/session_limit_reached），
    不终止已有会话。降低上限只阻止新会话，直至活动数低于上限。
  * 引用未知用户整批 `unknown_user`（退出码 5）。
  * 结果键序固定为 operation、user_id、status、max_sessions，status 为
    configured。

会话仅驻留当前进程内存、不落盘；数量不超过本批成功创建数。

整批操作先全部静态校验，再在注册表副本上依序执行；任一异常则凭据、认证状态、
会话与并发限额恢复到批次开始前，普通拒绝、会话过期与会话终止作为成功结果提交。未知用户报
`unknown_user`（退出码 5）。字段缺失、类型错误或多余字段报
`parameter_error`（退出码 2），范围错误报 `value_error`（退出码 3）。
详细字段限制与退出码见 `python access_auth.py --help`。
