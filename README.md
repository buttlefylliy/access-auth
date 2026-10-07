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
    用户配置空闲超时后的判定与活动刷新语义见 `set_session_idle_timeout`。
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
* `set_admission_policy`：为已登记用户设置准入策略，接收 user_id、`rules`。
  * `rules` 是最多 64 项的 JSON 数组，每项为仅含 `port_id` 与 `vlan_id`
    的对象；`port_id` 为 1..64 个无控制字符 (Cc) 的 Unicode 码点，
    `vlan_id` 为 1..4094 的 JSON 整数；(port_id, vlan_id) 匹配对不得重复，
    顺序不影响策略语义。
  * 未配置或空策略均默认拒绝准入；重复提交相同策略幂等，提交不同策略完整
    替换旧值；只替换精确规则，保留已配置的默认准入动作；不影响凭据、认证
    状态、已有会话与并发限额。
  * 引用未知用户整批 `unknown_user`（退出码 5）。
  * 结果键序固定为 operation、user_id、status、rule_count，status 为
    configured。
* `set_admission_default`：为已登记用户设置默认准入动作，接收 user_id、
  `default_action`（字符串 `allow` 或 `deny`）。
  * 重复设置相同值幂等，新值覆盖旧值；每用户至多保存一个默认动作。
  * 默认动作只影响 `check_admission` 对未命中精确规则时的判定，适用于所有
    合法端口和 VLAN；只配置默认动作而没有精确规则也视为策略已配置。
  * 设置默认动作不改写精确规则、凭据、认证状态、已有会话、并发限额或超时
    配置；已有活动会话在下一次 `check_admission` 时使用新值。
  * 引用未知用户整批 `unknown_user`（退出码 5）。
  * 结果键序固定为 operation、user_id、status、default_action，status 为
    configured。
* `set_admission_overrides`：为已登记用户配置有序准入覆盖规则，接收
  user_id、`rules`。
  * `rules` 是最多 64 项的 JSON 数组，每项为仅含 `port_id`、`vlan_id`
    与 `action` 的对象；`port_id` 为 null 或 1..64 个无控制字符 (Cc) 的
    Unicode 码点，`vlan_id` 为 null 或 1..4094 的 JSON 整数，null 表示该
    维度通配；`action` 为字符串 `allow` 或 `deny`。
  * `check_admission` 在会话有效性判定后、精确规则与默认动作之前按数组
    顺序采用首条匹配的覆盖规则：`allow` 返回 accepted 且 reason 为 null，
    `deny` 返回 denied/policy_denied；未命中则继续精确规则与默认动作判定。
  * 新数组完整替换旧值并保留顺序，重复提交相同内容幂等，空数组表示清除；
    未配置时原有精确规则、默认动作、拒绝原因与会话时间语义保持不变。
  * 覆盖规则只影响 `check_admission` 的判定：不改变终止、硬过期与空闲
    过期的既有优先级，不改变有效会话检查时间与活动时间的刷新规则，不产生
    认证或计费事件，也不改写精确规则、默认动作、凭据、认证状态、已有会话、
    并发限额或超时配置。
  * 引用未知用户整批 `unknown_user`（退出码 5）。
  * 结果键序固定为 operation、user_id、status、rule_count，status 为
    configured。
* `check_admission`：按注入时间检查会话有效性并按所属用户策略判定端口准入，
  接收 session_id、`now`、`port_id`、`vlan_id`，字段约束同上；会话状态与
  时间单调语义同 `validate_session`。
  * 已终止的会话返回 denied/session_terminated；已过期的会话返回
    denied/session_expired；活动会话先按所属用户的有序覆盖规则（见
    `set_admission_overrides`）采用首条匹配项，未命中时按所属用户策略
    精确匹配
    (port_id, vlan_id)：命中返回 accepted 且 reason 为 null；未命中时若该
    用户配置了默认准入动作，`allow` 返回 accepted 且 reason 为 null，
    `deny` 返回 denied/policy_denied；精确规则与默认动作均未配置返回
    denied/policy_not_configured；已配置精确规则（含空集）但未配置默认
    动作且未命中返回 denied/policy_denied。
  * 正常判定均提交本次会话检查时间，异常则整批回滚；未知 session_id 整批
    `unknown_session`（退出码 8），时间回退整批 `state_error`（退出码 6）。
  * 结果键序固定为 operation、session_id、user_id、port_id、vlan_id、
    status、reason。
* `set_session_idle_timeout`：为已登记用户设置会话空闲超时，接收 user_id、
  `idle_timeout`（0..86400 的 JSON 整数秒；0 或未配置表示关闭）。
  * 重复设置相同值幂等，新值覆盖旧值但只作用于此后创建的会话，已有会话
    沿用创建时快照的配置；`lifetime` 仍是不可延长的硬期限。
  * 启用后，新会话以创建时的 `now` 作为首次活动时间；`validate_session` 与
    `check_admission` 对仍有效的会话完成判定后以本次 `now` 刷新最近活动时间
    （策略拒绝也算活动）；异常、时间回退、硬过期、空闲过期与整批失败均不刷新。
  * 三个会话入口保留主动终止或空闲过期终态，否则先判断 `now` 是否达到
    `expires_at`，再判断是否达到 最近活动时间+`idle_timeout`；命中空闲期限
    返回 denied/session_idle_expired 并成为不可恢复终态：此后两个检查入口
    始终返回该原因，`terminate_session` 也返回该原因且 terminated_at 为 null。
  * 并发计数排除已达到空闲期限的会话，且不刷新活动时间；未到期限时保留
    原有准入、校验和终止语义。
  * 引用未知用户整批 `unknown_user`（退出码 5）。
  * 结果键序固定为 operation、user_id、status、idle_timeout，status 为
    configured。
* `list_authentication_events`：为已登记用户返回本进程当前批次内已提交的
  认证轨迹，仅接收 operation 和 user_id。
  * 轨迹只覆盖 `authenticate_stateful` 与 `authenticate_session`；无状态
    `authenticate` 继续只做口令校验，不产生事件。每个有状态认证操作在得到
    普通业务结果（accepted、invalid_password、account_locked、
    session_limit_reached）后为对应用户至多追加一条事件。
  * 事件按该用户提交顺序从 1 连续编号，固定键序为 sequence、source、now、
    status、reason、session_id；source 为触发操作名，now 使用显式输入值，
    status 与 reason 等于该操作的对外结果，`authenticate_stateful` 的
    session_id 为 null，`authenticate_session` 无论接受、口令拒绝、锁定或
    达到并发上限都记录请求中的 session_id。
  * 查询只读：重复查询返回逐字节相同内容，不推进认证时间、会话检查时间或
    活动时间，也不生成事件；events 按 sequence 升序，无事件时返回空数组和
    event_count 0。
  * 只有已经作为普通结果提交的认证尝试才进入轨迹：时间回退、重复
    session_id 等导致批次失败的异常不留下事件；本批后续任一操作失败时，
    先前新增事件随其他状态一起回滚。事件不含口令、盐、编码凭据或摘要。
  * 引用未知用户整批 `unknown_user`（退出码 5）；字段缺失、额外字段或类型
    错误仍为 `parameter_error`（退出码 2）。
  * 结果固定键序为 operation、user_id、status、event_count、events，
    status 为 reported。
* `list_accounting_events`：为指定 session_id 返回本进程当前批次内已提交的
  计费开始、中间与停止事件，仅接收 operation 和 session_id。
  * `authenticate_session` 成功创建会话时产生且仅产生一条 start 事件，时间
    取该请求显式传入的 `now`；口令拒绝、账户锁定、并发上限拒绝与整批异常均
    不产生开始事件。
  * `validate_session`、`check_admission`、`terminate_session` 或
    `record_accounting_interim` 首次将已有
    会话判为终态时追加且仅追加一条 stop 事件：主动终止取首次 terminated_at、
    reason 为 session_terminated；首次观察到硬过期取触发结果的 `now`、reason
    为 session_expired；首次观察到空闲过期取触发结果的 `now`、reason 为
    session_idle_expired。重复校验、重复终止或从另一入口再次观察同一终态不改写
    也不追加；尚未被这些入口观察到的超时不出现在轨迹中。
  * `record_accounting_interim` 对仍有效的会话追加 interim 事件，时间取该
    请求显式传入的 `now`，每个会话最多保存 64 条 interim。
  * 每个会话的 sequence 从 1 连续递增，正常轨迹为一条 start、至多 64 条
    interim 与至多一条 stop。
  * 查询只读：不推进用户或会话时间，也不生成事件；事件不含口令、盐或编码
    凭据；events 按 sequence 升序，每项固定键序为 sequence、event_type、
    now、reason。
  * 未知 session_id 整批 `unknown_session`（退出码 8）；字段缺失、额外字段
    或类型错误仍为 `parameter_error`（退出码 2）。
  * 结果固定键序为 operation、session_id、user_id、status、event_count、
    events，status 为 reported。
* `record_accounting_interim`：为有效会话写入一条中间计费点，仅接收
  operation、session_id、`now`，字段约束沿用现有会话入口，时间只取显式输入。
  * 未知 session_id 整批 `unknown_session`（退出码 8）；`now` 早于该会话
    最近已提交时间时整批 `state_error`（退出码 6）；两种异常均不改变轨迹或
    时间状态。
  * 提交前仍按现有优先级判断终态与超时：已主动终止、已空闲过期或已硬过期
    时不追加 interim，分别返回 denied/session_terminated、
    denied/session_idle_expired 或 denied/session_expired，sequence 为 null；
    若本次首次观察到硬过期或空闲过期，仍只追加一个 stop，时间取本次 `now`。
  * 活动会话提交成功时 status 为 recorded、reason 为 null、sequence 为新
    事件编号；同一会话以相同 `now` 重复提交时返回原 sequence，不重复追加。
  * 每个会话最多保存 64 条 interim；达到上限后返回
    denied/accounting_interim_limit_reached，sequence 为 null，且轨迹不变。
  * 中间计费只推进会话最近已提交时间，不刷新活动时间，不延长空闲或硬期限，
    也不改变认证、准入和并发上限状态。
  * 结果固定键序为 operation、session_id、user_id、status、reason、sequence。
* `reauthenticate_session`：凭终态源会话的归属与口令创建替代会话，接收
  operation、source_session_id、session_id、password、`now`、`lifetime`；
  字段约束同 `authenticate_session`（source_session_id 同 session_id 规则），
  `now` 须显式注入，不读取系统时间。
  * 先按既有优先级判定源会话：未知源会话整批 `unknown_session`（退出码 8）；
    `now` 早于源会话最近已提交时间或该用户最近已提交认证时间整批
    `state_error`（退出码 6）。
  * 源会话在 `now` 下仍有效（未终止、未达硬期限、未达空闲期限）时返回
    denied/session_active、`expires_at` 为 null：不校验口令、不刷新活动
    时间、不修改源会话，也不产生任何事件。
  * 源会话已主动终止、已硬过期、已空闲过期或本次首次达到超时（先硬期限
    后空闲期限）时，首次观察到超时只追加一条 stop 计费事件（时间取本次
    `now`），源会话记录与终态原因不变；随后按 `authenticate_stateful` 的
    失败计数、锁定与解锁语义校验所属用户口令：口令错误返回
    denied/invalid_password，锁定期间返回 denied/account_locked。
  * 口令正确后新 session_id 已存在（含终态记录）整批 `duplicate_session`
    （退出码 7）；再按既有规则检查并发上限，达到上限返回
    denied/session_limit_reached、`expires_at` 为 null；否则创建新会话，
    `expires_at = now + lifetime`，快照当前空闲超时配置，追加且仅追加一条
    start 计费事件。
  * 进入再次认证或并发上限判定（即除 session_active 与整批异常外的普通
    结果）时，认证轨迹追加 source 为 reauthenticate_session、携带新
    session_id 的一条事件。
  * 结果固定键序为 operation、source_session_id、session_id、user_id、
    status、reason、expires_at；成功时 status 为 accepted、reason 为
    null、expires_at 为新过期时刻，拒绝时 expires_at 为 null。
* `unlock_account`：对已登记用户执行确定性的人工解锁，仅接收 operation、
  user_id 与 `now`；字段约束同 `authenticate_stateful`，`now` 须显式注入，
  不读取系统时间。
  * 成功后将该用户的失败计数归零、锁定截止值置为 null，并把 `now` 记为
    最近已提交的认证状态时间；无论调用前处于锁定、只有累计失败、锁定已
    自然到期还是干净状态，都返回同一个幂等结果，以相同 `now` 重复提交时
    输出逐字节一致。
  * 遵循该用户现有的时间单调规则：`now` 早于最近已提交认证状态时间整批
    `state_error`（退出码 6），相等时间允许执行；未知 user_id 整批
    `unknown_user`（退出码 5）。
  * 本操作不校验口令，不产生认证或计费事件，也不修改编码凭据、无状态
    `authenticate` 的结果、既有会话及其超时、并发限额或准入策略；原有
    自动到期解锁、锁定期间拒绝及成功认证清零的语义不变，解锁后的新失败
    从一次重新累计。
  * 结果固定键序为 operation、user_id、status、reason、failed_attempts、
    locked_until，status 为 unlocked，reason 与 locked_until 为 null，
    failed_attempts 为 0。

会话仅驻留当前进程内存、不落盘；数量不超过本批成功创建数。

整批操作先全部静态校验，再在注册表副本上依序执行；任一异常则凭据、认证状态、
会话、并发限额、准入策略、默认准入动作、准入覆盖规则、空闲超时配置、认证事件
轨迹与计费事件
轨迹恢复到批次
开始前，普通
拒绝、会话过期、
空闲过期与会话终止作为成功结果提交。未知用户报
`unknown_user`（退出码 5）。字段缺失、类型错误或多余字段报
`parameter_error`（退出码 2），范围错误报 `value_error`（退出码 3）。
详细字段限制与退出码见 `python access_auth.py --help`。
