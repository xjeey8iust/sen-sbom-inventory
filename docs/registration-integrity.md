# SBOM 清单登记完整性说明（基于源码）

本说明围绕 `POST /sboms`（登记）与 `GET /sboms`（按制品分页查询），从请求解析到响应
返回追踪实际调用关系，回答三个问题：

1. 重复提交、写入失败之后，**清单身份**如何确定；
2. **原始内容**在规范化、冲突、回滚之后如何确定；
3. 查询得到的**读取结果**如何确定，以及 total 与明细在什么边界内一致。

所有结论标注代码位置（文件:行号）。第 8 节的验证用例逐条对应现有测试的真实断言，
并区分【测试覆盖】与【源码推导】。

范围与基线：当前已提供清单登记与按制品分页查询。`GET /healthz` 维持既有行为
（`internal/api/router.go:25-31`），差异比对不属于本次范围；本次不修改任何产品源码与
README，只新增本说明。

---

## 1. 贯穿全文的示例清单（两个组件、一条依赖）

下例刻意在所有字符串两端加空白、并把组件与依赖的数组顺序打乱，用于演示规范化。

请求（首次登记）：

```http
POST /sboms
Content-Type: application/json

{
  "artifact": "  atlas  ",
  "version":  " 1.0 ",
  "components": [
    {"coordinate": " svc-b ", "license": " MIT ",       "dependencies": []},
    {"coordinate": "svc-a",  "license": " Apache-2.0 ", "dependencies": [" svc-b "]}
  ]
}
```

预期响应：`201 Created`

```json
{
  "id": 1,
  "artifact": "atlas",
  "version": "1.0",
  "components": [
    {"coordinate": "svc-a", "license": "Apache-2.0", "dependencies": ["svc-b"]},
    {"coordinate": "svc-b", "license": "MIT",       "dependencies": []}
  ]
}
```

要点（代码依据见第 2、4 节）：

- 所有字符串的首尾空白被去除；
- 组件按 `coordinate` 升序输出（`svc-a` 在前，与输入顺序无关）；
- 每个组件的依赖也按坐标升序输出；空依赖序列化为 `[]` 而不是 `null`；
- `id` 是存储层分配的正整数（`internal/model/sbom.go:19`，
  响应处 `internal/api/sbom.go:163`）。

相同内容重提（数组换序、再加空白）：

```http
POST /sboms

{"artifact":" atlas ","version":"1.0","components":[
  {"coordinate":"svc-a","license":"Apache-2.0","dependencies":["svc-b"]},
  {"coordinate":"svc-b","license":" MIT ","dependencies":[]}
]}
```

预期响应：仍为 `201`，**响应体与首次完全一致、`id` 仍为 1**（不新建记录）。

随后 `GET /sboms?artifact=atlas` 预期 `200`：

```json
{"items":[{"id":1,"artifact":"atlas","version":"1.0","components":[
  {"coordinate":"svc-a","license":"Apache-2.0","dependencies":["svc-b"]},
  {"coordinate":"svc-b","license":"MIT","dependencies":[]}
]}],"total":1,"page":1,"pageSize":20}
```

- `total` 不随重提增加，始终为 1；
- 登记的回读（`loadSBOM`）与分页查询共用同一套重建装载器，因此登记响应、重提响应、
  查询响应三处内容必然一致（`internal/store/store.go:387-412`，
  测试 `TestReplayAndListReturnIdenticalManifest`）。

---

## 2. `POST /sboms` 调用链：从请求体到 201/400/409/503

入口注册：`internal/api/router.go:33` → 处理器
`(*sbomHandlers).register`，`internal/api/sbom.go:107-164`。

| # | 阶段 | 代码位置 | 行为 | 失败时的出口 |
|---|---|---|---|---|
| 1 | 读取 body | `sbom.go:108-112` | `io.ReadAll` 读取整个请求体 | 400 `InvalidSbomInputError` |
| 2 | JSON 解析 | `sbom.go:114-118`，自定义解码 `componentsInput.UnmarshalJSON` `sbom.go:45-99` | 严格类型校验（见第 6 节） | 400 |
| 3 | 单值校验 | `hasTrailingValue` `sbom.go:169-177`，调用点 `sbom.go:121-124` | 拒绝 `{} {}`、`{} garbage` 这类尾随内容 | 400 |
| 4 | 顶层必填 | `sbom.go:126-131` | trim `artifact`/`version`；二者为空、或 `components == nil`（缺失或 null）即拒 | 400 |
| 5 | 组件内规则 | `sbom.go:61-96` | trim 坐标/许可证/依赖；空坐标、空许可证、重复坐标、空依赖、自依赖、重复依赖即拒 | 400 |
| 6 | 悬空依赖 | `sbom.go:133-144` | 依赖目标必须是本清单内某个（trim 后的）坐标 | 400 |
| 7 | 规范化 | `sbom.go:145`、`sbom.go:152` | 依赖数组 `sort.Strings`；组件按 `Coordinate` 排序 | — |
| 8 | 存储登记 | `sbom.go:154-158` → `Store.Register` `store.go:146-229` | 单事务查重 / 插入（见第 5、7 节） | 409 / 503 |
| 9 | 成功响应 | `sbom.go:163` | `201` + 存储层返回的完整清单 | — |

注意第 8 步处理器丢弃了 `created` 返回值（`sbom, _, err`，`sbom.go:154`）：首次创建与
幂等重提在 HTTP 上**都是 201**，区别只存在于存储层（`store.go:228`）。

存储层错误映射：`writeStoreError`，`sbom.go:248-257`：

- `model.ErrConflict` → 409 `SbomConflictError`；
- `model.ErrStorageUnavailable` → 503 `storage_unavailable`；
- **任何其他未预期错误同样落 503**（`default` 分支），不向客户端透传原因。

## 3. `GET /sboms` 调用链

入口：`internal/api/router.go:34` →
`(*sbomHandlers).list`，`internal/api/sbom.go:186-209`。

1. `artifact` 参数先 trim，空白/缺失即 400（`sbom.go:187-191`）；
2. `page`、`pageSize` 经 `positiveQuery`（`sbom.go:213-231`）：缺省分别为 1、20；
   出现即必须是纯数字十进制正整数（无符号、无小数点、无空格），且 `pageSize ≤ 100`
   （`sbom.go:197-201`），否则 400；
3. 调 `Store.List`（`sbom.go:203` → `store.go:239-290`），一次只读事务内最多四条
   SELECT：
   - `COUNT(*)`（`store.go:241-245`）；
   - 本制品按 id 升序的页内清单行（`store.go:247-249`，`LIMIT/OFFSET`）；
   - 页内 id 集合的全部组件，单条批量查询（`loadComponentsInto`
     `store.go:298-321`，`ORDER BY sbom_id, coordinate`）；
   - 页内 id 集合的全部依赖边，单条批量查询（`loadDependenciesInto`
     `store.go:329-364`，`ORDER BY sbom_id, from, to`）；
   - 空页（未知制品或翻过末页）只发前两条 SELECT，且不会带空 IN 列表
     （`store.go:274-276`）；
4. 成功响应 `200`，字段 `items/total/page/pageSize`（`sbom.go:208`，结构定义
   `sbom.go:179-184`）。`items` 在存储层被初始化为非 nil 空切片
   （`store.go:255`），空页在网络上是 `[]` 而非 `null`；每个组件的 `dependencies`
   同理（`store.go:259`、`store.go:314`）。

依赖边的 JOIN 额外要求目标组件与源组件同属一个清单
（`tc.sbom_id = sc.sbom_id`，`store.go:333-334`）：不同版本/制品复用相同坐标时，边
不会串到别的清单。

## 4. 规范化：首尾空白与数组顺序怎样参与判定

规范化全部发生在 HTTP 入口（`internal/api/sbom.go`），发生在进入存储层之前：

- **trim 范围**：`artifact`、`version`（`sbom.go:126-127`）、每个 `coordinate`、
  `license`（`sbom.go:65-66`）、每个依赖目标（`sbom.go:78`）。trim 后为空即 400。
- **组件顺序不携带语义**：组件在调用存储层前按坐标升序排序（`sbom.go:152`），
  存储层回读时同样按坐标升序（`store.go:303`）。所以“换序重提 = 相同内容”。
- **依赖顺序不携带语义**：每个组件的依赖先 `sort.Strings`（`sbom.go:145`），回读按
  目标坐标升序（`store.go:336`）。
- **相等判定是规范化后的逐项精确比较**：`equalContent`（`store.go:416-435`）按下标
  比较组件数量、`Coordinate`、`License`、依赖数量与每个依赖；任一字节不同即内容不同。
- **大小写敏感**：比较一律是 Go 的 `==`（`store.go:422`、`store.go:429`），SQL 侧
  `artifact = ?` 与唯一约束也是大小写敏感的普通 TEXT 比较，代码中没有任何
  `LOWER`/折叠。`App` 与 `app` 是两个制品；同制品同版本下坐标 `a`/`A` 属于内容不同
  → 409（测试 `TestComparisonsAreCaseSensitive`，`internal/api/sbom_test.go:308-328`）。
- **空组件数组合法**：JSON `[]` 经自定义解码成为非 nil 空切片（`sbom.go:60`），
  通过必填检查（`sbom.go:128` 判的是 `nil`；`null` 在 `sbom.go:48-50` 直接拒，字段
  缺失则切片保持 nil 也被拒）。存储时只插清单行、跳过依赖预编译
  （`store.go:202` 的 `countDependencies` 守卫）。
- **空依赖数组合法**：组件正常插入，不产生依赖行；回读得到 `[]`
  （`store.go:314`，网络级断言 `TestListEmptyArraysAreNeverNull`）。
- **非自身依赖环允许**：例如 a→b、b→a。存储层先在一个循环里插完全部组件行
  （`store.go:189-200`），再在第二个循环里插依赖边（`store.go:209-217`），插边时
  两端组件行都已存在，环不会因为外键或插入顺序失败。HTTP 层唯一拒绝的环是**自依赖**
  （`dep == coordinate`，`sbom.go:82-84`）。

## 5. 清单身份、原始内容、读取结果如何确定

身份键是规范化后的 `(artifact, version)`：表上有唯一约束
（`UNIQUE (artifact, version)`，`store.go:461`），查重 SQL 用这两列
（`store.go:151-154`）。登记在 `BEGIN IMMEDIATE` 写事务内进行
（`store.go:111-118`），并发登记同一键时在写锁上串行化，败者读到胜者已提交的行，
而不是撞上唯一约束（注释 `store.go:113-117`；并发测试
`TestConcurrentIdenticalRegistersShareOneRecord`）。

`Store.Register` 的三种结局（`store.go:149-224`）：

1. **键不存在**：插入清单行 → 批量插组件 → 批量插依赖，全部成功才 COMMIT，返回
   新记录与 `created=true`（`store.go:171-223`）。HTTP 201。
2. **键已存在且内容相同**：通过 `loadSBOM` 把**已存储**的记录重建出来，
   `equalContent` 为真时直接返回该存储记录（`store.go:156-164`，
   `result = existing`），`created=false`。HTTP 仍 201；响应体来自数据库而不是请求
   副本，`id` 沿用原 id，`total` 不增加。
3. **键已存在但内容不同**（组件集合、许可证、依赖关系任一变化）：在发生任何插入
   之前返回 `model.ErrConflict`（`store.go:160-162`），事务回滚（本来就未写入），
   HTTP 409，**原记录不变**。

读取结果：无论登记时的回读还是分页查询，组件与依赖都由
`loadComponentsInto` / `loadDependenciesInto` 这同一对装载器重建
（`store.go:278-283` 与 `store.go:405-409`），排序、空数组、跨版本坐标作用域只有
一套规则（`store.go:292-364`）。

## 6. 两层保证：HTTP 入口执行的检查 vs 存储方法要求的前提

这两层不是同一层保证，不能互相替代：

**HTTP 入口实际执行的检查**（`internal/api/sbom.go`，失败统一 400
`InvalidSbomInputError`，覆盖 28 种形态，见
`TestRegisterRejectsInvalidInput`，`sbom_test.go:144-186`）：

- body 必须能解析为**恰好一个** JSON 对象（拒绝数组/标量/null、尾随第二值）；
- 顶层 `artifact`、`version`、`components` 必须存在且类型正确；
- 每个组件必须有字符串 `coordinate`、`license` 与字符串数组 `dependencies`
  （用指针字段区分“缺失/null”与零值，`sbom.go:39-43`、`sbom.go:62-64`）；
- trim 后坐标/许可证非空；坐标在清单内唯一（重复检测用 trim 后的键，
  `sbom.go:70-73`）；
- 依赖目标 trim 后非空、不等于自身坐标、在同一组件内不重复（`sbom.go:79-88`）；
- 依赖目标必须存在于本清单坐标集合（`sbom.go:139-144`）。

**存储方法 `Store.Register/List` 要求调用方满足的前提**（方法内部**不**重新校验）：

- 入参字符串已 trim、非空；组件坐标唯一且已排序；依赖已去重、已排序、无自依赖、
  目标都在组件集合内；`List` 的 `page > 0`、`0 < pageSize ≤ 100`。
- 这些前提目前只有 HTTP 处理器这一个调用方负责满足（`main.go:28` 的装配）。
- 存储层的防线是**数据库约束**：`UNIQUE(artifact, version)`、
  `UNIQUE(sbom_id, coordinate)`、`UNIQUE(component_id, target_id)` 与外键
  （`store.go:457-475`，`foreign_keys=1` 见 `store.go:37`）。若绕过 HTTP 直接喂入
  违例数据，冲突会以存储错误返回——经 `unavailable`（`store.go:445-450`）包装为
  `model.ErrStorageUnavailable`，HTTP 上是 **503 而不是 400**；悬空依赖在存储层会表现
  为目标 id 0 的外键违约，自依赖则没有任何约束阻止。上述绕过场景在现有测试中没有
  被构造，属于【源码推导】，不是受测行为。

## 7. 写入失败：为什么是 503、为什么查不到、为什么故障解除后能重提

统一事务生命周期在 `withTx`（`internal/store/store.go:102-140`），`Register` 与
`List` 都经过它（`store.go:149`、`store.go:240`）：

1. **独占连接并保证归还**：`db.Conn(ctx)` 取一条专用连接，`defer c.Close()`
   （`store.go:103-109`）在成功、业务错误、存储错误任一路径上都把连接还池；
2. **开启事务**：登记用 `BEGIN IMMEDIATE`（`store.go:111-121`）；
3. **执行业务回调**；
4. **仅全部成功才 COMMIT 一次**（`store.go:135-138`）；回调返回任何错误——包括
   `ErrConflict` 这种“提前的业务返回”——都不提交；
5. **未提交即 best-effort 回滚**（`store.go:123-130`），回滚用
   `context.Background()` 发起，不受请求取消影响；回滚自身的错误被**刻意丢弃**
   （`_, _ =`，`store.go:127-129`），不能覆盖已确定的业务/存储错误；
6. 回调错误原样透传（`store.go:132-134`），sentinel 保持 `errors.Is` 可识别；
   COMMIT 自身失败映射为 `ErrStorageUnavailable`（`store.go:135-137`）。

组件插入（预编译批量 INSERT，`store.go:183-200`）或依赖插入
（`store.go:202-217`）任一步失败，都经 `unavailable(err)`（`store.go:193`、
`store.go:213` 等）转为 `model.ErrStorageUnavailable`。由此：

- **为什么是 503**：`writeStoreError` 把该 sentinel 映射到 503 `storage_unavailable`
  （`sbom.go:252-253`），消息是固定串 `"database is not available"`
  （`sbom.go:239`）；
- **为什么失败清单查不到**：COMMIT 是写完三张表后的唯一提交点
  （`store.go:135`）。失败时回调带着错误返回，COMMIT 不执行，deferred ROLLBACK
  撤销同一事务内已插入的清单行与组件行（外键 `ON DELETE CASCADE` 也在
  `store.go:465`、`store.go:472-473` 提供结构兜底）。其他连接只能看到已提交数据，
  所以 `COUNT(*)` 为 0、页扫描也没有该行；
- **为什么故障解除后重提可正常登记**：服务不为失败缓存任何“失败状态”——每次请求
  重新走 `db.Conn` → `BEGIN`（`store.go:103-121`），连接已由 `defer c.Close()`
  归还；重提事务的查重 SELECT 看不到任何行（上一事务确已回滚），于是走完整插入
  分支（`store.go:165-223`）。测试用“一次性注入故障”验证了这条恢复路径
  （故障标志在返回错误前即被消费，`internal/storetest/storetest.go:210-220` 与
  `:232-245`）。这证明的是**服务自身不残留失败态、重试是全新事务**；对持续性故障，
  重试仍会继续得到 503，直到外部存储真正恢复。

## 8. 查询失败、total 与明细的一致性、快照边界

`Store.List` 的四条读取（count、页扫描、组件批读、依赖批读，含 `rows.Scan`/
`rows.Err`）任一失败都返回 `unavailable(err)`（`store.go:243`、`:250`、`:261`、
`:268`、`:307`、`:316`、`:320`、`:339`、`:358`、`:363`），事务回滚，
`List` 返回 `nil, 0, err`（`store.go:286-288`）。HTTP 层因此走错误分支
（`sbom.go:204-206`），写出的**只有**错误信封，响应体中不可能夹带部分 items
（网络级断言见 `TestListStorageFailureReturns503WithoutPartialItems`，
`internal/api/list_test.go:314-352`，其中 `envelope.Items != nil` 检查在
`:342-344`）。

**单次分页请求内**：`List` 用 `txDeferred`（普通 `BEGIN`，`store.go:79-84`、
`:240`）。四条 SELECT 全部运行在同一事务、同一专用连接上，因此 total 与本页明细
共享同一个已提交快照：total 计数时存在的已提交清单，其组件/依赖必然在同一快照下
可读；并发登记用 `BEGIN IMMEDIATE` 整体提交，读事务绝不会读到“插了清单行还没插
组件行”的半成品。这是“total 与 items 不自相矛盾、每个 item 都是完整清单”的源码
依据；受测形态见 `TestListSnapshotStaysConsistentUnderConcurrentWriters`
（`internal/store/list_test.go:353-409`，断言 items ≤ total、每条清单恰好两个
组件且依赖边完整）。

**跨页不是共享快照**【源码推导】：每次 `GET /sboms` 都独立进入一次
`Store.List` → 一次 `withTx` → 一次新的 `BEGIN`，请求结束即 COMMIT/ROLLBACK
（`store.go:102-140`、`:240-285`）；`Store` 只持有 `*sql.DB`（`store.go:16-18`），
请求之间不保留任何游标或事务状态。因此第 1 页与第 2 页可能落在不同快照上：并发写入
可改变后续页的 total 与行集；顺序仅保证已存在行按 `id ASC`（`store.go:248`）。
现有测试只覆盖**单请求内**的快照一致性与跨页“每个 item 完整、id 递增”
（`TestListServesCompleteManifestsAcrossPages`，`api/list_test.go:141-271`），
没有测试承诺跨页快照稳定，代码也未提供这种机制。

## 9. 错误响应信封与信息不泄漏

所有错误响应都是单个顶层 `error` 对象，仅含字符串 `code`、`message`
（`writeAPIError`，`sbom.go:242-244`；常量 `:233-240`）：

| 场景 | HTTP | code | message |
|---|---|---|---|
| 请求形态/字段/坐标/依赖类问题 | 400 | `InvalidSbomInputError` | `request is not a valid SBOM manifest` |
| 同键内容不同 | 409 | `SbomConflictError` | `an SBOM with different content already exists for this artifact and version` |
| 存储读/写/提交失败，及任何未预期存储错误 | 503 | `storage_unavailable` | `database is not available` |

不泄漏的两道闸：

1. 解码期的一切类型错误都收敛为包内哨兵 `errMalformed`（`sbom.go:21`、`:52-57`），
   出口统一写固定文案；
2. 存储错误的原始原因（如测试驱动的 `"forced write failure from test driver"`）
   只保留在 **Go 层错误链**里（`unavailable` 用 `%w: %v` 保留 cause，
   `store.go:449`），HTTP 层只用 `errors.Is` 判型后写固定文案
   （`sbom.go:248-257`），cause 不会上网络。

测试在网络响应字节上做黑名单断言，禁止出现 `SQLITE`、`sql:`、`goroutine`、`.go:`、
`/`、`INSERT/SELECT`、`forced` 等（`sbom_test.go:71-75`，
`register_failure_test.go:78-82`，`api/list_test.go:345-349`）；信封形态（顶层仅
`error`、内层仅 code/message 且均为非空字符串）由 `assertErrorOnlyEnvelope`
（`internal/api/register_failure_test.go:15-45`）逐字段校验。

---

## 10. 验证用例（可核对）

运行方式：`go test ./...`（当前全部通过）。每条给出初始记录、输入、预期状态与响应、
前后可见内容，并对应现有测试的相关断言。标注：【测试覆盖】=有自动化测试；
【源码推导】=由源码位置直接支持但无对应用例。

### A. 首次登记与幂等

**A1【测试覆盖】首次登记规范化。** 初始：空库。输入：第 1 节的空白+乱序请求。
预期：201，`id>0`，artifact/version 已 trim，组件 `[svc-a, svc-b]`、依赖
`svc-a→[svc-b]`、`svc-b→[]`。后可见：该规范化记录。对应
`TestRegisterCreatesNormalizedManifest`（`sbom_test.go:78-109`，`id>0` 断言
`:96-98`，整体相等 `assertSBOMEqual` `:538-560`）。

**A2【测试覆盖】相同内容换序重提。** 初始：A1 已登记。输入：同内容、数组洗牌、
再加空白。预期：两次都 201，第二次 `id` 与首次相同、响应体逐字段相等；随后
`GET /sboms?artifact=app` 的 `total=1, items=1`，列表记录与首次响应相等。对应
`TestRegisterIsIdempotentRegardlessOfOrder`（id 不变断言 `sbom_test.go:215-217`）
与 `TestReplayAndListReturnIdenticalManifest`（`:225-269`，total/items 断言
`:262-264`）。

**A3【测试覆盖】8 个并发相同请求只产生一条记录。** 预期：8×201 且 8 个响应同 id。
`TestConcurrentIdenticalRegistersShareOneRecord`（`sbom_test.go:475-520`）。

**A4【测试覆盖】重开数据库后幂等仍然成立。** 关闭再打开同一 DB 文件，重提同内容
201 且 id 不变；改内容仍 409；查询得到原记录。
`TestPersistsAcrossReopen`（`sbom_test.go:427-473`）。

### B. 冲突 409

初始：`app@1` 含组件 `a(L)`、`b(L)`，均无依赖。对以下三种输入各起一个独立子用例：

**B1【测试覆盖】许可证改变**：`a(OTHER)` → 409 `SbomConflictError`。
**B2【测试覆盖】组件集合改变**：只有 `b(L)`（少了 a）→ 409。
**B3【测试覆盖】依赖关系改变**：增加 `b→a` → 409。

每个子用例在冲突后查询：`total=1, items=1`，仍是两个组件的原记录。对应
`TestRegisterConflictLeavesOriginalUntouched`（`sbom_test.go:271-306`；
状态+code 断言 `:290` 走 `expectError`；原记录未变断言 `:298-303`）。

**B4【测试覆盖】大小写导致的冲突**：`App@1` 已存 `[a]`，提交坐标 `A` → 409；
而 `app@1`（小写制品）是另一条独立记录、可 201；`GET /sboms?artifact=App`
`total=1`。`TestComparisonsAreCaseSensitive`（`sbom_test.go:308-328`）。

### C. 400 输入拒绝（初始均为空库，失败后查询 total=0）

**C1【测试覆盖】缺字段/空值/类型错误**：空 body、坏 JSON、顶层数组/null/数字/字符串、
缺 artifact/version/components、`components:null`、空白 artifact/version、字段类型
错误（数字 artifact、字符串 components、标量/null 元素、null license/dependencies
等）、空白坐标——全部 400 `InvalidSbomInputError`。
`TestRegisterRejectsInvalidInput`（`sbom_test.go:144-186` 中同名子用例）。

**C2【测试覆盖】重复坐标**（含 trim 后重复，`" c "` 与 `"c"`）→ 400。同上
`"duplicate coordinates"`、`"duplicate after trimming"`（`:172-173`）。

**C3【测试覆盖】依赖问题**：重复依赖 `["x","x"]`、自依赖 `["c"]`、空白依赖、
依赖元素为数字、悬空目标 `"ghost"` → 400。同上 `:174-178`；悬空目标的判定代码在
`sbom.go:139-144`。

**C4【测试覆盖】查询参数**：缺/空白 `artifact`、空/0/负/小数/非数字 `page`、
`pageSize=0/101/abc/-20` → 400；`pageSize=100` 合法。
`TestListRejectsBadQuery`（`sbom_test.go:400-425`）。

**C5【测试覆盖】合法的空**：`components:[]` → 201 且回读空数组；无依赖组件 →
依赖回读 `[]`。`TestRegisterAllowsEmptyComponentsAndDependencies`
（`sbom_test.go:111-131`）。

**C6【测试覆盖】非自身环**：a→b、b→a → 201，并在查询时两条边都完整回读。
登记：`TestRegisterAllowsNonSelfCycles`（`sbom_test.go:133-142`）；回读：
`TestListServesCompleteManifestsAcrossPages` 中环断言（`api/list_test.go:251-270`）。

### D. 写入失败 503 与恢复

**D1【测试覆盖】组件插入失败。** 初始：空库。输入：第 1 节的两组件一依赖清单；
通过故障驱动让下一条 components INSERT 失败（`FailNextWrite("components")`）。
预期：503 `storage_unavailable`，信封仅 error/code/message，且不含
`INSERT/SQLITE/sql:/goroutine/.go:/forced//`；随后 `GET /sboms?artifact=app`
为 200 但 `total=0, items=[]`（失败登记不可见）；**同一请求原样重提**（一次性故障
已消耗）→ 201，返回完整两组件一依赖记录；再次查询 `total=1, items=1` 且与响应相等。
HTTP 层：`TestRegisterDetailWriteFailureReturns503` 的 `"components"` 子用例
（`register_failure_test.go:61-118`；状态/信封/泄漏 `:73-82`；不可见 `:85-91`；
恢复 `:95-115`）。存储层同构断言：
`TestRegisterDetailWriteFailureRollsBack/"components"`（`tx_test.go:24-60`）。

**D2【测试覆盖】依赖插入失败。** 同 D1，故障点换为 dependencies INSERT
（`FailNextWrite("dependencies")`）：503、不可见、重提 201、依赖边 `a→b` 完整。
对应 D1 两个测试的 `"dependencies"` 子用例；恢复后边的断言
`register_failure_test.go:104-108`、`tx_test.go:90-99`。

**D3【测试覆盖】已有清单旁的新登记失败不伤及旧记录。** 初始：`app@1` 含
`a(ORIGINAL)`。输入：注册 `app@2` 时制造 components 写入失败 → 503。查询
`artifact=app`：`total=1, items=1`，仍是 `app@1`，许可证仍是 `ORIGINAL`。
`TestRegisterWriteFailureLeavesExistingManifestsWhole`
（`register_failure_test.go:123-146`）。

**D4【测试覆盖】存储句柄关闭后的朴素 503。** 先 `st.Close()` 再登记/查询，均 503。
`TestStorageFailureMapsTo503`（`sbom_test.go:522-536`）。

### E. 查询失败与分页

**E1【测试覆盖】四步读取逐一失败。** 初始：两组件一依赖清单。分别对
count/sboms/components/dependencies 注入下一次读失败，`GET /sboms?artifact=app`
均 503 `storage_unavailable`，无 `items` 字段、无内部串泄漏。HTTP：
`TestListStorageFailureReturns503WithoutPartialItems`（`api/list_test.go:314-352`）；
存储层（且断言返回的 `items == nil`）：
`TestListReadFailuresReturnUnavailable`（`store/list_test.go:329-348`）。

**E2【测试覆盖】分页、total 与空页。** 初始：app 五个版本（乱序登记）+ other 两个。
`pageSize=2` 翻页：每页 `total=5`、回显 page/pageSize、页内 id 严格递增，末页 1 条；
`page=4` 为空 items 但 total 仍 5；未知制品 `total=0, items=[]`、默认 1/20。
`TestListPaginatesByIDWithTotal`（`sbom_test.go:330-398`）。SELECT 预算（非空页恰好
4 条、空页 2 条、明细行不越页不越制品）：
`TestListRequestUsesAtMostFourSelects`（`api/list_test.go:34-135`）与
`TestListUsesAtMostFourSelects`（`store/list_test.go:51-190`）。

**E3【测试覆盖】跨版本同坐标不串台、空数组在线缆上不是 null。**
`TestListKeepsSameCoordinatesScopedPerVersion`（`store/list_test.go:255-312`）、
`TestListEmptyArraysAreNeverNull`（`api/list_test.go:275-309`）。

### F. 回滚清理本身报错（见第 11 节的适用边界）

**F1【测试覆盖】写入失败 + ROLLBACK 报告失败。** 初始：`app@1` 两组件一依赖。
注册 `app@2` 时同时注入 components 写故障与下一次 ROLLBACK 故障。预期：调用方拿到
的错误仍是 `ErrStorageUnavailable` 且错误文本保留 `"forced write failure"`、不含
`"forced rollback failure"`；之后查询只有 `app@1` 原样存在；同连接/同池可以成功登记
`app@2`。`TestRollbackFailureKeepsOriginalError`（`tx_test.go:108-145`；断言
`:119-127`、`:130-140`、`:144`）。

**F2【测试覆盖】冲突提前返回 + ROLLBACK 报告失败。** 冲突方仍收到 `ErrConflict`
（不含清理错误串），原记录不变，随后相同内容重提仍拿回原记录。
`TestConflictReturnSurvivesRollbackFailure`（`tx_test.go:151-184`）。

## 11. 回滚失败测试中“真实数据库操作”与“模拟返回错误”的差别

F1/F2 容易被过度解读，必须把测试驱动实际做了什么说清楚。关键代码在
`internal/storetest/storetest.go:133-147`：

```go
if isRollback(query) {
    // Always run the real ROLLBACK first ...
    res, err := c.Conn.(driver.Execer).Exec(query, args) // 1) 真实 ROLLBACK 先执行
    ...
    if fail {
        return res, errors.New("forced rollback failure ...") // 2) 再返回一个合成错误
    }
    return res, err
}
```

即：

- **真实发生的数据库操作**：合成错误返回之前，驱动先把真正的 `ROLLBACK` 发给真实
  SQLite 驱动执行（`storetest.go:138`）。事务在数据库侧确实被撤销，连接也确实脱离
  了事务状态。F1 中“部分记录不可见”（`tx_test.go:130-136`）与“之后还能用同一存储
  成功登记”（`:144`）的结果，**依赖的是这次真实回滚已经成功**。
- **被模拟的部分**：只有“`ROLLBACK` 的返回值是错误”这件事是假的（一次性，标志在
  `storetest.go:140-142` 返回前清除）。它用来验证产品代码
  `withTx` 中 `_, _ = c.ExecContext(..., "ROLLBACK")` 刻意吞掉清理错误
  （`store.go:127-129`），以及业务/存储错误原样透传（`store.go:132-134`）——清理
  错误不得替换“写入失败”或“冲突”这个主结论。

因此这两个测试**不能**外推为：“即使 ROLLBACK 在真实数据库里真的失败、留下状态未决
或仍打开的事务，服务也保证后续操作正常”。那种情形没有被构造：真实 ROLLBACK 在此
总是先成功，`database/sql` 在“真回滚失败”时的连接丢弃行为也未被断言。能成立的
结论只有三条：错误优先级（主错误不被覆盖）、清理错误不外泄到 HTTP（固定 503
文案，D1 的泄漏断言）、以及在“回滚实际成功”的前提下连接可复用、重试可成功登记。

## 12. 不在本次范围

- 未修改任何产品源码与 `README.md`；`GET /healthz` 行为不变
  （`router.go:25-31`，`TestHealthzReportsOK` 仍通过）；
- 未涉及与外部基线/其他实现的差异比对；
- 未承诺跨页共享快照、未承诺持续性存储故障下的自动恢复（第 8、7 节已划界）。
