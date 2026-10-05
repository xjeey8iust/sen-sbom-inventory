# `GET /sboms/diff` 版本差异比对源码说明（基于源码）

本说明专门解释差异比对接口 `GET /sboms/diff`：从公开 HTTP 请求进入路由开始，沿
处理器 → 存储只读事务 → 组件/依赖重建 → 差异计算 → 最终响应，逐段追踪，并回答四个
问题：

1. 三个查询标识（`artifact`、`fromVersion`、`toVersion`）怎样去空白、怎样匹配；
2. 两份清单的组件差异怎样确定；
3. 两份清单怎样保证在同一个已提交快照上读取，组件与依赖怎样归属于各自的清单；
4. 参数错误、版本不存在、存储失败分别怎样返回。

每个关键结论都标注**源码文件、函数与行号**（形如 `internal/api/diff.go: diff, 17-24`）。
第 9 节逐条核对现有测试**真正断言到的内容**，全文区分【测试覆盖】与【源码推导】：
前者有自动化断言并在撰写时实际运行通过，后者由当前源码结构直接支持、但没有对应的
端到端断言，不能当作“测试已保证”。

范围与基线：当前已实现登记（`POST /sboms`）、按制品分页查询（`GET /sboms`）与版本
差异比对（`GET /sboms/diff`）。登记的幂等/冲突与分页语义已在
`docs/registration-integrity.md` 说明，本文不重复，只在差异链路实际依赖处引用。
本次只新增本说明，**不修改产品源码、`README.md` 或已有说明**；`GET /healthz`
（`internal/api/router.go:25-31`）、`POST /sboms`、`GET /sboms` 的行为保持原样。

撰写时运行记录：`go test ./...` 通过（`internal/api`、`internal/store` 为 ok；
`main`、`internal/model`、`internal/storetest` 无测试文件）。

---

## 1. 贯穿全文的示例：同一制品 `atlas` 的两份小清单

下面两份清单刻意覆盖四种情形：新增组件、移除组件、许可证改变、**仅依赖顺序变化**；
另含完全未变组件。两份都是合法登记请求（依赖目标都在本清单内、无自依赖、无重复）。

### 1.1 登记旧版本（fromVersion）

```http
POST /sboms
Content-Type: application/json

{
  "artifact": "atlas",
  "version": "1.0",
  "components": [
    {"coordinate": "lib-old", "license": "OLD",       "dependencies": []},
    {"coordinate": "stable",  "license": "S",         "dependencies": []},
    {"coordinate": "lib-edge","license": "E",         "dependencies": ["stable"]},
    {"coordinate": "lic",     "license": "MIT",       "dependencies": []},
    {"coordinate": "order",   "license": "O",         "dependencies": ["stable", "util"]},
    {"coordinate": "util",    "license": "U",         "dependencies": []}
  ]
}
```

预期 `201 Created`。登记处理器在入库前对依赖数组排序
（`internal/api/sbom.go: register, 145`）、对组件按坐标排序（同函数 `152`），
所以响应体组件顺序为 `lib-edge, lib-old, lic, order, stable, util`，`order` 的依赖
规范化为 `["stable","util"]`（组件/依赖排序的完整规则见登记完整性说明第 4 节）。

### 1.2 登记新版本（toVersion）

```http
POST /sboms
Content-Type: application/json

{
  "artifact": "atlas",
  "version": "2.0",
  "components": [
    {"coordinate": "lib-new", "license": "N",          "dependencies": []},
    {"coordinate": "stable",  "license": "S",          "dependencies": []},
    {"coordinate": "lib-edge","license": "E",          "dependencies": ["stable", "lib-new"]},
    {"coordinate": "lic",     "license": "Apache-2.0", "dependencies": []},
    {"coordinate": "order",   "license": "O",          "dependencies": ["util", "stable"]},
    {"coordinate": "util",    "license": "U",          "dependencies": []}
  ]
}
```

同样预期 `201`。注意 `order` 的依赖输入顺序与旧版本相反，但登记排序后存储形态仍是
`["stable","util"]`；`lib-edge` 新增了指向 `lib-new` 的直接依赖，排序后为
`["lib-new","stable"]`。

### 1.3 发起比对

```http
GET /sboms/diff?artifact=atlas&fromVersion=1.0&toVersion=2.0
```

### 1.4 预期响应：`200 OK`

```json
{
  "artifact": "atlas",
  "fromVersion": "1.0",
  "toVersion": "2.0",
  "added": [
    {"coordinate": "lib-new", "license": "N", "dependencies": []}
  ],
  "removed": [
    {"coordinate": "lib-old", "license": "OLD", "dependencies": []}
  ],
  "changed": [
    {
      "coordinate": "lib-edge",
      "before": {"coordinate": "lib-edge", "license": "E", "dependencies": ["stable"]},
      "after":  {"coordinate": "lib-edge", "license": "E", "dependencies": ["lib-new", "stable"]}
    },
    {
      "coordinate": "lic",
      "before": {"coordinate": "lic", "license": "MIT",       "dependencies": []},
      "after":  {"coordinate": "lic", "license": "Apache-2.0","dependencies": []}
    }
  ]
}
```

### 1.5 每个组件为什么落到这个结果

判定发生在 `internal/api/diff.go: buildDiff, 65-106`，先把两份清单各自按坐标建索引
（`66-67`，索引函数 `indexComponents, 108-114`），再做坐标集合运算：

- **`lib-new`（新增 → `added`）**：只在新清单坐标集合中（`buildDiff, 78-82`）。
- **`lib-old`（移除 → `removed`）**：只在旧清单坐标集合中（`83-87`）。
- **`lic`（许可证改变 → `changed`）**：两边都有该坐标，且 `License` 不等
  （判定条件 `93` 的左半；组装完整前后组件 `94-98`）。
- **`lib-edge`（直接依赖集合变化 → `changed`）**：许可证同为 `E`，但直接依赖坐标
  集合由 `{stable}` 变为 `{lib-new, stable}`（判定条件 `93` 的右半，
  `sameDependencySet, 120-134`）。它的许可证也随 `before`/`after` 完整带出。
  一个组件是否变化只看它**自身**：即使被引用的 `lib-new` 同时是新增组件，
  `lib-edge` 是否进 `changed` 仍仅由它自己的许可证与直接边决定。
- **`order`（仅依赖顺序变化 → 省略）**：两侧许可证相同，直接依赖是同一集合
  `{stable, util}`。入库时两侧数组都已被登记排序为相同形态；差异层另外显式按
  **集合**比较（`sameDependencySet, 120-134`：先比长度 `121-123`，再逐个验成员
  `124-132`，顺序不参与），因此顺序差异不构成变化。
- **`stable`、`util`（完全未变 → 省略）**：坐标两边都有，许可证与直接依赖集合都
  相同，不满足 `93` 的任一条件。`changed` 只收集发生变化的坐标，未变化组件不出现在
  任何数组中（`88-100` 的循环只 append 变化项）。

响应中没有清单 `id` 字段：成功结构体 `diffResponse` 只有三个标识与三个结果数组
（`internal/api/diff.go: diffResponse, 45-52`）。

---

## 2. 调用链总览：从公开请求到最终响应

路由注册：`internal/api/router.go: NewRouter, 18-41`。三个公开 GET/POST 各自独立：
`POST /sboms`（`router.go:33`）、`GET /sboms`（`router.go:34`）、
`GET /sboms/diff`（`router.go:35`，处理器 `h.diff`）。`/sboms` 与 `/sboms/diff`
是 gin 路由树上两条不同路径，互不遮蔽（守卫测试
`TestDiffKeepsExistingRoutesBehavior`，`internal/api/diff_test.go:400-413`）。

| # | 阶段 | 源码位置 | 行为 | 失败出口 |
|---|---|---|---|---|
| 1 | 取查询参数 | `internal/api/diff.go: diff, 17-19` | `c.Query` 取三个参数（查询串已按百分号解码），各自 `strings.TrimSpace` | — |
| 2 | 必填/空白校验 | `diff, 20-24` | 任一缺失或 trim 后为空 → 400，**在访问存储之前返回** | 400 `InvalidSbomInputError` |
| 3 | 存储读取 | `diff, 26` → `internal/store/store.go: Diff, 302-369` | 单个延迟只读事务内完成存在性扫描与两份清单重建 | 404 / 503 |
| 4 | 错误映射 | `diff, 27-30` → `internal/api/sbom.go: writeStoreError, 250-261` | sentinel → HTTP 状态码与固定 code/message | 404 / 503 |
| 5 | 差异计算 | `internal/api/diff.go: buildDiff, 65-106` | 坐标建索引 → added/removed/changed 分区 → 排序 | 纯内存，不失败 |
| 6 | 成功响应 | `diff, 31` | `c.JSON(http.StatusOK, …)`，200 + 第 1.4 节结构 | — |

成功与失败在处理器里是互斥两条路径：存储返回错误时 `writeStoreError` 写响应后
`return`（`diff.go:28-30`），不会继续走到第 31 行的成功 JSON。

---

## 3. 三个查询标识：去空白、必填与匹配规则

### 3.1 去空白与必填【测试覆盖】

- 三个参数都经过 `strings.TrimSpace`（`internal/api/diff.go: diff, 17-19`）：
  `artifact`、`fromVersion`、`toVersion`。
- 缺失与“去空白后为空”收敛为同一种拒绝（代码注释 `diff.go:20`，判定
  `21-24`）。gin 的 `c.Query` 在参数不存在时返回 `""`，`?toVersion=` 同样得到
  `""`，`?artifact=%20%20` 解码后是两个空格、trim 后也是 `""`，因此全部走同一个
  400 分支。
- HTTP 响应为 400，code `InvalidSbomInputError`，message 固定为
  `"request is not a valid SBOM manifest"`（调用点 `diff.go:22`；常量
  `internal/api/sbom.go: invalidInputCode/invalidInputMessage, 234, 238`）。
  注意差异接口复用的是登记接口的这句固定文案——查询参数错误时正文里也不会出现
  针对 diff 的定制消息，这是当前源码事实。
- 测试实际形态（8 个 URL，全部期望 400 + 该 code）：三个参数全缺、缺
  `artifact`、缺 `toVersion`、缺 `fromVersion`、`artifact` 为两个空格、
  `fromVersion` 为制表符 `%09`、`toVersion` 为空串、`toVersion` 为两个空格
  （`internal/api/diff_test.go: TestDiffRejectsMissingOrBlankParams, 285-300`）。
  该测试经 `expectError`（`internal/api/sbom_test.go:53-76`）还断言了 message
  非空且不含 `SQLITE`、`sql:`、`goroutine`、`.go:`、`/` 等串；**它不断言 message
  的具体文案**。

【源码推导】查询串的百分号解码由 gin/net/url 在进入处理器前完成，`%20`、`%09`
到达 `TrimSpace` 时已经是空格/制表符；`strings.TrimSpace` 去除的是 Unicode 空白。
上述测试通过编码后的空格与制表符间接覆盖了这一点，但没有测试逐个枚举其他 Unicode
空白字符。

### 3.2 精确、大小写敏感匹配

- 处理器只做 trim，**不做任何大小写折叠**；trim 后的值原样下传
  （`diff.go:17-19, 26`）并原样回显（`buildDiff` 把收到的三个参数放进响应，
  `diff.go:69-72`；回显断言 `internal/api/diff_test.go:341-343`）。
- 存储侧匹配就是普通 SQL TEXT 相等：存在性扫描为
  `WHERE artifact = ? AND version IN (?, …)`（`store.go: Diff, 312-320`），全代码
  没有 `LOWER` 之类的折叠。
- 【测试覆盖】制品名大小写敏感：先登记 `"  App  "/" 1 "` 与 `"App"/"2"`，带空白的
  请求 trim 后 200 且回显 `App/1/2`；而 `artifact=app`（小写）匹配不到任何行，
  返回 404（`TestDiffTrimsParamsAndMatchesCaseSensitively`，
  `internal/api/diff_test.go:330-351`，404 断言 `347-348`）。
- 【源码推导】**版本号**的大小写敏感没有专门的差异测试；它与制品名走同一个
  `=` 比较（`store.go:313-314`），源码上同为精确匹配。不能把制品名的大小写测试
  外推成“版本号大小写已被测试覆盖”。

### 3.3 版本只作标识，不推断先后；允许自比较

- 处理器注释明确：版本只是标识符，接口从不推断哪个更新，`fromVersion`/
  `toVersion` 由请求显式命名（`internal/api/diff.go:13-15`）。代码中不存在任何
  版本号大小比较或时间戳排序。
- **允许自比较**：参数校验只查非空（`diff.go:21`），没有“两个版本必须不同”的
  规则。存储侧发现两个版本号相等时把 IN 列表收缩为一个值（`store.go:308-311`），
  只扫描一次；随后用同一个 map 键填充两个结果槽（`store.go:347-348`），
  自比较得到的是同一条已存储记录。
  - 【测试覆盖】HTTP 层：存在的清单自比较返回 200 且三个数组都为空
    （`TestDiffSelfComparisonReturnsThreeEmptyArrays`，
    `internal/api/diff_test.go:193-208`，示例清单本身含 a↔b 环）。
  - 【测试覆盖】存储层：自比较时 `from.ID == to.ID`、内容相等，且整条请求只有
    3 条 SELECT、sboms 表只读 1 行（`TestDiffSelfLoadsOneManifestAndIsIdentity`，
    `internal/store/diff_test.go:83-113`，ID 断言 `95-97`，SELECT/行数断言
    `106-112`）。
  - 【测试覆盖】自比较一个**不存在**的版本仍是 404（收缩后单槽位也查不到）：
    HTTP 子用例 `"self missing"`（`internal/api/diff_test.go:314, 321-324`）。
- 【测试覆盖】两个**不同版本号但内容相同**的清单，即使请求方向与登记顺序相反
  （先登记 2 后登记 1，请求 `fromVersion=2&toVersion=1`），三个数组也全空
  （`TestDiffIdenticalDistinctVersionsReturnsEmpty`，
  `internal/api/diff_test.go:213-226`）。
- 【源码推导】方向相反且**内容不同**时，`added` 与 `removed` 会整体互换：
  `before`/`after` 仅由传入的两份清单决定（`buildDiff, 65-67, 78-87`），代码不
  区分方向语义。现有测试只验证了“内容相同、方向相反 → 空”，没有验证“内容不同、
  方向相反 → added/removed 对调”，故标注为源码推导。
- 【源码推导】两个版本通过同一条 `artifact = ?` 过滤读出（`store.go:313`），
  因此无法用本接口跨制品比较：某版本只存在于其他制品名下时，在本制品的扫描结果中
  不存在，按 404 处理（存在性判定见 4.3 节）。现有测试只覆盖未知制品 `ghost`
  两边都缺失（`internal/api/diff_test.go:313`），没有构造“版本号存在但属于另一
  制品”的用例。

---

## 4. 两份清单怎样在同一快照上一致读取

读取全部在 `Store.Diff` 的**一个**延迟读事务里完成
（`internal/store/store.go: Diff, 302-369`，开启事务 `304`）。

### 4.1 单事务、单连接、一个已提交快照

- 事务生命周期统一走 `withTx`（`store.go:102-140`）：先获取专用连接并在任何退出
  路径归还（`db.Conn` `103-106`，`defer c.Close()` `109`），再 `BEGIN`
  （`111-121`）。
- 差异比对用 `txDeferred`，即普通 `BEGIN`（枚举注释 `store.go:78-84`：延迟事务
  “pins one committed snapshot for every SELECT inside it”；调用点 `304`）。
  存在性扫描、组件批读、依赖批读三条 SELECT 全部运行在同一事务、同一连接上
  （`store.go:321`、`357`、`360`），因此两份清单必然取自**同一个已提交快照**：
  不可能一份来自旧提交、一份来自新提交。
- 登记侧 `Register` 使用 `BEGIN IMMEDIATE`（`store.go:149`，模式说明
  `113-118`），清单行、全部组件行、全部依赖行在同一事务内写入、只在最后
  `COMMIT` 一次（插入 `171-217`，提交 `135-138`）。所以差异读事务绝不会看到
  “清单行已插、组件行未插”的半成品（`Diff` 的文档注释同样说明了这一点，
  `store.go:292-301`）。
- 【测试覆盖】读取预算与作用域：两个不同版本整次 `Diff` 恰好 3 条 SELECT
  （sboms 一次、组件一次、依赖一次），行数严格等于这两份清单，并验证另一制品的
  同坐标组件不会泄漏进结果（`TestDiffUsesOneSnapshotReadEach`，
  `internal/store/diff_test.go:170-205`，SELECT 数 `190-192`，行数 `193-197`，
  泄漏检查 `198-204`）。
- “同一快照”这一结构性保证本身来自上述单事务源码；并发测试只做经验性观测，其
  断言边界见第 8 节。

### 4.2 组件与依赖的清单归属

表结构（`store.go: schema, 531-556`）决定了明细的归属：

- `sboms`：`(artifact, version)` 唯一（`536-541`），所以 IN 扫描对每个版本至多
  返回一行（`Diff` 注释 `store.go:305-307`）；
- `components`：外键 `sbom_id` 归属清单，`UNIQUE(sbom_id, coordinate)` 保证坐标
  在同一清单内唯一（`542-548`）；
- `dependencies`：边的两端都是组件 id，`UNIQUE(component_id, target_id)` 去重
  （`549-554`）。

读取时的归属与重建规则（与分页查询、登记幂等回读共用同一对装载器，
`store.go: Diff` 调用点 `357-362`）：

1. 先用一次 `artifact = ? AND version IN (…)` 扫描拿到清单 id 与按版本的映射
   （`store.go:312-340`，`byVersion` 建图 `330, 339`）；每个待重建清单在创建时
   就带上非 nil 的空组件切片（`store.go:332`）。
2. 组件批读 `loadComponentsInto`（`store.go:377-400`）只查这些 sbom id
   （IN 列表 `381`），按 `sbom_id ASC, coordinate ASC` 排序（`382`）；每个组件
   创建时 `Dependencies` 即为非 nil 空切片（`393`），保证无依赖组件回读为 `[]`
   而非 `null`。
3. 依赖批读 `loadDependenciesInto`（`store.go:408-443`）只查这些 sbom id
   （`414`），并且 JOIN 显式要求**目标组件与源组件同属一个清单**：
   `tc.sbom_id = sc.sbom_id`（`413`）。因此不同版本复用相同坐标时，边绝不会连到
   另一份清单的同坐标目标（函数注释 `402-407`）。结果按源坐标、目标坐标升序
   （`415`），挂回各组件（`433-441`），每个组件的依赖因此天然按坐标升序。

【测试覆盖】重建后的完整内容、坐标升序、空依赖非 nil、跨版本同坐标不串台：
存储层 `TestDiffPartitionsComponentsByPresenceAndChange`
（`internal/store/diff_test.go:25-79`，排序断言 `60-62`、空依赖非 nil `63-65`、
完整组件 `69-78`）；跨制品不泄漏见 4.1 的行数与 `SECRET` 检查。分页路径上更广的
跨版本作用域断言见 `TestListKeepsSameCoordinatesScopedPerVersion`
（`internal/store/list_test.go:255-312`），两条读路径共用同一装载器
（`store.go:466-491` 的 `loadSBOM` 同样委托这两个函数）。

### 4.3 存在性在明细读取之前一次性判定

扫描完成后、任何明细查询之前，代码用 map 查找同时定位两侧
（`store.go:347-348`），任一侧为 nil 即返回 `model.ErrNotFound`（`349-351`）：

- 任一侧缺失 → **一个** `model.ErrNotFound`；两侧都缺失时没有逐版本累积错误，
  仍是这一个返回值、HTTP 上一个错误信封。
- 判定先于组件/依赖读取（`357-362` 不会执行），所以“只有一侧存在”时也不会多读
  存在侧的明细【源码推导：提前返回 `350`，现有测试只验证错误与 nil 结果，未统计
  这种情况下的 SELECT 数】。

【测试覆盖】五种 404 形态：双方都缺、from 缺、to 缺、未知制品、自比较缺失，
HTTP 层全部 404 `SbomNotFoundError` 且信封只有 error
（`internal/api/diff_test.go:305-326`）；存储层断言 `errors.Is(err, ErrNotFound)`
且 `from`、`to` 都为 nil，没有部分清单
（`internal/store/diff_test.go:139-165`，nil 断言 `160-162`）。

### 4.4 存储失败：503，且不带部分差异

- 事务内任一步失败——取连接/开启事务（`withTx, 103-121`）、sboms 扫描
  （`store.go:321-324`、`341-343`）、组件批读（经 `357-359` →
  `loadComponentsInto` 的错误返回 `386, 395, 399`）、依赖批读
  （`360-362`、`417, 437, 442`）、COMMIT（`135-137`）——都经
  `unavailable`（`store.go:524-529`）包装为 `model.ErrStorageUnavailable`。
- `Diff` 对错误直接 `return nil, nil, txErr`（`store.go:365-367`），成功时才
  返回两份清单（`368`）。
- 存在性扫描本身报错属于**存储失败而非 404**：错误在 `322-324` 即返回，走不到
  `349-351` 的存在性判定。【测试覆盖】存储层对 sboms/components/dependencies
  三类读取各注入一次故障，全部 `ErrStorageUnavailable` 且两份清单均为 nil
  （`TestDiffReadFailuresReturnUnavailable`，
  `internal/store/diff_test.go:211-233`，其注释 `207-210` 明确了 sboms 故障不
  降级为 not-found）。
- 【测试覆盖】HTTP 层同样对三类读取逐一注故障：全部 503
  `storage_unavailable`、响应经 `assertErrorOnlyEnvelope` 验证只有顶层 error
  （不含任何 `added`/`removed`/`changed` 字段），且字节中不含 `SELECT`、
  `SQLITE`、`sql:`、`goroutine`、`.go:`、`forced read failure`
  （`TestDiffStorageFailureReturns503WithoutPartialResult`，
  `internal/api/diff_test.go:355-381`）。关闭数据库句柄后的朴素失败同样 503
  （`TestDiffWithClosedStoreReturns503`，`385-396`；失败点在
  `withTx` 取连接处，`store.go:103-106`）。

---

## 5. 组件差异怎样确定（`buildDiff` 的判定规则）

入口：处理器在存储成功后调用 `buildDiff(artifact, fromVersion, toVersion, before,
after)`（`internal/api/diff.go:31, 65-106`）。

1. **按坐标索引**：两份清单各建 `map[coordinate]Component`（`66-67`，
   `indexComponents, 108-114`）。登记已拒绝清单内重复坐标
   （`internal/api/sbom.go:70-73`），数据库还有 `UNIQUE(sbom_id, coordinate)`
   兜底（`store.go:547`），所以 map 键在一份清单内唯一，不存在“同坐标两条互相
   覆盖”的实际情形【源码推导：约束与登记校验支持，差异链路本身不去重】。
2. **added**：坐标只在新清单（`78-82`），成员是新清单中的**完整组件**
   （map 里存的是整个 `model.Component`，`110-112`）。
3. **removed**：坐标只在旧清单（`83-87`），成员是旧清单的完整组件。
4. **changed**：坐标两边都有（`88-92`），且满足
   `oldComp.License != newComp.License || !sameDependencySet(...)`（`93`）；
   每项为 `{coordinate, before, after}`，`before`/`after` 是旧、新清单中该坐标
   的两个**完整组件**（结构体 `componentChange, 37-41`，组装 `94-98`），组件
   字段即登记响应同款的 `coordinate/license/dependencies`
   （`internal/model/sbom.go: Component, 10-14`）。
5. **排序**：三个数组在返回前各自 `sort.Slice` 按坐标字符串升序
   （`diff.go:102-104`）。前面的收集循环遍历 map（`78, 83, 88`），Go map 遍历
   顺序不稳定，排序使响应与登记顺序、map 遍历都无关【源码推导：排序本身受测，
   “抵消 map 随机性”是其结构效果】。
6. **空数组而非 null**：三个结果字段在创建响应时就初始化为非 nil 空切片
   （`diff.go:73-75`），之后只 append，不可能为 nil。组件的 `dependencies`
   来自 4.2 节重建出的非 nil 切片（`store.go:393`）。

### 5.1 三类变化各自影响哪些结果

- **坐标改名**：坐标是组件在比对中的唯一身份，改名没有任何“同一组件”的推断，
  因此旧坐标进 `removed`、新坐标进 `added`，绝不进 `changed`（代码效果来自
  `78-87` 与 `89-92`，注释明示 `diff.go:58-60`）。【测试覆盖】
  `TestDiffCoordinateRenameIsRemovePlusAdd`（`internal/api/diff_test.go:138-157`）。
  【源码推导】若其他组件的直接边因改名而改指（例如从依赖旧坐标改为依赖新坐标），
  那些引用方会因**自身直接依赖集合变化**各自独立进入 `changed`——这是
  `93` 右半的直接推论；现有改名用例中没有任何组件引用被改名坐标，未覆盖此情形。
- **直接依赖集合变化（增边/删边）**：只影响该组件自身——它进入 `changed`，
  `before.dependencies` 与 `after.dependencies` 分别给出变化前后两个完整集合。
  若新增的边指向一个新坐标，那么“目标进 `added`”与“源组件进 `changed`”两件事
  各自独立成立。【测试覆盖】`moved-edge` 增边且两侧许可证都完整带出
  （`internal/api/diff_test.go:87-98`）、`zeta-change` 增边（`42, 43, 64`）、
  集合相等但顺序不同不算变化、删除一条依赖算变化
  （`TestBuildDiffComparesDependenciesAsSets`，`418-435`）。
- **目标许可证变化**：组件 b 的许可证变化只让 b 自己进 `changed`；引用 b 的组件
  a 只要自身许可证不变、自身直接依赖坐标集合不变，就**不**进 `changed`
  （判定只读取组件自身字段，`diff.go:93`）。【测试覆盖】见 5.2 的传播用例。
- **许可证改变**：仅该坐标进 `changed`，前后许可证在完整组件中对照
  （`rel` 的 `OLD`/`NEW` 断言 `internal/api/diff_test.go:84-86`；
  `alpha-change` 的 A/A2 见 `35, 43, 64`）。

### 5.2 不展开传递依赖、不传播目标变化

`sameDependencySet`（`diff.go:120-134`）只比较两个组件**直接声明**的依赖坐标
数组：先比长度（`121-123`），再把 a 建成集合、验证 b 的每个成员都在其中
（`124-132`）。整个 `diff.go` 没有任何沿边遍历或可达性计算：

- 传递闭包变化不标记中间组件；
- 依赖目标的许可证变化不沿边传播给引用方。

【测试覆盖】`TestDiffOnlyDirectRelationsAndNoPropagation`
（`internal/api/diff_test.go:163-189`）：旧清单 a→b、b→c、c 许可证 `OLD`；
新清单 a→b、b→c 不变，c 许可证变 `NEW` 且新增直接边 c→d，d 为新组件。结果
`changed` 只有 c、`added` 只有 d、`removed` 为空（`180-188`）——a、b 的传递
闭包因 c→d 而改变、且它们的直接目标 c 改了许可证，但二者都不进 `changed`。

### 5.3 现有测试对“完整前后组件 / 排序 / 空数组”的实际断言粒度

- 【测试覆盖】`changed` 四项按坐标升序（`alpha-change, moved-edge, rel,
  zeta-change`），每项前后坐标一致、前后 `dependencies` 均非 nil
  （`internal/api/diff_test.go:64-79`）；仅边变化时两侧许可证都携带
  （`96-98`）；多边时 after 依赖按升序完整给出（`91-94`）。
- 【测试覆盖】`added`/`removed` 多组件时分别按坐标升序（新增 `[b n y]`、
  移除 `[a m z]`），且 `changed` 为空
  （`TestDiffSortsAddedAndRemovedAcrossMultipleComponents`，
  `internal/api/diff_test.go:103-134`）。
- 【测试覆盖】三个顶层数组在线缆上是 `[]` 而不是 `null`：把响应解码为
  `*[]json.RawMessage` 指针并逐一检查非 nil、长度 0
  （`TestDiffEmptyManifestsAndEmptyArraysNeverNull`，`230-255`）。
- 【源码推导】`added`/`removed` 成员携带**非空依赖数组**这一点没有端到端用例：
  现有用例中的 born/gone 恰好都无依赖，断言只到 `len(dependencies)==0`
  （`internal/api/diff_test.go:55-62`；存储层同样是无依赖组件
  `internal/store/diff_test.go:69-74`）。源码上它们就是重建出的完整
  `model.Component`（`indexComponents, 110-112`），依赖非 nil、升序由共享装载器
  保证（4.2 节，非 nil 在差异路径另有 `changed` 断言 `76-78`，在分页路径有
  线缆级断言 `internal/api/list_test.go:275-309`）。

---

## 6. 错误怎样返回

所有错误都由 `writeAPIError` 写成同一个信封形态（`internal/api/sbom.go:244-246`）：

```json
{"error": {"code": "<字符串>", "message": "<字符串>"}}
```

差异接口的三种错误（状态码映射在 `writeStoreError, 250-261`，文案常量
`233-242`）：

| 触发条件 | HTTP | code | message | 源码位置 |
|---|---|---|---|---|
| 三个参数任一缺失，或 trim 后为空 | 400 | `InvalidSbomInputError` | `request is not a valid SBOM manifest` | `diff.go:21-24`；常量 `sbom.go:234,238` |
| 参数形态有效，但任一版本在该制品下不存在（含双方都缺、自比较缺失、未知制品） | 404 | `SbomNotFoundError` | `no SBOM is registered for this artifact and version` | `store.go:347-351` → `sbom.go:254-255`；常量 `236,240` |
| 任一步存储读取/事务失败，或任何未预期存储错误 | 503 | `storage_unavailable` | `database is not available` | `store.go:524-529` → `sbom.go:256-260`；常量 `237,241` |

要点：

- **单个顶层 error 对象**：失败路径在处理器里提前 `return`（`diff.go:27-30`），
  成功结构体永远不会与错误同时写出。信封形态（顶层恰好一个 `error`、内层恰好
  `code` 与 `message` 两个字符串字段且均非空）由
  `assertErrorOnlyEnvelope` 逐字段校验
  （`internal/api/register_failure_test.go:15-45`），404 与 503 的差异用例都调用
  了它（`internal/api/diff_test.go:323, 372`）。
- **校验顺序**：400 在任何存储访问之前（`diff.go:21-24` 先于 `26`）；存储侧
  404 在明细读取之前（`store.go:349-351` 先于 `357-362`）；扫描语句本身失败是
  503 而不是 404（`store.go:321-324` 先于存在性判定）。
- **message 不泄漏内部信息**：存储错误的原始原因只保留在 Go 错误链里
  （`unavailable` 用 `%w: %v` 包装，`store.go:528`），HTTP 映射只用 `errors.Is`
  判型（`sbom.go:252-260`），从不把 `err` 写进响应。差异用例在线缆字节上黑名单
  检查 `SELECT/SQLITE/sql:/goroutine/.go:/forced read failure`
  （`internal/api/diff_test.go:374-378`），参数错误路径的黑名单检查在共享助手
  `expectError` 中（`sbom_test.go:71-75`）。这是“固定文案 + 黑名单”双重保障，
  并非对 message 做白名单等值断言。
- 差异路径**不会**产生 409：`Store.Diff` 只读，不返回 `ErrConflict`；
  `writeStoreError` 中的 409 分支（`sbom.go:252-253`）服务于登记接口。【源码推导：
  由 `Diff` 函数体无写入、无该 sentinel 返回直接得出】

---

## 7. 三个简短补充例子

### 7.1 自比较：存在即三个空数组，清单只读一次

登记一份含依赖环的清单：

```http
POST /sboms
{"artifact":"atlas","version":"3.0","components":[
  {"coordinate":"a","license":"MIT","dependencies":["b"]},
  {"coordinate":"b","license":"ISC","dependencies":["a"]}
]}
```

请求：

```http
GET /sboms/diff?artifact=atlas&fromVersion=3.0&toVersion=3.0
```

响应：`200`

```json
{"artifact":"atlas","fromVersion":"3.0","toVersion":"3.0","added":[],"removed":[],"changed":[]}
```

含义：版本只作标识（3.3 节），自己与自己比必然无差异；存储层把相等版本收缩为一个
查询槽（`store.go:308-311`），两个结果槽指向同一条记录（`347-348`，测试断言
同 ID、整请求 3 条 SELECT、sboms 1 行，`internal/store/diff_test.go:95-112`）。
若该版本不存在，同样的请求是 404（`internal/api/diff_test.go:314`）。

### 7.2 空清单：两份 `components: []` 相比

```http
POST /sboms  {"artifact":"atlas","version":"4.0","components":[]}
POST /sboms  {"artifact":"atlas","version":"5.0","components":[]}
GET /sboms/diff?artifact=atlas&fromVersion=4.0&toVersion=5.0
```

`200`，三个数组均为 `[]`（不是 `null`）：空清单在重建时组件切片即为非 nil 空
（`store.go:332`），结果数组在 `buildDiff` 初始化时也是非 nil 空
（`diff.go:73-75`）。HTTP 线缆级断言：
`internal/api/diff_test.go:230-255`；存储层非 nil 断言：
`internal/store/diff_test.go:117-134`。

### 7.3 允许的依赖环：环不影响比较规则，只看自身许可证与直接边

非自身依赖环在登记时合法（登记只拒绝自依赖，`internal/api/sbom.go:82-84`；环的
两阶段写入使先有组件后有边，`store.go:189-217`）：

- 旧清单：`a(L) → b`、`b(L) → a`；
- 新清单：`a(OTHER) → b`、`b(L) → a`。

比对结果只有 a 进入 `changed`（`before.license=L`、`after.license=OTHER`，
`after.dependencies=["b"]`），b 不进 `changed`；环不被展开、不被当作错误。
【测试覆盖】`TestDiffCyclesFollowSameRules`
（`internal/api/diff_test.go:259-282`）；环的登记合法性另有
`TestRegisterAllowsNonSelfCycles`（`internal/api/sbom_test.go:133-142`），
环经分页读回完整见 `internal/api/list_test.go:251-270`。

传递依赖与目标许可证变化的短例见 5.2 节（a→b→c/d 用例）：新增的 d 只让 c 的直接
集合变化，a、b 不被标记。

---

## 8. 并发测试实际保证了什么（不扩大断言）

`TestDiffSnapshotStaysConsistentUnderConcurrentWriters`
（`internal/store/diff_test.go:238-289`）的真实做法：

1. 固定登记两个版本：`base-1`（a→b、b 无依赖）与 `base-2`（a 无依赖、b→a）；
2. 启动一个写协程，反复登记**其他版本号** `writer-0、writer-1、…`，其错误被
   显式忽略（`262-267` 的 `_, _, _`）；
3. 主循环连续 50 次对固定的 `base-1`/`base-2` 调 `Diff`，断言：不返回错误
   （`272-274`）、两侧都恰好重建出 2 个组件（`275-277`）、旧侧 a 的直接边恰为
   `[b]`、新侧 b 的直接边恰为 `[a]`（`278-285`）。

因此它**实际断言**的是：在有并发提交（提交的是其他版本）的情况下，50 次重复比对
固定版本都成功、内容完整且直接边稳定。

它**没有**断言、不能据测试名外推的内容：

- 没有断言事务隔离级别名称或“两侧来自同一快照”本身——该结论来自单事务单连接的
  源码结构（4.1 节，`store.go:304` + `withTx, 102-140`），测试只观测到完整一致
  的结果；
- 没有统计并发期间的 SELECT 数、没有断言读写互不阻塞或等待时延；
- 写协程登记的是**其他版本**且错误被忽略，因此不涉及“并发比对同一正被改写的
  版本”，也不评估写者成败；登记同键并发的串行化属于登记侧测试
  （`TestConcurrentIdenticalRegistersShareOneRecord`，
  `internal/api/sbom_test.go:475-520`），不能拿来当差异接口的保证；
- 不覆盖进程崩溃、磁盘故障等恢复语义。

---

## 9. 现有测试覆盖核对表

运行方式：`go test ./...`（撰写时实际运行，api/store 两个包均 ok）。标注说明：
【测试覆盖】给出测试与**它真正断言的内容**；【源码推导】列出无对应用例、仅由源码
支持的结论。不得仅凭测试名称认定覆盖。

### 9.1 【测试覆盖】清单（差异相关）

| 结论 | 测试（文件:行） | 实际断言到的粒度 |
|---|---|---|
| 参数全缺/缺单个/空格/制表符/空串 → 400 `InvalidSbomInputError` | `internal/api/diff_test.go:285-300` | 8 个 URL 的状态码与 code；经 `expectError`（`sbom_test.go:53-76`）断言 message 非空、无内部串；不断言文案原文 |
| trim 后回显；制品名小写匹配不到 → 404；空白版本 trim 后仍缺失 → 404 | `internal/api/diff_test.go:330-351` | 200 回显 `App/1/2`；`artifact=app` 404；`toVersion=" 9 "` 404。**未测版本号大小写** |
| 双方缺失/单侧缺失/未知制品/自比较缺失 → 404 且只有 error 信封 | `internal/api/diff_test.go:305-326` | 5 个子用例状态码、code 与信封形态（`register_failure_test.go:15-45`） |
| 存储层不存在语义：单一 `ErrNotFound`、无部分清单 | `internal/store/diff_test.go:139-165` | `errors.Is` 成立且 `from`、`to` 均为 nil（4 个子用例） |
| sboms/components/dependencies 任一读失败 → 503 无部分差异、无泄漏 | HTTP：`internal/api/diff_test.go:355-381`；存储：`internal/store/diff_test.go:211-233` | 三个注故障子用例：HTTP 503+code+仅 error 信封+六个黑名单串；存储层 sentinel 与双 nil。sboms 扫描故障按 503 而非 404 |
| 关闭的库句柄 → 503 | `internal/api/diff_test.go:385-396` | 状态码与 code |
| 三类分区 + 完整前后 + 排序 + 许可证变化 + 直接边变化 + 未变省略 | `internal/api/diff_test.go:26-99` | 见 5.3：changed 四成员升序、前后非 nil 依赖、许可证对照、多边升序；added/removed 成员仅覆盖**无依赖**组件 |
| added/removed 多组件坐标升序、changed 为空 | `internal/api/diff_test.go:103-134` | `[b n y]` 与 `[a m z]` 精确顺序 |
| 改名 = removed + added，不在 changed | `internal/api/diff_test.go:138-157` | 两侧各 1 项、坐标精确、changed 长度 0 |
| 直接依赖按集合比较：换序不变、删边则变 | `internal/api/diff_test.go:418-435` | **直接调用 `buildDiff` 的单元测试**，绕过 HTTP 与存储 |
| 不展开传递依赖、目标许可证变化不传播 | `internal/api/diff_test.go:163-189` | changed 仅 c、added 仅 d、removed 空 |
| 自比较 → 200 三空数组 | `internal/api/diff_test.go:193-208` | 三个数组长度 0（含环清单） |
| 自比较只读一次、两侧同记录 | `internal/store/diff_test.go:83-113` | `from.ID == to.ID`、内容相等、恰好 3 SELECT、sboms 1 行 |
| 不同版本号同内容、反向请求 → 三空数组 | `internal/api/diff_test.go:213-226` | 三数组长度 0；**未测内容不同时反向 added/removed 互换** |
| 顶层三数组线缆上为 `[]` 非 `null` | `internal/api/diff_test.go:230-255` | 解码为指针切片，非 nil 且长度 0 |
| 空清单重建为非 nil 空组件 | `internal/store/diff_test.go:117-134` | 旧清单组件非 nil 且长度 0；新清单组件依赖非 nil |
| 依赖环按同样规则比较、环边完整 | `internal/api/diff_test.go:259-282` | changed 仅 a、前后许可证、after 边 `[b]` |
| 一次比对 3 条 SELECT、行数不越两份清单、跨制品不泄漏 | `internal/store/diff_test.go:170-205` | SELECT=3；sboms/components/dependencies 行数精确；无 `SECRET` 组件 |
| 重建完整、组件坐标升序、空依赖非 nil | `internal/store/diff_test.go:25-79` | 两侧各 4 组件；旧侧首组件坐标 `edge`；born/gone 完整（均无依赖）；edge 多边升序 |
| 并发写下固定版本 50 次读取完整稳定 | `internal/store/diff_test.go:238-289` | 见第 8 节的边界 |
| 新增 diff 路由不影响 `GET /sboms` | `internal/api/diff_test.go:400-413` | 列表仍 200，total/items 正确 |

### 9.2 【源码推导】清单（无直接差异测试，仅由当前源码支持）

1. 版本号参数的大小写敏感（与制品共用 `=` 比较，`store.go:313-314`；测试只
   覆盖制品名）。
2. 内容不同而方向相反时 `added`/`removed` 互换（`buildDiff` 不区分方向，
   `diff.go:65-87`）。
3. 版本号存在但属于另一制品时按 404 处理（`artifact = ?` 过滤，`store.go:313`；
   测试只覆盖完全未知制品）。
4. 400 校验不触发任何数据库访问（`diff.go:21-26` 的先后顺序，未做 SELECT 计数）；
   404 时不读明细（`store.go:349-362`，未计数单侧缺失场景）。
5. `added`/`removed` 成员携带非空、已排序依赖（map 存完整组件
   `diff.go:110-112` + 共享装载器 `store.go:408-443`；差异用例中的增删组件均
   无依赖）。
6. 改名导致引用方直接边改变时，引用方独立进入 `changed`（`diff.go:93` 的推论；
   改名用例无引用方）。
7. 同一清单内重复坐标/重复依赖在差异计算中不可能出现（登记 400
   `sbom.go:70-73, 85-88` + 数据库唯一约束 `store.go:547, 553`）。
8. 排序抵消 Go map 遍历的不稳定性（收集遍历 map、输出前排序，
   `diff.go:78-104`）。
9. 成功响应不含清单 `id`（`diffResponse` 字段定义，`diff.go:45-52`）。
10. 差异路径不产生 409（`Store.Diff` 全程只读，`store.go:302-369`）。
11. “两份清单同一快照”的事务级保证本身（单延迟事务、单连接，
    `store.go:102-140, 304`；并发测试只提供经验性观测，见第 8 节）。

---

## 10. 不在本次范围

- 未修改任何产品源码、`README.md` 与 `docs/registration-integrity.md`；
  `POST /sboms` 的幂等与冲突（201 同 id / 409 原记录不变）、`GET /sboms` 的分页
  与 total、`GET /healthz` 的 200/503 响应继续保持原样
  （路由 `internal/api/router.go:25-35`；既有行为说明见登记完整性文档）。
- 本文不承诺跨请求快照（差异比对的读取边界是单次请求内的一个事务）、不承诺持续
  存储故障下的自动恢复，也不把并发读测试外推为第 8 节所列之外的保证。
- 所有语义以撰写时的当前源码与 `README.md` 已公开的接口约定为准。
