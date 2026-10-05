# 登记完整性说明：POST /sboms 与 GET /sboms

本文基于当前源码逐行追踪 `POST /sboms`（登记）与 `GET /sboms`（按制品分页查询）的实际调用关系，说明在重复提交与写入失败两种情形下，清单身份、原始内容与读取结果分别怎样确定。所有结论标注文件、函数与代码位置；文末附可核对的验证用例，并区分「源码推导」与「测试覆盖」两个层面的依据。

涉及文件：

| 文件 | 职责 |
|---|---|
| `internal/api/router.go` | 路由装配、`GET /healthz`、404 兜底 |
| `internal/api/sbom.go` | 请求解析、输入校验、规范化、错误映射 |
| `internal/store/store.go` | 事务生命周期、登记、分页查询、清单重建 |
| `internal/model/sbom.go` | 领域类型与哨兵错误 |
| `internal/storetest/storetest.go` | 测试专用：包装真实 SQLite 驱动的计数/故障注入驱动 |

---

## 1. 调用链总览

### 1.1 POST /sboms

```
router.go:33  router.POST("/sboms", h.register)
  └─ sbom.go:107  (*sbomHandlers).register
       ├─ sbom.go:108  io.ReadAll 读请求体（读失败 → 400）
       ├─ sbom.go:115  json.Unmarshal → registerRequest
       │     └─ sbom.go:45  componentsInput.UnmarshalJSON（逐元素严格校验，见 §4.2）
       ├─ sbom.go:121  hasTrailingValue（拒绝 "{} {}" 这类多值请求体）
       ├─ sbom.go:126-131  trim artifact/version，判空、判 components 缺失
       ├─ sbom.go:139-144  依赖目标必须存在于本清单坐标集合
       ├─ sbom.go:145,152  依赖数组、组件数组分别按坐标排序（规范化）
       └─ sbom.go:154  store.Register(ctx, *model.SBOM)
             └─ store.go:149  withTx(ctx, txImmediate, fn)
                  ├─ store.go:151-169  按 (artifact, version) 查已有记录
                  │     ├─ 命中：store.go:156 loadSBOM 重建 → store.go:160 equalContent 比较
                  │     │        ├─ 内容相同 → 返回原记录（created=false）
                  │     │        └─ 内容不同 → 返回 model.ErrConflict（业务提前退出）
                  │     └─ 未命中：继续插入
                  ├─ store.go:171-180  INSERT INTO sboms → LastInsertId
                  ├─ store.go:183-200  预编译语句逐条 INSERT components
                  └─ store.go:202-217  预编译语句逐条 INSERT dependencies
       └─ sbom.go:163  c.JSON(201, sbom)；出错走 sbom.go:160 writeStoreError
```

### 1.2 GET /sboms

```
router.go:34  router.GET("/sboms", h.list)
  └─ sbom.go:186  (*sbomHandlers).list
       ├─ sbom.go:187-191  trim artifact，空白 → 400
       ├─ sbom.go:192-201  positiveQuery 解析 page/pageSize（默认 1/20，上限 100）
       └─ sbom.go:203  store.List(ctx, artifact, page, pageSize)
             └─ store.go:240  withTx(ctx, txDeferred, fn)
                  ├─ store.go:241-245  SELECT COUNT(*)              （第 1 条 SELECT）
                  ├─ store.go:247-269  SELECT 本页清单行             （第 2 条 SELECT）
                  ├─ store.go:274-276  空页提前返回（不发明细查询）
                  ├─ store.go:278  loadComponentsInto               （第 3 条 SELECT）
                  └─ store.go:281  loadDependenciesInto             （第 4 条 SELECT）
       └─ sbom.go:208  c.JSON(200, listResponse{items, total, page, pageSize})
```

`GET /healthz`（`router.go:25-31`）保持既有行为：`st.Ping()` 成功返回 200 `{"status":"ok","database":"ok"}`，失败返回 503 `storage_unavailable`，不在本文变更范围内。

---

## 2. 贯穿示例：两个组件、一条依赖

以下清单贯穿全文。注意请求中刻意混入首尾空白、且组件与依赖数组都不是排序后的顺序。

**请求**

```http
POST /sboms HTTP/1.1
Content-Type: application/json

{
  "artifact": "  atlas  ",
  "version": " 1.2.0 ",
  "components": [
    {"coordinate": " lib-z ", "license": " MIT ", "dependencies": [" lib-a "]},
    {"coordinate": "lib-a", "license": "Apache-2.0", "dependencies": []}
  ]
}
```

**预期响应：HTTP 201**

```json
{
  "id": 1,
  "artifact": "atlas",
  "version": "1.2.0",
  "components": [
    {"coordinate": "lib-a", "license": "Apache-2.0", "dependencies": []},
    {"coordinate": "lib-z", "license": "MIT", "dependencies": ["lib-a"]}
  ]
}
```

该请求-响应对即 `internal/api/sbom_test.go:78` `TestRegisterCreatesNormalizedManifest` 的断言内容。

### 2.1 首尾空白怎样参与规范化

- `artifact`、`version` 在 `sbom.go:126-127` 经 `strings.TrimSpace` 去除首尾空白后才进入后续所有环节：唯一性查找（`store.go:151-154`）、落库（`store.go:171-173`）、响应回显。因此 `"  atlas  "` 与 `"atlas"` 是**同一条清单身份**。
- 组件的 `coordinate`、`license` 与每个 `dependencies` 元素在 `componentsInput.UnmarshalJSON` 内 trim（`sbom.go:65-66`、`sbom.go:78`）。trim 发生在**重复检测之前**（`sbom.go:70-73`），所以 `" c "` 和 `"c"` 会被判为重复坐标而返回 400（对应 `sbom_test.go:173` 用例 "duplicate after trimming"）。
- trim 后为空串即拒绝：坐标/许可证在 `sbom.go:67-69`，依赖项在 `sbom.go:79-81`，`artifact`/`version` 在 `sbom.go:128`。

### 2.2 数组顺序怎样参与规范化

- 每个组件的依赖数组在 `sbom.go:145` 用 `sort.Strings` 升序排序；组件数组在 `sbom.go:152` 按 `Coordinate` 升序排序。**排序发生在调用 `store.Register` 之前**，因此落库内容、内容比较、响应回显看到的都是同一规范形态。
- 由此，输入数组的顺序**不影响**清单身份与内容判定：同一份内容以不同数组顺序提交，规范化后逐字节一致（见 §3.2 的幂等重提）。
- 读取侧的排序由 SQL 保证并与写入侧一致：组件 `ORDER BY c.sbom_id, c.coordinate`（`store.go:303`），依赖 `ORDER BY sc.sbom_id, sc.coordinate, tc.coordinate`（`store.go:336`），所以 `GET /sboms` 重建出的清单与登记响应逐项相同。

---

## 3. 登记完整性：身份、内容、读取结果怎样确定

### 3.1 清单身份的确定

清单身份 = 规范化后的 `(artifact, version)` 二元组，由三层共同保证：

1. **数据库约束**：`sboms` 表 `UNIQUE (artifact, version)`（`store.go:461`）。
2. **事务模式**：登记使用 `BEGIN IMMEDIATE`（`store.go:117`），在事务开始时即取得写锁。两个并发登记同一 `(artifact, version)` 时串行化，后到者读到先到者已提交的行并走幂等/冲突分支，而不是撞唯一约束（`store.go:113-116` 注释）。对应测试 `sbom_test.go:475` `TestConcurrentIdenticalRegistersShareOneRecord`：8 个并发相同登记全部 201 且 id 相同。
3. **大小写敏感**：比较走 Go 字符串相等与 SQLite 默认 BINARY 排序规则，均区分大小写。`App` 与 `app` 是两条不同清单；同 `(artifact, version)` 下坐标仅大小写不同则判为内容不同 → 409。对应 `sbom_test.go:308` `TestComparisonsAreCaseSensitive`。

### 3.2 原始内容的确定与重复提交

登记时 `Register` 先在事务内查已有记录（`store.go:151-154`）：

- **首次登记**：未命中 → 依次插入 `sboms`、`components`、`dependencies`（`store.go:171-217`），`id` 取自 `LastInsertId`（`store.go:177`），返回 201 与完整清单。
- **相同内容重提**：命中后用 `loadSBOM`（`store.go:392-412`）把库存记录重建出来，与本次规范化后的输入经 `equalContent`（`store.go:416-435`）逐组件、逐依赖比较。相同则**直接返回库存记录**（`store.go:163`），不写任何行：HTTP 201、`id` 沿用原值、`GET /sboms` 的 `total` 不增加。
  - 因为比较双方都已按 §2.2 排序，重提时的数组顺序无关紧要。对应 `sbom_test.go:188` `TestRegisterIsIdempotentRegardlessOfOrder`（乱序+空白重提，id 不变）与 `sbom_test.go:225` `TestReplayAndListReturnIdenticalManifest`（登记响应、重提响应、查询响应三者逐项一致）。
  - 注意 `equalContent` 是**按下标逐项比较**（`store.go:420-432`），它正确工作的前提是输入已排序——这是存储方法要求调用方满足的前提之一（见 §4.3）。
- **内容不同的重提**：组件集合、任一许可证或任一依赖关系不同 → `equalContent` 返回 false → `store.go:161` 返回 `model.ErrConflict` → `sbom.go:250-251` 映射为 **409 `SbomConflictError`**。该返回是事务内的业务提前退出，未执行任何 INSERT，原记录不变。对应 `sbom_test.go:271` `TestRegisterConflictLeavesOriginalUntouched`（分别改变许可证、组件集合、依赖关系三种变异，冲突后查询仍为原记录）。

### 3.3 读取结果的确定

`GET /sboms` 的响应由 `List`（`store.go:239-290`）在一个事务内确定：

- `items` 按 `id` 升序（`store.go:248` 的 `ORDER BY id ASC`），每条的组件、依赖由与登记侧**同一对加载器**重建（`loadComponentsInto` / `loadDependenciesInto`，`store.go:298-364`）。`Register` 的幂等重载经 `loadSBOM`（`store.go:405-410`）也走这两个加载器，因此「登记读路径」与「分页读路径」只有一条重建规则——这是源码层面的构造性保证，对应 `register_test.go:16` `TestRegisterAndListShareReconstruction`。
- 依赖边的归属通过 `JOIN components tc ON tc.id = d.target_id AND tc.sbom_id = sc.sbom_id`（`store.go:334`）限定在同一清单内：不同版本复用相同坐标时，许可证与依赖边不会串清单。对应 `list_test.go:255` `TestListKeepsSameCoordinatesScopedPerVersion`。
- 空数组绝不序列化为 `null`：组件空切片在 `store.go:259` 初始化、依赖空切片在 `store.go:314` 初始化。对应 `list_test.go:275` `TestListEmptyArraysAreNeverNull`（在原始 JSON 层面断言）。

---

## 4. 输入校验：HTTP 入口的检查 vs 存储方法的前提

### 4.1 返回 400 `InvalidSbomInputError` 的规则（全部在 HTTP 层执行）

统一由 `sbom.go:110/116/122/129/141` 写出，code/message 为常量（`sbom.go:234,237`）。规则及代码位置：

| 规则 | 位置 |
|---|---|
| 请求体读失败、非 JSON、顶层不是对象 | `sbom.go:108-118` |
| 顶层 JSON 值之后还有内容（`{} {}`、`{} xxx`） | `sbom.go:121-124`，`hasTrailingValue` 169-177 |
| `artifact`/`version` 缺失、非字符串、trim 后为空 | `sbom.go:126-131`（类型错误由 `json.Unmarshal` 在 115 行拒绝） |
| `components` 缺失或为 `null`（区别于 `[]`） | `sbom.go:128`（`req.Components == nil`）；`null` 在 `sbom.go:48-50` 被显式拒绝 |
| 组件元素非对象、为 `null`，缺 `coordinate`/`license`/`dependencies` 字段或字段为 `null`/类型错误 | `sbom.go:51-64`（指针字段区分「缺失」与「零值」） |
| 坐标、许可证 trim 后为空 | `sbom.go:67-69` |
| 重复坐标（trim 后比较） | `sbom.go:70-73` |
| 依赖项 trim 后为空、重复依赖、自身依赖 | `sbom.go:79-88` |
| 依赖目标不在本清单坐标集合内 | `sbom.go:139-144` |
| 查询参数：`artifact` 缺失或 trim 后为空；`page`/`pageSize` 非纯十进制数字、≤0、超长；`pageSize > 100` | `sbom.go:187-201`，`positiveQuery` 213-231 |

上述每一类都有对应断言：`sbom_test.go:144` `TestRegisterRejectsInvalidInput`（33 个请求体用例）与 `sbom_test.go:400` `TestListRejectsBadQuery`（11 个查询串用例，另验证 `pageSize=100` 合法）。

### 4.2 已有规则的边界情形

- **大小写**：所有比较区分大小写（§3.1）。
- **空组件数组**：`"components":[]` 合法，登记后查询得到 `"components":[]`（`sbom_test.go:111` `TestRegisterAllowsEmptyComponentsAndDependencies`）。
- **空依赖数组**：`"dependencies":[]` 合法；但 `dependencies` 字段**缺失或为 null** 是 400（`sbom.go:62`）。
- **非自身依赖环**：只禁止 `dep == coordinate` 的自身依赖（`sbom.go:82-84`）；`a↔b` 这类环在 HTTP 层与存储层都无任何拒绝逻辑，允许保存并能完整读回（`sbom_test.go:133` `TestRegisterAllowsNonSelfCycles`、`list_test.go:194` `TestListReconstructsManifests` 的 cycle 段）。

### 4.3 两个层面不是同一层保证

`store.Register` / `store.List` 是**有前提的存储方法**，自身不重复 HTTP 层的校验：

- `Register` 假定输入已规范化：坐标唯一、依赖目标存在、组件与依赖已排序。`equalContent` 按下标比较（`store.go:416-435`）只有在双方同序时才等价于集合比较；`store.go:212` 直接用 `componentID[dep]` 取目标 id，若坐标缺失会得到零值并触发外键违例——那将是 503 而非 400。
- 数据库约束（`UNIQUE (sbom_id, coordinate)`，`store.go:468`；外键，`store.go:472-474`）是最后一道防线，但违例在存储层被 `unavailable`（`store.go:445-450`）包装为 `ErrStorageUnavailable`，经 `writeStoreError`（`sbom.go:248-257`）映射为 503。
- 因此「重复坐标 → 400」「依赖悬空 → 400」「自身依赖 → 400」**只是 HTTP 入口的承诺**（`sbom.go` 的显式检查），不是存储层提供的保证；绕过 HTTP 层直接调 `store.Register` 的调用方必须自己满足这些前提。本文及测试覆盖的都是经 HTTP 入口的公开行为。

---

## 5. 写入失败：为什么是 503、为什么查不到、为什么能重提

### 5.1 事务边界（`withTx`，`store.go:102-140`）

`Register` 与 `List` 共用同一个事务生命周期，四条规则：

1. **连接**：`s.db.Conn(ctx)` 取专用连接（`store.go:103`），`defer c.Close()`（`store.go:109`）保证无论成功、业务错误还是存储失败，连接都归还连接池。
2. **开始**：登记用 `BEGIN IMMEDIATE`、查询用 `BEGIN`（`store.go:111-121`）。
3. **执行**：`fn(c)` 在同一连接上跑全部读写。
4. **收尾**：`fn` 成功才 `COMMIT`（恰好一次，`store.go:135-138`）；否则——包括 `ErrConflict` 这种业务提前返回——走 deferred 的**尽力而为 ROLLBACK**（`store.go:126-130`）。ROLLBACK 用 `context.Background()` 发出，请求上下文取消不会阻断清理。`fn` 返回的错误原样透传（哨兵错误保持 `errors.Is` 可识别）；COMMIT 自身失败映射为 `ErrStorageUnavailable`；ROLLBACK 失败被**有意吞掉**，绝不覆盖已确定的业务或存储错误（`store.go:96-101` 注释）。

### 5.2 组件/依赖写入失败 → 503 storage_unavailable

以贯穿示例为例：若第二条 `INSERT INTO components` 或 `INSERT INTO dependencies` 失败——

1. 失败点把驱动错误包装为 `ErrStorageUnavailable`（`store.go:193`、`store.go:213`，包装函数 `unavailable` 在 `store.go:445-450`）；
2. `fn` 返回错误 → `withTx` 不 COMMIT → deferred ROLLBACK 撤销本事务已写入的 `sboms` 行与第一条 `components` 行 → 连接归还；
3. `writeStoreError` 把 `ErrStorageUnavailable` 映射为 **503 `storage_unavailable`**（`sbom.go:252-253`；default 分支同样落 503，`sbom.go:254-255`）。

**为什么失败清单查不到**：`sboms` 行的 INSERT 与全部明细行在同一事务，ROLLBACK 后该 `(artifact, version)` 在库中不存在任何行，`GET /sboms?artifact=atlas` 的 COUNT 为 0、`items` 为空数组——不存在「半个清单」。

**为什么故障解除后重提可正常登记**：故障是一次性的，连接已被 ROLLBACK 清理并归还连接池；重提走完全相同的代码路径，`SELECT` 未命中（无残留记录）→ 正常插入 → 201，且查询能读回完整清单。

对应测试（均用包装真实 SQLite 驱动的故障注入驱动，见 §8）：

- `internal/api/register_failure_test.go:61` `TestRegisterDetailWriteFailureReturns503`：分别注入组件、依赖写入故障 → 断言 503、错误信封仅含 `error.code`/`error.message`、响应不泄漏 `INSERT`/`SQLITE`/`forced`/`/` 等内部信息；随后查询 `total=0`、`items=[]`；同一请求体重提 → 201 且内容完整、查询 `total=1`。
- `internal/store/tx_test.go:24` `TestRegisterDetailWriteFailureRollsBack`：存储层同场景，另断言无关制品 `other` 的记录不受影响。
- `internal/api/register_failure_test.go:123` `TestRegisterWriteFailureLeavesExistingManifestsWhole`：已有 `app@1` 时 `app@2` 写入失败，`app@1` 原样可见。

### 5.3 回滚失败测试的精确含义（不要扩大解释）

`tx_test.go:108` `TestRollbackFailureKeepsOriginalError` 注入「写入失败 + ROLLBACK 报告失败」双重故障，断言：调用方仍看到**原始的写入错误**（含 "forced write failure"、不含 "forced rollback failure"）、失败登记不可见、原记录完整、连接可服务后续登记。

需要明确该测试的机制边界：故障驱动对 ROLLBACK 的处理是**先真实执行 ROLLBACK，再返回一个合成错误**（`storetest.go:134-147`，注释明确说明 "the connection must actually leave its transaction before going back to the pool"）。因此该测试证明的是：**当 ROLLBACK 实际成功、只是其返回值为错误时，`withTx` 吞掉该返回值、不让它覆盖原始错误**。它**不能**被扩大解释为「任意真实回滚失败（如连接已断、事务实际未撤销）之后系统仍能恢复」的保证——源码对真实回滚失败的唯一承诺是错误不替换（`store.go:96-101`），连接此后是否可用取决于驱动与 `database/sql` 的连接健康检查，不在本服务代码与测试的保证范围内。`tx_test.go:151` `TestConflictReturnSurvivesRollbackFailure` 同理：它证明业务错误 `ErrConflict` 不被清理错误覆盖，机制同上。

---

## 6. 查询路径：读取失败、快照与 total 一致性

### 6.1 单次请求的快照

`List` 在 `txDeferred`（普通 `BEGIN`）事务内依次发出至多 4 条 SELECT（`store.go:241-283`）：COUNT、本页清单行、批量组件、批量依赖。SQLite 的读事务为事务内所有 SELECT 固定同一份已提交快照，因此：

- **`total` 与明细一致**：COUNT 与明细读自同一快照，不会出现「total 算进了某条清单、明细却是另一时刻的内容」。
- **不会读到半个清单**：`Register` 的写入要么整体 COMMIT、要么整体 ROLLBACK，读事务只能看到完整的已提交清单。对应 `list_test.go:353` `TestListSnapshotStaysConsistentUnderConcurrentWriters`：写入 goroutine 并发登记时，每次 List 的 `len(items) ≤ total`、每条清单组件与依赖完整。
- **查询预算**：无论页大小，非空页恰好 4 条 SELECT、空页恰好 2 条（`store.go:274-276` 跳过空 IN 列表的明细查询）。对应 `list_test.go:51` `TestListUsesAtMostFourSelects` 与 `api/list_test.go:34` `TestListRequestUsesAtMostFourSelects`（含「明细行绝不溢出本页/本制品」的行数断言）。

**单次分页请求的快照不等于跨页共享快照**：每次 `GET /sboms` 各自开启并结束一个事务。翻页期间若有新登记提交，后一页的 `total` 与页成员可能反映更新的快照——这是逐请求一致、跨请求不串快照的语义，源码中不存在任何跨请求保持快照的机制（每次 `List` 调用独立走 `withTx`，`store.go:240`）。

### 6.2 任一步读取失败 → 503，不夹带部分 items

四条 SELECT 中任意一条失败，都在失败点包装为 `ErrStorageUnavailable`（`store.go:243、251、261、268、307、316、338、358`，游标终态错误经 `rowsError`，`store.go:367-372`），`fn` 返回错误 → ROLLBACK → `List` 返回 `(nil, 0, err)`（`store.go:286-289`）→ HTTP 503。

因为 `List` 出错时返回的 `items` 是 `nil` 且 `list` 处理器出错分支直接写错误响应（`sbom.go:204-207`），响应体里**不可能**出现部分 `items`。对应测试：

- `store/list_test.go:329` `TestListReadFailuresReturnUnavailable`：四种读取分别失败，断言 `errors.Is(err, ErrStorageUnavailable)` 且 `items == nil`。
- `api/list_test.go:314` `TestListStorageFailureReturns503WithoutPartialItems`：HTTP 层断言 503、`error.code == "storage_unavailable"`、响应无 `items` 字段、不泄漏 `SELECT`/`SQLITE`/`forced read failure` 等。
- 登记侧读失败（幂等重载的三个读步骤）同理：`register_test.go:72` `TestRegisterReadFailureReturnsUnavailable`，并断言失败重提后原记录不变。

---

## 7. 错误响应约定

所有错误响应由 `writeAPIError`（`sbom.go:242-244`）统一写出：单个顶层 `error` 对象，仅含字符串 `code` 与 `message`。三种 code 与固定文案定义在 `sbom.go:233-240`：

| HTTP | code | message |
|---|---|---|
| 400 | `InvalidSbomInputError` | `request is not a valid SBOM manifest` |
| 409 | `SbomConflictError` | `an SBOM with different content already exists for this artifact and version` |
| 503 | `storage_unavailable` | `database is not available` |

message 是常量，从不拼接 `err.Error()`，因此 SQL 文本、堆栈、文件路径、驱动错误详情都不会出现在响应里（存储错误的原始原因只留在服务端错误链中，供 `errors.Is` 识别）。信封的严格性由 `register_failure_test.go:15` `assertErrorOnlyEnvelope` 在 JSON 层面断言：顶层仅 `error` 一个键、内层恰好 `code`/`message` 两个字符串字段；`sbom_test.go:53` `expectError` 另断言响应不含 `SQLITE`、`sql:`、`goroutine`、`/`、`.go:`。未匹配路由返回 404 `route_not_found`（`router.go:36-38`），同样遵循该信封。

---

## 8. 验证用例

下表每个用例均可独立核对：给出初始记录、输入、预期状态与响应、前后可见内容，并标注对应的现有测试断言。除注明外，「查询」指 `GET /sboms?artifact=atlas`。

### 8.1 登记与规范化

| # | 初始记录 | 输入 | 预期 | 前后可见内容 | 对应测试 |
|---|---|---|---|---|---|
| V1 | 空库 | §2 的请求体（含空白、乱序数组） | 201，响应为 §2 的规范化清单，`id` 为正整数 | 前：`total=0`；后：`total=1`，内容与响应一致 | `sbom_test.go:78` `TestRegisterCreatesNormalizedManifest` |
| V2 | 空库 | `{"artifact":"a","version":"1","components":[]}` | 201，`components:[]` | 查询得空组件数组（非 null） | `sbom_test.go:111`、`list_test.go:275` |
| V3 | 空库 | 组件 `a→b`、`b→a`（非自身依赖环） | 201 | 查询完整读回两条边 | `sbom_test.go:133`、`list_test.go:194` |

### 8.2 重复提交

| # | 初始记录 | 输入 | 预期 | 前后可见内容 | 对应测试 |
|---|---|---|---|---|---|
| V4 | V1 已登记 | 同一内容、数组乱序、加空白重提 | 201，`id` 与 V1 相同 | 前：`total=1`；后：`total=1`，记录不变 | `sbom_test.go:188`、`sbom_test.go:225` |
| V5 | V1 已登记 | 同 `(artifact,version)`，改任一许可证/组件集合/依赖关系 | 409 `SbomConflictError` | 前：`total=1` 原内容；后：`total=1`，原记录逐项不变 | `sbom_test.go:271`（三种变异各一个子用例） |
| V6 | 已登记 `App@1` | 登记 `app@1`（仅大小写不同） | 201（是另一条清单） | `?artifact=App` 仍 `total=1`；再提 `App@1` 改坐标大小写 → 409 | `sbom_test.go:308` |
| V7 | 空库 | 8 个并发相同登记 | 全部 201，id 全相同 | `total=1` | `sbom_test.go:475` |
| V8 | V1 已登记，服务重启 | 同内容重提；再提变异内容 | 201 同 id；409 | 记录跨重开持久 | `sbom_test.go:427` `TestPersistsAcrossReopen` |

### 8.3 输入拒绝（400 InvalidSbomInputError）

| # | 初始记录 | 输入 | 预期 | 前后可见内容 | 对应测试 |
|---|---|---|---|---|---|
| V9 | 任意 | 缺 `version`；`components` 缺失或为 `null`；组件缺 `dependencies`；坐标 trim 后为空；`" c "` 与 `"c"` 重复坐标；依赖重复；自身依赖；依赖目标 `ghost` 不存在；请求体 `{} {}` 等 33 种 | 400，信封仅 `error.code`/`error.message` | 库内容前后不变（校验在 `store.Register` 之前全部完成，`sbom.go:107-152`） | `sbom_test.go:144` |
| V10 | 任意 | `GET /sboms` 缺 `artifact`；`artifact=%20%20`；`page=0/-1/abc/1.5`；`pageSize=0/101/-20` | 400 | 同上 | `sbom_test.go:400` |

### 8.4 写入失败与恢复

| # | 初始记录 | 输入 | 预期 | 前后可见内容 | 对应测试 |
|---|---|---|---|---|---|
| V11 | 空库（另有 `other@1` 一条无关记录） | 注入「下一条 components INSERT 失败」后提交 §2 请求体 | 503 `storage_unavailable`，信封仅 error，无内部信息 | 前：`total=0`；后：`total=0`（无部分记录），`other@1` 完整 | `register_failure_test.go:61`、`tx_test.go:24` |
| V12 | 同 V11（故障已消费） | 原请求体重提 | 201，内容完整 | `total=1`，查询与登记响应一致 | 同上两个测试的恢复段 |
| V13 | 已有 `app@1` | 注入写入失败后登记 `app@2` | 503 | `app@1` 原样可见，`total=1` | `register_failure_test.go:123` |
| V14 | 已有 `app@1` | 注入「写失败 + ROLLBACK 报告失败」后登记 `app@2` | 503，错误含原始写失败原因、不含 rollback 失败字样 | `total=1`，`app@1` 完整；随后 `app@2` 可正常登记 | `tx_test.go:108`（机制边界见 §5.3） |
| V15 | 已有 `app@1` | 注入「ROLLBACK 报告失败」后提交冲突内容 | 409 `SbomConflictError`，不被清理错误替换 | 原记录不变；同内容重提仍 201 同 id | `tx_test.go:151`（机制边界见 §5.3） |

### 8.5 查询与读取失败

| # | 初始记录 | 输入 | 预期 | 前后可见内容 | 对应测试 |
|---|---|---|---|---|---|
| V16 | `app` 5 条（乱序登记）+ `other` 2 条 | `?artifact=app&page=1..3&pageSize=2` | 200，`total=5`，items 按 id 升序、每条完整；`page=4` → `items=[]`、`total=5`；`?artifact=ghost` → `items=[]`、`total=0` | 跨页收集 id 严格递增 | `sbom_test.go:330` |
| V17 | 1 条记录 | 分别注入 count/sboms/components/dependencies 读失败后查询 | 503 `storage_unavailable`，响应无 `items` 字段 | 故障清除后查询恢复正常 | `api/list_test.go:314`、`store/list_test.go:329` |
| V18 | 1 条记录 | 注入读失败后同内容重提 | 503 | 原记录不变，`total=1` | `register_test.go:72` |
| V19 | 持续并发写入 | 50 次 `?artifact=app&pageSize=20` | 每次 200，`len(items) ≤ total ≤ 20 上限内`，每条清单完整 | 无半写入清单可见 | `store/list_test.go:353` |
| V20 | 1 条记录 | `?artifact=%20%20app%20%20&page=3&pageSize=50` | 200，trim 后匹配，`total=1`、越界页 `items=[]`，回显 `page=3,pageSize=50`；`?artifact=APP` → `total=0` | — | `api/list_test.go:356` |

### 8.6 查询预算（源码推导 + 计数驱动断言）

| # | 初始记录 | 输入 | 预期 | 对应测试 |
|---|---|---|---|---|
| V21 | 1 条 / 100 条 / 中间页 / 空页 | 各查一次 | 非空页恰好 4 条 SELECT、空页恰好 2 条；明细行数恰好覆盖本页本制品，不溢出 | `store/list_test.go:51`、`api/list_test.go:34` |

---

## 9. 源码推导与测试覆盖的界限

- **源码推导**的结论：调用链与事务边界（§1、§5.1）、规范化的执行点与顺序（§2）、身份与内容比较机制（§3）、两层保证的划分（§4.3）、错误映射与信封形状（§7）。这些直接来自对 `sbom.go`、`store.go`、`router.go` 的阅读，行为由代码结构保证（例如「登记与查询共用重建规则」是因为两条路径调用同一对加载器，而非仅靠测试观察）。
- **测试覆盖**的结论：§8 表格中每个用例都对应现有测试的具体断言；故障类用例（V11–V15、V17–V18）依赖 `internal/storetest` 的故障注入驱动，该驱动包装**真实** SQLite 驱动、真实执行 SQL，只在注入点返回合成错误。
- **特别边界**：回滚失败测试（V14、V15）中，ROLLBACK 在驱动层是**真实执行**的，合成的只是「返回错误」这一结果（`storetest.go:134-147`）。因此这两个用例证明的是「`withTx` 不被清理阶段的错误报告干扰」，而不是「真实回滚失败后的恢复保证」；后者既无源码机制也无测试支撑，本文不作此承诺（详见 §5.3）。
- 本文不修改任何产品源码与 `README.md`；`GET /healthz` 行为不在本文范围；与任何外部实现的差异比对不在本次范围。
