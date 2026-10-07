# manifest 包 Go 调用边界说明（ParseRegistration 与 Compare）

本说明面向仓库内的 Go 调用者，解释 `internal/manifest` 包两个公开入口
`ParseRegistration` 与 `Compare` 的使用边界：它们与 HTTP 层、存储层如何分工，合法
输入如何被规范化，非法输入如何被拒绝，以及返回值与入参之间的内存归属。

所有结论标注代码位置（文件:行号），并区分两类证据：

- 【测试覆盖】：现有测试中有对应断言，测试名与位置一并给出；
- 【源码推导】：由函数体直接读出，现有测试未逐字断言。

范围与基线：本次只新增本说明，产品源码、README 与既有说明
（`docs/registration-integrity.md`、`docs/diff-comparison.md`）保持原样；
`POST /sboms`、`GET /sboms`、`GET /sboms/diff` 与 `GET /healthz` 的公开行为均不改变。

---

## 1. 两个入口与 HTTP、存储的职责关系

### 1.1 源码位置

| 角色 | 位置 |
| --- | --- |
| 解析入口 `ParseRegistration` | `internal/manifest/register.go:129` |
| 比较入口 `Compare` | `internal/manifest/compare.go:59` |
| 比较结果类型 `Diff` / `ComponentChange` | `internal/manifest/compare.go:13`、`internal/manifest/compare.go:25` |
| 领域类型 `model.SBOM` / `model.Component` | `internal/model/sbom.go:18`、`internal/model/sbom.go:10` |
| 哨兵错误 `model.ErrInvalidInput` | `internal/model/sbom.go:30` |
| HTTP 登记处理器（调用解析） | `internal/api/sbom.go:21`，调用点在 `internal/api/sbom.go:32` |
| HTTP 差异处理器（调用比较） | `internal/api/diff.go:15`，调用点在 `internal/api/diff.go:34` |
| 存储入口 `Store.Register` | `internal/store/store.go:146` |

### 1.2 职责划分：解析/比较是纯函数，HTTP 与存储各管一段

`internal/manifest` 的包注释自述「不拥有 HTTP 也不拥有存储」
（`internal/manifest/register.go:1-4`）。从导入即可核实：两个源文件只导入
`bytes`、`encoding/json`、`sort`、`strings`、`fmt` 与 `internal/model`
（`internal/manifest/register.go:7-14`、`internal/manifest/compare.go:3-8`），
不导入 `internal/store`、`database/sql` 或任何网络库。【源码推导】**这两个入口
不访问数据库**：它们的一切判断只作用于调用者传入的字节或结构体。

完整调用路径是三段拼接，HTTP 层只是把同两个入口接在存储两侧：

```
POST /sboms:       请求体字节 ──► manifest.ParseRegistration ──► 未登记 *model.SBOM（ID=0）
                                                        │
                                                        ▼
                                            store.Register（分配 ID、写库）
                                                        │
                                                        ▼
                                              201 + 已登记 *model.SBOM

GET /sboms/diff:   查询参数 ──► store.Diff（从事务内同一快照读出两份已登记清单）
                                                        │
                                                        ▼
                                            manifest.Compare（纯比较）
                                                        │
                                                        ▼
                                              200 + *manifest.Diff
```

- `POST /sboms` 处理器先调 `manifest.ParseRegistration(body)`
  （`internal/api/sbom.go:32`），成功后才把零 ID 的清单交给
  `h.store.Register`（`internal/api/sbom.go:38`）。解析失败直接 400，根本不到
  存储层——【测试覆盖】`TestInvalidRegistrationNeverReachesStore`
  （`internal/api/register_shared_test.go:152`）用计数驱动断言每种非法请求
  观察到的 SQL 语句数为 0。
- `GET /sboms/diff` 处理器先调 `h.store.Diff` 取出两份清单
  （`internal/api/diff.go:25`），再调 `manifest.Compare(before, after)`
  （`internal/api/diff.go:34`）。
- 因为两条路径共用同一入口，Go 调用者直接用 `ParseRegistration`/`Compare`
  得到的规则与线上 HTTP 行为一致——【测试覆盖】
  `TestStandaloneParseAndHTTPRegistrationShareNormalization`
  （`internal/api/register_shared_test.go:34`）断言独立解析结果与 HTTP 登记
  响应除 ID 外逐字段相等。

### 1.3 导入范围受 Go internal 规则限制

两个入口位于 `internal/manifest`，模块路径为
`github.com/xjeey8iust/sen-sbom-inventory`（`go.mod:1`）。按 Go 的 internal
包规则，只有本模块内的代码可以 `import
"github.com/xjeey8iust/sen-sbom-inventory/internal/manifest"`；模块外的仓库在
编译期即被拒绝。因此本说明的读者是**本仓库内**的调用者（如 `internal/api`、
`internal/store` 的测试），不是外部 SDK 用户。【源码推导】

---

## 2. ParseRegistration：从原始 JSON 到未登记清单

### 2.1 合法输入示例（首尾空白 + 乱序 + 前向依赖）

下例取自 `validMessy`（`internal/manifest/register_test.go:15-22`）：每个业务
字符串都带首尾空白，组件与依赖数组乱序，且 `lib-z` 依赖在它之后列出的 `lib-a`
（前向依赖）：

```go
raw := []byte(`{
	"artifact": "  atlas  ",
	"version": " 1.2.0 ",
	"components": [
		{"coordinate": " lib-z ", "license": " MIT ", "dependencies": [" lib-a "]},
		{"coordinate": "lib-a", "license": "Apache-2.0", "dependencies": []}
	]
}`)
sbom, err := manifest.ParseRegistration(raw)
```

预期结果（【测试覆盖】`TestParseRegistrationNormalizes`，
`internal/manifest/register_test.go:27`，用 `reflect.DeepEqual` 逐字段断言）：

```go
err == nil
sbom.ID == 0            // 零 ID：尚未登记，ID 由存储层分配
sbom.Artifact == "atlas"
sbom.Version  == "1.2.0"
sbom.Components == []model.Component{
	{Coordinate: "lib-a", License: "Apache-2.0", Dependencies: []string{}},
	{Coordinate: "lib-z", License: "MIT",        Dependencies: []string{"lib-a"}},
}
```

规范化规则与代码位置：

- 每个业务字符串去除首尾空白，大小写与内部格式保留
  （`internal/manifest/register.go:58-59`、`:143-144`）。【测试覆盖】
  `TestParseKeepsCaseAndUnknownFields`（`internal/manifest/register_test.go:171`）
  断言 `" Lib-A "` 规范为 `"Lib-A"` 而非折叠为小写，未知字段被忽略。
- 组件按坐标升序排序（`internal/manifest/register.go:168`）；每个组件的依赖
  列表也按坐标升序排序（`internal/manifest/register.go:161`）。
- 空数组保持空数组，绝不变成 nil/null：`components: []` 与 `dependencies: []`
  都合法且结果非 nil（`internal/manifest/register.go:68` 用 `make` 构造）。
  【测试覆盖】`TestParseEmptyArraysStayArrays`
  （`internal/manifest/register_test.go:61`）。
- 返回值的 ID 是零值：结果字面量根本没有设置 ID 字段
  （`internal/manifest/register.go:170-174`）。【源码推导 + 测试覆盖】
  同一测试断言 `got.ID != 0` 即失败。
- 同一份清单的「加空白 + 乱序」与「整洁」两种写法解析出完全相等的值——
  【测试覆盖】`TestParseWhitespaceAndShuffleCanonicalizeEqually`
  （`internal/manifest/register_test.go:235`）。

### 2.2 前向依赖与非自身依赖环为何合法

依赖目标只要求「坐标出现在同一份清单里」，校验发生在全部组件解析完成之后
（先在 `internal/manifest/register.go:149-152` 收集全部坐标，再在 `:156-160`
逐个核对依赖目标），与组件在数组中的先后无关，所以指向后面才列出的组件的
「前向依赖」合法。同理，`a` 依赖 `b`、`b` 又依赖 `a` 的非自身环也合法：校验
只禁止 `dep == coordinate` 的自依赖（`internal/manifest/register.go:75-77`），
不做任何环检测。【测试覆盖】
`TestParseAllowsForwardReferencesAndNonSelfCycles`
（`internal/manifest/register_test.go:84`）两种形状都断言解析成功。

```go
cycle := []byte(`{"artifact":"a","version":"1","components":[
	{"coordinate":"a","license":"L","dependencies":["b"]},
	{"coordinate":"b","license":"L","dependencies":["a"]}
]}`)
sbom, err := manifest.ParseRegistration(cycle)
// err == nil，len(sbom.Components) == 2
```

### 2.3 失败形态：一律 nil + errors.Is 可识别的 model.ErrInvalidInput

任何拒绝都返回 `nil` 清单和一个 `errors.Is(err, model.ErrInvalidInput)` 为真
的错误。下表每行都有【测试覆盖】：`TestParseRejectsInvalidInput`
（`internal/manifest/register_test.go:109-167`）对每个用例同时断言
`err != nil`、`errors.Is(err, model.ErrInvalidInput)`、`sbom == nil`。

| 类别 | 示例输入 | 拒绝代码位置 |
| --- | --- | --- |
| 空 body / 畸形 JSON | `""`、`{` | `register.go:131-133` |
| 顶层不是对象 | `[]`、`null`、`42`、`"x"` | `register.go:131-133` |
| 尾随 JSON（第二个值或垃圾） | `{...}{}`、`{...} xxx` | `register.go:136-138`（`hasTrailingValue`，`:181-189`） |
| 字段缺失 | 缺 artifact / version / components | `register.go:139-141` |
| 字段为 null | `"artifact":null`、`"components":null` 等 | `register.go:139-141`、`:41-43`、`:55-57` |
| 类型错误 | `"artifact":7`、`"components":"x"`、依赖元素为数字/null | `register.go:45-50` |
| 去空白后为空 | `"artifact":""`、`"version":"   "`、`"coordinate":"  "` | `register.go:60-62`、`:145-147` |
| 规范化后坐标重复 | `" c "` 与 `"c"` 同现 | `register.go:63-66` |
| 规范化后依赖重复 | `[" x ","x"]` | `register.go:78-81` |
| 自身依赖（含去空白后） | `{"coordinate":"c",...,"dependencies":[" c "]}` | `register.go:75-77` |
| 悬空依赖目标 | 依赖 `"ghost"` 但清单中没有该坐标 | `register.go:156-160` |

调用侧识别方式：

```go
sbom, err := manifest.ParseRegistration(raw)
if errors.Is(err, model.ErrInvalidInput) {
	// 调用者可修复的输入问题；sbom 必为 nil
}
```

---

## 3. Compare：比较同一制品的两份清单

### 3.1 完整 before/after 示例

下例取自 `compareV1`/`compareV2`（`internal/manifest/compare_test.go:17-35`），
同一制品 `app` 的两个版本（注册载荷刻意乱序，解析已将其规范化）：

```json
// before（version "1"）
{"artifact":"app","version":"1","components":[
	{"coordinate":"gone","license":"G","dependencies":[]},
	{"coordinate":"stable","license":"S","dependencies":[]},
	{"coordinate":"rel","license":"OLD","dependencies":["stable"]},
	{"coordinate":"edge","license":"E","dependencies":["stable"]},
	{"coordinate":"watcher","license":"W","dependencies":["rel"]},
	{"coordinate":"cyc-a","license":"CA","dependencies":["cyc-b"]},
	{"coordinate":"cyc-b","license":"CB","dependencies":["cyc-a"]}
]}
```

```json
// after（version "2"）
{"artifact":"app","version":"2","components":[
	{"coordinate":"born","license":"B","dependencies":[]},
	{"coordinate":"stable","license":"S","dependencies":[]},
	{"coordinate":"rel","license":"NEW","dependencies":["stable"]},
	{"coordinate":"edge","license":"E","dependencies":["born","stable"]},
	{"coordinate":"watcher","license":"W","dependencies":["rel"]},
	{"coordinate":"cyc-a","license":"CA","dependencies":["cyc-b"]},
	{"coordinate":"cyc-b","license":"CB","dependencies":["cyc-a"]}
]}
```

```go
before, _ := manifest.ParseRegistration([]byte(compareV1))
after, _  := manifest.ParseRegistration([]byte(compareV2))
diff, err := manifest.Compare(before, after)
```

预期结果（【测试覆盖】`TestComparePartitionsAndSorts`，
`internal/manifest/compare_test.go:70`）：

```go
err == nil
diff.Artifact == "app"
diff.FromVersion == "1"
diff.ToVersion == "2"

// Added：只有 after 才有的坐标，完整组件
diff.Added == []model.Component{
	{Coordinate: "born", License: "B", Dependencies: []string{}},
}

// Removed：只有 before 才有的坐标，完整组件
diff.Removed == []model.Component{
	{Coordinate: "gone", License: "G", Dependencies: []string{}},
}

// Changed：两边都有、但许可证或直接依赖集合不同的坐标；
// Before/After 都是完整组件（含未变的一侧字段），按坐标升序
diff.Changed 的坐标序列 == []string{"edge", "rel"}
// edge：许可证两边都是 "E"，直接依赖从 ["stable"] 变为 ["born","stable"]
// rel：许可证 "OLD" → "NEW"，依赖 ["stable"] 未变
```

规则要点与代码位置：

- 三个数组始终非 nil（空则为 `[]`，`internal/manifest/compare.go:75-77`），
  且都按坐标升序排序（`:104-106`）。【测试覆盖】
  `TestCompareEmptyArraysSerializeAsArrays`（`compare_test.go:310`）断言序列化
  后为 `"added":[]` 等而非 `null`。
- **传递影响不传播**：`watcher` 依赖 `rel`，`rel` 的许可证变了，但
  `watcher` 不出现在 Changed 里——比较只看每个组件自身的许可证与**直接**
  依赖集合（`compare.go:95`），不展开传递边。【测试覆盖】
  `TestComparePartitionsAndSorts` 断言 Changed 恰为 `["edge","rel"]`，
  不含 `watcher`；未受影响的非自身环 `cyc-a`/`cyc-b` 同样整体缺席。
- **坐标改名按增删处理**：`old-name` → `new-name` 是一条 Removed 加一条
  Added，绝不是 Changed。【测试覆盖】`TestCompareRenameIsRemovePlusAdd`
  （`compare_test.go:259`）。
- **版本只是标签**：FromVersion/ToVersion 原样照抄（`compare.go:73-74`），
  不排序、不比较——内容相同的两份清单即使版本标为 "2" 与 "1"（故意倒置）
  也比较出三个空数组。【测试覆盖】
  `TestCompareIgnoresIDsAndTreatsVersionsAsLabels`（`compare_test.go:173`）。
- **ID 不参与比较**：存储分配的 ID 既不进入结果也不影响判断；同一测试把
  两边 ID 设为 7 与 99 仍得到空差异，并断言结果 JSON 中不出现 `"id"`。
- 自身与自身（或相同副本）比较得到三个空数组——【测试覆盖】
  `TestCompareSelfYieldsThreeEmptyArrays`（`compare_test.go:150`）。交换两个
  输入则 Added/Removed 互换、每条 Changed 的 Before/After 翻转——
  【测试覆盖】`TestCompareReverseSwapsSides`（`compare_test.go:279`）。

### 3.2 拒绝形态：nil 清单或不同制品

```go
diff, err := manifest.Compare(nil, valid)
// diff == nil，errors.Is(err, model.ErrInvalidInput) == true
```

- 任一侧（或两侧）为 nil：返回 `nil` + 包装了 `model.ErrInvalidInput` 的错误
  （`compare.go:60-62`）。
- 两份清单的 Artifact 不同：同样 `nil` + `ErrInvalidInput`
  （`compare.go:63-66`）。比较是精确且大小写敏感的（`"app"` 与 `"APP"` 拒绝）。

【测试覆盖】`TestCompareRejectsNilAndForeignManifests`
（`compare_test.go:110-146`）对五种组合逐一断言 `diff == nil` 且
`errors.Is(err, model.ErrInvalidInput)`。

### 3.3 Compare 的输入自由度：不重复登记校验，不去除标识空白

`Compare` 假设输入已经是合法清单（由 `ParseRegistration` 或存储层重建产生），
它**不重复执行登记校验**：

- 接受组件数组与依赖数组乱序的副本，输出仍规范化——【测试覆盖】
  `TestCompareArrayOrderIsIrrelevant`（`compare_test.go:201`）把两侧组件顺序
  与依赖顺序全部打乱，断言结果与规范比较逐字段相等。
- 不检查悬空依赖、重复坐标等登记规则——【测试覆盖】
  `TestCompareDependenciesComparedAsSets`（`compare_test.go:231-236`）直接用手工
  构造的 `model.SBOM` 字面量比较，其依赖目标 `"x","y","z"` 在清单中根本没有
  对应组件（`ParseRegistration` 会拒绝），`Compare` 照常给出结果。
- 直接依赖按**集合**比较：同一组目标的不同排列不算变化，少一个目标才算
  （`compare.go:135-149` 的 `sameDependencySet`）。【测试覆盖】同上测试。
- **不额外去除输入标识的空白**：`Compare` 全函数没有任何 `TrimSpace`，
  Artifact 按字节直接比较（`compare.go:63`），版本原样照抄
  （`compare.go:73-74`）。因此 `"app "` 与 `"app"` 会被判为不同制品而拒绝；
  空白规范化是 `ParseRegistration` 的职责，调用者若绕过解析手工构造清单，
  需自行保证标识已规范化。【源码推导】

---

## 4. 数据归属：谁拥有哪块内存

### 4.1 解析不修改原始字节，多次解析相互独立

- `ParseRegistration` 对入参 `raw` 只读：成功与失败路径都不写回。
  【测试覆盖】`TestParseDoesNotMutateInput`（`register_test.go:189`）对合法、
  空组件、畸形三种输入在解析前后做字节级比较。
- 两次解析返回不同的指针，结果的所有切片各自独立分配；修改一个结果的任何
  字段（包括依赖元素）不影响另一个结果，也不影响后续解析。
  【测试覆盖】`TestParseCallsAreIndependent`（`register_test.go:202`）。

```go
raw := []byte(`{"artifact":"app","version":"1","components":[
	{"coordinate":"a","license":"L1","dependencies":["b"]},
	{"coordinate":"b","license":"L2","dependencies":[]}
]}`)
snapshot := append([]byte(nil), raw...)

first, _  := manifest.ParseRegistration(raw)
second, _ := manifest.ParseRegistration(raw)

first.Components[0].Dependencies[0] = "MUTATED"
// second.Components[0].Dependencies[0] 仍为 "b"（两次解析互不共享切片）
// bytes.Equal(raw, snapshot) 仍为 true（原始字节未被修改）
```

### 4.2 比较不修改输入，结果与输入互不影响

`Compare` 的每个输出组件都经 `copyComponent` 深复制（`compare.go:121-130`：
新建依赖切片、拷贝、排序），结果与输入不共享任何可到达的切片。
【测试覆盖】`TestCompareDoesNotShareMemory`（`compare_test.go:329`）双向断言：
修改返回的 Diff（含 Changed 条目的 Before/After 依赖元素）不改变输入，也不
改变后续比较的结果；事后修改输入清单也不改变已返回的 Diff。

```go
diff, _ := manifest.Compare(before, after)
diff.Changed[0].After.Dependencies[0] = "MUTATED"
// before/after 内容不变；再次 Compare(before, after) 的结果也不变

before.Components[0].License = "MUTATED"
// 已返回的 diff 不变
```

### 4.3 存储入口的边界不同：不要把 Compare 的深复制保证套到 Store.Register

`Store.Register` 的返回值归属按路径区分，这是与 `Compare` 不同的契约：

- **首次登记（created == true）**：返回值是 `out := *in; out.ID = id` 的浅拷贝
  （`internal/store/store.go:219-221`）。`out` 是新的 `model.SBOM` 头部（所以
  入参的 ID 保持 0——【测试覆盖】`TestParsedManifestRegistersThroughStore`，
  `internal/api/register_shared_test.go:91`，断言 `saved.ID > 0` 且
  `first.ID == 0`），**但 `out.Components` 与入参 `in.Components` 是同一个
  切片**，每个 `Component.Dependencies` 也同样共享。【源码推导】

  ```go
  in, _ := manifest.ParseRegistration(raw) // 含非空依赖：a 依赖 b
  saved, created, _ := st.Register(ctx, in)
  // created == true，saved.ID > 0，in.ID 仍为 0
  in.Components[0].Dependencies[0] = "MUTATED"
  // saved.Components[0].Dependencies[0] 随之变为 "MUTATED"：
  // 首次登记的返回值与入参共享组件切片及其依赖切片
  ```

  注意这只影响内存中的两个 Go 值：数据库行已在事务内写入
  （`store.go:171-217`），事后修改入参不会改变已存储的内容，也不会影响
  后续的幂等/冲突判断（那些判断读的是库内记录，`store.go:151-163`）。
  【源码推导】

- **重放（created == false，内容相同的重复登记）**：返回值是
  `loadSBOM` 从数据库重新读出的清单（`store.go:156-163`），与本次入参不
  共享内存，且内容与首次登记一致——【测试覆盖】
  `TestRegisterAndListShareReconstruction`（`internal/store/register_test.go:16`）
  断言重放结果与首次结果逐组件相等（含合法依赖环）。

因此：需要长期持有或继续修改的清单，若来自 `Store.Register` 的首次登记返回，
调用者应自行复制组件切片，或改用重放/查询路径取回独立副本；`Compare` 结果
「与输入零共享」的保证不适用于存储入口。

---

## 5. 证据索引

| 结论 | 证据 |
| --- | --- |
| 两入口不访问数据库 | 【源码推导】`register.go:7-14`、`compare.go:3-8` 的导入；【测试覆盖】`TestInvalidRegistrationNeverReachesStore`（`internal/api/register_shared_test.go:152`） |
| internal 导入限制 | 【源码推导】`go.mod:1` + 包路径 `internal/manifest` |
| 解析规范化（裁剪/排序/空数组/零 ID） | 【测试覆盖】`TestParseRegistrationNormalizes`、`TestParseEmptyArraysStayArrays`（`internal/manifest/register_test.go:27`、`:61`） |
| 前向依赖与非自身环合法 | 【测试覆盖】`TestParseAllowsForwardReferencesAndNonSelfCycles`（`register_test.go:84`） |
| 解析失败 = nil + ErrInvalidInput | 【测试覆盖】`TestParseRejectsInvalidInput`（`register_test.go:109`） |
| 比较分区/排序/不传播/完整 Before-After | 【测试覆盖】`TestComparePartitionsAndSorts`（`compare_test.go:70`） |
| 改名 = 增删；版本是标签；ID 不参与 | 【测试覆盖】`compare_test.go:259`、`:173` |
| 比较拒绝 nil/异制品 | 【测试覆盖】`TestCompareRejectsNilAndForeignManifests`（`compare_test.go:110`） |
| 比较接受乱序副本、不重做登记校验 | 【测试覆盖】`compare_test.go:201`、`:231` |
| 比较不去除标识空白 | 【源码推导】`compare.go:63`、`:73-74` 无 TrimSpace |
| 解析不改字节、多次解析独立 | 【测试覆盖】`register_test.go:189`、`:202` |
| 比较不改输入、结果零共享 | 【测试覆盖】`TestCompareDoesNotShareMemory`（`compare_test.go:329`） |
| Register 首次返回浅拷贝共享组件切片 | 【源码推导】`internal/store/store.go:219-221`；入参 ID 不变见【测试覆盖】`internal/api/register_shared_test.go:91` |
| Register 重放返回库内重建副本 | 【源码推导】`store.go:156-163`；【测试覆盖】`internal/store/register_test.go:16` |
