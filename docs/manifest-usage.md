# `internal/manifest` 使用边界说明（面向仓库内 Go 调用者）

本说明面向**在仓库内直接调用 Go 函数**的开发者，解释清单解析与差异计算两个纯内存
入口的契约：

- `ParseRegistration(raw []byte) (*model.SBOM, error)`——把一段原始登记 JSON 变成
  一份“未登记、已规范化”的清单；
- `Compare(before, after *model.SBOM) (*Diff, error)`——比较同一制品的两份清单，
  产出新增/移除/变化三个数组。

所有结论都标注**源码位置**（形如 `internal/manifest/register.go: ParseRegistration,
129-175`），并区分【测试覆盖】（有现有自动化断言）与【源码推导】（当前源码直接支持、
但没有对应用例）。本文只新增说明，**不修改产品源码、`README.md` 与已有说明**；
`POST /sboms`、`GET /sboms`、`GET /sboms/diff`、`GET /healthz` 的公开行为不变。

撰写时运行记录：`go build ./...` 通过，`go test ./...` 全部 ok（`internal/api`、
`internal/manifest`、`internal/store`）。

---

## 1. 包定位：两个纯函数入口，不碰 HTTP、不碰数据库

`internal/manifest` 只导入标准库（`bytes`、`encoding/json`、`sort`、`strings`、
`fmt`）和领域类型包 `internal/model`
（`internal/manifest/register.go:7-14`、`internal/manifest/compare.go:3-7`）。
它**不导入** `internal/api`、`internal/store`，也不导入任何数据库驱动或 HTTP 库，因此：

- 不读取请求、不写响应、不感知 Gin；
- 不打开数据库、不执行 SQL、不依赖 `*store.Store`。

两个入口各自独立、可在任意 Go 代码中直接调用，不必经过 HTTP。

### 1.1 与 HTTP、存储入口的职责关系

```
原始 JSON 字节
   │
   │ manifest.ParseRegistration        ← 纯内存：解析 + 严格校验 + 规范化（本文）
   ▼
*model.SBOM（ID 为零，未登记）
   │
   │ (*store.Store).Register           ← 存储入口：分配 ID、查重、落 SQLite
   ▼
*model.SBOM（带存储分配的 ID）

已登记的两份 *model.SBOM（来自 ParseRegistration，或由存储重建）
   │
   │ manifest.Compare                   ← 纯内存：按坐标集合做差异（本文）
   ▼
*manifest.Diff
```

HTTP 层只是这两个函数的调用方之一，且顺序固定：

- `POST /sboms` 处理器先 `manifest.ParseRegistration(body)`，成功后才调
  `h.store.Register(...)`（`internal/api/sbom.go: register, 21-44`，解析在 `32`、
  入库在 `38`）。解析失败在访问存储**之前**就返回 400。
- `GET /sboms/diff` 处理器先 `h.store.Diff(...)` 从同一只读事务重建两份清单，
  再 `manifest.Compare(before, after)`（`internal/api/diff.go: diff, 15-40`，
  读存储在 `25`、比较在 `34`）。

关键点：**登记校验只存在于 `ParseRegistration` 这一处**，HTTP 处理器和存储层都不重复
实现；比较规则只存在于 `Compare` 这一处。处理器注释明确说明这种“一处规则、两种调用方”
的安排（`internal/api/sbom.go:28-31`、`internal/api/diff.go:30-33`），所以线上接口
与仓库内 Go 调用者拿到的行为不会漂移。

存储是独立的第三层：`Store.Register`（`internal/store/store.go: Register, 146-229`）
与 `Store.Diff`（`internal/store/store.go: Diff, 302-369`）负责持久化与一致读取，
不属于本包；本文只在第 6 节说明与它们交接时的数据归属边界。

### 1.2 可见性受 Go `internal` 包规则限制

包的导入路径是 `github.com/xjeey8iust/sen-sbom-inventory/internal/manifest`，
位于 `internal/` 之下。按 Go 的 internal 目录规则，它只能被以
`…/sen-sbom-inventory`（`internal` 的父目录）为根的目录树内的代码导入；
**本模块之外的任何模块都无法 `import` 它**。当前仓库内实际引用它的只有 `internal/api`
（`internal/api/sbom.go:12`、`internal/api/diff.go:9` 及两个对应 `_test.go`）；
`main.go` 只装配 `internal/api` 与 `internal/store`（`main.go:8-9`），并不直接引用
本包。`ParseRegistration`、`Compare`、`Diff`、`ComponentChange` 是导出标识符；
解析期的中间类型（`registerInput`、`componentsInput`、`rawComponent`、
`componentInput`）不导出，仓库内调用者也只通过两个函数与它们交互。

---

## 2. 涉及的领域类型

定义在 `internal/model/sbom.go`：

- `model.Component`（`Component, 10-14`）：`Coordinate string`、`License string`、
  `Dependencies []string`，三者都带 JSON tag。
- `model.SBOM`（`SBOM, 18-23`）：`ID int64`、`Artifact string`、`Version string`、
  `Components []Component`。
- `model.ErrInvalidInput`（`sbom.go:30`）：值为 `"InvalidSbomInputError"` 的哨兵，
  标记“调用方可以修正的输入问题”。两个 manifest 入口的一切拒绝都返回它（或
  `fmt.Errorf("…: %w", model.ErrInvalidInput)` 包一层），因此调用方统一用
  `errors.Is(err, model.ErrInvalidInput)` 判型。

本包产出的差异类型（`internal/manifest/compare.go:10-32`）：

- `ComponentChange{ Coordinate string; Before, After model.Component }`
  （`13-17`）；
- `Diff{ Artifact, FromVersion, ToVersion string; Added, Removed []model.Component;
  Changed []ComponentChange }`（`25-32`），可直接 `json.Marshal`，线上
  `GET /sboms/diff` 的响应体就是它（类型别名 `diffResponse`，
  `internal/api/diff.go:45-48`）。

---

## 3. `ParseRegistration`：从原始 JSON 到未登记清单

签名：`func ParseRegistration(raw []byte) (*model.SBOM, error)`
（`internal/manifest/register.go:129`）。

### 3.1 它做什么

1. 把 `raw` 解析为**恰好一个** JSON 对象：数组、标量、`null`、第二个 JSON 值、
   尾随杂字节一律拒绝（`json.Unmarshal` 在 `131-133`；尾随值检查
   `hasTrailingValue, 181-189`，调用点 `136-138`）。未知字段被忽略而不是拒绝
   【测试覆盖】`TestParseKeepsCaseAndUnknownFields`（`register_test.go:171-185`）。
2. 顶层 `artifact`、`version`、`components` 必须存在且类型正确。三个字段用指针承载，
   因此“字段缺失/null”与“零值字符串”可区分（`registerInput, 98-102`；必填检查
   `139-141`）。
3. 每个业务字符串（`artifact`、`version`、每个 `coordinate`、`license`、每个依赖
   目标）都 `strings.TrimSpace` 去首尾空白，**保留内部大小写与内部格式**
   （`143-144`、`58-59`、`71`）；trim 后为空即拒（`145-147`、`60-62`、`72-74`）。
4. 依赖数组逐项校验：trim 后非空、不等于组件自身坐标、同一组件内不重复
   （`68-83`）；依赖目标必须是本清单内某个组件坐标（悬空目标拒绝，`155-160`）。
5. 规范化输出：每个组件的依赖 `sort.Strings` 升序（`161`），组件整体按
   `Coordinate` 升序（`168`）。
6. 返回的清单 `ID` 保持零值 `0`——它从未被登记，ID 由存储层在入库时分配
   （函数文档 `121-124`）。

数组形态的严格性由自定义 `componentsInput.UnmarshalJSON`（`38-92`）保证：顶层
`components` 为 JSON `null` 直接拒（`41-43`，区别于合法的空数组 `[]`）；元素必须是
对象、三个字段都不能缺/null（`44-57`）；坐标 trim 后在清单内唯一，重复（含 trim
后归一的重复）拒绝（`63-66`）。

### 3.2 合法输入：首尾空白、乱序、前向依赖、非自身依赖环

下面这份输入刻意带首尾空白、组件乱序，并让 `lib-z` 依赖一个**排在它后面**的
`lib-a`（前向引用）；它就是测试里的 `validMessy`（`register_test.go:15-22`）：

```go
raw := []byte(`{
    "artifact": "  atlas  ",
    "version": " 1.2.0 ",
    "components": [
        {"coordinate": " lib-z ", "license": " MIT ", "dependencies": [" lib-a "]},
        {"coordinate": "lib-a",  "license": "Apache-2.0", "dependencies": []}
    ]
}`)

sbom, err := manifest.ParseRegistration(raw)
if err != nil {
    log.Fatal(err) // 不会发生：前向引用合法、空依赖数组合法
}
fmt.Printf("%+v\n", sbom)
// 输出（顺序已规范化、空白已去除、ID 为零）：
// &{ID:0 Artifact:atlas Version:1.2.0 Components:[
//   {Coordinate:lib-a License:Apache-2.0 Dependencies:[]}
//   {Coordinate:lib-z License:MIT Dependencies:[lib-a]}
// ]}
```

- 【测试覆盖】规范化结果逐字段 `reflect.DeepEqual`，并断言 `ID == 0`、组件切片非
  nil、每个依赖切片非 nil：`TestParseRegistrationNormalizes`
  （`register_test.go:27-57`）。
- 【测试覆盖】前向引用与非自身环（a→b、b→a）都合法，自依赖才拒绝：
  `TestParseAllowsForwardReferencesAndNonSelfCycles`（`register_test.go:84-104`）。
  非自身环合法的原因是：解析只拒绝 `dep == coordinate`（`register.go:75-77`），
  不做环检测；存储层也是先插完所有组件、再插依赖边（`store.go:189-217`），环不会因
  外键或插入顺序失败。
- 【测试覆盖】大小写保留：`" App "`→`"App"`、`" Lib-A "`→`"Lib-A"`，不做大小写
  折叠：`TestParseKeepsCaseAndUnknownFields`（`register_test.go:171-185`）。

### 3.3 空数组与零 ID

```go
empty, err := manifest.ParseRegistration(
    []byte(`{"artifact":"a","version":"1","components":[]}`))
// empty.Components 是非 nil、长度 0 的切片（线上是 []，不是 null）

withComp, err := manifest.ParseRegistration([]byte(
    `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":[]}]}`))
// withComp.Components[0].Dependencies 同样是非 nil 空切片
```

【测试覆盖】两种空形态都断言“非 nil 且长度 0”：
`TestParseEmptyArraysStayArrays`（`register_test.go:61-79`）。来源是解码时主动
`make([]string, 0, …)`（`register.go:68`）与组件结果切片 `make(…, 0, …)`（`53`）。
两次解析返回的指针不同、内容相等（`TestParseCallsAreIndependent, 202-230` 中
`first == second` 必须不成立，`211-213`）。

### 3.4 非法输入：返回 `nil` 与 `model.ErrInvalidInput`

任何拒绝都返回 `(nil, err)`，且 `errors.Is(err, model.ErrInvalidInput)` 成立。
下表每一行都有对应用例（表驱动用例体在 `register_test.go:110-152`，统一断言在
`153-166`：错误非 nil、`errors.Is` 成立、返回清单为 nil）：

| 类别 | 具体输入（用例名） | 拒绝位置 |
|---|---|---|
| 顶层不是单对象 | 空 body、坏 JSON `{`、顶层数组 `[]`、顶层 `null`、数字 `42`、字符串 `"x"`、两个对象 `{} {}`、对象后杂字节 `{} xxx` | `register.go:131-138` |
| 顶层字段缺失/空 | 缺全部 `{}`、缺 version、缺 artifact、缺 components、`artifact:null`、`version:null`、`components:null`、空 artifact、空白 version | `139-147` |
| 顶层类型错误 | `artifact` 为数字、`version` 为布尔、`components` 为字符串、组件元素为标量/`null` | `131-133` + `44-50` |
| 组件字段问题 | 缺 coordinate、缺 license、缺 dependencies、`coordinate:null`、`license:null`、`dependencies:null`、空白 coordinate、空白 license、coordinate 类型错误 | `55-62` |
| 规范化后重复 | 两个相同 coordinate；`" c "` 与 `"c"`（trim 后重复） | `63-66` |
| 依赖问题 | 重复依赖 `["x","x"]`；trim 后重复 `[" x ","x"]`；自依赖 `["c"]`；trim 后自依赖 `[" c "]`；空白依赖；依赖元素是数字；依赖元素为 `null` | `70-83` |
| 悬空目标 | 组件 `c` 依赖清单内不存在的 `"ghost"` | `155-160` |

调用方判型方式：

```go
if _, err := manifest.ParseRegistration([]byte(`{"components":null}`)); err != nil {
    var invalid interface{ Unwrap() error }
    _ = invalid
    if errors.Is(err, model.ErrInvalidInput) { // true
        // …调用方修正请求体后重试
    }
}
```

（线上处理器据此统一映射为 400 `InvalidSbomInputError`，
`internal/api/sbom.go:32-36`；该 HTTP 映射不是本包行为。）

### 3.5 不修改原始字节、多次解析相互独立

- 【测试覆盖】`TestParseDoesNotMutateInput`（`register_test.go:189-198`）对成功与
  失败三类输入都在解析前后 `bytes.Equal`，断言入参切片逐字节不变。
- 【测试覆盖】`TestParseCallsAreIndependent`（`register_test.go:202-230`）：解析
  两次得到不同指针；随后把第一份结果的 `Artifact`、组件坐标、依赖、甚至 append
  新组件全部改坏，第二份结果与一次全新解析仍 `DeepEqual`。
- 结构原因：输出组件切片（`register.go:154`）与每个依赖切片（`68`）都是函数内
  `make` 的新分配，只把 trim 后的字符串拷入；JSON 反序列化的中间对象也不暴露给
  调用方。因此 `ParseRegistration` 的结果与 `raw`、与其他调用的结果之间**没有共享
  内存**。

---

## 4. `Compare`：比较同一制品的两份清单

签名：`func Compare(before, after *model.SBOM) (*Diff, error)`
（`internal/manifest/compare.go:59`）。

它接受两份**已经合法、已规范化**的清单（来自 `ParseRegistration` 或由存储重建），
在内存里按坐标分三类：

- **added**：坐标只在 `after`（`compare.go:80-84`）；
- **removed**：坐标只在 `before`（`85-89`）；
- **changed**：两边都有，且 `License` 不同，或**直接依赖坐标集合**不同
  （`90-102`，判定条件在 `95`，集合比较 `sameDependencySet, 135-149`）。

三个数组在返回前各自按坐标升序排序（`104-106`），且在构造 `Diff` 时就初始化为非
nil 空切片（`75-77`），因此**永远是数组、不会是 null**。未变化组件不出现在任何数组。

### 4.1 同一制品两个版本：新增、移除、许可证与直接依赖变化

下例改编自测试夹具 `compareV1`/`compareV2`（`compare_test.go:17-35`）。两份清单
都含非空依赖，覆盖：移除 `gone`、新增 `born`、`rel` 许可证改变、`edge` 增加一条直接
依赖（同时保留一条原有依赖）、以及完全未变的 `stable`/`watcher`：

```go
before, _ := manifest.ParseRegistration([]byte(`{"artifact":"app","version":"1","components":[
    {"coordinate":"gone",   "license":"G", "dependencies":[]},
    {"coordinate":"stable", "license":"S", "dependencies":[]},
    {"coordinate":"rel",    "license":"OLD","dependencies":["stable"]},
    {"coordinate":"edge",   "license":"E", "dependencies":["stable"]}
]}`))
after, _ := manifest.ParseRegistration([]byte(`{"artifact":"app","version":"2","components":[
    {"coordinate":"born",   "license":"B", "dependencies":[]},
    {"coordinate":"stable", "license":"S", "dependencies":[]},
    {"coordinate":"rel",    "license":"NEW","dependencies":["stable"]},
    {"coordinate":"edge",   "license":"E", "dependencies":["born","stable"]}
]}`))

diff, err := manifest.Compare(before, after)
```

结果（逐坐标排序后）：

```json
{
  "artifact": "app",
  "fromVersion": "1",
  "toVersion": "2",
  "added":   [{"coordinate":"born","license":"B","dependencies":[]}],
  "removed": [{"coordinate":"gone","license":"G","dependencies":[]}],
  "changed": [
    {"coordinate":"edge",
     "before":{"coordinate":"edge","license":"E","dependencies":["stable"]},
     "after": {"coordinate":"edge","license":"E","dependencies":["born","stable"]}},
    {"coordinate":"rel",
     "before":{"coordinate":"rel","license":"OLD","dependencies":["stable"]},
     "after": {"coordinate":"rel","license":"NEW","dependencies":["stable"]}}
  ]
}
```

【测试覆盖】`TestComparePartitionsAndSorts`（`compare_test.go:70-105`）断言：
三个标识字段、added 恰为 `[born]`、removed 恰为 `[gone]`、changed 坐标恰为
`[edge rel]`；`rel` 的 `OLD/NEW` 许可证成对断言（`94-97`）；`edge` 两边许可证都
是 `E`、after 依赖恰为 `[born stable]`（`98-104`）。`before`/`after` 是两个
**完整组件**（含 `coordinate/license/dependencies` 全字段，结构定义
`compare.go:13-17`）。

### 4.2 三条容易误解的规则

**传递影响不传播。** 比较只看每个组件**自身**的许可证与直接边，不沿依赖图展开：
中间组件的变化不标记，依赖目标的许可证变化也不传播给引用方。判定式
`oldComp.License != newComp.License || !sameDependencySet(...)`（`compare.go:95`）
里没有任何沿边遍历。【测试覆盖】
`TestCompareDependenciesComparedAsSets`（`compare_test.go:231-255`，集合相同仅顺序
不同→不算变化；删掉一条→变化）证明了直接边按集合处理；“不传播”由
`TestComparePartitionsAndSorts` 中 `watcher`（依赖 `rel`，而 `rel` 许可证变了却
不进 changed）间接覆盖，目标许可证变化不向上传播的 a→b→c/d 专例在线上链路文档
`docs/diff-comparison.md` 第 5.2 节有用例。

**坐标改名 = 一条 removed + 一条 added，绝不进 changed。** 坐标是比对中的唯一
身份，代码不做“同一组件改名”的推断。【测试覆盖】
`TestCompareRenameIsRemovePlusAdd`（`compare_test.go:259-275`）。推论：若别的组件
的直接边因改名而改指新坐标，那些引用方会因**自身直接依赖集合变化**各自独立进入
changed（`compare.go:95` 右半的直接推论；现有改名用例中没有组件引用被改名坐标，
故该连带情形为【源码推导】）。

**版本只是标签，ID 不参与比较。** `Diff.Artifact/FromVersion/ToVersion` 只是从输入
原样拷贝的标识符（`compare.go:72-74`），代码不比较版本新旧、不要求二者不同，
`ID` 根本不读。【测试覆盖】
`TestCompareIgnoresIDsAndTreatsVersionsAsLabels`（`compare_test.go:173-196`）：
把两份内容相同的清单人为改成不同 ID（7/99）与“倒置”的版本标签（2/1），差异仍三个
空数组、标签原样回显，并断言序列化结果里不含 `"id"`（`189-195`）。

### 4.3 `nil` 清单或不同制品：返回 `nil` 与 `model.ErrInvalidInput`

```go
manifest.Compare(nil, after)                 // nil 清单
manifest.Compare(before, nil)                // nil 清单
manifest.Compare(otherArtifact, after)       // Artifact 不同
```

三种/两类情形都返回 `(nil, err)` 且 `errors.Is(err, model.ErrInvalidInput)`：
nil 边在 `compare.go:60-62` 用 `fmt.Errorf("compare manifests: %w", …)` 包哨兵；
制品不同在 `63-66` 把双方制品名带进错误消息再包哨兵。制品名比较是**精确、大小写
敏感**的（`63` 的 `!=`，没有折叠）。【测试覆盖】
`TestCompareRejectsNilAndForeignManifests`（`compare_test.go:110-146`）覆盖 nil
before / nil after / 双 nil、不同制品的正反两个方向，以及同内容但 `APP` 与 `app`
大小写不同也拒绝（`142-145`）。

### 4.4 接受乱序副本，不重复登记校验

`Compare` 不重新跑 `ParseRegistration` 的任何登记规则：它不查重复坐标、不查悬空/
自依赖。索引直接用 map（`indexComponents, 110-116`），依赖按集合比较
（`sameDependencySet`）。因此：

- 组件顺序、依赖顺序无关：两侧都洗牌后结果与规范输入 `DeepEqual`，输出依赖仍有序。
  【测试覆盖】`TestCompareArrayOrderIsIrrelevant`（`compare_test.go:201-221`）。
- 同一对象自比、或与一份内容相同的副本相比，得到三个非 nil 空数组、版本原样回显。
  【测试覆盖】`TestCompareSelfYieldsThreeEmptyArrays`（`compare_test.go:150-168`）。
- 交换两份输入：added 与 removed 整体互换，每个 changed 项的 before/after 翻转，
  标识字段跟随交换。【测试覆盖】`TestCompareReverseSwapsSides`
  （`compare_test.go:279-306`）。
- 空清单序列化：三个数组在线缆上是 `[]` 不是 `null`。【测试覆盖】
  `TestCompareEmptyArraysSerializeAsArrays`（`compare_test.go:310-323`）。

【源码推导】调用方应只传入 `ParseRegistration` 或存储重建出的合法规范化清单。
若手工构造一份含重复坐标的清单传给 `Compare`，`indexComponents` 会用后一个同键
组件静默覆盖前一个（map 赋值 `113`），`Compare` 不会报错——登记期的“重复坐标拒绝”
（`register.go:63-66`）在这里不执行。当前测试中所有 `Compare` 输入都来自
`mustParse`（`compare_test.go:37-44`）或已规范化的手写结构体
（`TestCompareDependenciesComparedAsSets, 232-237`），没有为“Compare 喂入违例
清单”构造用例。

### 4.5 不修改输入、深拷贝结果

`Compare` 从不写 `before`/`after`，且结果与输入**不共享内存**：进入结果的每个组件
都经 `copyComponent`（`compare.go:121-130`）复制——它 `make` 新的依赖切片、
`copy` 元素、再排序，`Before`/`After` 两侧各复制一份（`82`、`87`、`98-99`）。

【测试覆盖】`TestCompareDoesNotShareMemory`（`compare_test.go:329-358`）双向验证：

- 改坏返回值（`Added[0].License`、append 依赖、`Removed`、`Changed.Before/After`）
  不影响两份输入，也不影响随后一次 `Compare` 的结果；
- 事后改坏两份输入（许可证、依赖、坐标）不改变已经返回的 `Diff`。

注意这是 `Compare` **特有**的深拷贝保证，不能外推到存储入口（见 6.3）。

---

## 5. 错误如何识别

两个入口的错误约定一致：

| 入口 | 触发 | 返回 | 判型 |
|---|---|---|---|
| `ParseRegistration` | 第 3 节任一非法形态 | `nil, model.ErrInvalidInput`（解码处直接返回哨兵，`register.go:42,49,56,…`） | `errors.Is(err, model.ErrInvalidInput)` |
| `Compare` | 任一入参为 nil；两份清单制品不同 | `nil, fmt.Errorf("…: %w", model.ErrInvalidInput)` | 同上 |

`ParseRegistration` 成功时错误为 nil 且清单非 nil（`register.go:170-174`）；
`Compare` 成功时 `Diff` 非 nil（`compare.go:107`）。两个入口都**不**产生
`model.ErrConflict` / `model.ErrNotFound` / `model.ErrStorageUnavailable`——那些是
存储层的哨兵（`internal/model/sbom.go:33-39`），只有经过 `Store.Register` /
`Store.Diff` 才可能出现。换言之，拿到这两个纯函数的 `ErrInvalidInput` 一定是调用方
传入内容的问题，与数据库是否可用无关（函数根本不触库）。

---

## 6. 数据归属：谁分配内存、与谁共享、谁深拷贝

这是仓库内 Go 调用者最容易踩坑的一节。三个入口的别名边界**不同**，不要互相套用。

### 6.1 `ParseRegistration`：全新分配，与输入字节及其他调用完全隔离

- 输入 `raw []byte` 不被修改（`TestParseDoesNotMutateInput`）。
- 返回的 `*model.SBOM` 中组件切片、每个依赖切片都是函数内新 `make`
  （`register.go:154`、`68`），与 `raw` 的反序列化缓冲、与历史/后续调用的结果都不
  共享（`TestParseCallsAreIndependent`）。调用方可以自由保留并改写返回值。

### 6.2 `Compare`：输入只读，结果深拷贝

- 不修改 `before`/`after`（`TestCompareDoesNotShareMemory` 后半）。
- `Diff` 里的组件是 `copyComponent` 深拷贝（`compare.go:121-130`），改结果不回灌
  输入、也不影响其他调用（同测试前半）。

### 6.3 `Store.Register`：浅拷贝入参，首次登记的返回值与入参共享组件底层数组

存储入口**不是**本包函数，但 Go 调用者常把 `ParseRegistration` 的结果直接传给它，
需要知道真实边界。`Store.Register` 在新建分支末尾是：

```go
out := *in                       // internal/store/store.go:219
out.ID = id                      // :220  ID 写在副本上
result = &out                    // :221
```

`out := *in` 是对 `model.SBOM` 结构体的**浅拷贝**：标量字段（含 `Artifact`、
`Version`）与切片头被复制，但 `out.Components` 与入参 `in.Components` **共用同一
底层数组**，组件内的 `Dependencies` 也共用。也就是说：

- **顶层身份字段不共享**：存储把 ID 写到 `out`，入参 `in.ID` 不变。这正是
  `TestParsedManifestRegistersThroughStore`（`internal/api/register_shared_test.go:
  91-105`）断言的边界：`saved.ID > 0` 而解析入参 `first.ID` 仍是 `0`
  （`102-105`）。
- **组件/依赖内容在首次登记返回值与入参之间是别名**（【源码推导】，`store.go:219`
  的浅拷贝；`Register` 在写入循环里只读 `comp.Coordinate/License` 与依赖坐标
  `189-217`，不修改这些切片，所以函数自身不会通过别名制造可见写入）。现有测试只做
  内容 `DeepEqual` 与 ID 归属断言，**没有**像 `Compare` 那样在事后改写两侧验证隔离，
  因此“深隔离”在存储入口不被测试保证，调用方不应假设它。
- **幂等重放（`created=false`）走的是另一条路**：返回值来自 `loadSBOM` 从数据库的
  重建（`store.go:156-164` → `471-491`，经共享装载器新建切片），与入参不共享内存。
  所以“再次登记同内容返回原记录”的那个结果是独立副本；只有**首次创建**的返回值带
  与入参共享的组件底层数组。

实践建议：把 `ParseRegistration` 的结果传给 `Store.Register` 后，若还要继续使用入参
或返回值中的组件/依赖切片，不要就地改写其中任何一个；需要独立副本时自行深拷贝，或改用
重放/`List`/`Diff` 重建出的副本。不要把 `Compare` 的深拷贝保证（6.2）套到
`Register` 上——两者的拷贝策略在源码里本就不同。

### 6.4 可核对的最小示例

```go
parsed, _ := manifest.ParseRegistration(raw)   // parsed 与 raw 完全独立（6.1）

saved, created, err := store.Register(ctx, parsed)
// saved.ID 是存储分配的新 ID；parsed.ID 仍为 0
//   - created=true ：saved.Components 与 parsed.Components 共享底层数组（6.3，勿就地改）
//   - created=false：saved 是数据库重建的独立副本，与 parsed 不共享

d1, _ := manifest.Compare(before, after)        // d1 深拷贝，与 before/after 隔离（6.2）
d2, _ := manifest.Compare(before, after)        // 独立的另一份深拷贝
```

---

## 7. 证据索引（可核对）

运行方式：`go test ./...`（撰写时全部通过）。【测试覆盖】=有自动化断言；
【源码推导】=仅由当前源码支持、无对应用例，不得当作“测试已保证”。

### 7.1 `ParseRegistration`

| 结论 | 证据 | 类别 |
|---|---|---|
| trim、大小写保留、组件/依赖排序、空数组非 nil、ID 为零 | `register_test.go: TestParseRegistrationNormalizes, 27-57` | 测试覆盖 |
| 空 components、空 dependencies 都成非 nil 空切片 | `TestParseEmptyArraysStayArrays, 61-79` | 测试覆盖 |
| 前向引用、非自身环合法；自依赖拒绝 | `TestParseAllowsForwardReferencesAndNonSelfCycles, 84-104` | 测试覆盖 |
| 表中全部非法形态 → nil + `ErrInvalidInput` | `TestParseRejectsInvalidInput, 109-167` | 测试覆盖 |
| 未知字段忽略、大小写不折叠 | `TestParseKeepsCaseAndUnknownFields, 171-185` | 测试覆盖 |
| 输入字节成功/失败都不变 | `TestParseDoesNotMutateInput, 189-198` | 测试覆盖 |
| 多次解析不同指针、改坏一份不影响其他 | `TestParseCallsAreIndependent, 202-230` | 测试覆盖 |
| 悬空目标拒绝 | 同上表用例 `"dangling dependency"`，判定 `register.go:155-160` | 测试覆盖 |
| 顶层“恰好一个 JSON 值”（尾随值）拒绝 | `hasTrailingValue, register.go:181-189`，用例 `{} {}`/`{} xxx` | 测试覆盖 |

### 7.2 `Compare`

| 结论 | 证据 | 类别 |
|---|---|---|
| added/removed/changed 分区、完整 before/after、排序、许可证/直接边变化 | `compare_test.go: TestComparePartitionsAndSorts, 70-105` | 测试覆盖 |
| nil 边、双 nil、不同制品（双向）、制品名大小写敏感 → nil + `ErrInvalidInput` | `TestCompareRejectsNilAndForeignManifests, 110-146` | 测试覆盖 |
| 自比/相同内容副本 → 三个非 nil 空数组、版本回显 | `TestCompareSelfYieldsThreeEmptyArrays, 150-168` | 测试覆盖 |
| 忽略 ID、版本仅作标签、结果不含 `id` | `TestCompareIgnoresIDsAndTreatsVersionsAsLabels, 173-196` | 测试覆盖 |
| 组件/依赖乱序不影响结果 | `TestCompareArrayOrderIsIrrelevant, 201-221` | 测试覆盖 |
| 直接依赖按集合比较、删边算变化、after 完整有序 | `TestCompareDependenciesComparedAsSets, 231-255` | 测试覆盖 |
| 改名 = removed + added，不进 changed | `TestCompareRenameIsRemovePlusAdd, 259-275` | 测试覆盖 |
| 交换输入交换 added/removed 并翻转 before/after | `TestCompareReverseSwapsSides, 279-306` | 测试覆盖 |
| 三数组序列化为 `[]` 非 `null` | `TestCompareEmptyArraysSerializeAsArrays, 310-323` | 测试覆盖 |
| 不修改输入、结果深拷贝、调用间隔离 | `TestCompareDoesNotShareMemory, 329-358` | 测试覆盖 |
| 不重复登记校验（喂入违例清单不报错、map 静默覆盖） | `indexComponents, compare.go:110-116`；无对应用例 | 源码推导 |
| 改名导致引用方直接边变化时引用方独立进 changed | 判定式 `compare.go:95` 的推论；改名用例无引用方 | 源码推导 |

### 7.3 与 HTTP / 存储的边界

| 结论 | 证据 | 类别 |
|---|---|---|
| 解析是 POST 与库内调用共用的唯一规则，解析失败不触库 | `internal/api/sbom.go:28-38`；`TestInvalidRegistrationNeverReachesStore`（计数驱动 0 条 SELECT，`register_shared_test.go:156-190`） | 测试覆盖 |
| 库内解析结果带零 ID 入库后由存储分配 ID，入参 ID 不被写 | `register_shared_test.go: TestParsedManifestRegistersThroughStore, 91-105` | 测试覆盖 |
| 存储重建（重放/List/Diff）与解析共用规范化形态 | `TestStandaloneParseAndHTTPRegistrationShareNormalization, register_shared_test.go:34-86`；装载器 `store.go:377-443` | 测试覆盖 |
| `Store.Register` 首次返回 `out := *in` 浅拷贝、与入参共享组件数组 | `internal/store/store.go:219-221`；无隔离对应用例 | 源码推导 |
| 包仅被本模块 `internal/` 树内代码导入，模块外不可见 | 导入路径含 `/internal/`；全仓引用仅 `internal/api/*` | 源码推导 |

HTTP 状态码、存储事务与快照语义不在本文展开：登记链路见
`docs/registration-integrity.md`，差异链路见 `docs/diff-comparison.md`。

---

## 8. 不在本次范围

- 本次只新增 `docs/manifest-usage.md`，**不改动任何产品源码、`README.md` 与两份
  既有 docs**。`POST /sboms`、`GET /sboms`、`GET /sboms/diff`、`GET /healthz`
  的公开 HTTP 行为（状态码、信封、分页、事务）保持原样。
- 本文不规定 HTTP 状态码与 `writeStoreError` 映射、不规定 SQLite 事务/快照/并发
  语义——那些分别属于上述两份既有文档；本文只在函数契约与数据归属处引用边界。
- `ParseRegistration`/`Compare` 是无状态纯函数：本文不涉及任何缓存、连接生命周期或
  上下文取消（两个函数都不接收 `context.Context`）。
