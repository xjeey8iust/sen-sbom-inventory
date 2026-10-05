# `GET /sboms/diff` 差异比对源码说明

本说明专门解释差异比对接口 `GET /sboms/diff`：从一次公开 HTTP 请求进入路由开始，
追踪查询参数规范化、存储层在同一快照下读取两份清单、组件差异的划分规则，直到成功或
错误响应离开服务。已有《SBOM 清单登记完整性说明》（`docs/registration-integrity.md`）
覆盖 `POST /sboms` 与 `GET /sboms`，不覆盖本接口；本篇不重复其结论，只在需要处引用。

所有关键结论都标注**源码文件:函数:行号**。第 9 节逐条核对现有测试的**实际断言**，
全文区分【测试覆盖】（存在自动化测试且断言了该结论）与【源码推导】（由源码直接支持、
但没有对应用例）。测试状态以本次实跑为准：`go test ./...` 在 Go 1.26.8 下全部通过
（`internal/api`、`internal/store` 两个包）。未被测试断言的事情，本文不会说成已验证。

范围与基线：当前实现包含登记、分页查询与差异比对三个业务入口。本次只新增本说明，
不修改任何产品源码、`README.md` 或已有说明；`POST /sboms` 的幂等与 409 冲突行为、
`GET /sboms` 的分页、`GET /healthz` 的响应均维持原样（路由并列见
`internal/api/router.go:33-35`，健康检查 `internal/api/router.go:25-31`）。

---

## 1. 贯穿全文的示例：同一制品的两份小清单

以制品 `shop` 的两个版本为例。两份清单刻意覆盖四类情形：新增组件、移除组件、
许可证改变、仅依赖数组顺序变化；另有完全不变的组件。

### 1.1 登记旧版本 `1`

```http
POST /sboms
Content-Type: application/json

{
  "artifact": "shop",
  "version": "1",
  "components": [
    {"coordinate": "reorder",  "license": "MIT",         "dependencies": ["zlib", "keep"]},
    {"coordinate": "relup",    "license": "GPL-2.0",     "dependencies": []},
    {"coordinate": "keep",     "license": "MIT",         "dependencies": []},
    {"coordinate": "zlib",     "license": "Zlib",        "dependencies": []},
    {"coordinate": "lib-legacy","license": "BSD-3-Clause","dependencies": []}
  ]
}
```

预期 `201 Created`。登记时组件按坐标升序、依赖按目标坐标升序规范化（规范化代码
`internal/api/sbom.go:145` 与 `internal/api/sbom.go:152`），所以响应体为：

```json
{
  "id": 1,
  "artifact": "shop",
  "version": "1",
  "components": [
    {"coordinate": "keep",      "license": "MIT",          "dependencies": []},
    {"coordinate": "lib-legacy","license": "BSD-3-Clause", "dependencies": []},
    {"coordinate": "relup",     "license": "GPL-2.0",      "dependencies": []},
    {"coordinate": "reorder",   "license": "MIT",          "dependencies": ["keep", "zlib"]},
    {"coordinate": "zlib",      "license": "Zlib",         "dependencies": []}
  ]
}
```

### 1.2 登记新版本 `2`

```http
POST /sboms
Content-Type: application/json

{
  "artifact": "shop",
  "version": "2",
  "components": [
    {"coordinate": "reorder", "license": "MIT",        "dependencies": ["keep", "zlib"]},
    {"coordinate": "relup",   "license": "GPL-3.0",    "dependencies": []},
    {"coordinate": "keep",    "license": "MIT",        "dependencies": []},
    {"coordinate": "zlib",    "license": "Zlib",       "dependencies": []},
    {"coordinate": "lib-next","license": "BSD-3-Clause","dependencies": []}
  ]
}
```

变化点：`lib-next` 新增；`lib-legacy` 移除（许可证相同，仅坐标不同，视为改名）；
`relup` 许可证 `GPL-2.0 → GPL-3.0`；`reorder` 的依赖输入顺序由 `[zlib, keep]` 变为
`[keep, zlib]`，但规范化后两边都是 `[keep, zlib]`；`keep`、`zlib` 完全不变。

### 1.3 发起比对

```http
GET /sboms/diff?artifact=shop&fromVersion=1&toVersion=2
```

预期 `200 OK`：

```json
{
  "artifact": "shop",
  "fromVersion": "1",
  "toVersion": "2",
  "added": [
    {"coordinate": "lib-next", "license": "BSD-3-Clause", "dependencies": []}
  ],
  "removed": [
    {"coordinate": "lib-legacy", "license": "BSD-3-Clause", "dependencies": []}
  ],
  "changed": [
    {
      "coordinate": "relup",
      "before": {"coordinate": "relup", "license": "GPL-2.0", "dependencies": []},
      "after":  {"coordinate": "relup", "license": "GPL-3.0", "dependencies": []}
    }
  ]
}
```

逐类归属（规则的代码依据见第 5 节）：

- **新增**：`lib-next` 只在新版本中出现，整条完整组件进入 `added`；
- **移除**：`lib-legacy` 只在旧版本中出现，整条完整组件进入 `removed`。两者许可证
  相同也**不**构成 `changed`——差异只按坐标认身份，改名 = 一条 removed + 一条 added
  （`internal/api/diff.go:58-60` 的注释与 `:78-87` 的两个循环）；
- **改变**：只有 `relup`。判定条件是同坐标组件的 `license` 或直接依赖坐标**集合**
  不同（`internal/api/diff.go:93`）；
- **省略**：`reorder` 只有依赖数组顺序不同，登记规范化后两边逐元素相同，且比对本身
  也按集合比较（`sameDependencySet`，`internal/api/diff.go:120-134`），故不进
  `changed`；`keep`、`zlib` 两版逐字段相同，同样省略。未变化组件在响应中没有任何
  位置，三个数组里都不会出现它们。

---

## 2. 调用链总览：请求怎样变成响应

| # | 阶段 | 代码位置 | 说明 |
|---|---|---|---|
| 1 | 路由注册 | `internal/api/router.go:35` | `router.GET("/sboms/diff", h.diff)`，与 `GET /sboms`（`:34`）是两条独立路由，互不遮蔽（有守卫测试，见第 9 节 T14） |
| 2 | 参数读取与 trim | `(*sbomHandlers).diff`，`internal/api/diff.go:16-19` | 用 `c.Query` 取 `artifact`/`fromVersion`/`toVersion`，各自 `strings.TrimSpace` |
| 3 | 必填校验 | `internal/api/diff.go:21-24` | 三者任一（含 trim 后）为空 → 400 `InvalidSbomInputError`，直接返回 |
| 4 | 存储读取 | `internal/api/diff.go:26` → `(*Store).Diff`，`internal/store/store.go:302-369` | 在一个延迟读事务内一次性取出两份完整清单 |
| 5 | 错误映射 | `internal/api/diff.go:27-30` → `writeStoreError`，`internal/api/sbom.go:250-261` | 不存在 → 404；存储失败及任何其他错误 → 503 |
| 6 | 差异计算 | `buildDiff`，`internal/api/diff.go:65-106`（调用点 `internal/api/diff.go:31`） | 纯内存比较，输出划分与排序 |
| 7 | 成功响应 | `internal/api/diff.go:31` | `c.JSON(http.StatusOK, ...)`，HTTP 200 |

第 4 步成功返回前，HTTP 层拿不到任何组件数据；第 5 步一旦走入错误分支就 `return`，
`buildDiff` 不会被调用（`internal/api/diff.go:28-30`）。这是“错误响应不夹带部分
差异”在处理层的结构原因，存储层的对应保证见第 6.4 节。

---

## 3. 三个查询标识：去空白与大小写匹配

### 3.1 规则

- **去空白（trim）**：三个参数都经 `strings.TrimSpace`（`internal/api/diff.go:17-19`），
  去掉首尾空白（含空格、制表符等 Unicode 空白，Go `strings.TrimSpace` 语义）。
  trim 同时作用于“匹配键”和“响应回显”：成功响应里的 `artifact`/`fromVersion`/
  `toVersion` 直接取自 trim 后的参数（`internal/api/diff.go:70-72`），不是取自数据库
  行。由于匹配本身也用 trim 后的值（第 4 步的 SQL 参数即这三个变量，
  `internal/store/store.go:316-320`），两者必然一致。【源码推导】回显值来自参数而非
  数据库这一点没有专门断言，但有测试断言回显值等于规范化后的参数（见第 9 节 T11）。
- **缺失与空白等价**：参数完全缺省时 `c.Query` 返回 `""`，纯空白参数 trim 后也是
  `""`，两者汇入同一个拒绝分支（`internal/api/diff.go:20-24`）。【测试覆盖】8 种 URL
  形态（全缺、缺一个、空值、纯空格、纯制表符 `%09` 等）均断言 400
  （`internal/api/diff_test.go:285-300`）。
- **大小写敏感、精确匹配**：代码里没有任何大小写折叠；SQL 为
  `artifact = ? AND version IN (...)`（`internal/store/store.go:312-315`），SQLite 对
  TEXT 列默认使用 BINARY 排序规则，即逐字节比较。登记侧同样只 trim、不折叠大小写
  （`internal/api/sbom.go:126-127`）。因此 `App` 与 `app` 是不同制品；版本 `v1` 与
  `V1` 也是不同版本。【测试覆盖】登记 `App` 后用小写 `artifact=app` 查询得到 404
  （`internal/api/diff_test.go:347-348`），带空白填充的版本先 trim 再按字面值匹配，
  匹配不到仍是 404（`internal/api/diff_test.go:349-350`）。
- **不做的事**：处理器不校验版本格式、不做 URL 解码之外的转换、不检查两个版本是否
  “属于同一产品线”——唯一的范围约束是它们都挂在同一个 `artifact` 下
  （SQL 中的 `artifact = ?`，`internal/store/store.go:313-314`）。【源码推导】

### 3.2 “版本只作标识”与“允许自比较”的含义

- **版本只作标识**：接口不推断哪个版本更新。处理器注释明确说明请求显式命名旧清单
  `fromVersion` 与新清单 `toVersion`，服务端不做任何新旧判断
  （`internal/api/diff.go:13-15`）。存储层对两个版本完全对称处理：一条 IN-list 同时
  取回，再按版本号分别放入两个结果位（`internal/store/store.go:308-311`、`:347-348`）。
  因此反向请求 `fromVersion=2&toVersion=1` 同样合法，added/removed 的归属随方向对调
  （`buildDiff` 固定以 `before`=from、`after`=to 计算，`internal/api/diff.go:66-67`）。
  【测试覆盖】两个**不同**版本内容完全相同时，反方向比对也返回三个空数组
  （`internal/api/diff_test.go:213-226`）。
- **允许自比较**：`fromVersion == toVersion` 不是错误。存储层识别相等版本后把 IN-list
  收缩为一个值（`internal/store/store.go:308-311`），清单只读一次，取回的同一条记录
  同时填充两个结果位（`internal/store/store.go:347-348`）；比较阶段两份输入是同一内容，
  坐标集合相同、每个组件自身相对自身许可证与依赖集合都相等，于是三个数组全空
  （`internal/api/diff.go:78-100`）。前提只是该版本存在；不存在时自比较同样是 404
  （见第 7.2 节）。【测试覆盖】见第 8.1 节与第 9 节 T5、T10、S2。

---

## 4. 存储读取链路：两份清单怎样被取出来

`(*Store).Diff`（`internal/store/store.go:302-369`）是本接口唯一的读路径，全程在
`withTx` 开启的**一个**事务里完成（调用点 `internal/store/store.go:304`）。

### 4.1 一个事务、一个已提交快照

- `Diff` 使用 `txDeferred` 模式，即普通 `BEGIN`（`internal/store/store.go:304`；
  模式定义 `internal/store/store.go:79-84`，BEGIN 语句选择 `:111-121`）。事务在一条
  专用连接上执行，连接在任何退出路径上都归还连接池（`internal/store/store.go:103-109`）。
- 该事务内的全部 SELECT 固定在**同一个已提交快照**上：服务以 WAL 模式打开数据库
  （`PRAGMA journal_mode=WAL`，`internal/store/store.go:43`），代码注释对延迟读事务的
  定义即“为其中每条 SELECT 钉住一个已提交快照”（`internal/store/store.go:79-81`）。
- 比对的三份读取——清单行、组件批读、依赖批读——全部发生在这一个事务内
  （`internal/store/store.go:321`、`:357`、`:360`），所以调用方不可能把来自两个不同
  提交点的清单拼在一起比较（方法注释 `internal/store/store.go:292-301`）。
- 写侧的对应保证：登记在一个 `BEGIN IMMEDIATE` 事务里插完清单行、全部组件行、全部
  依赖行后只 COMMIT 一次（`internal/store/store.go:149`、`:171-223`、提交点 `:135`）。
  因此读事务要么看不到某次登记，要么看到完整清单，**不可能读到半写入的登记**
  （`internal/store/store.go:296-298` 的注释）。这是“读取一致性”的源码依据；并发压测
  实际断言到的范围见第 9 节 S7，请勿超出其断言外推。

### 4.2 清单行：一条 IN-list 取回，自比较只读一次

```go
versions := []string{fromVersion, toVersion}
if fromVersion == toVersion {
    versions = []string{fromVersion}
}
// SELECT id, artifact, version FROM sboms
// WHERE artifact = ? AND version IN (?,?) ORDER BY id ASC
```

代码：`internal/store/store.go:308-320`。

- 表上有唯一约束 `UNIQUE (artifact, version)`（`internal/store/store.go:540`），所以
  IN-list 对每个版本至多返回一行，查询不需要也没有做“多行取一”的处理。
- 取回的行按 `id ASC` 排序（`internal/store/store.go:315`），扫描进 `items`/`ids`/
  `indexByID`/`byVersion` 四个结构（`internal/store/store.go:327-340`）：前三个服务于
  后续批量明细读取，`byVersion` 把版本号映射回清单指针。
- 自比较时 IN-list 只有一个参数，物理上只读一行；随后两个结果位都指向同一个
  `*model.SBOM`（`internal/store/store.go:347-348`）。【测试覆盖】自比较恰好发出 3 条
  SELECT、sboms 行恰好 1 行、两个结果位 ID 相同（`internal/store/diff_test.go:106-112`
  与 `:95-97`）。

### 4.3 存在性判定先于一切明细读取

扫描完清单行后立即判定：

```go
fromSBOM = byVersion[fromVersion]
toSBOM   = byVersion[toVersion]
if fromSBOM == nil || toSBOM == nil {
    return model.ErrNotFound
}
```

代码：`internal/store/store.go:347-351`。

- 任一版本缺失即返回 `model.ErrNotFound`（`internal/model/sbom.go:36`），**两个都缺也
  只返回这一个错误**：条件是“或”，返回值是单个 error，没有错误数组
  （`internal/store/store.go:349-350`）。
- 判定发生在组件/依赖批读之前（`internal/store/store.go:345-351` 在 `:357-362`
  之前），版本不存在时根本不会去读明细表。【测试覆盖】双方都缺、单边缺、未知制品、
  缺失版本自比较四种形态，存储层断言 `errors.Is(err, ErrNotFound)` 且两个返回清单均为
  nil（`internal/store/diff_test.go:139-165`）；HTTP 层五种形态断言 404 与严格错误信封
  （`internal/api/diff_test.go:305-326`）。

### 4.4 组件与依赖的清单归属：同一对共享装载器

存在性通过后，`Diff` 调用与分页查询、登记幂等检查**完全相同**的两个装载器：
`loadComponentsInto`（`internal/store/store.go:377-400`，调用点 `:357-359`）与
`loadDependenciesInto`（`internal/store/store.go:408-443`，调用点 `:360-362`）。差异
路径不另写重建规则。

- **组件**按 `sbom_id IN (...)` 批量取回，`ORDER BY sbom_id ASC, coordinate ASC`
  （`internal/store/store.go:378-383`），凭 `sbom_id` 经 `indexByID` 挂回各自清单
  （`internal/store/store.go:390-398`）。每个组件在装入时就把 `Dependencies` 初始化为
  非 nil 空切片（`internal/store/store.go:393`）；清单对象自身也以非 nil 空组件切片
  创建（`internal/store/store.go:332`）。
- **依赖边**的查询对两端组件都做 JOIN，并要求目标与源属于**同一个清单**：

  ```sql
  FROM dependencies d
  JOIN components sc ON sc.id = d.component_id
  JOIN components tc ON tc.id = d.target_id AND tc.sbom_id = sc.sbom_id
  WHERE sc.sbom_id IN (...)
  ORDER BY sc.sbom_id ASC, sc.coordinate ASC, tc.coordinate ASC
  ```

  代码：`internal/store/store.go:409-415`。`tc.sbom_id = sc.sbom_id` 这一条件
  （`:413`）保证边不会跨版本/跨制品串台：即使两个版本里存在相同坐标，目标行也必须是
  同一清单内的那一行。边再按 `(sbom ID, 源坐标, 目标坐标)` 挂回组件
  （`internal/store/store.go:424-441`）。
- 数据库约束为归属关系提供结构兜底：`UNIQUE(sbom_id, coordinate)`
  （`internal/store/store.go:547`）使同一清单内坐标唯一，`(sbom ID, 坐标)` 定位组件无
  歧义（注释 `internal/store/store.go:422-423`）；依赖表对 `(component_id, target_id)`
  去重并带外键级联（`internal/store/store.go:549-554`），外键在每个连接上启用
  （`_pragma=foreign_keys(1)`，`internal/store/store.go:37`）。
- **读取预算有实测**：两个不同版本的比对固定发出 3 条 SELECT（清单 1、组件 1、
  依赖 1），明细行数严格等于这两份清单之和；测试还注册了另一个含相同坐标的制品，
  断言其组件（标记 `SECRET`）不会出现在任何一份比对清单里
  （`internal/store/diff_test.go:170-205`）。空清单的组件重建为非 nil 的 `[]`
  （`internal/store/diff_test.go:117-134`）。

---

## 5. 差异如何确定：`buildDiff` 的划分规则

`buildDiff`（`internal/api/diff.go:65-106`）是纯函数，输入是两份重建后的
`*model.SBOM`，输出 `diffResponse`。它不访问存储、不看版本号内容，只比较组件。

### 5.1 以坐标为身份建索引

- 两份清单各自经 `indexComponents` 转成 `map[坐标]组件`
  （`internal/api/diff.go:66-67`，函数 `:108-114`）。因此比对与登记时的数组顺序、
  回读时的排序都无关——身份只由坐标字符串决定。
- 响应对象在创建时把三个数组都初始化为**非 nil 空切片**
  （`internal/api/diff.go:73-75`），所以无差异时线上形态是 `[]` 而非 `null`。

### 5.2 三类成员的归属

三轮独立的 map 扫描（`internal/api/diff.go:78-100`）：

1. **added**：坐标只在新清单中（`:78-82`）。放入的是新清单里的**完整组件**
   （coordinate、license、dependencies 三个字段，结构定义 `internal/model/sbom.go:10-14`）。
2. **removed**：坐标只在旧清单中（`:83-87`）。放入旧清单里的完整组件。
3. **changed**：坐标两边都在（`:88-92` 先跳过 added 坐标），**仅当**许可证不同或直接
   依赖坐标集合不同（`:93`）：

   ```go
   if oldComp.License != newComp.License || !sameDependencySet(oldComp.Dependencies, newComp.Dependencies)
   ```

   每项是 `componentChange{coordinate, before, after}`（结构体 `internal/api/diff.go:37-41`），
   `before`/`after` 分别是旧、新清单中的**完整组件**（`:94-98`），不是差异字段列表；
   只改依赖时两侧许可证也原样携带，只改许可证时两侧依赖也原样携带。

- 三种典型变化的影响：
  - **改名（坐标变化，其余全同）**：旧坐标进 removed、新坐标进 added，changed 不受影响
    （规则注释 `internal/api/diff.go:58-60`）。
  - **直接依赖集合变化（增/删一条直接边）**：该组件进 changed，其 `before`/`after`
    体现两个集合；其他组件不受影响。
  - **目标许可证变化**：只有目标组件自身可能进 changed；**引用它的组件不进 changed**，
    因为比较的是各组件自己的许可证与自己的直接边集合（`internal/api/diff.go:61-64`）。
- **不展开传递依赖**：装载器只重建登记时写入的直接边（第 4.4 节），`buildDiff` 也只比
  直接边集合（`internal/api/diff.go:62-64`、`:93`）。深层边的增减不会出现在上游组件的
  `before`/`after` 中，也不会把上游组件标为 changed。

### 5.3 依赖按集合比较，顺序无关

`sameDependencySet`（`internal/api/diff.go:120-134`）先比较长度，再把第一个数组放入
集合、对第二个数组逐个做成员检查。顺序不同但元素相同即相等；重复元素会在长度或成员
检查中暴露差异（登记侧本来就禁止重复依赖，`internal/api/sbom.go:85-87`）。注释说明
两层防御：登记已排序去重，集合比较把“顺序无关”这条契约显式化
（`internal/api/diff.go:116-119`）。

因此第 1 节的 `reorder` 即使绕过登记规范化、直接以不同数组顺序喂给 `buildDiff`，也
不会被判为变化【测试覆盖】（直接对纯函数的单测：洗牌不报告、删边才报告，
`internal/api/diff_test.go:418-435`）。

### 5.4 排序与空数组

- 三个数组在返回前各自按坐标字符串升序排序
  （`sort.Slice` + `Coordinate < Coordinate`，`internal/api/diff.go:102-104`）。这是必要
  的一步：前面的扫描遍历 Go map，顺序本身不确定；排序让响应可复现。【源码推导】map
  遍历不确定是 Go 语言语义；【测试覆盖】多组件下 added/removed 的精确顺序
  （`internal/api/diff_test.go:103-134`）与 changed 的坐标升序（`:64-79`）。
- 三个数组永远是数组：无新增/移除/变化时分别为 `[]`，绝不会出现 `null`
  （初始化 `internal/api/diff.go:73-75`）。【测试覆盖】在线缆 JSON 字节层面用指针字段
  验证三者非 null 且长度为 0（`internal/api/diff_test.go:230-255`）。
- 组件内的 `dependencies` 保持登记/回读时的目标坐标升序（第 4.4 节的
  `ORDER BY ... tc.coordinate ASC`），空依赖为 `[]`；HTTP 测试断言 changed 项两侧依赖
  数组非 nil（`internal/api/diff_test.go:76-78`）。

### 5.5 成功响应的字段边界

`diffResponse` 只有六个字段：三个标识与三个数组（`internal/api/diff.go:45-52`）。
组件结构里没有 id（`internal/model/sbom.go:10-14`），差异响应也**不回显**清单的数据库
`id`、不回显分页字段。成功状态码固定 200（`internal/api/diff.go:31`）。【源码推导】
字段全集由结构体确定；【测试覆盖】标识字段与三个数组的内容（第 9 节 T1 等）。

---

## 6. 错误怎样返回

### 6.1 400：参数缺失或去空白后为空

- 触发点唯一：`internal/api/diff.go:21-24`，三个 trim 后变量任一为 `""` 即调用
  `writeAPIError(c, http.StatusBadRequest, invalidInputCode, invalidInputMessage)`。
- code/message 常量：`InvalidSbomInputError` / `request is not a valid SBOM manifest`
  （`internal/api/sbom.go:234`、`:238`）。
- 注意 400 **先于**存储访问（`internal/api/diff.go:21-24` 在 `:26` 之前）：空参数不会
  产生任何数据库读取，也就不可能与 404/503 叠加。【源码推导】；参数形态矩阵
  【测试覆盖】`internal/api/diff_test.go:285-300`。

### 6.2 404：参数有效但任一版本不存在

- 来源只有一个：存储层的存在性判定 `model.ErrNotFound`
  （`internal/store/store.go:349-350`）。
- 映射在 `writeStoreError`：`errors.Is(err, model.ErrNotFound)` → 404，code
  `SbomNotFoundError`，message `no SBOM is registered for this artifact and version`
  （`internal/api/sbom.go:254-255`，消息常量 `:240`）。
- 触发情形包括：fromVersion 不存在、toVersion 不存在、两个都不存在、artifact 本身未知
  （IN-list 一行都不返回）、缺失版本的自比较。五种 HTTP 形态均有测试
  （`internal/api/diff_test.go:305-326`）。
- “双方缺失也只有一个错误”有两层含义：存储层只返回一个 error 值而非两个
  （`internal/store/store.go:349-350`），HTTP 层只输出一个顶层 `error` 对象
  （第 6.4 节）。【测试覆盖】存储层断言拿到的就是一个 err、两个清单为 nil
  （`internal/store/diff_test.go:156-163`）；HTTP 层对“both versions missing”子用例还
  做了严格信封断言（`internal/api/diff_test.go:310`、`:323`）。

### 6.3 503：存储读取失败，不夹带部分差异

- 读路径上每个可能失败的点都收敛为 `model.ErrStorageUnavailable`：清单查询失败
  （`internal/store/store.go:321-324`）、行扫描失败（`:333-335`）、游标终结错误
  （`:341-343`）、组件/依赖装载器失败（`:357-362`，装载器内部各自的错误出口经
  `unavailable` 包装，见 `:386`、`:395`、`:399`、`:417`、`:437`、`:442`）；
  取连接、BEGIN、COMMIT 失败同理（`internal/store/store.go:103-106`、`:119-121`、
  `:135-137`）。`unavailable` 把任意原因包进同一个 sentinel（`internal/store/store.go:524-529`）。
- 关键顺序：**存在性扫描本身失败时，得到的是存储错误而不是 404**——扫描出错直接
  返回（`internal/store/store.go:322-324`），走不到 `:349` 的存在性判断。【测试覆盖】
  专门对 sboms/components/dependencies 三个读取点分别注入故障，断言均为
  `ErrStorageUnavailable`（`internal/store/diff_test.go:207-233`）。
- **无部分结果**：事务回调一旦返回错误，`withTx` 原样透传该错误、不提交并 best-effort
  回滚（`internal/store/store.go:132-139`）；`Diff` 对外返回 `nil, nil, txErr`
  （`internal/store/store.go:365-367`），不可能返回“一份完整 + 一份缺失”。HTTP 侧
  `writeStoreError` 之后立即 return，`buildDiff` 不执行（`internal/api/diff.go:27-30`）。
  【测试覆盖】存储层断言两个返回清单都为 nil（`internal/store/diff_test.go:228-230`）；
  HTTP 层断言 503 且响应体通过严格信封检查（`internal/api/diff_test.go:369-373`）。
- HTTP 映射：sentinel 与**任何其他未预期错误**都落 503（`internal/api/sbom.go:256-259`
  的两个分支），code `storage_unavailable`，message 固定为
  `database is not available`（`internal/api/sbom.go:237`、`:241`）。数据库句柄关闭这
  类朴素故障同样 503【测试覆盖】（`internal/api/diff_test.go:385-396`）。

### 6.4 错误信封：单个顶层 error，code/message 为字符串，不泄漏内部信息

- 所有错误响应由同一个函数写出：

  ```go
  c.JSON(status, gin.H{"error": gin.H{"code": code, "message": message}})
  ```

  `internal/api/sbom.go:244-246`。即顶层只有 `error` 一个对象，内层只有字符串字段
  `code`、`message`；常量均为非空字符串（`internal/api/sbom.go:233-242`）。
- 严格的逐字段信封形态（顶层恰好 1 个键、error 内恰好 2 个键、两者都是非空字符串）由
  测试辅助函数 `assertErrorOnlyEnvelope` 校验（`internal/api/register_failure_test.go:15-45`）。
  在本接口上，**404 五个子用例**（`internal/api/diff_test.go:323`）与**503 三个故障
  子用例**（`internal/api/diff_test.go:372`）调用了它；400 用例走的是 `expectError`
  （`internal/api/sbom_test.go:53-76`），它解码并断言状态码、code 相等、message 非空，
  但**没有**断言“顶层只有 error”——400 的单信封形态属于【源码推导】（同一个
  `writeAPIError` 出口），不是逐字段测到的结论。
- 不泄漏：存储错误的底层原因只保留在 Go 错误链里（`unavailable` 用 `%w: %v` 包装，
  `internal/store/store.go:528`），HTTP 层只用 `errors.Is` 判型后写固定文案
  （`internal/api/sbom.go:250-261`）。差异接口的 503 测试在响应字节上做黑名单断言，
  禁止出现 `SELECT`、`SQLITE`、`sql:`、`goroutine`、`.go:`、`forced read failure`
  （`internal/api/diff_test.go:374-378`）；400/404/关库 503 用例经 `expectError` 断言
  不含 `SQLITE`、`sql:`、`goroutine`、`/`、`.go:`（`internal/api/sbom_test.go:71-75`）。
- 需要如实说明故障注入的边界：测试驱动对读故障的模拟是**在真实查询发出之前直接返回
  合成错误**（`internal/storetest/storetest.go:181-193`，`:192` 处 return，不调用真实
  驱动），且故障一次性消费（`:185-189`）。因此这些测试证明的是“某次读返回错误时错误
  被正确映射、无部分差异、内部串不上网”，并**没有**构造“读到损坏/半截行”的情形。

---

## 7. 三个补充小例子

### 7.1 自比较

已登记 `shop@1`（可含依赖环，本例为 a→b、b→a）后：

```http
GET /sboms/diff?artifact=shop&fromVersion=1&toVersion=1
```

`200`，三个空数组。存储层只读一份清单、两个结果位指向同一记录（第 3.2、4.2 节）。
【测试覆盖】`internal/api/diff_test.go:193-208`（HTTP）、
`internal/store/diff_test.go:83-113`（读一次、同 ID、3 条 SELECT）。

### 7.2 空清单

登记两份空组件清单（`"components": []`，登记允许空数组，见
`internal/api/sbom.go:128` 对 nil 与空切片的区分）后比对，`200` 且
`added/removed/changed` 在线缆上都是 `[]`。【测试覆盖】HTTP 线缆级断言
`internal/api/diff_test.go:230-255`；存储层断言空组件重建为非 nil 空切片
`internal/store/diff_test.go:117-134`。

### 7.3 允许的依赖环、不展开传递依赖、不传播目标变化

非自身依赖环在登记时就是合法的（组件行先全部插完再插依赖边，
`internal/store/store.go:189-217`；自依赖在 HTTP 入口被拒，
`internal/api/sbom.go:82-84`），差异比对不做任何图遍历，环按普通直接边处理。例如：

- v1：`a(L)→b`、`b(L)→c`、`c(OLD)→∅`；v2：`a(L)→b`、`b(L)→c`、`c(NEW)→d`、
  `d(L)→∅`。结果只有 `added=[d]`、`changed=[c]`、`removed=[]`：`c` 改许可证且新增
  直接边 c→d，但这条边是 `c` 的直接边；`a`、`b` 各自的许可证与直接边集合未变，尽管
  它们传递可达的子图发生了变化，仍不进 changed。【测试覆盖】
  `internal/api/diff_test.go:163-189`。
- 环内仅一个组件改许可证：v1 `a(L)→b`、`b(L)→a`；v2 `a(OTHER)→b`、`b(L)→a`。结果
  `changed=[a]`（带完整两侧与环边），`b` 不被传播标记。【测试覆盖】
  `internal/api/diff_test.go:259-282`。

---

## 8. 端到端的读取一致性（基于实际读取链路的小结）

一次成功的 diff 请求中，组件与依赖的“清单归属”由以下事实共同确定：

1. 两份目标清单由同一条带 `artifact = ?` 的 IN-list 在一个延迟读事务中选定
   （`internal/store/store.go:304`、`:312-320`），其他制品、其他版本在行级就被排除；
2. 组件只按这批 `sbom_id` 批量读取并按 `sbom_id` 挂回（`:377-400`）；
3. 依赖边的 JOIN 强制两端同清单（`:413`），跨版本复用坐标也不会串边；
4. 三类读取共享同一已提交快照（第 4.1 节），而写端整份清单原子提交
   （`internal/store/store.go:149`、`:135`）——所以读到的每份清单都对应某个已提交
   快照上的完整登记：它的组件集合、直接边集合都属于那一刻的同一个版本，不会出现
   “v2 的头配 v1 的边”。

以上 1–3 有行计数与防串台断言（`internal/store/diff_test.go:170-205`）；第 4 点的
单事务/原子性是源码结构给出的保证，并有并发压测佐证，但其断言边界见第 9 节 S7。

---

## 9. 现有测试真正验证到的范围（逐条核对）

下列结论全部来自阅读断言代码，而非测试名称。

### 9.1 HTTP 层 `internal/api/diff_test.go`

| 编号 | 测试（行号） | 实际断言到的内容 | 没有断言的内容 |
|---|---|---|---|
| T1 | `TestDiffPartitionsAddedRemovedChanged`（`:26-99`） | 200；三个标识回显；added 恰为完整 `born`（含 license、空依赖长度 0）；removed 恰为完整 `gone`；changed 恰 4 项且按坐标升序 `[alpha-change, moved-edge, rel, zeta-change]`；每项前后都带坐标、依赖数组非 nil；`rel` 许可证 OLD→NEW；`moved-edge` 前 `[stable]`、后 `[born stable]` 且两侧许可证均为 M | 未逐项断言 `alpha-change`/`zeta-change` 的前后许可证与依赖内容（只断言了坐标、非 nil 与总数） |
| T2 | `TestDiffSortsAddedAndRemovedAcrossMultipleComponents`（`:103-134`） | added 顺序恰为 `[b n y]`、removed 恰为 `[a m z]`、changed 为空 | 未校验数组成员的 license/deps |
| T3 | `TestDiffCoordinateRenameIsRemovePlusAdd`（`:138-157`） | 改名 = removed `old-name` + added `new-name`，changed 为空 | 未断言两边许可证内容 |
| T4 | `TestDiffOnlyDirectRelationsAndNoPropagation`（`:163-189`） | changed 仅 `c`、added 仅 `d`、removed 为空（无传播、无传递展开） | 未检查 `c` 两侧完整字段 |
| T5 | `TestDiffSelfComparisonReturnsThreeEmptyArrays`（`:193-208`） | 自比较 200，三个数组长度均为 0（清单本身含 a↔b 环） | 未在 HTTP 层验证“只读一次”（那是 S2） |
| T6 | `TestDiffIdenticalDistinctVersionsReturnsEmpty`（`:213-226`） | 不同版本同内容、且反向（from=2,to=1）比对，三数组为空 | — |
| T7 | `TestDiffEmptyManifestsAndEmptyArraysNeverNull`（`:230-255`） | 线缆 JSON 上三个数组都不是 `null` 且长度 0 | 仅用于空清单情形 |
| T8 | `TestDiffCyclesFollowSameRules`（`:259-282`） | 环场景 changed 仅 `a`，许可证 L→OTHER，after 依赖恰为 `[b]` | 未断言 `b` 的字段（只验证其缺席于 changed） |
| T9 | `TestDiffRejectsMissingOrBlankParams`（`:285-300`） | 8 种缺参/空白 URL 全为 400 且 code 为 `InvalidSbomInputError`，message 非空、无泄漏黑名单串（经 `expectError`） | 未用严格信封校验“顶层仅 error”（第 6.4 节） |
| T10 | `TestDiffMissingVersionsReturns404`（`:305-326`） | 双方缺、from 缺、to 缺、未知制品、缺失版本自比较 5 子用例均 404 `SbomNotFoundError`，且通过严格信封校验 | 未区分各子用例的响应体差异（信封一致即通过） |
| T11 | `TestDiffTrimsParamsAndMatchesCaseSensitively`（`:330-351`） | 带空格/制表符填充的三参数 trim 后 200 且回显为 `App`/`1`/`2`；小写制品 404；`" 9 "` trim 后按 `9` 匹配仍 404 | 未直接断言 SQL 比较规则（404 是行为证据） |
| T12 | `TestDiffStorageFailureReturns503WithoutPartialResult`（`:355-381`） | sboms/components/dependencies 三处读故障逐个注入，均 503、`storage_unavailable`、严格信封、六项泄漏黑名单 | 故障是合成驱动错误（第 6.4 节），未模拟损坏行 |
| T13 | `TestDiffWithClosedStoreReturns503`（`:385-396`） | 关闭句柄后 diff 返回 503 `storage_unavailable`（经 `expectError`） | 未做严格信封校验 |
| T14 | `TestDiffKeepsExistingRoutesBehavior`（`:400-413`） | 新路由未遮蔽 `GET /sboms`：登记后列表仍 200，total/items 均为 1 | 只覆盖这一条既有路由 |
| T15 | `TestBuildDiffComparesDependenciesAsSets`（`:418-435`） | 直接对纯函数：`[x y z]` 与 `[z x y]` 不产生 changed；删掉 `z` 后产生 1 项 | 仅单组件情形 |

### 9.2 存储层 `internal/store/diff_test.go`

| 编号 | 测试（行号） | 实际断言到的内容 |
|---|---|---|
| S1 | `TestDiffPartitionsComponentsByPresenceAndChange`（`:25-79`） | 两份清单各自完整（各 4 组件）、身份字段正确、组件坐标升序、空依赖非 nil；`gone`/`born` 内容完整；`edge` 的依赖排序完整为 `[born stable]` |
| S2 | `TestDiffSelfLoadsOneManifestAndIsIdentity`（`:83-113`） | 自比较两位 `ID` 相同、`equalContent` 为真；恰好 3 条 SELECT、sboms 行恰好 1（同版本不查两次） |
| S3 | `TestDiffEmptyManifestsLoadFine`（`:117-134`） | 空清单组件为非 nil 空切片；另一清单组件与空依赖重建正确 |
| S4 | `TestDiffMissingVersionsReturnsNotFound`（`:139-165`） | 双方缺/单边缺/未知制品均 `errors.Is ErrNotFound`，且两个返回清单都为 nil（无部分结果） |
| S5 | `TestDiffUsesOneSnapshotReadEach`（`:170-205`） | 恰 3 条 SELECT；行数 sboms=2、components=3、dependencies=1；另一制品的同坐标组件（`SECRET`）不出现在任何结果中 |
| S6 | `TestDiffReadFailuresReturnUnavailable`（`:211-233`） | 三个读取点逐个故障均为 `ErrStorageUnavailable`、两份清单均为 nil；注释明确指出存在性扫描故障是存储错误而非 not-found（`:207-210`） |
| S7 | `TestDiffSnapshotStaysConsistentUnderConcurrentWriters`（`:238-289`） | 见下方专节 |

### 9.3 并发测试 S7 的真实边界（避免过度概括）

该测试做的事：先登记两个固定版本 `base-1`、`base-2`；启动一个 goroutine 循环登记
**其他版本** `writer-0、writer-1、…`（`internal/store/diff_test.go:253-268`）；主循环
对两个固定版本连续做 50 次 `Diff`（`:270-286`），每次断言：无错误、两份清单都恰好
2 个组件、`base-1` 中 `a` 的边恰为 `[b]`、`base-2` 中 `b` 的边恰为 `[a]`；最后停止
goroutine 并等待退出（`:287-288`）。

它能支持的结论：在“有并发写入其他版本”的扰动下，50 次取样中比对固定版本始终成功且
两份清单完整、边未串台——与单快照、原子登记的源码设计相符。

它**没有**断言、不能外推的内容：

- 被比对的 `base-1`/`base-2` 自身从未被并发改写，所以它**没有**测试“同一版本被并发
  重写时读到什么”；同键并发写的行为由登记侧测试覆盖，不在本测试范围；
- 没有直接断言隔离级别或快照标识，也没有测量多个 SELECT 是否落在同一 OS 线程/连接
  之外的东西——快照共享是源码事实（第 4.1 节），此测试只是行为佐证；
- 写 goroutine 的错误被显式丢弃（`_, _, _ = st.Register(...)`，`:262`），它不验证
  并发写者的返回状态；也没有断言“绝不出现 SQLITE_BUSY/503”，只是主循环一旦收到错误
  即失败——在本次运行的 50 次取样里没有出现，这不构成对繁忙程度的任何概率或上限保证；
- 50 次是有限的压力取样，不是完备的并发正确性证明。

---

## 10. 不在本次范围

- 未修改任何产品源码、`README.md` 与 `docs/registration-integrity.md`；本次新增的
  只有本文件；
- `POST /sboms` 的规范化、幂等重提、409 冲突与写失败回滚，`GET /sboms` 的分页、
  total 一致性，`GET /healthz` 的 200/503 响应，均保持既有实现与既有说明；
- 本接口不比较跨制品版本、不推断版本先后、不展开传递依赖；这些是源码当前行为
  （第 3、5 节），不是遗留待办承诺；
- 测试中的读故障为查询发出前的一次性合成错误（第 6.4 节）；“读到损坏数据行”
  “持续存储故障期间的重试成功率”等场景没有被构造，相关结论均标注为【源码推导】。
