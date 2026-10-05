# sen-sbom-inventory

把软件物料清单的组件名称、版本、许可证、依赖关系与所属制品记录成可查询的服务，支持清单登记与按制品分页读取组件清单。

## 运行要求

- Go 1.26 或以上
- SQLite（本服务自带存储，不需要外部数据库）

## 构建、测试与启动

```bash
go build ./...
go test ./...
go run .
```

服务默认监听 `127.0.0.1:8080`。可用环境变量覆盖：

| 变量 | 默认值 | 用途 |
|---|---|---|
| `ADDR` | `127.0.0.1:8080` | HTTP 监听地址 |
| `DB_PATH` | `sen-sbom-inventory.db` | SQLite 数据库文件路径 |

## 已公开的入口

### `GET /healthz`

返回服务与存储状态。正常时 HTTP 200：

```json
{"status":"ok","database":"ok"}
```

存储不可用时 HTTP 503：

```json
{"error":{"code":"storage_unavailable","message":"database is not available"}}
```

### `POST /sboms`

登记一份清单。请求体是单个 JSON 对象：

- `artifact`、`version`：字符串，去除首尾空白后保存，比较时区分大小写；
- `components`：组件数组，允许为空；每个组件包含字符串 `coordinate`、`license` 和字符串数组 `dependencies`（允许为空），依赖引用本清单内的组件坐标；
- 字符串均去除首尾空白；空字符串、缺失字段、类型错误、重复坐标、重复依赖、自身依赖、依赖目标不存在、请求体无法解析为单个 JSON 对象，都返回 400 `InvalidSbomInputError`；
- 除自身依赖外的依赖环允许保存。

成功返回 HTTP 201 和完整清单：`id` 为正整数；组件按坐标升序、每个组件的依赖也按坐标升序排列，字段值为规范化后的值：

```json
{"id":1,"artifact":"app","version":"1.2.0","components":[{"coordinate":"lib-a","license":"Apache-2.0","dependencies":[]}]}
```

同一 `artifact` 与 `version` 已存在时：

- 内容相同（与输入数组顺序无关）返回 201 及原记录，`id` 不变；
- 组件集合、许可证或依赖关系不同，返回 409 `SbomConflictError`，原记录保持不变。

清单与全部组件、依赖在同一个事务中写入，失败时不会留下部分记录。

### `GET /sboms`

按制品分页查询清单，必须提供 `artifact` 参数（同样去除首尾空白，空白值返回 400）。

- `page`、`pageSize` 省略时分别为 `1` 和 `20`；
- 提供时必须是正十进制整数，`pageSize` 最大为 `100`，否则返回 400 `InvalidSbomInputError`。

返回 HTTP 200：`items` 为按 `id` 升序的完整清单页，`total` 为匹配总数；未知制品或页码超出末页时 `items` 为空数组。

```json
{"items":[],"total":0,"page":1,"pageSize":20}
```

存储不可用时返回 503 `storage_unavailable`。

### `GET /sboms/diff`

比较同一制品已登记的两个版本。三个查询参数均为必填字符串，去除首尾空白后精确匹配、区分大小写：

- `artifact`：制品标识；
- `fromVersion`：旧版本；
- `toVersion`：新版本。

版本只作标识，接口不推断版本先后，也不要求两个版本不同。参数缺失或去空白后为空，返回 400 `InvalidSbomInputError`。参数有效但任一版本不存在（含双方都不存在），返回 404 `SbomNotFoundError`。

成功返回 HTTP 200，对象只包含规范化后的三个标识字段和 `added`、`removed`、`changed`：

- `added`：仅存在于新版本的完整组件；`removed`：仅存在于旧版本的完整组件；组件结构与登记响应一致（`coordinate`、`license`、`dependencies`，空依赖为 `[]`）；
- 相同坐标仅当 `license` 或直接依赖坐标集合改变时才进入 `changed`，每项含 `coordinate` 以及来自旧、新清单的完整组件 `before`、`after`；
- 坐标改名算一条 `removed` 加一条 `added`，不进入 `changed`；未变化组件不输出；
- 依赖只比较直接关系，不展开传递依赖，依赖目标的许可证变化也不传播给引用它的组件；
- 三个数组始终是数组（无差异为 `[]`，不返回 `null`），并按坐标字符串升序；组件内依赖保持既有排序；比较结果与登记时的数组顺序无关。

```json
{
  "artifact": "app",
  "fromVersion": "1.0.0",
  "toVersion": "2.0.0",
  "added": [{"coordinate":"lib-new","license":"MIT","dependencies":[]}],
  "removed": [{"coordinate":"lib-old","license":"MIT","dependencies":[]}],
  "changed": [
    {"coordinate":"lib-a","before":{"coordinate":"lib-a","license":"GPL-2.0","dependencies":[]},
     "after":{"coordinate":"lib-a","license":"GPL-3.0","dependencies":[]}}
  ]
}
```

同版本与自身比较（`fromVersion` 与 `toVersion` 相同）时，只要清单存在，就返回三个空数组。空清单以及允许的非自身依赖环遵循同一比较规则。

两份清单在同一个只读事务、同一个已提交数据快照中读取，因此不会读到半写入清单；任一读取失败返回 503 `storage_unavailable`，不返回部分差异。

## 错误约定

所有错误响应都是单个顶层 `error` 对象，包含 `code` 与 `message` 两个字符串字段；`message` 不包含 SQL、堆栈或文件路径。
