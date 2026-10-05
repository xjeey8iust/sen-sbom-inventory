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

## 错误约定

所有错误响应都是单个顶层 `error` 对象，包含 `code` 与 `message` 两个字符串字段；`message` 不包含 SQL、堆栈或文件路径。
