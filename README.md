# sen-sbom-inventory

把软件物料清单的组件名称、版本、许可证、依赖关系与所属制品记录成可查询的服务，支持登记清单并按制品分页读取。同一制品两次清单的差异比对暂未提供。

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

登记一份软件物料清单。请求体必须是**单个 JSON 对象**，字段如下：

| 字段 | 类型 | 说明 |
|---|---|---|
| `artifact` | 字符串 | 制品名 |
| `version` | 字符串 | 制品版本 |
| `components` | 数组 | 组件列表，允许为空数组 |
| `components[].coordinate` | 字符串 | 组件坐标，清单内唯一 |
| `components[].license` | 字符串 | 组件许可证 |
| `components[].dependencies` | 字符串数组 | 依赖的本清单组件坐标，允许为空数组 |

字符串保存前去除首尾空白，所有比较区分大小写。下列情况一律返回 HTTP 400
（`InvalidSbomInputError`）：字段缺失或类型错误、字符串去空白后为空、请求体无法解析为
单个 JSON 对象、坐标重复、依赖重复、组件依赖自身、依赖目标在本清单中不存在。组件之间的
其他依赖环（如 `a -> b -> a`）允许登记。

成功返回 HTTP 201 及完整清单对象；`id` 为正整数，组件按 `coordinate` 升序、每个组件的
依赖也按坐标升序排列：

```json
{
  "id": 1,
  "artifact": "app",
  "version": "1.0",
  "components": [
    {"coordinate": "pkg-a", "license": "Apache-2.0", "dependencies": []},
    {"coordinate": "pkg-b", "license": "MIT", "dependencies": ["pkg-a"]}
  ]
}
```

同一 `artifact` 与 `version` 再次登记时，按内容而非数组顺序判断：

- 组件集合、各组件许可证与依赖关系完全相同：返回 HTTP 201 及原记录，`id` 不变；
- 任一部分不同：返回 HTTP 409（`SbomConflictError`），原记录保持不变。

清单表头与全部组件、依赖明细在同一数据库事务中批量写入，写入失败不会留下部分记录，
查询也读不到半写入的清单；重新打开同一数据库后，已登记记录与重复登记语义继续有效。

### `GET /sboms`

按制品分页查询清单，必须提供 `artifact` 参数（同样适用去除首尾空白的字符串规则）：

| 参数 | 默认 | 规则 |
|---|---|---|
| `artifact` | 无，必填 | 去空白后不能为空 |
| `page` | `1` | 正十进制整数 |
| `pageSize` | `20` | 正十进制整数，且不超过 `100` |

参数不满足规则时返回 HTTP 400（`InvalidSbomInputError`）。成功时返回 HTTP 200：

```json
{
  "items": [ /* 按 id 升序排列的完整清单对象 */ ],
  "total": 3,
  "page": 1,
  "pageSize": 20
}
```

`total` 为该制品的清单总数；未知制品或页码超出末页时 `items` 为空数组、`total` 仍为
匹配总数。存储不可用时返回 HTTP 503（`storage_unavailable`）。

## 错误约定

所有错误响应都是单个顶层 `error` 对象，包含 `code` 与 `message` 两个字符串字段；`message`
不包含 SQL、堆栈或文件路径。业务错误的 `code` 取值：

| HTTP | code | 触发场景 |
|---|---|---|
| 400 | `InvalidSbomInputError` | 请求体或查询参数不满足登记/查询规则 |
| 409 | `SbomConflictError` | 同制品同版本已登记且内容不同 |
| 503 | `storage_unavailable` | 存储层不可用 |
| 404 | `route_not_found` | 未匹配任何路由 |
