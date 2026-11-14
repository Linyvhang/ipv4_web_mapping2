# IPv4 资产分析 API 接口契约（v1）

## 1. 基础说明

- 数据格式：`application/json`；
- Swagger：`GET /docs`；
- OpenAPI：`GET /openapi.json`；
- `scan_round=null` 或不传时，读取该 IP 最近一次扫描批次；
- 所有资产查询仅访问已有数据库数据，不触发主动扫描；
- 时间字段使用 ISO 8601 字符串；
- 第一版只支持 IPv4。

本地 Mock 联调启动：

```powershell
python -m uvicorn agent_service.api.mock_main:app --host 127.0.0.1 --port 8003
```

## 2. NetScope 合并前端初始化

```http
GET /api/health
```

验证 FastAPI 到现有 MySQL 的连接，返回 `ok` 和数据库名称。该接口不返回账号、密码或连接串。

```http
GET /api/bootstrap
```

读取数据库中的最新扫描批次，返回：

- `overview`：扫描批次、存活主机、已发现服务、TCP/UDP、风险和占比；
- `stats`：端口、服务类型、真实扫描日期趋势、内网风险和高风险资产；
- `assets`：由 `service_instance_l2` 生成的服务资产行；
- `limitations`：数据库当前缺失的 TTL、地理位置、风险分析或趋势范围说明。

存活主机数量来自最新批次的 `active_host`；资产行只包含该批次中 `scan_status=1` 的
`service_instance_l2` 记录；风险来自相同批次已经保存的 Agent 分析结果。没有分析结果时风险为
`unknown`，不会用端口或服务名称猜测风险。当前接口不创建 SQLite，也不触发扫描或模型调用。

```http
GET /api/search?q=port%3D22%20%26%26%20service%3Dopenssh&page=1
```

只读过滤最新批次的服务资产，支持 `loc`、`port`、`proto`、`risk`、`service` 和 `subnet`。
多个条件使用 `&&`，每页 15 条；响应包含总数、查询耗时、当前页 `rows` 和全量命中 `list`。
接口只解析固定白名单字段，不接受 SQL。语法错误返回 `400`。

## 3. 查询原始扫描数据

```http
GET /assets/{ip}/scan-data?scan_round={可选正整数}
```

示例：

```http
GET /assets/1.2.163.154/scan-data
```

响应包含 IP、扫描批次、发现时间、扫描节点、端口、协议、服务类型、产品版本、Banner、
L3 明细和数据限制。该接口不调用模型、不创建任务。

## 4. 查询已保存分析结果

```http
GET /assets/{ip}/analysis?scan_round={可选正整数}
```

返回：

```json
{
  "analysis_id": "analysis-id",
  "ip": "1.2.163.154",
  "scan_round": 1,
  "result": {
    "summary": {},
    "services": [],
    "risks": [],
    "evidence": [],
    "recommendations": [],
    "limitations": [],
    "metadata": {}
  },
  "created_at": "2026-11-14T10:00:00",
  "updated_at": "2026-11-14T10:00:00"
}
```

没有保存结果时返回 `404`，不会重新调用模型。

## 5. 创建并执行单 IP 分析

```http
POST /analysis/ip
```

请求：

```json
{
  "ip": "1.2.163.154",
  "scan_round": null,
  "save_result": true
}
```

当前接口为同步接口：请求会等待分析完成后返回。`reused=true` 表示直接复用了保存结果。

```json
{
  "task_id": 123,
  "task_item_id": 456,
  "reused": false,
  "result": {}
}
```

## 6. 流式执行单 IP 分析

```http
POST /analysis/ip/stream
```

请求参数与 `/analysis/ip` 相同，响应类型为 `application/x-ndjson`。前端逐行读取：

```json
{"type":"node","node":"load_asset","label":"读取扫描数据","status":"completed"}
{"type":"result","data":{}}
```

需要实时进度时使用该接口；当前不需要通过任务状态接口轮询单 IP 实时进度。

## 7. 创建有限批量 IP 分析

```http
POST /analysis/batch
```

请求必须显式提供 2～50 个 IPv4，不接受 CIDR 网段；重复 IP 会按首次出现顺序去重：

```json
{
  "ips": ["1.2.163.154", "1.2.163.155"],
  "scan_round": null
}
```

系统会先检查所有 IP 是否存在扫描数据。只要有一个不存在，就返回 `404` 和
`missing_ips`，并且不创建任务。全部通过后返回 `202 Accepted`：

```json
{
  "task_id": 200,
  "status": "pending",
  "target_count": 2,
  "targets": [
    {"ip": "1.2.163.154", "scan_round": 1},
    {"ip": "1.2.163.155", "scan_round": 1}
  ]
}
```

后台任务默认最多同时处理 3 个 IP，单个 IP 失败不影响其他 IP。已有相同 IP 和扫描批次
的结果会直接复用。第一版后台任务运行在 FastAPI 进程内，服务重启会中断尚未完成的任务。

## 8. 查询任务状态

```http
GET /analysis/tasks/{task_id}
```

```json
{
  "task_id": 123,
  "task_type": "ip_analysis",
  "status": "success",
  "save_result": true,
  "total": 1,
  "pending": 0,
  "running": 0,
  "success": 1,
  "failed": 0,
  "cancelled": 0,
  "error_message": null,
  "created_at": "2026-11-14T10:00:00",
  "started_at": "2026-11-14T10:00:01",
  "completed_at": "2026-11-14T10:00:05",
  "items": []
}
```

状态取值：`pending`、`running`、`success`、`failed`、`cancelled`。

## 9. 查询任务结果

```http
GET /analysis/tasks/{task_id}/result
```

- 任务完成或失败：返回父任务状态和各 IP 子项结果；
- 任务不存在：`404`；
- 任务仍为 `pending` 或 `running`：`409`；
- 失败子项的 `result` 为 `null`，并通过 `error_message` 说明原因。

## 10. 生成和查询批量统计报告

批量任务完成后生成并保存确定性 JSON 报告：

```http
POST /analysis/tasks/{task_id}/report
```

查询已保存报告，不会重新生成：

```http
GET /analysis/tasks/{task_id}/report
```

响应中的 `reused` 表示是否复用了已有报告。`report` 包含：

- `overview`：目标、成功、失败、有效结果、服务、风险和异常数量；
- `asset_type_distribution`：资产类型分布；
- `asset_risk_distribution`：按资产最高风险等级统计；
- `finding_risk_distribution`：按疑似风险条目等级统计；
- `products`：产品、版本、服务数量、资产数量和对应 IP；
- `ports`：端口、传输协议、服务类型、数量和对应 IP；
- `failed_items`：失败 IP 和错误原因；
- `attention_items`：需重点关注的高风险资产；
- `missing_result_ips`：子任务成功但找不到保存结果的异常 IP；
- `limitation_distribution`：数据限制出现次数。

报告由程序根据已保存结果统计，不调用大模型。任务未完成时 POST 返回 `409`，非批量任务
返回 `400`，尚未生成报告时 GET 返回 `404`。

## 11. 自然语言 Agent

```http
POST /agent/chat
```

```json
{
  "question": "查询 1.2.163.154 开放了哪些服务和产品？",
  "scan_round": null,
  "conversation_id": null
}
```

首次请求的 `conversation_id` 可以为空。响应包含服务端生成的 `conversation_id`、是否复用
上下文的 `context_reused`、自然语言回答、意图、模型来源、工具轨迹、LangGraph 节点轨迹、
证据和限制。客户端继续追问时应把相同的 `conversation_id` 原样传回：

```json
{
  "question": "哪个资产需要优先处理？",
  "conversation_id": "8f58505b96984626b43c63a723a94c0d"
}
```

只有明确的追问才会复用已验证的 IP、扫描批次或任务 ID。问题中出现新的显式标识时，不会被
旧上下文覆盖。会话 ID 只允许 8～64 位字母、数字、下划线和连字符。

批量报告问答还会返回 `priority_assets`。该数组依次包含 `rank`、`ip`、`scan_round`、
`risk_level`、`risk_count`、`risk_titles`、`exposed_services`、`products` 和 `reasons`。
排序规则固定为整体风险等级从高到低、疑似风险数量从多到少、IP 从小到大。它只使用报告中
的 `attention_items` 和聚合事实，便于前端展示和审计，不把疑似风险解释为已确认漏洞。

```http
DELETE /agent/conversations/{conversation_id}
```

删除当前会话的 Checkpoint，成功返回 `200` 和删除确认。当前实现使用进程内存，服务重启后
会话自动清空，也不能跨多个 Uvicorn Worker 共享；生产环境必须使用持久化 Checkpointer，
并通过登录身份限制会话访问。

自然语言 Agent 当前支持五个白名单工具：

- `get_ip_scan_data`：读取已有扫描数据；
- `get_ip_analysis_result`：读取已保存单 IP 分析；
- `create_ip_analysis`：用户明确授权时创建单 IP 分析；
- `compare_ip_scan_rounds`：只读比较同一 IP 的两个扫描批次；
- `get_batch_report`：按任务 ID 读取已保存批量统计报告。

示例问题：

```text
比较 1.2.3.4 扫描批次 1 和扫描批次 2 的变化
查询批量任务 11 的统计报告
```

程序会从原问题独立提取并校验 IP、批次号和任务 ID。即使模型选择了正确工具，也不能
改变已经验证的参数、执行 SQL 或触发主动扫描。

## 12. 查询单 IP 跨扫描批次变化

```http
GET /assets/{ip}/changes?from_scan_round=1&to_scan_round=2
```

该接口只读取两个指定扫描批次及其已保存分析结果，不触发扫描、不调用大模型。返回内容包括：

- `change_status`：`added`、`removed`、`changed` 或 `unchanged`；
- `service_changes`：新增、消失和保持存在的服务；
- `product_changes`：新识别、识别丢失、产品变化和版本变化；
- `risk_changes`：整体风险升高、降低或不变，以及新增/消失的疑似风险；
- `limitations`：风险报告缺失、常用端口扫描等数据限制。

服务使用“端口 + 传输协议 + 服务类型”匹配。风险变化需要两个批次都存在已保存分析结果；
缺少风险结果时仍正常返回服务和产品变化，并把风险对比标记为 `unavailable`。

两个批次相同时返回 `400`；指定扫描批次不存在时返回 `404` 和 `missing_scan_rounds`；
IP 在两个有效批次中都不存在时返回 `404`；IP 只存在于一个有效批次时正常返回资产新增或消失。

## 13. 错误处理

统一错误结构：

```json
{"detail":"错误原因"}
```

| 状态码 | 含义 |
| --- | --- |
| `200` | 成功 |
| `202` | 批量任务已创建并进入后台处理 |
| `404` | 扫描数据、分析结果或任务不存在 |
| `409` | 任务未完成或缓存模型冲突 |
| `422` | IP、扫描批次或请求字段校验失败 |
| `500` | 服务内部错误 |
| `502` | 模型服务调用失败 |

## 14. 前端推荐调用方式

- 扫描详情页面：`GET /assets/{ip}/scan-data`；
- 已保存报告页面：`GET /assets/{ip}/analysis`；
- 立即创建分析：`POST /analysis/ip`；
- 展示实时分析步骤：`POST /analysis/ip/stream`；
- 创建有限批量分析：`POST /analysis/batch`，之后轮询任务状态；
- 查询持久化任务：`GET /analysis/tasks/{task_id}`；
- 获取任务下所有结果：`GET /analysis/tasks/{task_id}/result`；
- 生成批量统计：`POST /analysis/tasks/{task_id}/report`；
- 查询批量统计：`GET /analysis/tasks/{task_id}/report`；
- 对比两个扫描批次：`GET /assets/{ip}/changes`；
- 自然语言问答：`POST /agent/chat`。
- 清除自然语言会话：`DELETE /agent/conversations/{conversation_id}`。

前后端分开启动时，推荐前端开发服务器配置 `/api` 代理；正式部署时由 Nginx 将前端与
FastAPI 放在同一域名下，避免浏览器跨域问题。
