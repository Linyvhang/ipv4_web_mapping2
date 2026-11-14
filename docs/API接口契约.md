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

## 2. 查询原始扫描数据

```http
GET /assets/{ip}/scan-data?scan_round={可选正整数}
```

示例：

```http
GET /assets/1.2.163.154/scan-data
```

响应包含 IP、扫描批次、发现时间、扫描节点、端口、协议、服务类型、产品版本、Banner、
L3 明细和数据限制。该接口不调用模型、不创建任务。

## 3. 查询已保存分析结果

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

## 4. 创建并执行单 IP 分析

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

## 5. 流式执行单 IP 分析

```http
POST /analysis/ip/stream
```

请求参数与 `/analysis/ip` 相同，响应类型为 `application/x-ndjson`。前端逐行读取：

```json
{"type":"node","node":"load_asset","label":"读取扫描数据","status":"completed"}
{"type":"result","data":{}}
```

需要实时进度时使用该接口；当前不需要通过任务状态接口轮询单 IP 实时进度。

## 6. 创建有限批量 IP 分析

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

## 7. 查询任务状态

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

## 8. 查询任务结果

```http
GET /analysis/tasks/{task_id}/result
```

- 任务完成或失败：返回父任务状态和各 IP 子项结果；
- 任务不存在：`404`；
- 任务仍为 `pending` 或 `running`：`409`；
- 失败子项的 `result` 为 `null`，并通过 `error_message` 说明原因。

## 9. 自然语言 Agent

```http
POST /agent/chat
```

```json
{
  "question": "查询 1.2.163.154 开放了哪些服务和产品？",
  "scan_round": null
}
```

响应包含自然语言回答、意图、模型来源、工具轨迹、LangGraph 节点轨迹、证据和限制。

## 10. 错误处理

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

## 11. 前端推荐调用方式

- 扫描详情页面：`GET /assets/{ip}/scan-data`；
- 已保存报告页面：`GET /assets/{ip}/analysis`；
- 立即创建分析：`POST /analysis/ip`；
- 展示实时分析步骤：`POST /analysis/ip/stream`；
- 创建有限批量分析：`POST /analysis/batch`，之后轮询任务状态；
- 查询持久化任务：`GET /analysis/tasks/{task_id}`；
- 获取任务下所有结果：`GET /analysis/tasks/{task_id}/result`；
- 自然语言问答：`POST /agent/chat`。

前后端分开启动时，推荐前端开发服务器配置 `/api` 代理；正式部署时由 Nginx 将前端与
FastAPI 放在同一域名下，避免浏览器跨域问题。
