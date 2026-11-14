# IPv4 Web Mapping Agent

本项目读取已经保存到 MySQL 的 IPv4 扫描与 L3 指纹数据，通过 FastAPI、
LangGraph 和大模型生成单 IP 资产画像、疑似风险、证据与处置建议。

> 本系统是只读分析型 Agent：只分析已有数据，不会主动扫描、漏洞利用或进行弱口令测试。

## 当前功能

- 读取 Web、SSH、数据库、IoT、RDP 等 L3 指纹；
- 产品名称与版本归一化；
- 单 IP 标准 JSON 分析结果；
- Mock 与 DeepSeek 模型适配；
- LangGraph 多节点编排、结果复用、证据校验、一次修正重试和安全降级；
- FastAPI、Swagger 和简易分析进度页面；
- Agent 任务和分析结果持久化。
- 白名单 Agent 工具层：扫描数据查询、已保存结果查询和受控分析任务创建。
- 面向可视化模块的只读扫描数据、已保存分析、任务状态和任务结果接口。
- 有限批量 IP 分析：显式提交 2～50 个 IPv4，预检、去重、并发处理、缓存复用和逐项失败隔离。
- 批量统计 JSON 报告：汇总资产类型、风险等级、产品版本、端口服务和异常项，可直接用于可视化。
- 单 IP 历史变化：对比两个扫描批次中的服务新增/消失、产品版本和风险等级变化。
- Agent 可观测性：返回 LangGraph 节点顺序、耗时、决策、工具和安全降级原因。
- LangGraph 多轮会话：使用 Checkpoint 复用已经验证的 IP、扫描批次或任务 ID，支持安全追问。
- 批量资产优先级问答：根据报告中的风险等级和疑似风险数量确定排序，并返回结构化依据。
- NetScope 合并首页：FastAPI 同源托管单文件前端，读取现有 MySQL 最新扫描批次并调用 Agent。

自然语言问答的意图、工具轨迹、证据、响应 Schema 和 LangGraph 初始 State 已完成。
自然语言 Agent 第一版 LangGraph 已完成，支持规则模式和 DeepSeek 模式。DeepSeek 负责
问题理解、从五个白名单工具中选择工具，以及根据工具事实生成回答；程序始终负责 IP、
扫描批次和任务 ID 校验、创建权限、工具白名单和最多两次调用。新增的历史变化对比和
批量报告查询均为只读工具。模型失败时自动降级为规则理解和模板回答。

自然语言 Agent 的角色、权限、工作流和返回契约见
[自然语言 Agent 设计方案](docs/自然语言Agent设计方案.md)。

前后端接口说明见 [API 接口契约](docs/API接口契约.md)，可直接转发的前端说明见
[可视化模块对接说明](docs/可视化模块对接说明.md)。

## 1. 首次准备本地环境

以下命令均在项目根目录 `H:\ipv4_web_mapping2` 中执行。

```powershell
cd H:\ipv4_web_mapping2
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

激活成功后，PowerShell 提示符前面会出现 `(.venv)`。

如果同时显示 `(.venv) (base)`，表示 Conda base 也处于激活状态。可以先执行
`conda deactivate`，然后重新激活 `.venv`，避免混用两个 Python 环境。

## 2. 快速启动 Mock API

Mock 模式不连接 MySQL，也不会调用真实大模型，适合先检查 API、LangGraph 和页面。

```powershell
python -m uvicorn agent_service.api.mock_main:app --host 127.0.0.1 --port 8001
```

启动后访问：

- NetScope 合并首页：<http://127.0.0.1:8001/>
- 原分析预览页：<http://127.0.0.1:8001/preview>
- Swagger API：<http://127.0.0.1:8001/docs>
- 自然语言问答页：<http://127.0.0.1:8001/chat>
- OpenAPI JSON：<http://127.0.0.1:8001/openapi.json>

停止程序：回到运行 Uvicorn 的终端，按 `Ctrl+C`。

## 3. 连接云端 MySQL

如果 MySQL 位于云服务器，并且本地通过 SSH 隧道访问，请另开一个 PowerShell 窗口：

```powershell
ssh -N -L 13306:127.0.0.1:3306 -i "你的私钥文件路径" root@云服务器地址
```

注意：

- `-i` 后必须是私钥文件，不是以 `.pub` 结尾的公钥；
- 隧道运行期间不要关闭这个终端；
- 不需要把 MySQL 的 `3306` 端口直接暴露到公网。

另开一个终端验证本地隧道：

```powershell
Test-NetConnection 127.0.0.1 -Port 13306
```

看到 `TcpTestSucceeded : True` 才表示本地程序可以通过该端口访问云端 MySQL。

## 4. 配置真实数据运行环境

在项目根目录创建 `.env` 文件：

```dotenv
AGENT_DB_HOST=127.0.0.1
AGENT_DB_PORT=13306
AGENT_DB_NAME=ipv4scan
AGENT_DB_USER=数据库用户名
AGENT_DB_PASSWORD=数据库密码

# 先使用 Mock 模型分析真实数据库数据
AGENT_MODEL_PROVIDER=mock
AGENT_CHAT_PROVIDER=rules

# 有限批量分析（可选，以下为默认值）
AGENT_BATCH_CONCURRENCY=3
AGENT_BATCH_MAX_IPS=50
```

`.env` 已被 `.gitignore` 忽略，不要把密码或 API Key 提交到 Git。

第一次使用 Agent 表时执行：

```powershell
python init_agent_tables.py
```

该命令只负责创建 Agent 使用的任务和分析结果表，不会删除原有扫描数据。

## 5. 启动真实数据库 API

确保 SSH 隧道仍在运行，并在已经激活 `.venv` 的项目终端执行：

```powershell
python -m uvicorn agent_service.api.real_main:app --host 127.0.0.1 --port 8001
```

然后访问：

- NetScope 合并首页：<http://127.0.0.1:8001/>
- 原分析预览页：<http://127.0.0.1:8001/preview>
- Swagger API：<http://127.0.0.1:8001/docs>
- 自然语言问答页：<http://127.0.0.1:8001/chat>

平台首页和 Agent 使用同源接口，不需要单独设置 `AGENT_BASE` 或 CORS。首页登录按钮当前只是
开发联调入口，不执行身份认证。首页概览读取最新扫描批次；没有 TTL、公网地理位置或足够历史
批次时会明确返回限制，不生成模拟统计。

合并首页当前提供 `GET /api/health`、`GET /api/bootstrap`、只读 `GET /api/search` 和
`POST /api/report`。平台报告固定统计最新扫描批次中已经发现服务的全部资产；统计数字由
代码生成，DeepSeek 只接收不含 IP、Banner 和原始指纹的汇总数据并撰写分析段落，调用失败
时自动降级为模板报告。数据库只有单次扫描时不会展示虚构的“最近 7 天/30 天”报告。

在 Swagger 中可以使用 `POST /analysis/ip`，请求示例：

```json
{
  "ip": "1.2.3.4",
  "scan_round": null,
  "save_result": true
}
```

`scan_round` 为 `null` 时查询该 IP 的最近扫描批次。只能分析数据库中已经存在的 IP。

有限批量分析使用 `POST /analysis/batch`：

```json
{
  "ips": ["1.2.3.4", "1.2.3.5"],
  "scan_round": null
}
```

接口返回 `202` 和 `task_id`，随后用 `GET /analysis/tasks/{task_id}` 查询进度，完成后用
`GET /analysis/tasks/{task_id}/result` 获取各 IP 结果。批量只接受明确 IP 列表，不会展开
CIDR，也不会触发扫描。第一版任务在 FastAPI 进程内运行，服务重启会中断未完成任务。

批量任务完成后，通过以下接口生成并读取统计报告：

```text
POST /analysis/tasks/{task_id}/report
GET  /analysis/tasks/{task_id}/report
```

POST 第一次调用会把 JSON 报告保存到 `agent_report` 表，后续调用直接复用。统计过程不会
再次调用大模型，也不会产生额外 Token。

两个扫描批次的资产变化使用：

```http
GET /assets/1.2.3.4/changes?from_scan_round=1&to_scan_round=2
```

该接口只读取已有扫描数据和已保存分析结果。即使某个批次没有风险分析结果，也会继续
返回服务和产品变化，并在 `limitations` 中说明风险变化暂不可用。

自然语言问答可以在 Swagger 中使用 `POST /agent/chat`：

```json
{
  "question": "查询 1.2.3.4 开放了哪些服务",
  "scan_round": null,
  "conversation_id": null
}
```

`question` 为必填自然语言问题，长度为 1～2000 个字符；`scan_round` 为可选正整数，传
`null` 时读取该 IP 最近一次扫描批次。首次请求把 `conversation_id` 传 `null`，响应会
返回服务端生成的会话 ID；后续追问把该 ID 原样传回，即可省略已经确认的 IP、批次或任务 ID。

```json
{
  "question": "哪个资产需要优先处理？",
  "conversation_id": "首次响应返回的会话ID"
}
```

程序只在明确的追问中复用经过校验的上下文；问题中出现新的 IP、批次或任务 ID 时，以新参数
为准。调用 `DELETE /agent/conversations/{conversation_id}` 可以清除会话，`/chat` 页面中的
“新会话”按钮会自动执行该操作。

针对批量报告继续询问“哪个资产需要优先处理？”或“为什么？”时，响应中的
`priority_assets` 会按整体风险等级、疑似风险数量和 IP 稳定排序，包含暴露服务、产品和
排序原因。排序只依据已保存报告，不代表漏洞已经验证；失败或缺少结果的资产会单独提示补齐数据。

接口返回识别意图、模型来源、是否发生安全降级、LangGraph 节点执行轨迹、白名单工具
轨迹、结构化证据和数据限制。
创建分析任务必须使用“帮我分析 1.2.3.4”等明确表达。
历史变化可以询问“比较 1.2.3.4 扫描批次 1 和扫描批次 2 的变化”；批量报告可以询问
“查询批量任务 11 的统计报告”。程序会重新校验 IP、两个批次号和任务 ID，忽略模型
试图改写的工具参数。
也可以打开 `/chat` 使用简洁对话页面，并在右侧查看本轮工具调用和证据。
页面中的“LangGraph 工作流”会按执行顺序展示节点状态与耗时；黄色节点表示已安全降级。
当前 Checkpoint 使用进程内存保存，适合本地开发和演示；Uvicorn 重启后会话会清空，且不支持
多进程共享。生产部署应替换为持久化 Checkpointer，并将会话 ID 与登录用户绑定。

## 6. 切换到 DeepSeek

在 `.env` 中修改或增加：

```dotenv
AGENT_MODEL_PROVIDER=deepseek
AGENT_CHAT_PROVIDER=deepseek
DEEPSEEK_API_KEY=你的API密钥
DEEPSEEK_MODEL=deepseek-flash
```

保存后必须停止并重新启动 Uvicorn。真实模型调用会发送目标 IP 的已有指纹数据，
并消耗模型账户额度。更完整的说明见 [DeepSeek 接入说明](docs/DeepSeek接入说明.md)。

`AGENT_MODEL_PROVIDER` 控制资产分析模型，`AGENT_CHAT_PROVIDER` 控制自然语言问答；两者
可以独立配置。`AGENT_CHAT_PROVIDER` 未设置时会跟随前者，设置为 `rules` 可只使用规则
理解器和模板回答。

## 7. 运行测试

不要把测试文件作为普通脚本直接运行。请在项目根目录通过 pytest 执行：

```powershell
# 单个测试文件
python -m pytest agent_service/tests/test_analysis_validation.py -v

# Agent 完整测试
python -m pytest agent_service/tests -q
```

真实数据库 API 启动后，可以重复执行自然语言 Agent 端到端验收：

```powershell
python -m agent_service.scripts.verify_chat_e2e --base-url http://127.0.0.1:8002 --ip 数据库中已有的IP
```

错误示例：

```powershell
python agent_service/tests/test_analysis_validation.py
```

上述错误方式可能导致 `ModuleNotFoundError: No module named 'agent_service'`。

## 8. 常见问题

### 端口 8001 已被占用

如果出现 Windows 错误 `10048`，说明已经有程序占用 8001。可以继续使用已启动的服务，
或者把启动命令中的端口改成 `8002`，随后访问对应端口。

### 页面返回 500

先查看运行 Uvicorn 的终端中的完整异常。常见原因包括：

1. SSH 隧道没有运行；
2. `.env` 中数据库配置错误；
3. Agent 数据表尚未初始化；
4. DeepSeek 密钥、额度或返回 JSON 不符合约定。

### 数据库中查到 IP，但 API 提示没有数据

确认请求中的 `scan_round` 与数据库记录一致；不确定时先传 `null` 使用最近批次。

## 9. 当前 LangGraph 流程

```text
读取扫描数据
  → 检查已有结果
  → 创建任务
  → 模型分析
  → 校验事实和证据
      ├─ 通过：保存结果
      └─ 失败：携带错误重试一次
                 ├─ 通过：保存结果
                 └─ 仍失败：生成安全降级报告并保存
```

## 10. 文档维护要求

后续新增或修改以下内容时，必须同步更新本 README：

- 安装依赖；
- 环境变量；
- 数据库初始化或迁移；
- 启动命令和端口；
- API 验收步骤；
- 测试命令；
- 部署方式。

产品范围见 [产品设计方案](产品设计方案.md)，技术选型见 [技术栈方案](docs/技术栈方案.md)。
