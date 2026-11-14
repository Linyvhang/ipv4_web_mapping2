# 自然语言资产分析 Agent 设计方案

## 1. 文档目的

本文档确定自然语言 Agent 第一版的角色、权限、工作流、数据契约和验收标准，
作为后续数据模型、LangGraph、API 与可视化开发的共同依据。

当前状态：**设计、数据模型、安全校验、多节点 LangGraph、`POST /agent/chat` API、
工具轨迹预览页、DeepSeek 自然语言能力、节点级可观测性、历史批次对比、批量报告查询和
基于 Checkpoint 的安全多轮追问均已完成**。

## 2. 角色定位

角色名称：**IPv4 网络资产分析助手**。

Agent 面向技术人员和普通用户，负责：

- 理解用户对已有扫描数据的查询或分析要求；
- 查询指定 IP 的端口、服务、产品、版本和 L3 指纹；
- 查询已经保存且通过校验的资产分析结果；
- 用户明确要求时，基于已有扫描数据创建分析任务；
- 比较同一 IP 两个有效扫描批次的变化；
- 按任务 ID 查询已保存的批量统计报告；
- 先给出容易理解的结论，再补充技术证据和数据限制。

Agent 不是扫描器、漏洞验证器或数据库管理工具。

## 3. 第一版范围

第一版支持：

1. 单轮问答和同一会话内的多轮追问；
2. 单个 IPv4 地址；
3. 查询已有扫描数据；
4. 查询已有分析结果；
5. 用户明确要求时创建单 IP 分析；
6. 解释已保存结果中的风险和证据；
7. 对禁止操作和信息不足给出明确说明；
8. 返回自然语言回答、工具记录和结构化证据；
9. 查询历史批次变化和批量统计报告；
10. 使用会话 Checkpoint 复用已经验证的 IP、扫描批次或任务 ID。
11. 基于批量报告事实回答资产处置优先级及原因。

第一版暂不支持：

- 一次查询多个 IP；
- 全网段统计问答；
- 任意 SQL；
- 多 IP 历史批次对比；
- 用户登录和权限系统；
- 主动扫描、爆破、漏洞利用或弱口令测试。

## 4. 权限与安全边界

### 4.1 允许的行为

- 读取已有扫描数据；
- 读取已保存的分析结果；
- 使用五个已注册的白名单工具；
- 基于工具结果组织回答；
- 用户明确要求分析时创建受控分析任务；
- 证据不足时回答“信息不足，无法判断”。

### 4.2 禁止的行为

- 生成或执行任意 SQL；
- 直接访问模型未被授权的数据表；
- 修改或删除扫描数据；
- 主动扫描 IP、端口或服务；
- 执行漏洞利用、爆破或弱口令测试；
- 未经用户明确要求自动创建分析任务；
- 把疑似风险描述成已确认漏洞；
- 根据常识补写数据库中不存在的服务或证据。

安全边界由程序强制执行，不能只依赖 Prompt。

## 5. 第一版用户意图

| 意图 | 示例 | 默认处理 |
| --- | --- | --- |
| `query_scan_data` | “1.2.3.4 开放了哪些服务？” | 调用 `get_ip_scan_data` |
| `query_analysis_result` | “1.2.3.4 有哪些风险？” | 调用 `get_ip_analysis_result` |
| `create_analysis` | “帮我分析 1.2.3.4” | 明确授权后调用 `create_ip_analysis` |
| `explain_result` | “为什么它被判断为低风险？” | 查询保存结果并根据证据解释 |
| `compare_scan_rounds` | “比较 1.2.3.4 批次 1 和批次 2” | 调用 `compare_ip_scan_rounds` |
| `query_batch_report` | “查询批量任务 11 的统计报告” | 调用 `get_batch_report` |
| `unsupported` | “帮我扫描或攻击这个 IP” | 拒绝，不调用工具 |
| `missing_target` | “这个 IP 有什么服务？”但没有 IP | 提示用户补充 IPv4 地址 |

对于“查询风险”但没有已保存分析结果的情况，Agent 只能说明当前没有结果并建议用户
明确提出创建分析；不能在本轮中静默创建任务。

## 6. 白名单工具

当前只能选择已经实现的五个工具：

### `get_ip_scan_data`

- 性质：只读；
- 输入：IPv4、可选扫描批次；
- 输出：已有扫描批次、服务和 L3 指纹；
- 不会触发新扫描。

### `get_ip_analysis_result`

- 性质：只读；
- 输入：IPv4、可选扫描批次；
- 输出：已保存且符合标准 Schema 的分析结果；
- 不重新调用模型。

### `create_ip_analysis`

- 性质：受控写入任务和结果；
- 输入：IPv4、可选扫描批次、是否保存结果；
- 前提：用户明确要求创建分析；
- 执行：复用既有单 IP LangGraph；
- 不会执行主动扫描或主动测试。

### `compare_ip_scan_rounds`

- 性质：只读；
- 输入：IPv4、起始扫描批次和目标扫描批次；
- 输出：服务新增/消失、产品版本变化和风险变化；
- 程序会重新校验 IP 和两个批次号。

### `get_batch_report`

- 性质：只读；
- 输入：批量任务 ID；
- 输出：已经保存的批量统计 JSON 报告；
- 不生成新报告，不调用模型分析资产。

任何未注册工具，包括 `run_sql`，都必须被程序拒绝。

## 7. LangGraph 工作流程

```text
START
  ↓
understand_question
  ↓
validate_request
  ├─ 缺少 IP ──────────────→ compose_answer → END
  ├─ 禁止操作 ─────────────→ reject_unsupported_request → END
  └─ 合法请求
       ↓
select_tool
  ↓
execute_tool
  ↓
evaluate_result
  ├─ 结果足够 ─────────────→ compose_answer → END
  ├─ 没有数据/结果 ─────────→ compose_answer → END
  ├─ 允许且需要第二个工具 ──→ select_tool
  └─ 达到调用上限 ─────────→ compose_answer → END
```

### 7.1 节点职责

#### `understand_question`

- 提取 IPv4；
- 提取两个扫描批次或批量任务 ID；
- 分类用户意图；
- 判断用户是否明确要求创建分析；
- 不访问数据库。

当请求携带有效 `conversation_id` 且问题属于明确追问时，本节点之后的上下文解析会复用
Checkpoint 中已经验证的 IP、两个扫描批次或批量任务 ID。问题中出现新的显式标识时，禁止
用旧上下文覆盖。

#### `validate_request`

- 验证 IPv4 格式；
- 验证批次号、任务 ID 与原问题一致；
- 检测扫描、爆破、漏洞利用等禁止意图；
- 缺少必要参数时生成可解释错误；
- 程序规则优先于模型判断。

#### `select_tool`

- 只从白名单选择工具；
- 生成结构化工具参数；
- `create_ip_analysis` 必须携带显式授权；
- 已经达到调用次数上限时不能继续选择。

#### `execute_tool`

- 通过 `AssetAgentToolRegistry` 校验并执行；
- 保存工具名称、参数摘要、状态和返回数据；
- 不接受 SQL 或数据库表名。

#### `evaluate_result`

- 判断工具结果是 `success` 还是 `not_found`；
- 判断现有信息是否足够回答；
- 最多允许调用两个工具，防止循环和意外 Token 消耗。

#### `compose_answer`

- 先输出普通用户摘要；
- 再输出端口、服务、产品、版本或风险证据；
- 不修改工具返回的事实；
- 必须说明数据来自已有扫描，且扫描范围有限。
- 批量报告追问使用确定性规则生成 `priority_assets`，模型只能组织表达，不能修改排序事实。

#### `reject_unsupported_request`

- 拒绝主动扫描、攻击、爆破和漏洞利用请求；
- 说明 Agent 只能分析已有数据；
- 不调用任何工具。

## 8. 状态设计

第一版 LangGraph State 计划包含：

```text
question                 原始用户问题
conversation_id          LangGraph thread_id；首次请求由服务端生成
context_reused           本轮是否复用了经过验证的会话上下文
scan_round               用户指定的扫描批次，可为空
from_scan_round          历史对比起始批次，可为空
to_scan_round            历史对比目标批次，可为空
task_id                  批量报告任务 ID，可为空
intent                   结构化用户意图
target_ip                提取到的 IPv4，可为空
explicit_analysis_request 是否明确要求创建分析
request_error            请求校验错误，可为空
selected_tool            当前选择的工具，可为空
tool_arguments           已校验或待校验的工具参数
tool_history             工具调用记录
tool_call_count          已调用工具次数
max_tool_calls           最大工具调用次数，固定为 2
answer                   最终自然语言回答
evidence                 供 API/可视化使用的结构化证据
limitations              数据和能力限制
workflow_trace           节点顺序、状态、耗时、工具和降级原因
```

State 保存原始事实和结构化结果，不保存已经拼接完成的 Prompt。

### 8.1 Checkpoint 与会话生命周期

- FastAPI 为每个首次请求生成不可预测的会话 ID，并作为 LangGraph `thread_id`；
- Checkpoint 保存图状态，后续请求只抽取经过程序验证的上下文字段；
- 客户端通过 `DELETE /agent/conversations/{conversation_id}` 主动结束会话；
- 第一版使用 `InMemorySaver`，进程重启后自动清空，且不支持多 Worker 共享；
- 当前版本面向本地开发，未实现用户身份系统。生产环境必须使用持久化 Checkpointer，并把
  会话所有权绑定到经过认证的用户，防止跨用户读取上下文。

### 8.2 可观测性边界

`workflow_trace` 记录本轮实际执行过的节点，而不是静态流程图。每项包含执行顺序、节点、
状态、脱敏决策摘要、毫秒耗时、可选工具名和安全降级原因。轨迹不保存 API Key、数据库
密码、数据库连接信息、完整 Prompt、模型原始响应或模型内部思维过程。

## 9. 模型与程序的职责

### 程序负责

- IPv4 格式验证；
- 扫描批次和任务 ID 验证；
- 明确禁止操作；
- 工具白名单和参数 Schema；
- 创建任务的授权判断；
- 最大工具调用次数；
- 工具执行和数据库访问；
- 工具返回事实的结构化保存。

### 模型负责

- 理解自然语言表达；
- 在允许范围内识别意图；
- 从白名单中选择合适工具；
- 把工具事实组织成面向用户的回答；
- 解释已有分析结果中的风险和证据。

规则模式用于离线开发和安全降级；DeepSeek 模式负责灵活理解、原生工具选择和自然回答。
只要模型任一步失败，本轮后续步骤就停止调用模型并切换到规则和模板，避免重复消耗。

## 10. 返回数据契约

计划中的标准返回结构：

```json
{
  "answer": "该 IP 发现 SSH 服务，产品指纹为 OpenSSH 9.2。",
  "intent": "query_scan_data",
  "target_ip": "1.2.3.4",
  "status": "success",
  "model_provider": "deepseek",
  "fallback_used": false,
  "workflow_trace": [
    {
      "sequence": 1,
      "node": "understand_question",
      "status": "success",
      "detail": "识别意图：query_scan_data",
      "duration_ms": 842.31,
      "tool_name": null,
      "fallback_reason": null
    }
  ],
  "tools_used": [
    {
      "name": "get_ip_scan_data",
      "status": "success"
    }
  ],
  "evidence": [
    {
      "source": "service_fingerprint",
      "port": 22,
      "service_type": "ssh",
      "product": "OpenSSH",
      "version": "9.2"
    }
  ],
  "limitations": [
    "回答仅基于已有扫描数据",
    "当前扫描只覆盖指定常用端口"
  ]
}
```

自然语言回答用于阅读；`tools_used` 和 `evidence` 用于审计、测试和可视化。
`workflow_trace` 用于观察 LangGraph 的真实执行路径与各节点耗时，不包含密钥、数据库密码
或模型原始思维过程。

## 11. 异常与分支处理

| 情况 | 处理方式 |
| --- | --- |
| 没有 IPv4 | 提示用户补充，不调用工具 |
| IPv4 格式错误 | 返回参数错误，不访问数据库 |
| 数据库没有该 IP | 返回 `not_found`，明确说明没有已有扫描数据 |
| 没有保存的分析结果 | 说明尚无结果，建议用户明确要求创建分析 |
| 用户要求主动扫描 | 拒绝并说明能力边界 |
| 模型选择未知工具 | 程序拒绝并记录错误 |
| 未授权创建分析 | 程序拒绝 `create_ip_analysis` |
| 工具调用达到 2 次 | 停止循环，用已有信息回答 |
| 模型生成回答失败 | 使用程序模板返回工具事实和限制 |

## 12. 第一版验收标准

1. 能从常见中文问题中提取一个 IPv4；
2. 能区分扫描数据查询、结果查询、创建分析和禁止请求；
3. 能选择并执行正确的白名单工具；
4. 未明确要求时不会创建分析任务；
5. 禁止请求不会调用任何工具；
6. 工具调用次数不超过两次；
7. 回答包含结构化工具记录和证据；
8. 没有数据时不编造结果；
9. Mock 决策器测试稳定、无需真实数据库和模型 API；
10. 相同会话 ID 能安全追问，显式新参数不会被旧上下文覆盖；
11. 删除会话后不能继续复用旧参数；
12. 完整测试通过并创建对应 Git commit。

## 13. 分阶段开发顺序

1. 定义意图、State、工具调用记录和回答 Schema；
2. 实现请求验证、规则安全边界和 Mock 决策器；
3. 实现六节点 LangGraph 和条件路由；
4. 为正常、缺失数据、禁止请求和调用上限编写测试；
5. 增加 `POST /agent/chat` API；
6. 增加简洁对话与工具轨迹页面；
7. 接入 DeepSeek 工具选择和回答生成；
8. 使用真实云端扫描数据完成验收。
9. 增加 LangGraph Checkpoint、多轮追问和会话清理接口。
