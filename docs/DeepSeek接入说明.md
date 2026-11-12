# DeepSeek 接入与验收

在项目根目录 `.env` 中保留数据库配置，并添加：

```dotenv
AGENT_MODEL_PROVIDER=deepseek
AGENT_CHAT_PROVIDER=deepseek
DEEPSEEK_API_KEY="实际密钥"
DEEPSEEK_MODEL=deepseek-flash
```

重新启动 `python -m uvicorn agent_service.api.real_main:app --host 127.0.0.1 --port 8001`。
保持 SSH 隧道运行，访问 http://127.0.0.1:8001/，选择一个尚未保存分析结果的真实 IP。
密钥变动需要重启进程；`.env` 不提交 Git。

Provider 调用官方 HTTPS Chat Completions，启用 JSON Output，并用 Pydantic
校验输出。设置 90 秒超时、8192 输出 Token 上限，不自动重试以避免意外重复扣费。
HTTP 错误、超时、空输出、截断和结构校验失败会显示可读错误；不记录原始响应及密钥。
真实请求会把该 IP 的指纹数据发送给 DeepSeek，并消耗账户额度。

自然语言问答的 DeepSeek 接入包含三个阶段：

1. 把用户问题转换成结构化意图和目标 IP；
2. 使用原生 Tool Calls 从 `get_ip_scan_data`、`get_ip_analysis_result`、
   `create_ip_analysis` 三个白名单工具中选择一个；
3. 只根据程序执行后的工具事实、证据和限制生成自然语言回答。

模型返回的 IP、扫描批次和保存参数不会直接执行。程序会根据已校验的用户输入重新构造
工具参数，并强制限制最大调用次数为 2；未明确要求分析时，模型不能调用创建工具。
DeepSeek 任一步出现网络、结构或安全校验错误后，本轮剩余步骤使用规则理解器和模板回答，
API 响应中的 `fallback_used` 会变为 `true`，页面显示“已安全降级”。

当前数据库对 IP + scan_round 有唯一约束：匹配模型/Prompt 的结果继续复用；
模型或 Prompt 不匹配返回 HTTP 409，不覆盖历史 Mock 结果。
多模型并存需要后续迁移表约束；当前验收使用新 IP。

检查保存结果的 metadata.model_provider 应为 deepseek，model_name 为配置型号。
再次提交同一 IP 应复用结果。切回 Mock 时设置 AGENT_MODEL_PROVIDER=mock 并重启。

资产分析与自然语言问答均已完成 DeepSeek 适配；多节点 LangGraph、证据语义校验和
有限修正重试已经接入。异步任务查询仍属于后续开发内容。

官方参考：

- https://api-docs.deepseek.com/guides/json_mode/
- https://api-docs.deepseek.com/guides/tool_calls/
- https://api-docs.deepseek.com/api/create-chat-completion/
