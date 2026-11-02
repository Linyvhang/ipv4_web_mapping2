# DeepSeek 接入与验收

在项目根目录 `.env` 中保留数据库配置，并添加：

```dotenv
AGENT_MODEL_PROVIDER=deepseek
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

当前数据库对 IP + scan_round 有唯一约束：匹配模型/Prompt 的结果继续复用；
模型或 Prompt 不匹配返回 HTTP 409，不覆盖历史 Mock 结果。
多模型并存需要后续迁移表约束；当前验收使用新 IP。

检查保存结果的 metadata.model_provider 应为 deepseek，model_name 为配置型号。
再次提交同一 IP 应复用结果。切回 Mock 时设置 AGENT_MODEL_PROVIDER=mock 并重启。

此步骤完成模型适配和现有 Service 接入；多节点 LangGraph、证据语义校验、
有限修正重试与异步任务查询属于后续开发内容。

官方参考：https://api-docs.deepseek.com/guides/json_mode/
