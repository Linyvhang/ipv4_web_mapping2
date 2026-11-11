"""用于开发验收的单 IP 分析结果预览页。"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse


PREVIEW_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IPv4 资产分析预览</title>
  <style>
    :root { color-scheme: light; --bg:#f3f6fb; --card:#fff; --ink:#142033;
      --muted:#687386; --line:#dce3ee; --brand:#2563eb; --brand-soft:#eaf1ff;
      --success:#15803d; --success-soft:#eaf8ef; --danger:#b42318; --danger-soft:#fff0ee; }
    * { box-sizing: border-box; }
    body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.6 system-ui,
      -apple-system,"Segoe UI","Microsoft YaHei",sans-serif; }
    main { width:min(1080px, calc(100% - 32px)); margin:40px auto 72px; }
    h1 { margin:0; font-size:30px; }
    h2 { margin:0 0 14px; font-size:19px; }
    p { margin:8px 0; }
    .muted { color:var(--muted); }
    .card { margin-top:20px; padding:22px; border:1px solid var(--line);
      border-radius:14px; background:var(--card); box-shadow:0 8px 24px rgba(35,55,80,.06); }
    form { display:grid; grid-template-columns:minmax(220px,1fr) 160px auto; gap:12px; }
    input, button { min-height:44px; border-radius:9px; font:inherit; }
    input { width:100%; padding:9px 12px; border:1px solid #b9c4d4; }
    input:focus { outline:3px solid #dbeafe; border-color:var(--brand); }
    button { padding:9px 20px; border:0; background:var(--brand); color:white;
      font-weight:700; cursor:pointer; }
    button:disabled { opacity:.58; cursor:wait; }
    #status { min-height:25px; margin-top:12px; }
    .error { color:var(--danger); }
    .workflow-head { display:flex; justify-content:space-between; gap:16px;
      align-items:flex-start; margin-bottom:18px; }
    .workflow-badge { padding:4px 10px; border-radius:999px; color:#1647a8;
      background:var(--brand-soft); font-size:13px; font-weight:700; white-space:nowrap; }
    .steps { display:grid; grid-template-columns:repeat(6,minmax(0,1fr)); gap:10px; }
    .step { position:relative; min-height:108px; padding:14px 12px; border:1px solid var(--line);
      border-radius:12px; background:#f8fafc; transition:.2s ease; }
    .step-number { display:grid; place-items:center; width:28px; height:28px; margin-bottom:10px;
      border-radius:50%; background:#e5eaf2; color:#5f6c80; font-weight:800; font-size:13px; }
    .step strong { display:block; font-size:14px; }
    .step small { color:var(--muted); }
    .step.active { border-color:#7aa2f7; background:var(--brand-soft);
      box-shadow:0 0 0 3px rgba(37,99,235,.09); transform:translateY(-2px); }
    .step.active .step-number { background:var(--brand); color:white; }
    .step.completed { border-color:#b9dfc6; background:var(--success-soft); }
    .step.completed .step-number { background:var(--success); color:white; }
    .step.skipped { opacity:.55; }
    .step.failed { border-color:#f1b5ae; background:var(--danger-soft); }
    .step.failed .step-number { background:var(--danger); color:white; }
    .step.fallback { border-color:#f0cc82; background:#fff8e8; }
    .step.fallback .step-number { background:#b7791f; color:white; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:12px; }
    .metric { padding:14px; border-radius:10px; background:#f7f9fc; }
    .metric small { display:block; color:var(--muted); }
    .metric strong { font-size:17px; overflow-wrap:anywhere; }
    .tag { display:inline-block; margin:3px 6px 3px 0; padding:2px 9px;
      border-radius:999px; background:#e8efff; color:#1647a8; }
    .item { margin-top:10px; padding:14px; border-left:4px solid #93a4be;
      border-radius:6px; background:#f8fafc; }
    .risk-high, .risk-critical { border-left-color:#dc2626; }
    .risk-medium { border-left-color:#d97706; }
    pre { max-height:460px; overflow:auto; margin:0; padding:16px; border-radius:10px;
      background:#111827; color:#dbeafe; font:13px/1.5 ui-monospace,Consolas,monospace; }
    .hidden { display:none; }
    @media (max-width:850px) { .steps { grid-template-columns:1fr 1fr; } }
    @media (max-width:700px) { form { grid-template-columns:1fr; } main { margin-top:22px; }
      .steps { grid-template-columns:1fr; } .workflow-head { display:block; }
      .workflow-badge { display:inline-block; margin-top:8px; } }
  </style>
</head>
<body>
<main>
  <h1>IPv4 资产分析预览</h1>
  <p class="muted">读取已有扫描数据并展示标准 JSON 分析结果。当前模型类型以返回结果为准。</p>

  <section class="card">
    <form id="analysis-form">
      <input id="ip" name="ip" value="1.12.69.71" aria-label="IPv4 地址"
        placeholder="输入 IPv4，例如 1.12.69.71" required>
      <input id="scan-round" name="scan_round" type="number" min="1"
        aria-label="扫描批次" placeholder="扫描批次（默认最新）">
      <button id="submit" type="submit">开始分析</button>
    </form>
    <div id="status" class="muted" aria-live="polite">等待提交分析任务</div>
  </section>

  <section id="workflow" class="card hidden" aria-label="LangGraph 执行进度">
    <div class="workflow-head">
      <div>
        <h2>LangGraph 分析进度</h2>
        <p class="muted">页面根据后端节点事件实时更新，不使用模拟进度。</p>
      </div>
      <span id="workflow-badge" class="workflow-badge">准备执行</span>
    </div>
    <div class="steps" id="workflow-steps">
      <div class="step" data-node="load_asset"><span class="step-number">1</span>
        <strong>读取扫描数据</strong><small>读取指定 IP 的最新指纹</small></div>
      <div class="step" data-node="check_cache"><span class="step-number">2</span>
        <strong>检查已有结果</strong><small>避免重复调用模型</small></div>
      <div class="step" data-node="create_task"><span class="step-number">3</span>
        <strong>创建分析任务</strong><small>记录任务和运行状态</small></div>
      <div class="step" data-node="analyze_asset"><span class="step-number">4</span>
        <strong>模型分析资产</strong><small>生成画像、风险和建议</small></div>
      <div class="step" data-node="validate_analysis"><span class="step-number">5</span>
        <strong>校验分析证据</strong><small>检查事实、证据和风险表述</small></div>
      <div class="step" data-node="persist_result"><span class="step-number">6</span>
        <strong>保存分析结果</strong><small>持久化标准 JSON 报告</small></div>
    </div>
  </section>

  <div id="result" class="hidden">
    <section class="card">
      <h2>普通用户摘要</h2>
      <div id="summary" class="grid"></div>
      <p id="description"></p>
    </section>
    <section class="card">
      <h2>已发现服务</h2>
      <div id="services"></div>
    </section>
    <section class="card">
      <h2>风险提示</h2>
      <div id="risks"></div>
    </section>
    <section class="card">
      <h2>建议与限制</h2>
      <div id="recommendations"></div>
      <div id="limitations"></div>
    </section>
    <section class="card">
      <h2>完整标准 JSON</h2>
      <pre id="raw-json"></pre>
    </section>
  </div>
</main>
<script>
  const form = document.querySelector('#analysis-form');
  const statusBox = document.querySelector('#status');
  const resultBox = document.querySelector('#result');
  const submitButton = document.querySelector('#submit');
  const workflowBox = document.querySelector('#workflow');
  const workflowBadge = document.querySelector('#workflow-badge');
  const orderedNodes = ['load_asset', 'check_cache', 'create_task', 'analyze_asset', 'validate_analysis', 'persist_result'];
  let activeNode = null;
  let retryCount = 0;

  function clearAndText(element, text) {
    element.replaceChildren(document.createTextNode(text));
  }
  function metric(label, value) {
    const box = document.createElement('div'); box.className = 'metric';
    const small = document.createElement('small'); small.textContent = label;
    const strong = document.createElement('strong'); strong.textContent = value ?? '未知';
    box.append(small, strong); return box;
  }
  function showEmpty(element, text) { clearAndText(element, text); element.className = 'muted'; }
  function stepElement(node) { return document.querySelector(`.step[data-node="${node}"]`); }
  function resetWorkflow() {
    workflowBox.classList.remove('hidden'); workflowBadge.textContent = '正在启动';
    activeNode = 'load_asset';
    retryCount = 0;
    for (const node of orderedNodes) stepElement(node).className = 'step';
    stepElement(activeNode).classList.add('active');
  }
  function setNextActive(node) {
    const index = orderedNodes.indexOf(node);
    activeNode = index >= 0 && index + 1 < orderedNodes.length ? orderedNodes[index + 1] : null;
    if (activeNode) stepElement(activeNode).classList.add('active');
  }
  function completeNode(node) {
    if (node === 'return_cached') {
      for (const skipped of orderedNodes.slice(2)) stepElement(skipped).className = 'step skipped';
      activeNode = null; workflowBadge.textContent = '已复用结果'; return;
    }
    if (node === 'prepare_retry') {
      retryCount += 1;
      stepElement('analyze_asset').className = 'step active';
      stepElement('validate_analysis').className = 'step';
      stepElement('persist_result').className = 'step';
      activeNode = 'analyze_asset'; workflowBadge.textContent = `校验未通过，重试 ${retryCount}/1`;
      return;
    }
    if (node === 'build_fallback') {
      stepElement('validate_analysis').className = 'step fallback';
      workflowBadge.textContent = '已生成安全降级结果'; return;
    }
    const step = stepElement(node); if (!step) return;
    step.className = 'step completed'; workflowBadge.textContent = step.querySelector('strong').textContent;
    setNextActive(node);
  }
  function failActiveStep() {
    if (activeNode && stepElement(activeNode)) stepElement(activeNode).className = 'step failed';
    workflowBadge.textContent = '执行失败';
  }
  function render(response) {
    const data = response.result || {};
    const summary = data.summary || {};
    const summaryBox = document.querySelector('#summary');
    summaryBox.replaceChildren(
      metric('IP 地址', data.ip), metric('扫描批次', data.scan_round),
      metric('资产类型', summary.primary_asset_type), metric('风险等级', summary.risk_level),
      metric('置信度', summary.confidence == null ? '未知' : `${Math.round(summary.confidence * 100)}%`),
      metric('任务结果', response.reused ? '复用已有结果' : `新任务 #${response.task_id ?? '-'}`)
    );
    clearAndText(document.querySelector('#description'), summary.description || '暂无摘要');

    const servicesBox = document.querySelector('#services'); servicesBox.replaceChildren();
    if (!(data.services || []).length) showEmpty(servicesBox, '当前分析结果没有返回服务详情。');
    for (const service of data.services || []) {
      const item = document.createElement('div'); item.className = 'item';
      const product = service.product || {};
      const name = product.normalized_product_name || product.raw_product_name || '未知产品';
      const version = product.normalized_version || product.raw_version || '版本未知';
      item.textContent = `${service.port}/${service.transport_protocol} · ${service.service_type} · ${name} ${version}`;
      if (service.banner) { const detail = document.createElement('p'); detail.className='muted'; detail.textContent=service.banner; item.append(detail); }
      servicesBox.append(item);
    }

    const risksBox = document.querySelector('#risks'); risksBox.replaceChildren();
    if (!(data.risks || []).length) showEmpty(risksBox, '当前没有模型返回的风险提示。');
    for (const risk of data.risks || []) {
      const item = document.createElement('div'); item.className = `item risk-${risk.level}`;
      const title = document.createElement('strong'); title.textContent = `[${risk.level}] ${risk.title}`;
      const detail = document.createElement('p'); detail.textContent = risk.description;
      item.append(title, detail); risksBox.append(item);
    }

    const recBox = document.querySelector('#recommendations'); recBox.replaceChildren();
    if (!(data.recommendations || []).length) showEmpty(recBox, '暂无处置建议。');
    for (const rec of data.recommendations || []) {
      const item = document.createElement('div'); item.className='item';
      item.textContent = `${rec.title}：${rec.description}`; recBox.append(item);
    }
    const limitsBox = document.querySelector('#limitations'); limitsBox.replaceChildren();
    for (const limit of data.limitations || []) { const tag=document.createElement('span'); tag.className='tag'; tag.textContent=limit; limitsBox.append(tag); }
    clearAndText(document.querySelector('#raw-json'), JSON.stringify(response, null, 2));
    resultBox.classList.remove('hidden');
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault(); submitButton.disabled = true; resultBox.classList.add('hidden');
    resetWorkflow(); statusBox.className = 'muted'; statusBox.textContent = '正在启动 LangGraph 分析流程…';
    const roundValue = document.querySelector('#scan-round').value.trim();
    const payload = { ip: document.querySelector('#ip').value.trim(),
      scan_round: roundValue ? Number(roundValue) : null, save_result: true };
    try {
      const response = await fetch('/analysis/ip/stream', { method:'POST',
        headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) });
      if (!response.ok || !response.body) throw new Error(`请求失败（HTTP ${response.status}）`);
      const reader = response.body.getReader(); const decoder = new TextDecoder(); let buffer = '';
      let finalResponse = null;
      while (true) {
        const {value, done} = await reader.read(); buffer += decoder.decode(value || new Uint8Array(), {stream: !done});
        const lines = buffer.split('\\n'); buffer = lines.pop() || '';
        for (const line of lines) {
          if (!line.trim()) continue;
          const message = JSON.parse(line);
          if (message.type === 'node') {
            completeNode(message.node); statusBox.textContent = `${message.label}已完成`;
          } else if (message.type === 'result') {
            finalResponse = message.data;
          } else if (message.type === 'error') {
            throw new Error(message.detail || `分析失败（${message.status_code}）`);
          }
        }
        if (done) break;
      }
      if (!finalResponse) throw new Error('分析流程没有返回结果');
      render(finalResponse); workflowBadge.textContent = finalResponse.reused ? '已复用结果' : '分析完成';
      statusBox.textContent = finalResponse.reused ? '已加载保存过的分析结果。' : '分析完成，结果已保存。';
    } catch (error) {
      failActiveStep(); statusBox.className = 'error'; statusBox.textContent = error.message || '分析失败';
    } finally { submitButton.disabled = false; }
  });
</script>
</body>
</html>"""


def create_preview_router() -> APIRouter:
    """创建无需额外前端构建步骤的预览页面路由。"""

    router = APIRouter(include_in_schema=False)

    @router.get("/", response_class=HTMLResponse)
    @router.get("/preview", response_class=HTMLResponse)
    def preview() -> HTMLResponse:
        return HTMLResponse(PREVIEW_HTML)

    return router
