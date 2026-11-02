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
    :root { color-scheme: light; --bg:#f4f7fb; --card:#fff; --ink:#172033;
      --muted:#687386; --line:#dce3ee; --brand:#2563eb; --danger:#b42318; }
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
    @media (max-width:700px) { form { grid-template-columns:1fr; } main { margin-top:22px; } }
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
    statusBox.className = 'muted'; statusBox.textContent = '正在读取扫描数据并分析…';
    const roundValue = document.querySelector('#scan-round').value.trim();
    const payload = { ip: document.querySelector('#ip').value.trim(),
      scan_round: roundValue ? Number(roundValue) : null, save_result: true };
    try {
      const response = await fetch('/analysis/ip', { method:'POST',
        headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.detail || `请求失败（HTTP ${response.status}）`);
      render(body); statusBox.textContent = body.reused ? '已加载保存过的分析结果。' : '分析完成，结果已保存。';
    } catch (error) {
      statusBox.className = 'error'; statusBox.textContent = error.message || '分析失败';
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
