"""自然语言资产分析 Agent 的本地对话预览页。"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse


CHAT_PREVIEW_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IPv4 资产分析助手</title>
  <style>
    :root { color-scheme:light; --bg:#eef3f9; --panel:#fff; --ink:#122033;
      --muted:#65748a; --line:#dce5f0; --brand:#225ee6; --brand-dark:#1747b5;
      --brand-soft:#eaf1ff; --success:#147a45; --success-soft:#eaf8f0;
      --warn:#a15c05; --warn-soft:#fff7e7; --danger:#b42318; --shadow:0 18px 50px rgba(26,47,76,.09); }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; background:
      radial-gradient(circle at 12% 0%, #dfeaff 0, transparent 34%), var(--bg);
      color:var(--ink); font:15px/1.65 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif; }
    button,input { font:inherit; }
    .shell { width:min(1180px,calc(100% - 32px)); margin:0 auto; padding:28px 0 64px; }
    nav { display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:24px; }
    .brand { display:flex; align-items:center; gap:10px; font-weight:800; }
    .brand-mark { display:grid; place-items:center; width:36px; height:36px; border-radius:11px;
      background:linear-gradient(135deg,var(--brand),#6c8fff); color:white; box-shadow:0 8px 20px #b8caff; }
    .nav-links { display:flex; gap:8px; }
    .nav-links a { padding:7px 12px; border-radius:9px; color:var(--muted); text-decoration:none; }
    .nav-links a[aria-current="page"] { background:white; color:var(--brand-dark); font-weight:700; }
    header { display:flex; justify-content:space-between; align-items:flex-end; gap:24px; margin-bottom:20px; }
    h1 { margin:0; font-size:clamp(28px,4vw,46px); letter-spacing:-.035em; line-height:1.15; }
    header p { max-width:720px; margin:10px 0 0; color:var(--muted); font-size:16px; }
    .mode { flex:none; padding:7px 12px; border:1px solid #bdd0fa; border-radius:999px;
      color:var(--brand-dark); background:var(--brand-soft); font-weight:700; font-size:13px; }
    .layout { display:grid; grid-template-columns:minmax(0,1.55fr) minmax(300px,.8fr); gap:18px; align-items:start; }
    .panel { border:1px solid rgba(207,219,233,.9); border-radius:20px; background:rgba(255,255,255,.94);
      box-shadow:var(--shadow); overflow:hidden; }
    .conversation { min-height:560px; display:flex; flex-direction:column; }
    .messages { flex:1; min-height:360px; max-height:590px; overflow:auto; padding:24px; }
    .message { display:flex; gap:11px; margin-bottom:18px; animation:rise .22s ease-out; }
    .message.user { justify-content:flex-end; }
    .avatar { flex:0 0 32px; display:grid; place-items:center; width:32px; height:32px; border-radius:10px;
      background:var(--brand-soft); color:var(--brand-dark); font-size:12px; font-weight:800; }
    .bubble { max-width:min(82%,680px); padding:12px 15px; border:1px solid var(--line); border-radius:5px 16px 16px;
      background:#f8fafc; white-space:pre-wrap; overflow-wrap:anywhere; }
    .user .bubble { order:-1; color:white; border-color:var(--brand); border-radius:16px 5px 16px 16px;
      background:linear-gradient(135deg,var(--brand),#477cf1); }
    .composer { padding:18px; border-top:1px solid var(--line); background:#fbfcfe; }
    .examples { display:flex; gap:7px; overflow:auto; padding-bottom:10px; }
    .example { flex:none; padding:5px 10px; border:1px solid var(--line); border-radius:999px; color:var(--muted);
      background:white; cursor:pointer; font-size:12px; }
    form { display:grid; grid-template-columns:minmax(0,1fr) 112px auto; gap:9px; }
    input { min-width:0; height:46px; padding:10px 13px; border:1px solid #b8c5d6; border-radius:11px; background:white; }
    input:focus { outline:3px solid #dce8ff; border-color:var(--brand); }
    #send { min-width:96px; padding:0 18px; border:0; border-radius:11px; background:var(--brand);
      color:white; font-weight:800; cursor:pointer; }
    #send:hover { background:var(--brand-dark); }
    #send:disabled { opacity:.58; cursor:wait; }
    .side { display:grid; gap:18px; }
    .side section { padding:20px; }
    h2 { margin:0 0 14px; font-size:17px; }
    .empty { color:var(--muted); padding:18px 0; }
    .meta { display:flex; flex-wrap:wrap; gap:7px; margin-bottom:14px; }
    .badge { padding:4px 9px; border-radius:999px; background:#f0f3f8; color:#526278; font-size:12px; font-weight:700; }
    .badge.success { background:var(--success-soft); color:var(--success); }
    .badge.not_found,.badge.invalid_request { background:var(--warn-soft); color:var(--warn); }
    .badge.failed,.badge.unsupported { background:#fff0ee; color:var(--danger); }
    .tool { position:relative; margin:0 0 12px 7px; padding:0 0 12px 20px; border-left:2px solid #d7e1ef; }
    .tool:last-child { padding-bottom:0; }
    .tool::before { content:""; position:absolute; left:-6px; top:4px; width:10px; height:10px; border-radius:50%;
      background:var(--brand); box-shadow:0 0 0 4px var(--brand-soft); }
    .tool strong { display:block; font-size:13px; overflow-wrap:anywhere; }
    .tool small { color:var(--muted); }
    .flow-step { display:grid; grid-template-columns:30px 1fr auto; gap:10px; align-items:start;
      position:relative; padding:10px 0; }
    .flow-step:not(:last-child)::after { content:""; position:absolute; left:14px; top:39px; bottom:-7px;
      width:2px; background:#dbe5f2; }
    .step-index { display:grid; place-items:center; width:30px; height:30px; border-radius:10px;
      color:var(--brand-dark); background:var(--brand-soft); font-size:12px; font-weight:800; z-index:1; }
    .flow-step.fallback .step-index { color:var(--warn); background:var(--warn-soft); }
    .flow-step.failed .step-index,.flow-step.denied .step-index { color:var(--danger); background:#fff0ee; }
    .step-body strong,.step-body small { display:block; overflow-wrap:anywhere; }
    .step-body small { color:var(--muted); }
    .duration { color:#718198; font-size:11px; white-space:nowrap; }
    .evidence { padding:11px 12px; margin-bottom:9px; border:1px solid var(--line); border-radius:11px; background:#f9fbfd; }
    .evidence strong { display:block; font-size:13px; }
    .evidence small { display:block; color:var(--muted); overflow-wrap:anywhere; }
    .limits { margin:14px 0 0; padding:12px 14px; border-radius:11px; background:var(--warn-soft); color:#815015; font-size:12px; }
    .limits ul { margin:5px 0 0; padding-left:18px; }
    @keyframes rise { from { opacity:0; transform:translateY(5px); } }
    @media (max-width:900px) { .layout { grid-template-columns:1fr; } .side { grid-template-columns:1fr 1fr; }
      .conversation { min-height:500px; } }
    @media (max-width:660px) { .shell { width:min(100% - 20px,1180px); padding-top:16px; }
      nav,header { align-items:flex-start; } header { display:block; } .mode { display:inline-block; margin-top:12px; }
      .brand span:last-child { display:none; } .nav-links { font-size:13px; }
      form { grid-template-columns:1fr 92px; } #question { grid-column:1/-1; }
      .side { grid-template-columns:1fr; } .messages { padding:17px; } .bubble { max-width:88%; } }
  </style>
</head>
<body>
<div class="shell">
  <nav>
    <div class="brand"><span class="brand-mark">IP</span><span>IPv4 Web Mapping</span></div>
    <div class="nav-links"><a href="/">资产分析</a><a href="/chat" aria-current="page">智能问答</a><a href="/docs">API 文档</a></div>
  </nav>
  <header>
    <div><h1>网络资产分析助手</h1><p>用自然语言查询已有扫描指纹和分析结果。Agent 只调用受控工具，不会主动扫描或测试目标。</p></div>
    <span class="mode">单轮问答 · 工具可追踪</span>
  </header>
  <div class="layout">
    <section class="panel conversation" aria-label="对话区域">
      <div id="messages" class="messages" aria-live="polite">
        <div class="message assistant"><div class="avatar">AI</div><div class="bubble">你好，我可以查询单个 IPv4 的已有服务指纹、分析结果，或在你明确要求时创建分析任务。</div></div>
      </div>
      <div class="composer">
        <div class="examples" aria-label="示例问题">
          <button class="example" type="button">查询 192.0.2.10 开放了哪些服务</button>
          <button class="example" type="button">192.0.2.10 有哪些风险</button>
          <button class="example" type="button">帮我分析 192.0.2.10</button>
        </div>
        <form id="chat-form">
          <input id="question" aria-label="问题" maxlength="2000" placeholder="输入问题，例如：1.2.3.4 开放了哪些服务？" required>
          <input id="scan-round" type="number" min="1" aria-label="扫描批次" placeholder="批次">
          <button id="send" type="submit">发送</button>
        </form>
      </div>
    </section>
    <aside class="side" aria-label="Agent 执行详情">
      <section class="panel"><h2>本轮状态</h2><div id="meta" class="meta"><span class="badge">等待提问</span></div>
        <div id="limitations" class="limits">回答将明确展示数据范围和能力限制。</div></section>
      <section class="panel"><h2>LangGraph 工作流</h2><div id="workflow" class="empty">回答后显示节点执行轨迹</div></section>
      <section class="panel"><h2>工具调用轨迹</h2><div id="tools" class="empty">尚未调用工具</div></section>
      <section class="panel"><h2>引用证据</h2><div id="evidence" class="empty">回答后显示结构化证据</div></section>
    </aside>
  </div>
</div>
<script>
  const form = document.querySelector('#chat-form');
  const questionInput = document.querySelector('#question');
  const roundInput = document.querySelector('#scan-round');
  const sendButton = document.querySelector('#send');
  const messages = document.querySelector('#messages');
  const meta = document.querySelector('#meta');
  const workflow = document.querySelector('#workflow');
  const tools = document.querySelector('#tools');
  const evidence = document.querySelector('#evidence');
  const limitations = document.querySelector('#limitations');

  function textElement(tag, text, className) {
    const element = document.createElement(tag); element.textContent = text;
    if (className) element.className = className; return element;
  }
  function addMessage(role, text) {
    const row = textElement('div', '', `message ${role}`);
    const avatar = textElement('div', role === 'user' ? '你' : 'AI', 'avatar');
    const bubble = textElement('div', text, 'bubble'); row.append(avatar, bubble);
    messages.append(row); messages.scrollTop = messages.scrollHeight;
  }
  function showMeta(data) {
    meta.replaceChildren();
    meta.append(textElement('span', data.status, `badge ${data.status}`));
    meta.append(textElement('span', data.intent, 'badge'));
    if (data.target_ip) meta.append(textElement('span', data.target_ip, 'badge'));
    meta.append(textElement('span', `模型：${data.model_provider || 'rules'}`, 'badge'));
    if (data.fallback_used) meta.append(textElement('span', '已安全降级', 'badge not_found'));
  }
  function showTools(items) {
    tools.replaceChildren(); tools.className = '';
    if (!items.length) { tools.className='empty'; tools.textContent='本轮没有调用工具'; return; }
    for (const item of items) {
      const box = textElement('div', '', 'tool');
      box.append(textElement('strong', item.name), textElement('small', `${item.status} · ${item.message || '已执行'}`));
      tools.append(box);
    }
  }
  function showWorkflow(items) {
    workflow.replaceChildren(); workflow.className = '';
    if (!items.length) { workflow.className='empty'; workflow.textContent='本轮没有工作流轨迹'; return; }
    for (const item of items) {
      const row = textElement('div', '', `flow-step ${item.status}`);
      const index = textElement('span', String(item.sequence), 'step-index');
      const body = textElement('div', '', 'step-body');
      const detail = item.fallback_reason ? `${item.detail}；${item.fallback_reason}` : item.detail;
      body.append(textElement('strong', item.node), textElement('small', detail));
      row.append(index, body, textElement('span', `${item.duration_ms.toFixed(2)} ms`, 'duration'));
      workflow.append(row);
    }
  }
  function showEvidence(items) {
    evidence.replaceChildren(); evidence.className = '';
    if (!items.length) { evidence.className='empty'; evidence.textContent='本轮没有可引用的结构化证据'; return; }
    for (const item of items) {
      const box = textElement('div', '', 'evidence');
      const heading = [item.port, item.service_type, item.product, item.version].filter(Boolean).join(' · ') || item.source;
      box.append(textElement('strong', heading), textElement('small', item.detail)); evidence.append(box);
    }
  }
  function showLimitations(items) {
    limitations.replaceChildren();
    const title = textElement('strong', '数据与能力限制'); const list = document.createElement('ul');
    for (const item of items) list.append(textElement('li', item));
    limitations.append(title, list);
  }
  for (const button of document.querySelectorAll('.example')) {
    button.addEventListener('click', () => { questionInput.value = button.textContent; questionInput.focus(); });
  }
  form.addEventListener('submit', async (event) => {
    event.preventDefault(); const question = questionInput.value.trim(); if (!question) return;
    addMessage('user', question); questionInput.value=''; sendButton.disabled=true; sendButton.textContent='处理中';
    meta.replaceChildren(textElement('span','LangGraph 执行中','badge'));
    const round = roundInput.value.trim();
    try {
      const response = await fetch('/agent/chat', {method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({question, scan_round:round ? Number(round) : null})});
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `请求失败（HTTP ${response.status}）`);
      addMessage('assistant', data.answer); showMeta(data); showWorkflow(data.workflow_trace || []); showTools(data.tools_used || []);
      showEvidence(data.evidence || []); showLimitations(data.limitations || []);
    } catch (error) {
      addMessage('assistant', `请求失败：${error.message || '未知错误'}`);
      meta.replaceChildren(textElement('span','failed','badge failed'));
    } finally { sendButton.disabled=false; sendButton.textContent='发送'; questionInput.focus(); }
  });
</script>
</body>
</html>"""


def create_chat_preview_router() -> APIRouter:
    """创建无需构建步骤的对话预览路由。"""

    router = APIRouter(include_in_schema=False)

    @router.get("/chat", response_class=HTMLResponse)
    def chat_preview() -> HTMLResponse:
        return HTMLResponse(CHAT_PREVIEW_HTML)

    return router
