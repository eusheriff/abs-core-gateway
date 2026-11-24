/**
 * Zero-dependency local HTML dashboard served at `GET /ui` by `mcp-gateway serve`.
 * Shows live ALLOW / DENY / SHADOW_DENY / ESCALATE events, latency stats,
 * human escalation resolution controls, and 1-click JSONL audit export.
 */

export function renderDashboardHtml(mode: 'enforce' | 'shadow'): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ABS Core — Sovereign MCP Governance UI</title>
  <style>
    :root { --bg:#0b1020; --panel:#121933; --border:#233058; --text:#e6ecff; --muted:#8c9bc2; --ok:#22c55e; --deny:#ef4444; --warn:#f59e0b; --accent:#38bdf8; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); }
    header { display:flex; align-items:center; justify-content:space-between; padding:16px 24px; border-bottom:1px solid var(--border); background:var(--panel); }
    .badge { padding:4px 10px; border-radius:999px; font-size:12px; font-weight:600; text-transform:uppercase; }
    .badge.enforce { background:rgba(34,197,94,.18); color:var(--ok); }
    .badge.shadow { background:rgba(245,158,11,.18); color:var(--warn); }
    main { max-width:1100px; margin:24px auto; padding:0 20px; display:grid; gap:18px; }
    .cards { display:grid; grid-template-columns:repeat(auto-fit, minmax(180px,1fr)); gap:12px; }
    .card { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:14px 16px; }
    .card .label { font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }
    .card .value { font-size:28px; font-weight:700; margin-top:4px; }
    .toolbar { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
    button, select { background:var(--panel); color:var(--text); border:1px solid var(--border); border-radius:8px; padding:8px 12px; font-size:13px; cursor:pointer; }
    button.primary { background:var(--accent); color:#04111d; border-color:transparent; font-weight:600; }
    button.approve { background:rgba(34,197,94,.2); color:var(--ok); border-color:var(--ok); }
    button.reject { background:rgba(239,68,68,.2); color:var(--deny); border-color:var(--deny); }
    table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:10px; overflow:hidden; }
    th, td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--border); font-size:13px; }
    th { color:var(--muted); font-size:11px; text-transform:uppercase; }
    .pill { padding:2px 8px; border-radius:6px; font-weight:600; font-size:11px; }
    .ALLOW, .SHADOW_ALLOW, .APPROVED { background:rgba(34,197,94,.18); color:var(--ok); }
    .DENY, .REJECTED { background:rgba(239,68,68,.18); color:var(--deny); }
    .ESCALATE, .SHADOW_DENY { background:rgba(245,158,11,.18); color:var(--warn); }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; }
  </style>
</head>
<body>
  <header>
    <div><strong>ABS Core</strong> &middot; Sovereign MCP Governance</div>
    <span class="badge ${mode}">${mode} mode</span>
  </header>
  <main>
    <div class="cards">
      <div class="card"><div class="label">Total Decisions</div><div class="value" id="m-total">0</div></div>
      <div class="card"><div class="label">Allowed</div><div class="value" id="m-allow" style="color:var(--ok)">0</div></div>
      <div class="card"><div class="label">Blocked</div><div class="value" id="m-deny" style="color:var(--deny)">0</div></div>
      <div class="card"><div class="label">Escalated / Shadow</div><div class="value" id="m-esc" style="color:var(--warn)">0</div></div>
    </div>
    <div class="toolbar">
      <select id="filter">
        <option value="ALL">All decisions</option>
        <option value="DENY">Blocked only</option>
        <option value="ESCALATE">Escalated only</option>
        <option value="ALLOW">Allowed only</option>
      </select>
      <button onclick="refresh()">Refresh</button>
      <button class="primary" onclick="exportAudit()">Export Audit JSONL</button>
    </div>
    <table>
      <thead><tr><th>Time</th><th>Tool</th><th>Decision</th><th>Reason / Receipt</th><th>Human Action</th></tr></thead>
      <tbody id="rows"><tr><td colspan="5" style="color:var(--muted)">Loading audit stream...</td></tr></tbody>
    </table>
  </main>
  <script>
    let records = [];
    async function refresh() {
      const res = await fetch('/v1/audit');
      const data = await res.json();
      records = (data.records || []).slice().reverse();
      render();
    }
    async function resolveEsc(traceId, action) {
      await fetch('/v1/escalations/' + encodeURIComponent(traceId) + '/resolve', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ resolution: action })
      });
      await refresh();
    }
    function exportAudit() {
      const blob = new Blob([records.slice().reverse().map(r => JSON.stringify(r)).join('\\n') + '\\n'], { type: 'application/x-ndjson' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'abs-core-audit.ndjson';
      a.click();
    }
    function escHtml(s) {
      return String(s ?? '').replace(/[&<>"']/g, ch => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[ch]));
    }
    function render() {
      const f = document.getElementById('filter').value;
      const allow = records.filter(r => ['ALLOW','SHADOW_ALLOW','APPROVED'].includes(r.decision?.decision)).length;
      const deny = records.filter(r => ['DENY','REJECTED'].includes(r.decision?.decision)).length;
      const esc = records.filter(r => ['ESCALATE','SHADOW_DENY'].includes(r.decision?.decision)).length;
      document.getElementById('m-total').textContent = records.length;
      document.getElementById('m-allow').textContent = allow;
      document.getElementById('m-deny').textContent = deny;
      document.getElementById('m-esc').textContent = esc;
      const filtered = records.filter(r => f === 'ALL' || r.decision?.decision === f);
      const tbody = document.getElementById('rows');
      if (!filtered.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="color:var(--muted)">No matching records yet.</td></tr>';
        return;
      }
      tbody.innerHTML = filtered.slice(0, 100).map(r => {
        const d = r.decision?.decision || 'UNKNOWN';
        const actions = d === 'ESCALATE' && !r.human_resolution
          ? '<button class="approve" onclick="resolveEsc(\\'' + escHtml(r.trace_id) + '\\',\\'APPROVED\\')">Approve</button> <button class="reject" onclick="resolveEsc(\\'' + escHtml(r.trace_id) + '\\',\\'REJECTED\\')">Reject</button>'
          : (r.human_resolution ? '<span class="pill ' + escHtml(r.human_resolution) + '">' + escHtml(r.human_resolution) + '</span>' : '&mdash;');
        return '<tr>'
          + '<td><code>' + escHtml((r.recorded_at || '').slice(11, 19)) + '</code></td>'
          + '<td><code>' + escHtml(r.tool) + '</code></td>'
          + '<td><span class="pill ' + escHtml(d) + '">' + escHtml(d) + '</span></td>'
          + '<td>' + escHtml(r.decision?.reason || '') + '</td>'
          + '<td>' + actions + '</td>'
          + '</tr>';
      }).join('');
    }
    document.getElementById('filter').addEventListener('change', render);
    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>`;
}
