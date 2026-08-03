const params = new URLSearchParams(window.location.search);
const sampleId = params.get('id');
const root = document.getElementById('report-root');

if (!sampleId) {
  root.innerHTML = `<div class="empty-state">No sample ID provided.</div>`;
} else {
  loadReport();
  const poll = setInterval(async () => {
    const detail = await apiGet(`/reports/${sampleId}`).catch(() => null);
    if (detail && detail.status === 'complete') { clearInterval(poll); }
    if (detail) renderReport(detail);
  }, 6000);
}

async function loadReport() {
  try {
    const detail = await apiGet(`/reports/${sampleId}`);
    renderReport(detail);
  } catch (err) {
    root.innerHTML = `<div class="empty-state">Could not load report: ${err.message}</div>`;
  }
}

function renderReport(s) {
  const iocsByType = {};
  (s.iocs || []).forEach(i => {
    iocsByType[i.ioc_type] = iocsByType[i.ioc_type] || [];
    iocsByType[i.ioc_type].push(i);
  });

  const staticReport = s.static_report || {};
  const yaraMatches = (staticReport.yara && staticReport.yara.matches) || [];
  const riskReasons = staticReport.risk_reasons || [];
  const formatSpecific = staticReport.format_specific || {};

  root.innerHTML = `
    <div class="page-header">
      <div>
        <h1>${escapeHtml(s.original_filename)}</h1>
        <p class="mono" style="color:var(--text-muted)">${s.sha256}</p>
      </div>
      <div style="display:flex; align-items:center; gap:16px;">
        <div style="text-align:right;">
          <div style="font-family:var(--font-display); font-size:30px; font-weight:600;">${s.risk_score}<span style="font-size:14px; color:var(--text-muted);">/100</span></div>
          <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase;">${s.status.replace(/_/g,' ')}</div>
        </div>
        <div class="verdict-hex ${s.verdict}">${verdictLabel(s.verdict).slice(0,4).toUpperCase()}</div>
      </div>
    </div>

    <div class="card">
      <h2>Sample details</h2>
      <table class="data">
        <tr><th style="width:160px;">File type</th><td>${escapeHtml(s.file_type)} (${s.target_os})</td></tr>
        <tr><th>Size</th><td>${fmtBytes(s.file_size)}</td></tr>
        <tr><th>SHA-256</th><td class="mono">${s.sha256}</td></tr>
        <tr><th>SHA-1</th><td class="mono">${s.sha1}</td></tr>
        <tr><th>MD5</th><td class="mono">${s.md5}</td></tr>
        ${s.ssdeep ? `<tr><th>ssdeep</th><td class="mono">${s.ssdeep}</td></tr>` : ''}
      </table>
    </div>

    ${riskReasons.length ? `
    <div class="card">
      <h2>Why this verdict</h2>
      <ul style="margin:0; padding-left:1.1rem; font-size:13.5px; color:var(--text-secondary);">
        ${riskReasons.map(r => `<li style="margin-bottom:6px;">${escapeHtml(r)}</li>`).join('')}
      </ul>
    </div>` : ''}

    <div class="card">
      <h2>Indicators of compromise</h2>
      ${Object.keys(iocsByType).length ? Object.entries(iocsByType).map(([type, list]) => `
        <div style="margin-bottom:10px;">
          <div style="font-size:11.5px; text-transform:uppercase; color:var(--text-muted); margin-bottom:4px;">${type.replace(/_/g,' ')}</div>
          ${list.map(i => `<span class="badge-tag" title="confidence ${(i.confidence*100).toFixed(0)}%">${escapeHtml(i.value)}</span>`).join('')}
        </div>
      `).join('') : `<div class="empty-state">No indicators extracted.</div>`}
    </div>

    <div class="card">
      <h2>YARA matches</h2>
      ${yaraMatches.length ? `
      <table class="data">
        <thead><tr><th>Rule</th><th>Severity</th><th>Description</th></tr></thead>
        <tbody>
          ${yaraMatches.map(m => `
            <tr><td class="mono">${escapeHtml(m.rule)}</td>
                <td><span class="pill ${severityToPill(m.meta.severity)}">${escapeHtml(m.meta.severity || 'n/a')}</span></td>
                <td>${escapeHtml(m.meta.description || '')}</td></tr>
          `).join('')}
        </tbody>
      </table>` : `<div class="empty-state">No YARA rule matches.</div>`}
    </div>

    ${renderFormatSpecific(formatSpecific)}

    <div class="card">
      <h2>Dynamic sandbox analysis</h2>
      ${renderSandbox(s.sandbox_report)}
    </div>

    <div class="card">
      <h2>Network forensics</h2>
      ${renderNetwork(s.network_report)}
    </div>

    <div style="display:flex; gap:10px; margin-top:1.25rem;">
      <a class="btn" href="${apiBaseAbsolute()}/reports/${s.id}/html" target="_blank">View full HTML report</a>
      <a class="btn" href="${apiBaseAbsolute()}/reports/${s.id}/download">Download JSON report</a>
    </div>
  `;
}

function renderFormatSpecific(fmt) {
  if (fmt.pe && fmt.pe.available) {
    return `<div class="card"><h2>PE analysis (Windows)</h2>
      <table class="data">
        <tr><th style="width:160px;">DLL</th><td>${fmt.pe.is_dll}</td></tr>
        <tr><th>Signed</th><td>${fmt.pe.has_authenticode_signature}</td></tr>
        <tr><th>Overlay data</th><td>${fmt.pe.has_overlay_data}</td></tr>
      </table>
      ${fmt.pe.suspicious_api_calls && fmt.pe.suspicious_api_calls.length ? `
        <div style="margin-top:10px; font-size:11.5px; color:var(--text-muted); text-transform:uppercase;">Suspicious API calls</div>
        ${fmt.pe.suspicious_api_calls.map(a => `<span class="badge-tag">${escapeHtml(a)}</span>`).join('')}` : ''}
    </div>`;
  }
  if (fmt.apk && fmt.apk.available) {
    return `<div class="card"><h2>APK analysis (Android)</h2>
      <table class="data">
        <tr><th style="width:160px;">Package</th><td class="mono">${escapeHtml(fmt.apk.package_name || 'unknown')}</td></tr>
        <tr><th>Signed</th><td>${fmt.apk.is_signed}</td></tr>
      </table>
      ${fmt.apk.high_risk_permissions && fmt.apk.high_risk_permissions.length ? `
        <div style="margin-top:10px; font-size:11.5px; color:var(--text-muted); text-transform:uppercase;">High-risk permissions</div>
        ${fmt.apk.high_risk_permissions.map(p => `<span class="badge-tag">${escapeHtml(p.replace('android.permission.',''))}</span>`).join('')}` : ''}
    </div>`;
  }
  if (fmt.elf && fmt.elf.available) {
    return `<div class="card"><h2>ELF analysis (Linux)</h2>
      <table class="data">
        <tr><th style="width:160px;">Stripped</th><td>${fmt.elf.is_stripped}</td></tr>
        <tr><th>Interpreter</th><td class="mono">${escapeHtml(fmt.elf.interpreter || 'static')}</td></tr>
      </table>
    </div>`;
  }
  return '';
}

function renderSandbox(sb) {
  if (!sb || !sb.available) {
    return `<div class="notice info">${sb ? escapeHtml(sb.reason) : 'Dynamic sandbox analysis was not run for this sample.'}</div>`;
  }
  return `
    <table class="data">
      <tr><th style="width:160px;">Task ID</th><td class="mono">${sb.task_id}</td></tr>
      <tr><th>Malscore</th><td>${sb.malscore}</td></tr>
      <tr><th>Dropped files</th><td>${(sb.dropped_files||[]).join(', ') || 'none'}</td></tr>
    </table>
    <ul>${(sb.signatures||[]).map(s => `<li>${escapeHtml(s)}</li>`).join('')}</ul>
  `;
}

function renderNetwork(net) {
  if (!net || !net.available) {
    return `<div class="notice info">${net ? escapeHtml(net.reason) : 'Network forensics was not run for this sample (requires a sandbox PCAP).'}</div>`;
  }
  return `
    <table class="data">
      <tr><th style="width:200px;">Packets captured</th><td>${net.packet_count}</td></tr>
      <tr><th>External IPs contacted</th><td class="mono">${(net.unique_external_ips||[]).join(', ') || 'none'}</td></tr>
      <tr><th>DNS queries</th><td class="mono">${(net.dns_queries||[]).join(', ') || 'none'}</td></tr>
      <tr><th>Beaconing detected</th><td>${net.beaconing_detected ? `<span class="pill malicious">yes</span>` : `<span class="pill clean">no</span>`}</td></tr>
    </table>
  `;
}

function severityToPill(sev) {
  return { critical: 'malicious', high: 'malicious', medium: 'suspicious', low: 'unknown' }[sev] || 'unknown';
}

function apiBaseAbsolute() {
  return window.MALINFO_API_BASE || '/api';
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str ?? '');
  return div.innerHTML;
}
