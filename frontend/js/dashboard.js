const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('file-input');
const tableBody = document.getElementById('sample-rows');
const statsEl = {
  total: document.getElementById('stat-total'),
  malicious: document.getElementById('stat-malicious'),
  suspicious: document.getElementById('stat-suspicious'),
  clean: document.getElementById('stat-clean'),
};

let pollTimer = null;

dropzone.addEventListener('click', () => fileInput.click());
dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropzone.classList.remove('dragover');
  if (e.dataTransfer.files.length) handleUpload(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', () => {
  if (fileInput.files.length) handleUpload(fileInput.files[0]);
});

async function handleUpload(file) {
  const original = dropzone.innerHTML;
  dropzone.innerHTML = `<div class="primary">Uploading ${file.name}&hellip;</div>`;
  try {
    const form = new FormData();
    form.append('file', file);
    const result = await apiPostForm('/upload', form);
    dropzone.innerHTML = `<div class="primary" style="color:var(--safe)">Queued for analysis</div><div class="secondary">Sample ID: ${result.sample_id}</div>`;
    setTimeout(() => { dropzone.innerHTML = original; }, 2500);
    loadSamples();
  } catch (err) {
    dropzone.innerHTML = `<div class="primary" style="color:var(--danger)">Upload failed</div><div class="secondary">${err.message}</div>`;
    setTimeout(() => { dropzone.innerHTML = original; }, 3000);
  }
}

async function loadSamples() {
  let samples = [];
  try {
    samples = await apiGet('/reports');
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="6"><div class="empty-state">Could not reach the MALINFO backend. Is it running?</div></td></tr>`;
    return;
  }

  statsEl.total.textContent = samples.length;
  statsEl.malicious.textContent = samples.filter(s => s.verdict === 'malicious').length;
  statsEl.suspicious.textContent = samples.filter(s => s.verdict === 'suspicious').length;
  statsEl.clean.textContent = samples.filter(s => s.verdict === 'clean').length;

  if (!samples.length) {
    tableBody.innerHTML = `<tr><td colspan="6"><div class="empty-state"><div class="icon">&#9679;</div>No samples analyzed yet. Upload a file to get started.</div></td></tr>`;
    return;
  }

  tableBody.innerHTML = samples.map(s => `
    <tr onclick="window.location.href='report.html?id=${s.id}'">
      <td>
        <div style="font-weight:500">${escapeHtml(s.original_filename)}</div>
        <div class="mono" style="font-size:11px;color:var(--text-muted)">${s.sha256.slice(0, 24)}&hellip;</div>
      </td>
      <td>${escapeHtml(s.file_type)}</td>
      <td>${fmtBytes(s.file_size)}</td>
      <td><span class="pill ${s.verdict}">${verdictLabel(s.verdict)}</span></td>
      <td class="mono">${s.risk_score}</td>
      <td style="color:var(--text-secondary)">${fmtDate(s.created_at)}</td>
    </tr>
  `).join('');
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

loadSamples();
pollTimer = setInterval(loadSamples, 8000);
