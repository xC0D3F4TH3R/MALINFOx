// VM Management Page
// ISO upload, VM template management, and dynamic analysis

import { API } from '../api.js';
import { UI } from '../ui.js';

export const VMPage = {
  currentTab: 'templates',
  
  async render() {
    const main = document.getElementById('appMain');
    if (!main) return;

    main.innerHTML = `
      <div class="page-header">
        <div>
          <h1>VM Management</h1>
          <p>ISO uploads, VM templates, and dynamic analysis orchestration</p>
        </div>
        <div class="page-header-actions">
          <button class="btn btn-primary" id="uploadISOBtn">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="17 8 12 3 7 8"></polyline>
              <line x1="12" y1="3" y2="15"></line>
            </svg>
            Upload ISO
          </button>
          <button class="btn btn-primary" id="createTemplateBtn">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="12" y1="5" x2="12" y2="19"></line>
              <line x1="5" y1="12" x2="19" y2="12"></line>
            </svg>
            Create Template
          </button>
        </div>
      </div>

      <div class="tabs">
        <button class="tab-btn active" data-tab="isos">ISOs</button>
        <button class="tab-btn" data-tab="templates">Templates</button>
        <button class="tab-btn" data-tab="analyze">Submit Analysis</button>
        <button class="tab-btn" data-tab="tasks">Analysis Tasks</button>
      </div>

      <div class="tab-content active" id="tab-isos">
        <div class="card">
          <div id="isosTable">${UI.showLoading()}</div>
        </div>
      </div>

      <div class="tab-content" id="tab-templates">
        <div class="card">
          <div id="templatesTable">${UI.showLoading()}</div>
        </div>
      </div>

      <div class="tab-content" id="tab-analyze">
        <div class="card">
          <div class="card-header"><h2>Submit Sample for Dynamic Analysis</h2></div>
          <div id="analysisForm">${this.renderAnalysisForm()}</div>
        </div>
      </div>

      <div class="tab-content" id="tab-tasks">
        <div class="card">
          <div class="card-header">
            <h2>Analysis Tasks</h2>
            <button class="btn btn-sm" id="refreshTasksBtn">Refresh</button>
          </div>
          <div id="tasksTable">${UI.showLoading()}</div>
        </div>
      </div>
    `;

    this.setupEventListeners();
    await this.loadISOs();
    await this.loadTemplates();
    await this.loadTasks();
  },

  renderAnalysisForm() {
    return `
      <div class="form-row">
        <div class="form-group" style="flex: 1;">
          <label>Sample</label>
          <div class="dropzone" id="analysisDropzone">
            <div class="icon">&#8593;</div>
            <div class="primary">Drop sample here, or click to browse</div>
            <div class="secondary">Or select from uploaded samples</div>
          </div>
          <input type="file" id="analysisFileInput" style="display:none;">
          <select id="analysisSampleSelect" style="width:100%; margin-top:0.5rem; display:none;">
            <option value="">Select from uploaded samples...</option>
          </select>
        </div>
      </div>

      <div class="form-row" style="margin-top:1rem;">
        <div class="form-group">
          <label>VM Template</label>
          <select id="analysisTemplate" style="width:100%;">
            <option value="">Select a template...</option>
          </select>
        </div>
        <div class="form-group">
          <label>Timeout (seconds)</label>
          <input type="number" id="analysisTimeout" value="300" min="60" max="3600" style="width:100%;">
        </div>
      </div>

      <div class="form-row" style="margin-top:1rem;">
        <div class="form-group">
          <label>Options</label>
          <div style="display:flex; gap:1rem; flex-wrap:wrap;">
            <label style="display:flex; align-items:center; gap:0.5rem; cursor:pointer;">
              <input type="checkbox" id="optScreenshots" checked> Screenshots
            </label>
            <label style="display:flex; align-items:center; gap:0.5rem; cursor:pointer;">
              <input type="checkbox" id="optMemory" checked> Memory Dumps
            </label>
            <label style="display:flex; align-items:center; gap:0.5rem; cursor:pointer;">
              <input type="checkbox" id="optNetwork" checked> Network Capture
            </label>
            <label style="display:flex; align-items:center; gap:0.5rem; cursor:pointer;">
              <input type="checkbox" id="optAPI" checked> API Monitoring
            </label>
          </div>
        </div>
      </div>

      <div class="form-actions">
        <button class="btn btn-primary" id="submitAnalysis" disabled>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
            <polyline points="17 8 12 3 7 8"></polyline>
            <line x1="12" y1="3" x2="12" y2="15"></line>
          </svg>
          Submit Analysis
        </button>
      </div>

      <div id="analysisResult" style="margin-top:1rem;"></div>
    `;
  },

  setupEventListeners() {
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
        this.currentTab = btn.dataset.tab;
      });
    });

    // Upload ISO button
    document.getElementById('uploadISOBtn')?.addEventListener('click', () => this.showISOUploadModal());

    // Create Template button
    document.getElementById('createTemplateBtn')?.addEventListener('click', () => this.showCreateTemplateModal());

    // Refresh tasks
    document.getElementById('refreshTasksBtn')?.addEventListener('click', () => this.loadTasks());

    // Analysis form
    this.setupAnalysisForm();
  },

  setupAnalysisForm() {
    const dropzone = document.getElementById('analysisDropzone');
    const fileInput = document.getElementById('analysisFileInput');
    const sampleSelect = document.getElementById('analysisSampleSelect');
    const templateSelect = document.getElementById('analysisTemplate');
    const submitBtn = document.getElementById('submitAnalysis');

    let selectedFile = null;
    let selectedSampleId = null;

    // Load samples for dropdown
    this.loadSamplesForDropdown();

    // Dropzone events
    dropzone?.addEventListener('click', () => fileInput?.click());
    dropzone?.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
    dropzone?.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone?.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files.length) this.handleFileSelect(e.dataTransfer.files[0]);
    });

    fileInput?.addEventListener('change', (e) => {
      if (e.target.files.length) this.handleFileSelect(e.target.files[0]);
    });

    sampleSelect?.addEventListener('change', (e) => {
      selectedSampleId = e.target.value || null;
      if (selectedSampleId) {
        selectedFile = null;
        dropzone.innerHTML = `
          <div class="icon" style="color:var(--safe)">✓</div>
          <div class="primary" style="color:var(--safe)">Sample selected from library</div>
          <div class="secondary">Sample ID: ${selectedSampleId}</div>
        `;
      } else {
        this.updateDropzoneUI(dropzone, null);
      }
      this.updateSubmitButton();
    });

    templateSelect?.addEventListener('change', () => this.updateSubmitButton());

    this.handleFileSelect = (file) => {
      if (file.size > 250 * 1024 * 1024) {
        UI.toast('File exceeds 250 MB limit', 'error');
        return;
      }
      selectedFile = file;
      selectedSampleId = null;
      sampleSelect.value = '';
      dropzone.innerHTML = `
        <div class="icon" style="color:var(--safe)">✓</div>
        <div class="primary" style="color:var(--safe)">${file.name}</div>
        <div class="secondary">${UI.formatBytes(file.size)}</div>
      `;
      this.updateSubmitButton();
    };

    this.updateDropzoneUI = (dz, file) => {
      if (file) {
        dz.innerHTML = `
          <div class="icon" style="color:var(--safe)">✓</div>
          <div class="primary" style="color:var(--safe)">${file.name}</div>
          <div class="secondary">${UI.formatBytes(file.size)}</div>
        `;
      } else {
        dz.innerHTML = `
          <div class="icon">&#8593;</div>
          <div class="primary">Drop sample here, or click to browse</div>
          <div class="secondary">Or select from uploaded samples</div>
        `;
      }
    };

    this.updateSubmitButton = () => {
      const hasSample = selectedFile || selectedSampleId;
      const hasTemplate = templateSelect?.value;
      submitBtn.disabled = !(hasSample && hasTemplate);
    };

    submitBtn?.addEventListener('click', async () => {
      if (!selectedFile && !selectedSampleId) return;
      if (!templateSelect?.value) return;

      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span class="spinner spinner-sm"></span> Submitting...';

      try {
        let sampleId = selectedSampleId;
        
        // If file uploaded, upload it first
        if (selectedFile) {
          const uploadResult = await API.uploadFile(selectedFile);
          sampleId = uploadResult.sample_id;
        }

        const options = {
          screenshots: document.getElementById('optScreenshots').checked,
          memory: document.getElementById('optMemory').checked,
          network: document.getElementById('optNetwork').checked,
          api_monitor: document.getElementById('optAPI').checked,
        };

        const result = await API.submitVMAnalysis(sampleId, templateSelect.value, {
          timeout: parseInt(document.getElementById('analysisTimeout').value),
          options,
        });

        document.getElementById('analysisResult').innerHTML = `
          <div style="background:var(--safe-dim);border:1px solid var(--safe);border-radius:var(--radius);padding:1rem;color:var(--safe);">
            <strong>Analysis submitted successfully!</strong>
            <div class="mono" style="margin-top:0.5rem;">Task ID: ${result.task_id}</div>
            <div style="font-size:12px;margin-top:0.25rem;">Sample ID: ${sampleId}</div>
          </div>
        `;

        UI.toast('Analysis submitted to VM orchestrator', 'success');
        
        // Reset form
        selectedFile = null;
        selectedSampleId = null;
        fileInput.value = '';
        sampleSelect.value = '';
        this.updateDropzoneUI(dropzone, null);
        this.updateSubmitButton();
        submitBtn.disabled = true;
        submitBtn.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
            <polyline points="17 8 12 3 7 8"></polyline>
            <line x1="12" y1="3" x2="12" y2="15"></line>
          </svg>
          Submit Analysis
        `;

        // Switch to tasks tab
        document.querySelector('[data-tab="tasks"]').click();
        await this.loadTasks();

      } catch (error) {
        UI.toast(`Submission failed: ${error.message}`, 'error');
        submitBtn.disabled = false;
        submitBtn.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
            <polyline points="17 8 12 3 7 8"></polyline>
            <line x1="12" y1="3" x2="12" y2="15"></line>
          </svg>
          Submit Analysis
        `;
      }
    });
  },

  async loadSamplesForDropdown() {
    try {
      const samples = await API.getSamples({ limit: 100 });
      const select = document.getElementById('analysisSampleSelect');
      if (select) {
        samples.forEach(s => {
          const opt = document.createElement('option');
          opt.value = s.id;
          opt.textContent = `${s.original_filename} (${s.sha256.slice(0,16)}...)`;
          select.appendChild(opt);
        });
      }
    } catch (error) {
      console.error('Failed to load samples for dropdown:', error);
    }
  },

  async loadISOs() {
    const container = document.getElementById('isosTable');
    if (!container) return;

    try {
      const isos = await API.getISOs();
      container.innerHTML = UI.renderTable(
        [
          { field: 'name', label: 'Name', render: (v) => `<strong>${v}</strong>` },
          { field: 'size', label: 'Size', render: (v) => UI.formatBytes(v) },
          { field: 'modified', label: 'Modified', render: (v) => UI.formatDate(v) },
          { field: 'actions', label: 'Actions', render: (v, r) => `
            <button class="btn btn-sm btn-danger" onclick="VMPage.deleteISO('${r.name}')">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="3 6 5 6 21 6"></polyline>
                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
              </svg>
            </button>
          ` },
        ],
        isos,
        { emptyMessage: 'No ISO files uploaded. Click "Upload ISO" to add one.' }
      );
    } catch (error) {
      container.innerHTML = UI.showEmptyState('', 'Failed to load ISOs', '⚠');
    }
  },

  async loadTemplates() {
    const container = document.getElementById('templatesTable');
    if (!container) return;

    try {
      const templates = await API.getVMTemplates();
      container.innerHTML = UI.renderTable(
        [
          { field: 'name', label: 'Name', render: (v) => `<strong>${v}</strong>` },
          { field: 'os_type', label: 'OS', render: (v) => UI.createPill(v.charAt(0).toUpperCase() + v.slice(1), 'info') },
          { field: 'os_version', label: 'Version' },
          { field: 'arch', label: 'Arch' },
          { field: 'memory_mb', label: 'Memory', render: (v) => `${v} MB` },
          { field: 'vcpus', label: 'vCPUs' },
          { field: 'network_mode', label: 'Network', render: (v) => UI.createPill(v, 'info') },
          { field: 'state', label: 'Status', render: (v) => {
            const states = {
              'ready': { label: 'Ready', class: 'safe' },
              'building': { label: 'Building', class: 'warn' },
              'error': { label: 'Error', class: 'danger' },
            };
            const s = states[v] || { label: v, class: 'info' };
            return UI.createPill(s.label, s.class);
          }},
          { field: 'actions', label: 'Actions', render: (v, r) => `
            <div style="display:flex; gap:0.5rem;">
              ${r.state === 'ready' ? `
                <button class="btn btn-sm" onclick="VMPage.rebuildTemplate('${r.id}')" title="Rebuild">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="23 4 23 10 17 10"></polyline>
                    <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
                  </svg>
                </button>
              ` : ''}
              <button class="btn btn-sm btn-danger" onclick="VMPage.deleteTemplate('${r.id}')" title="Delete">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <polyline points="3 6 5 6 21 6"></polyline>
                  <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                </svg>
              </button>
            </div>
          ` },
        ],
        templates,
        { emptyMessage: 'No VM templates created. Click "Create Template" to build one from an ISO.' }
      );
    } catch (error) {
      container.innerHTML = UI.showEmptyState('', 'Failed to load templates', '⚠');
    }
  },

  async loadTasks() {
    const container = document.getElementById('tasksTable');
    if (!container) return;

    try {
      const tasks = await API.getVMTasks();
      container.innerHTML = UI.renderTable(
        [
          { field: 'id', label: 'Task ID', render: (v) => `<code class="mono" style="font-size:11px;">${v.slice(0,8)}...</code>` },
          { field: 'sample_id', label: 'Sample', render: (v) => `<code class="mono" style="font-size:11px;">${v.slice(0,8)}...</code>` },
          { field: 'template_id', label: 'Template', render: (v) => `<code class="mono" style="font-size:11px;">${v.slice(0,8)}...</code>` },
          { field: 'state', label: 'Status', render: (v) => {
            const states = {
              'queued': { label: 'Queued', class: 'info' },
              'preparing': { label: 'Preparing', class: 'warn' },
              'booting': { label: 'Booting', class: 'warn' },
              'injecting': { label: 'Injecting', class: 'warn' },
              'running': { label: 'Running', class: 'info' },
              'monitoring': { label: 'Monitoring', class: 'info' },
              'collecting': { label: 'Collecting', class: 'warn' },
              'completed': { label: 'Completed', class: 'safe' },
              'failed': { label: 'Failed', class: 'danger' },
            };
            const s = states[v] || { label: v, class: 'info' };
            return UI.createPill(s.label, s.class);
          }},
          { field: 'progress', label: 'Progress', render: (v) => `
            <div style="width:100px; height:6px; background:var(--line); border-radius:3px; overflow:hidden;">
              <div style="width:${v}%; height:100%; background:var(--saffron); transition:width 0.3s;"></div>
            </div>
            <span style="font-size:11px; color:var(--text-muted);">${v}%</span>
          ` },
          { field: 'malscore', label: 'MalScore', render: (v) => {
            const cls = v >= 80 ? 'danger' : v >= 40 ? 'warn' : v >= 20 ? 'info' : 'safe';
            return `<span class="mono" style="color:var(--${cls})">${v}/100</span>`;
          }},
          { field: 'created_at', label: 'Created', render: (v) => UI.formatDate(v) },
          { field: 'actions', label: 'Actions', render: (v, r) => `
            <div style="display:flex; gap:0.5rem;">
              <button class="btn btn-sm" onclick="VMPage.viewTask('${r.id}')" title="View Details">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                  <circle cx="12" cy="12" r="3"></circle>
                </svg>
              </button>
              ${['queued','preparing','booting','injecting','running','monitoring','collecting'].includes(r.state) ? `
                <button class="btn btn-sm btn-danger" onclick="VMPage.cancelTask('${r.id}')" title="Cancel">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="15" y1="9" x2="9" y2="15"></line>
                    <line x1="9" y1="9" x2="15" y2="15"></line>
                  </svg>
                </button>
              ` : ''}
            </div>
          ` },
        ],
        tasks,
        { emptyMessage: 'No analysis tasks submitted yet.' }
      );
    } catch (error) {
      container.innerHTML = UI.showEmptyState('', 'Failed to load tasks', '⚠');
    }
  },

  showISOUploadModal() {
    UI.showModal(`
      <div class="modal-header">
        <h3 class="modal-title">Upload ISO</h3>
        <button class="modal-close" aria-label="Close modal">&times;</button>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label>ISO File</label>
          <div class="dropzone" id="isoDropzone">
            <div class="icon">&#8593;</div>
            <div class="primary">Drop ISO file here, or click to browse</div>
            <div class="secondary">Windows, Linux, Android, or macOS installation media. Max 10 GB.</div>
          </div>
          <input type="file" id="isoFileInput" accept=".iso" style="display:none;">
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>OS Type</label>
            <select id="isoOSType" style="width:100%;">
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="android">Android</option>
              <option value="macos">macOS</option>
            </select>
          </div>
          <div class="form-group">
            <label>OS Version</label>
            <input type="text" id="isoOSVersion" placeholder="e.g., 10, 11, 22.04, 13" style="width:100%;">
          </div>
        </div>
        <div class="form-group">
          <label>Custom Name (optional)</label>
          <input type="text" id="isoName" placeholder="Auto-generated if empty" style="width:100%;">
        </div>
        <div class="form-actions">
          <button class="btn" id="cancelISOUpload">Cancel</button>
          <button class="btn btn-primary" id="confirmISOUpload" disabled>Upload ISO</button>
        </div>
      </div>
    `, 'isoUploadModal');

    const dropzone = document.getElementById('isoDropzone');
    const fileInput = document.getElementById('isoFileInput');
    const confirmBtn = document.getElementById('confirmISOUpload');
    let selectedFile = null;

    dropzone?.addEventListener('click', () => fileInput?.click());
    dropzone?.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
    dropzone?.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone?.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files.length) handleFileSelect(e.dataTransfer.files[0]);
    });

    fileInput?.addEventListener('change', (e) => {
      if (e.target.files.length) handleFileSelect(e.target.files[0]);
    });

    const handleFileSelect = (file) => {
      if (!file.name.endsWith('.iso')) {
        UI.toast('File must be an ISO image', 'error');
        return;
      }
      if (file.size > 10 * 1024 * 1024 * 1024) {
        UI.toast('ISO exceeds 10 GB limit', 'error');
        return;
      }
      selectedFile = file;
      dropzone.innerHTML = `
        <div class="icon" style="color:var(--safe)">✓</div>
        <div class="primary" style="color:var(--safe)">${file.name}</div>
        <div class="secondary">${UI.formatBytes(file.size)}</div>
      `;
      confirmBtn.disabled = false;
    };

    document.getElementById('cancelISOUpload')?.addEventListener('click', () => {
      UI.closeModal('isoUploadModal');
    });

    confirmBtn?.addEventListener('click', async () => {
      if (!selectedFile) return;

      confirmBtn.disabled = true;
      confirmBtn.innerHTML = '<span class="spinner spinner-sm"></span> Uploading...';

      try {
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('os_type', document.getElementById('isoOSType').value);
        formData.append('os_version', document.getElementById('isoOSVersion').value);
        const name = document.getElementById('isoName').value;
        if (name) formData.append('name', name);

        const response = await fetch('/api/vm/isos/upload', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${API.getToken()}` },
          body: formData,
        });

        if (!response.ok) throw new Error(await response.text());

        UI.toast('ISO uploaded successfully', 'success');
        UI.closeModal('isoUploadModal');
        await this.loadISOs();
      } catch (error) {
        UI.toast(`Upload failed: ${error.message}`, 'error');
        confirmBtn.disabled = false;
        confirmBtn.textContent = 'Upload ISO';
      }
    });
  },

  showCreateTemplateModal() {
    // First load ISOs to populate dropdown
    this.loadISOsForTemplateModal().then(() => {
      UI.showModal(`
        <div class="modal-header">
          <h3 class="modal-title">Create VM Template</h3>
          <button class="modal-close" aria-label="Close modal">&times;</button>
        </div>
        <div class="modal-body">
          <div class="form-group">
            <label>Template Name</label>
            <input type="text" id="tmplName" placeholder="e.g., Windows 10 x64 Clean" style="width:100%;">
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>Base ISO</label>
              <select id="tmplISO" style="width:100%;">
                <option value="">Select an ISO...</option>
              </select>
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>Architecture</label>
              <select id="tmplArch" style="width:100%;">
                <option value="x86_64">x86_64</option>
                <option value="aarch64">ARM64</option>
              </select>
            </div>
            <div class="form-group">
              <label>Disk Size (GB)</label>
              <input type="number" id="tmplDisk" value="60" min="20" max="500" style="width:100%;">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>Memory (MB)</label>
              <input type="number" id="tmplMemory" value="4096" min="1024" max="32768" style="width:100%;">
            </div>
            <div class="form-group">
              <label>vCPUs</label>
              <input type="number" id="tmplVCPUs" value="2" min="1" max="16" style="width:100%;">
            </div>
          </div>
          <div class="form-group">
            <label>Network Mode</label>
            <select id="tmplNetwork" style="width:100%;">
              <option value="isolated">Isolated (no network)</option>
              <option value="routed">Routed (via host)</option>
              <option value="nat">NAT</option>
            </select>
          </div>
          <div class="form-actions">
            <button class="btn" id="cancelTemplateCreate">Cancel</button>
            <button class="btn btn-primary" id="confirmTemplateCreate">Create Template</button>
          </div>
        </div>
      `, 'createTemplateModal');

      document.getElementById('cancelTemplateCreate')?.addEventListener('click', () => {
        UI.closeModal('createTemplateModal');
      });

      document.getElementById('confirmTemplateCreate')?.addEventListener('click', async () => {
        const name = document.getElementById('tmplName').value;
        const iso = document.getElementById('tmplISO').value;
        
        if (!name || !iso) {
          UI.toast('Please fill in all required fields', 'error');
          return;
        }

        const btn = document.getElementById('confirmTemplateCreate');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner spinner-sm"></span> Creating...';

        try {
          await API.createVMTemplate({
            name,
            os_type: '', // Will be extracted from ISO metadata
            os_version: '',
            iso_name: iso,
            arch: document.getElementById('tmplArch').value,
            disk_size_gb: parseInt(document.getElementById('tmplDisk').value),
            memory_mb: parseInt(document.getElementById('tmplMemory').value),
            vcpus: parseInt(document.getElementById('tmplVCPUs').value),
            network_mode: document.getElementById('tmplNetwork').value,
          });

          UI.toast('Template creation started', 'success');
          UI.closeModal('createTemplateModal');
          await this.loadTemplates();
        } catch (error) {
          UI.toast(`Creation failed: ${error.message}`, 'error');
          btn.disabled = false;
          btn.textContent = 'Create Template';
        }
      });
    });
  },

  async loadISOsForTemplateModal() {
    try {
      const isos = await API.getISOs();
      const select = document.getElementById('tmplISO');
      if (select) {
        isos.forEach(iso => {
          const opt = document.createElement('option');
          opt.value = iso.name;
          opt.textContent = `${iso.name} (${UI.formatBytes(iso.size)})`;
          select.appendChild(opt);
        });
      }
    } catch (error) {
      console.error('Failed to load ISOs for template modal:', error);
    }
  },

  async deleteISO(name) {
    if (!confirm(`Delete ISO "${name}"?`)) return;
    try {
      await API.deleteISO(name);
      UI.toast('ISO deleted', 'success');
      await this.loadISOs();
    } catch (error) {
      UI.toast(`Delete failed: ${error.message}`, 'error');
    }
  },

  async deleteTemplate(id) {
    if (!confirm('Delete this template? This cannot be undone.')) return;
    try {
      await API.deleteVMTemplate(id);
      UI.toast('Template deleted', 'success');
      await this.loadTemplates();
    } catch (error) {
      UI.toast(`Delete failed: ${error.message}`, 'error');
    }
  },

  async rebuildTemplate(id) {
    if (!confirm('Rebuild template? This will reinstall the OS and agent.')) return;
    try {
      await API.rebuildVMTemplate(id);
      UI.toast('Template rebuild started', 'success');
      await this.loadTemplates();
    } catch (error) {
      UI.toast(`Rebuild failed: ${error.message}`, 'error');
    }
  },

  async viewTask(taskId) {
    try {
      const task = await API.getVMTask(taskId);
      this.showTaskDetailModal(task);
    } catch (error) {
      UI.toast(`Failed to load task: ${error.message}`, 'error');
    }
  },

  showTaskDetailModal(task) {
    const verdictClass = task.malscore >= 80 ? 'malicious' : task.malscore >= 40 ? 'suspicious' : task.malscore >= 20 ? 'clean' : 'unknown';
    
    UI.showModal(`
      <div class="modal-header">
        <h3 class="modal-title">Analysis Task Details</h3>
        <button class="modal-close" aria-label="Close modal">&times;</button>
      </div>
      <div class="modal-body" style="max-height:70vh; overflow:auto;">
        <div style="display:flex; align-items:center; gap:1rem; margin-bottom:1rem;">
          <div class="verdict-hex ${verdictClass}" style="width:64px; height:64px; font-size:18px;">${task.malscore}</div>
          <div>
            <div style="font-weight:600; font-size:14px;">MALSCORE: ${task.malscore}/100</div>
            <div class="mono" style="font-size:11px; color:var(--text-muted);">Task: ${task.id}</div>
            <div class="mono" style="font-size:11px; color:var(--text-muted);">Sample: ${task.sample_id}</div>
          </div>
        </div>

        <div class="stat-grid" style="margin-bottom:1rem;">
          <div class="stat-card"><div class="label">Status</div><div class="value">${UI.createPill(task.state.charAt(0).toUpperCase() + task.state.slice(1), 
            task.state === 'completed' ? 'safe' : task.state === 'failed' ? 'danger' : 'warn')}</div></div>
          <div class="stat-card"><div class="label">Processes</div><div class="value">${task.processes_count}</div></div>
          <div class="stat-card"><div class="label">API Calls</div><div class="value">${task.signatures_count}</div></div>
          <div class="stat-card"><div class="label">Network Events</div><div class="value">${task.network_events_count}</div></div>
          <div class="stat-card"><div class="label">File Events</div><div class="value">${task.file_events_count}</div></div>
          <div class="stat-card"><div class="label">MITRE Techniques</div><div class="value">${task.mitre_techniques.length}</div></div>
        </div>

        ${task.mitre_techniques.length > 0 ? `
          <div class="card" style="margin-bottom:1rem;">
            <div class="card-header"><h2>MITRE ATT&CK Techniques</h2></div>
            <div style="display:flex; flex-wrap:wrap; gap:0.5rem;">
              ${task.mitre_techniques.map(t => `<span class="badge" style="background:var(--teal-dim); color:var(--teal);">${t}</span>`).join('')}
            </div>
          </div>
        ` : ''}

        ${task.signatures.length > 0 ? `
          <div class="card" style="margin-bottom:1rem;">
            <div class="card-header"><h2>Signatures</h2></div>
            <table style="width:100%; font-size:12px;">
              <thead><tr><th>Description</th><th>Severity</th><th>MITRE</th></tr></thead>
              <tbody>
                ${task.signatures.map(s => `<tr><td>${s.description}</td><td>${UI.createPill(s.severity || 'info', 'info')}</td><td>${(s.mitre || []).join(', ')}</td></tr>`).join('')}
              </tbody>
            </table>
          </div>
        ` : ''}

        <div class="form-actions">
          <button class="btn btn-primary" onclick="VMPage.downloadReport('${task.id}')">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="7 10 12 15 17 10"></polyline>
            </svg>
            Download Report
          </button>
          <button class="btn" onclick="VMPage.downloadPCAP('${task.id}')">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="7 10 12 15 17 10"></polyline>
            </svg>
            Download PCAP
          </button>
        </div>
      </div>
    `, 'taskDetailModal');
  },

  async cancelTask(taskId) {
    if (!confirm('Cancel this analysis task?')) return;
    try {
      await API.cancelVMTask(taskId);
      UI.toast('Task cancelled', 'success');
      await this.loadTasks();
    } catch (error) {
      UI.toast(`Cancel failed: ${error.message}`, 'error');
    }
  },

  async downloadReport(taskId) {
    try {
      const report = await API.getVMTaskReport(taskId, 'html');
      const blob = new Blob([report.html], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `malinfo-report-${taskId}.html`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      UI.toast(`Download failed: ${error.message}`, 'error');
    }
  },

  async downloadPCAP(taskId) {
    try {
      const response = await fetch(`/api/vm/tasks/${taskId}/pcap`, {
        headers: { 'Authorization': `Bearer ${API.getToken()}` },
      });
      if (!response.ok) throw new Error('PCAP not available');
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `capture-${taskId}.pcap`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      UI.toast(`Download failed: ${error.message}`, 'error');
    }
  },

  refresh() {
    this.loadISOs();
    this.loadTemplates();
    this.loadTasks();
  },
};

// Make globally accessible for inline handlers
window.VMPage = VMPage;