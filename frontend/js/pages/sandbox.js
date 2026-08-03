// Sandbox Page
// Dynamic analysis sandbox management and monitoring

import { API } from '../api.js';
import { UI } from '../ui.js';

export const SandboxPage = {
  async render() {
    const main = document.getElementById('appMain');
    if (!main) return;

    main.innerHTML = `
      <div class="page-header">
        <div>
          <h1>Sandbox</h1>
          <p>Dynamic analysis detonation and behavioral monitoring</p>
        </div>
        <div class="page-header-actions">
          <button class="btn btn-primary" id="refreshSandboxBtn">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="23 4 23 10 17 10"></polyline>
              <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
            </svg>
            Refresh
          </button>
        </div>
      </div>

      <div class="stat-grid" id="sandboxStats">
        <div class="stat-card">
          <div class="label">Sandbox Status</div>
          <div class="value" id="sandboxStatus">—</div>
        </div>
        <div class="stat-card">
          <div class="label">Active Tasks</div>
          <div class="value" id="activeTasks">—</div>
        </div>
        <div class="stat-card">
          <div class="label">Completed Today</div>
          <div class="value" id="completedToday">—</div>
        </div>
        <div class="stat-card">
          <div class="label">Queue Depth</div>
          <div class="value" id="queueDepth">—</div>
        </div>
      </div>

      <div class="tabs">
        <button class="tab-btn active" data-tab="profiles">Profiles</button>
        <button class="tab-btn" data-tab="active">Active Tasks</button>
        <button class="tab-btn" data-tab="history">History</button>
        <button class="tab-btn" data-tab="submit">Submit Sample</button>
      </div>

      <div class="tab-content active" id="tab-profiles">
        <div class="card">
          <div id="profilesTable">${UI.showLoading()}</div>
        </div>
      </div>

      <div class="tab-content" id="tab-active">
        <div class="card">
          <div id="activeTasksTable">${UI.showLoading()}</div>
        </div>
      </div>

      <div class="tab-content" id="tab-history">
        <div class="card">
          <div id="historyTable">${UI.showLoading()}</div>
        </div>
      </div>

      <div class="tab-content" id="tab-submit">
        <div class="card">
          <div class="card-header"><h2>Submit Sample for Dynamic Analysis</h2></div>
          <div id="submitForm">${this.renderSubmitForm()}</div>
        </div>
      </div>
    `;

    this.setupEventListeners();
    await this.loadProfiles();
    await this.loadActiveTasks();
    await this.loadHistory();
  },

  renderSubmitForm() {
    return `
      <div class="dropzone" id="sandboxDropzone">
        <div class="icon">&#8593;</div>
        <div class="primary">Drop sample here, or click to browse</div>
        <div class="secondary">Executables, documents, archives. Max 250 MB.</div>
      </div>
      <input type="file" id="sandboxFileInput" style="display:none;">
      
      <div class="form-row" style="margin-top:1.5rem;">
        <div class="form-group">
          <label>Sandbox Profile</label>
          <select id="sandboxProfile" style="width:100%;">
            <option value="">Auto-detect from file type</option>
          </select>
        </div>
        <div class="form-group">
          <label>Timeout (seconds)</label>
          <input type="number" id="sandboxTimeout" value="600" min="60" max="3600" style="width:100%;">
        </div>
      </div>
      
      <div class="form-actions">
        <button class="btn btn-primary" id="submitToSandbox" disabled>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
            <polyline points="17 8 12 3 7 8"></polyline>
            <line x1="12" y1="3" x2="12" y2="15"></line>
          </svg>
          Submit to Sandbox
        </button>
      </div>
      
      <div id="submissionResult" style="margin-top:1rem;"></div>
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
      });
    });

    // Refresh button
    document.getElementById('refreshSandboxBtn')?.addEventListener('click', async () => {
      await Promise.all([
        this.loadProfiles(),
        this.loadActiveTasks(),
        this.loadHistory(),
      ]);
    });

    // Submit form
    const dropzone = document.getElementById('sandboxDropzone');
    const fileInput = document.getElementById('sandboxFileInput');
    const submitBtn = document.getElementById('submitToSandbox');

    let selectedFile = null;

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

    this.handleFileSelect = (file) => {
      if (file.size > 250 * 1024 * 1024) {
        UI.toast('File exceeds 250 MB limit', 'error');
        return;
      }
      selectedFile = file;
      dropzone.innerHTML = `
        <div class="icon" style="color:var(--safe)">✓</div>
        <div class="primary" style="color:var(--safe)">${file.name}</div>
        <div class="secondary">${UI.formatBytes(file.size)}</div>
      `;
      submitBtn.disabled = false;
    };

    submitBtn?.addEventListener('click', async () => {
      if (!selectedFile) return;
      
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span class="spinner spinner-sm"></span> Submitting...';
      
      try {
        const profile = document.getElementById('sandboxProfile').value || null;
        const timeout = parseInt(document.getElementById('sandboxTimeout').value);
        
        // First upload the file
        const uploadResult = await API.uploadFile(selectedFile);
        
        // Then trigger sandbox
        const result = await API.triggerSandbox(uploadResult.sample_id, profile);
        
        document.getElementById('submissionResult').innerHTML = `
          <div style="background:var(--safe-dim);border:1px solid var(--safe);border-radius:var(--radius);padding:1rem;color:var(--safe);">
            <strong>Submitted successfully!</strong>
            <div class="mono" style="margin-top:0.5rem;">Task ID: ${result.task_id}</div>
            <div style="font-size:12px;margin-top:0.25rem;">Sample ID: ${uploadResult.sample_id}</div>
          </div>
        `;
        
        UI.toast('Sample submitted to sandbox', 'success');
        selectedFile = null;
        fileInput.value = '';
        dropzone.innerHTML = `
          <div class="icon">&#8593;</div>
          <div class="primary">Drop sample here, or click to browse</div>
          <div class="secondary">Executables, documents, archives. Max 250 MB.</div>
        `;
        submitBtn.disabled = true;
        submitBtn.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
            <polyline points="17 8 12 3 7 8"></polyline>
            <line x1="12" y1="3" x2="12" y2="15"></line>
          </svg>
          Submit to Sandbox
        `;
        
        // Refresh active tasks
        await this.loadActiveTasks();
      } catch (error) {
        UI.toast(`Submission failed: ${error.message}`, 'error');
        submitBtn.disabled = false;
        submitBtn.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
            <polyline points="17 8 12 3 7 8"></polyline>
            <line x1="12" y1="3" x2="12" y2="15"></line>
          </svg>
          Submit to Sandbox
        `;
      }
    });
  },

  async loadProfiles() {
    const container = document.getElementById('profilesTable');
    if (!container) return;

    try {
      const profiles = await API.getSandboxProfiles();
      const select = document.getElementById('sandboxProfile');
      
      if (select) {
        // Clear existing options except first
        while (select.options.length > 1) select.remove(1);
        
        Object.entries(profiles).forEach(([key, value]) => {
          if (value && value !== 'unavailable-requires-apple-silicon-host' && value !== 'static-analysis-only') {
            const opt = document.createElement('option');
            opt.value = key;
            opt.textContent = `${key} (${value})`;
            select.appendChild(opt);
          }
        });
      }

      container.innerHTML = UI.renderTable(
        [
          { field: 'key', label: 'Profile', render: (v, r) => `<strong>${v}</strong>` },
          { field: 'value', label: 'VM Template' },
          { field: 'status', label: 'Status', render: (v, r) => {
            if (r.value === 'unavailable-requires-apple-silicon-host') {
              return UI.createPill('Unavailable (macOS)', 'warning');
            }
            if (r.value === 'static-analysis-only') {
              return UI.createPill('Static Only (iOS)', 'warning');
            }
            return UI.createPill('Available', 'safe');
          }},
        ],
        Object.entries(profiles).map(([key, value]) => ({ key, value })),
        { emptyMessage: 'No sandbox profiles configured' }
      );
    } catch (error) {
      container.innerHTML = UI.showEmptyState('', 'Failed to load sandbox profiles', '⚠');
    }
  },

  async loadActiveTasks() {
    const container = document.getElementById('activeTasksTable');
    if (!container) return;

    // Note: Would need backend endpoint for active sandbox tasks
    container.innerHTML = UI.showEmptyState('', 'No active sandbox tasks', '📋');
  },

  async loadHistory() {
    const container = document.getElementById('historyTable');
    if (!container) return;

    // Note: Would need backend endpoint for sandbox history
    container.innerHTML = UI.showEmptyState('', 'Sandbox history not available', '📋');
  },

  refresh() {
    this.loadProfiles();
    this.loadActiveTasks();
    this.loadHistory();
  },
};