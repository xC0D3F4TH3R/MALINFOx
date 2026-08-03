// Dashboard Page
// Main analyst dashboard with stats, recent samples, and quick actions

import { API } from '../api.js';
import { UI } from '../ui.js';

export const Dashboard = {
  async render() {
    const main = document.getElementById('appMain');
    if (!main) return;

    main.innerHTML = `
      <div class="page-header">
        <div>
          <h1>Dashboard</h1>
          <p>Overview of analysis activity and threat landscape</p>
        </div>
        <div class="page-header-actions">
          <button class="btn btn-primary" id="quickUploadBtn">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="12" y1="5" x2="12" y2="19"></line>
              <line x1="5" y1="12" x2="19" y2="12"></line>
            </svg>
            Upload Sample
          </button>
        </div>
      </div>

      <div class="stat-grid" id="statGrid">
        <div class="stat-card">
          <div class="label">Total Samples</div>
          <div class="value" id="stat-total">—</div>
          <div class="trend" id="stat-total-trend"></div>
        </div>
        <div class="stat-card">
          <div class="label">Malicious</div>
          <div class="value danger" id="stat-malicious">—</div>
          <div class="trend" id="stat-malicious-trend"></div>
        </div>
        <div class="stat-card">
          <div class="label">Suspicious</div>
          <div class="value warn" id="stat-suspicious">—</div>
          <div class="trend" id="stat-suspicious-trend"></div>
        </div>
        <div class="stat-card">
          <div class="label">Clean</div>
          <div class="value safe" id="stat-clean">—</div>
          <div class="trend" id="stat-clean-trend"></div>
        </div>
      </div>

      <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 1.5rem;">
        <div class="card">
          <div class="card-header">
            <h2>Recent Samples</h2>
            <a href="#samples" class="btn btn-ghost btn-sm">View All</a>
          </div>
          <div id="recentSamplesTable">
            ${UI.showLoading()}
          </div>
        </div>

        <div style="display: flex; flex-direction: column; gap: 1rem;">
          <div class="card">
            <div class="card-header">
              <h2>Threat Summary</h2>
            </div>
            <div id="threatSummary">
              ${UI.showLoading()}
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <h2>Top IOCs</h2>
            </div>
            <div id="topIocs">
              ${UI.showLoading()}
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <h2>Sandbox Queue</h2>
            </div>
            <div id="sandboxQueue">
              ${UI.showLoading()}
            </div>
          </div>
        </div>
      </div>
    `;

    // Setup event listeners
    document.getElementById('quickUploadBtn')?.addEventListener('click', () => {
      UI.showModal('uploadModal');
    });

    // Load initial data
    await this.refresh();
  },

  async refresh() {
    try {
      // Load stats and recent samples in parallel
      const [samples, stats] = await Promise.all([
        API.getSamples({ limit: 10 }),
        this.loadStats(),
      ]);

      this.renderStats(stats);
      this.renderRecentSamples(samples);
      await this.loadThreatSummary();
      await this.loadTopIOCs();
      await this.loadSandboxQueue();
    } catch (error) {
      console.error('[Dashboard] Refresh failed:', error);
      UI.toast('Failed to load dashboard data', 'error');
    }
  },

  async loadStats() {
    try {
      const samples = await API.getSamples({ limit: 1000 });
      const total = samples.length;
      const malicious = samples.filter(s => s.verdict === 'malicious').length;
      const suspicious = samples.filter(s => s.verdict === 'suspicious').length;
      const clean = samples.filter(s => s.verdict === 'clean').length;
      
      return { total, malicious, suspicious, clean };
    } catch {
      return { total: 0, malicious: 0, suspicious: 0, clean: 0 };
    }
  },

  renderStats(stats) {
    document.getElementById('stat-total').textContent = stats.total;
    document.getElementById('stat-malicious').textContent = stats.malicious;
    document.getElementById('stat-suspicious').textContent = stats.suspicious;
    document.getElementById('stat-clean').textContent = stats.clean;
  },

  renderRecentSamples(samples) {
    const container = document.getElementById('recentSamplesTable');
    if (!container) return;

    if (!samples.length) {
      container.innerHTML = UI.showEmptyState('', 'No samples analyzed yet. Upload a file to get started.');
      return;
    }

    container.innerHTML = UI.renderTable(
      [
        { field: 'original_filename', label: 'File', render: (v, r) => `
          <div style="font-weight:500">${UI.escapeHtml(v)}</div>
          <div class="mono" style="font-size:11px;color:var(--text-muted)">${r.sha256?.slice(0, 24)}…</div>
        ` },
        { field: 'file_type', label: 'Type' },
        { field: 'file_size', label: 'Size', render: v => UI.formatBytes(v) },
        { field: 'verdict', label: 'Verdict', render: v => UI.createPill(v, v) },
        { field: 'risk_score', label: 'Risk', render: v => `<span class="mono">${v}</span>` },
        { field: 'created_at', label: 'Submitted', render: v => UI.formatRelativeTime(v) },
      ],
      samples,
      { clickable: true, keyField: 'id', emptyMessage: 'No samples yet' }
    );
  },

  async loadThreatSummary() {
    const container = document.getElementById('threatSummary');
    if (!container) return;

    try {
      // Get recent malicious samples for threat summary
      const samples = await API.getSamples({ limit: 50 });
      const malicious = samples.filter(s => s.verdict === 'malicious').slice(0, 5);
      
      if (!malicious.length) {
        container.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:1rem">No recent threats detected</p>';
        return;
      }

      container.innerHTML = malicious.map(s => `
        <div style="padding:0.75rem 0;border-bottom:1px solid var(--line);">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.25rem;">
            <strong>${UI.escapeHtml(s.original_filename)}</strong>
            ${UI.createPill(s.verdict, s.verdict)}
          </div>
          <div style="font-size:12px;color:var(--text-secondary)">
            ${UI.formatRelativeTime(s.created_at)} • ${UI.escapeHtml(s.file_type)} • Risk: ${s.risk_score}
          </div>
        </div>
      `).join('');
    } catch (error) {
      container.innerHTML = '<p style="color:var(--danger);text-align:center;padding:1rem">Failed to load threat summary</p>';
    }
  },

  async loadTopIOCs() {
    const container = document.getElementById('topIocs');
    if (!container) return;

    try {
      const samples = await API.getSamples({ limit: 100 });
      const iocCounts = {};
      
      samples.forEach(s => {
        if (s.iocs) {
          s.iocs.forEach(ioc => {
            const key = `${ioc.ioc_type}:${ioc.value}`;
            if (!iocCounts[key]) {
              iocCounts[key] = { type: ioc.ioc_type, value: ioc.value, count: 0 };
            }
            iocCounts[key].count++;
          });
        }
      });

      const topIocs = Object.values(iocCounts)
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);

      if (!topIocs.length) {
        container.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:1rem">No IOCs extracted yet</p>';
        return;
      }

      container.innerHTML = topIocs.map(ioc => `
        <div style="padding:0.5rem 0;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;">
          <div>
            <span class="badge-tag">${ioc.type}</span>
            <code class="mono" style="margin-left:0.5rem">${UI.escapeHtml(ioc.value)}</code>
          </div>
          <span class="mono" style="color:var(--text-muted)">${ioc.count} samples</span>
        </div>
      `).join('');
    } catch (error) {
      container.innerHTML = '<p style="color:var(--danger);text-align:center;padding:1rem">Failed to load IOCs</p>';
    }
  },

  async loadSandboxQueue() {
    const container = document.getElementById('sandboxQueue');
    if (!container) return;

    try {
      const status = await API.getMonitoringStatus();
      
      container.innerHTML = `
        <div style="display:flex;justify-content:space-between;padding:0.5rem 0;border-bottom:1px solid var(--line);">
          <span>Sandbox Status</span>
          <span class="pill ${status.sandbox_enabled ? 'safe' : 'unknown'}">${status.sandbox_enabled ? 'Enabled' : 'Disabled'}</span>
        </div>
        <div style="display:flex;justify-content:space-between;padding:0.5rem 0;border-bottom:1px solid var(--line);">
          <span>Queue Size</span>
          <span class="mono">${status.pending_queue_size || 0}</span>
        </div>
        <div style="display:flex;justify-content:space-between;padding:0.5rem 0;">
          <span>Results Cached</span>
          <span class="mono">${status.results_cached || 0}</span>
        </div>
      `;
    } catch (error) {
      container.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:1rem">Sandbox not available</p>';
    }
  },

  updateStats(data) {
    if (data.total !== undefined) document.getElementById('stat-total').textContent = data.total;
    if (data.malicious !== undefined) document.getElementById('stat-malicious').textContent = data.malicious;
    if (data.suspicious !== undefined) document.getElementById('stat-suspicious').textContent = data.suspicious;
    if (data.clean !== undefined) document.getElementById('stat-clean').textContent = data.clean;
  },

  handleAnalysisUpdate(data) {
    // Refresh dashboard on analysis completion
    if (data.status === 'complete') {
      this.refresh();
    }
  },
};