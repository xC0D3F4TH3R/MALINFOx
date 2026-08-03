// Network Page
// Network flow analysis and C2 detection

import { API } from '../api.js';
import { UI } from '../ui.js';

export const NetworkPage = {
  currentFilters: {
    suspiciousOnly: true,
    minPackets: 5,
  },

  async render() {
    const main = document.getElementById('appMain');
    if (!main) return;

    main.innerHTML = `
      <div class="page-header">
        <div>
          <h1>Network Forensics</h1>
          <p>Network flow analysis, beaconing detection, and C2 identification</p>
        </div>
        <div class="page-header-actions">
          <button class="btn btn-primary" id="refreshNetworkBtn">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="23 4 23 10 17 10"></polyline>
              <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
            </svg>
            Refresh
          </button>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h2>Network Flows</h2>
          <div style="display:flex;gap:1rem;align-items:center;">
            <label style="display:flex;align-items:center;gap:0.5rem;font-weight:normal;cursor:pointer;">
              <input type="checkbox" id="suspiciousOnlyFilter" checked> Suspicious only
            </label>
            <div class="form-group" style="width:120px;">
              <select id="minPacketsFilter" style="width:100%;">
                <option value="1">1+ packets</option>
                <option value="5" selected>5+ packets</option>
                <option value="10">10+ packets</option>
                <option value="25">25+ packets</option>
                <option value="50">50+ packets</option>
              </select>
            </div>
          </div>
        </div>
        <div id="networkFlowsTable">${UI.showLoading()}</div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-top:1.5rem;">
        <div class="card">
          <div class="card-header"><h2>Beaconing Candidates</h2></div>
          <div id="beaconingTable">${UI.showLoading()}</div>
        </div>
        <div class="card">
          <div class="card-header"><h2>C2 Server Details</h2></div>
          <div id="c2Table">${UI.showLoading()}</div>
        </div>
      </div>
    `;

    this.setupEventListeners();
    await this.loadFlows();
    await this.loadBeaconing();
    await this.loadC2Details();
  },

  setupEventListeners() {
    const suspiciousFilter = document.getElementById('suspiciousOnlyFilter');
    const minPacketsFilter = document.getElementById('minPacketsFilter');
    const refreshBtn = document.getElementById('refreshNetworkBtn');

    suspiciousFilter?.addEventListener('change', (e) => {
      this.currentFilters.suspiciousOnly = e.target.checked;
      this.loadFlows();
    });

    minPacketsFilter?.addEventListener('change', (e) => {
      this.currentFilters.minPackets = parseInt(e.target.value);
      this.loadFlows();
    });

    refreshBtn?.addEventListener('click', () => {
      this.loadFlows();
      this.loadBeaconing();
      this.loadC2Details();
    });
  },

  async loadFlows() {
    const container = document.getElementById('networkFlowsTable');
    if (!container) return;

    container.innerHTML = UI.showLoading();

    try {
      const flows = await API.getNetworkFlows({
        suspicious_only: this.currentFilters.suspiciousOnly,
        min_packets: this.currentFilters.minPackets,
      });

      this.renderFlows(flows);
    } catch (error) {
      container.innerHTML = UI.showEmptyState('', 'Network monitoring not enabled or failed to load', '📡');
    }
  },

  renderFlows(flows) {
    const container = document.getElementById('networkFlowsTable');
    if (!container) return;

    if (!flows.length) {
      container.innerHTML = UI.showEmptyState('', 'No network flows detected');
      return;
    }

    container.innerHTML = UI.renderTable(
      [
        { field: 'src_ip', label: 'Source IP' },
        { field: 'src_port', label: 'Src Port' },
        { field: 'dst_ip', label: 'Destination IP' },
        { field: 'dst_port', label: 'Dst Port' },
        { field: 'protocol', label: 'Proto' },
        { field: 'start_time', label: 'Start', render: v => UI.formatRelativeTime(v) },
        { field: 'end_time', label: 'End', render: v => v ? UI.formatRelativeTime(v) : 'Active' },
        { field: 'bytes_sent', label: 'Sent', render: v => UI.formatBytes(v) },
        { field: 'bytes_recv', label: 'Recv', render: v => UI.formatBytes(v) },
        { field: 'packet_count', label: 'Packets', render: v => `<span class="mono">${v}</span>` },
        { field: 'process_name', label: 'Process' },
      ],
      flows,
      { emptyMessage: 'No flows found' }
    );
  },

  async loadBeaconing() {
    const container = document.getElementById('beaconingTable');
    if (!container) return;

    try {
      const flows = await API.getNetworkFlows({ suspicious_only: true, min_packets: 5 });
      
      // Filter for potential beaconing (regular intervals)
      const beaconing = flows.filter(f => {
        if (!f.start_time || !f.end_time) return false;
        const duration = new Date(f.end_time) - new Date(f.start_time);
        const interval = duration / Math.max(f.packet_count - 1, 1);
        return interval > 10000 && interval < 3600000 && f.packet_count >= 5; // 10s to 1h interval
      });

      if (!beaconing.length) {
        container.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:1rem">No beaconing patterns detected</p>';
        return;
      }

      container.innerHTML = UI.renderTable(
        [
          { field: 'dst_ip', label: 'Destination IP' },
          { field: 'dst_port', label: 'Port' },
          { field: 'protocol', label: 'Proto' },
          { field: 'packet_count', label: 'Check-ins', render: v => `<span class="mono">${v}</span>` },
          { field: 'start_time', label: 'First Seen', render: v => UI.formatRelativeTime(v) },
          { field: 'end_time', label: 'Last Seen', render: v => UI.formatRelativeTime(v) },
          { field: 'interval', label: 'Avg Interval', render: (v, r) => {
            if (!r.start_time || !r.end_time) return '—';
            const duration = new Date(r.end_time) - new Date(r.start_time);
            const interval = duration / Math.max(r.packet_count - 1, 1);
            return `${(interval / 1000).toFixed(1)}s`;
          }},
        ],
        beaconing,
        { emptyMessage: 'No beaconing candidates' }
      );
    } catch (error) {
      container.innerHTML = '<p style="color:var(--danger);text-align:center;padding:1rem">Failed to load beaconing data</p>';
    }
  },

  async loadC2Details() {
    const container = document.getElementById('c2Table');
    if (!container) return;

    try {
      // Get recent malicious samples with network reports
      const samples = await API.getSamples({ limit: 50 });
      const maliciousWithNetwork = samples.filter(s => 
        s.verdict === 'malicious' && s.network_report?.available
      ).slice(0, 10);

      if (!maliciousWithNetwork.length) {
        container.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:1rem">No C2 servers identified</p>';
        return;
      }

      container.innerHTML = maliciousWithNetwork.map(s => {
        const netReport = s.network_report || {};
        const c2Servers = netReport.c2_servers || [];
        
        return c2Servers.map(c2 => `
          <div style="padding:0.75rem;border:1px solid var(--line);border-radius:var(--radius);margin-bottom:0.5rem;background:var(--panel-raised);">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
              <strong>${UI.escapeHtml(c2.ip || c2.domain || 'Unknown')}</strong>
              ${UI.createPill(`${Math.round(c2.confidence * 100)}%`, c2.confidence > 0.7 ? 'danger' : c2.confidence > 0.4 ? 'warn' : 'unknown')}
            </div>
            <div style="font-size:12px;color:var(--text-secondary);margin-bottom:0.25rem;">
              ${c2.associated_domains?.map(d => UI.createTag(d)).join(' ') || 'No associated domains'}
            </div>
            <div style="font-size:11px;color:var(--text-muted);">
              Check-ins: ${c2.check_in_count || 'N/A'} • Interval: ${c2.mean_interval_sec ? c2.mean_interval_sec + 's' : 'N/A'}
            </div>
            <div style="font-size:11px;color:var(--text-muted);margin-top:0.25rem;">
              ${c2.reasons?.join('; ') || 'Network correlation'}
            </div>
          </div>
        `).join('');
      }).join('');
    } catch (error) {
      container.innerHTML = '<p style="color:var(--danger);text-align:center;padding:1rem">Failed to load C2 details</p>';
    }
  },

  refresh() {
    this.loadFlows();
    this.loadBeaconing();
    this.loadC2Details();
  },
};