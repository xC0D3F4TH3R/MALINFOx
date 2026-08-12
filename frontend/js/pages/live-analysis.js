// Live Analysis Dashboard Page
// Real-time dynamic analysis monitoring with process tree, network graph, timeline, MITRE heatmap

import { API } from '../api.js';
import { UI } from '../ui.js';

export const LiveAnalysisPage = {
  currentTaskId: null,
  ws: null,
  taskData: null,
  updateInterval: null,
  
  async render() {
    const main = document.getElementById('appMain');
    if (!main) return;

    // Get task ID from hash if available
    const hash = window.location.hash.slice(1);
    if (hash.startsWith('live-analysis/')) {
      this.currentTaskId = hash.split('/')[1];
    }

    main.innerHTML = `
      <div class="page-header">
        <div>
          <h1>Live Analysis</h1>
          <p id="taskSubtitle">${this.currentTaskId ? `Task: ${this.currentTaskId.slice(0,8)}...` : 'No active analysis task'}</p>
        </div>
        <div class="page-header-actions">
          <button class="btn btn-primary" id="refreshLiveBtn" disabled>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="23 4 23 10 17 10"></polyline>
              <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
            </svg>
            Refresh
          </button>
          ${this.currentTaskId ? `
          <button class="btn" id="viewReportBtn">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
              <polyline points="14 2 14 8 20 8"></polyline>
              <line x1="16" y1="13" x2="8" y2="13"></line>
              <line x1="16" y1="17" x2="8" y2="17"></line>
              <polyline points="10 9 9 9 8 9"></polyline>
            </svg>
            View Report
          </button>
          ` : ''}
        </div>
      </div>

      ${this.currentTaskId ? this.renderLiveDashboard() : this.renderTaskSelector()}
    `;

    this.setupEventListeners();
    
    if (this.currentTaskId) {
      await this.loadTaskData();
      this.connectWebSocket();
      this.startPeriodicUpdates();
    }
  },

  renderTaskSelector() {
    return `
      <div class="card" style="max-width: 800px; margin: 2rem auto;">
        <div class="card-header"><h2>Select Analysis Task</h2></div>
        <div class="card-body">
          <div class="form-group" style="margin-bottom: 1.5rem;">
            <label>Recent Analysis Tasks</label>
            <select id="taskSelector" style="width: 100%;">
              <option value="">Loading tasks...</option>
            </select>
          </div>
          <div class="form-actions">
            <button class="btn btn-primary" id="goToLiveBtn" disabled>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                <polyline points="15 3 21 3 21 9"></path>
                <line x1="10" y1="14" x2="21" y2="3"></line>
              </svg>
              Open Live View
            </button>
          </div>
        </div>
      </div>
    `;
  },

  renderLiveDashboard() {
    return `
      <!-- Status Bar -->
      <div class="stat-grid" id="liveStats">
        <div class="stat-card">
          <div class="label">Status</div>
          <div class="value" id="liveStatus">
            <span class="spinner spinner-sm"></span> Connecting...
          </div>
        </div>
        <div class="stat-card">
          <div class="label">Progress</div>
          <div class="value" id="liveProgress">0%</div>
        </div>
        <div class="stat-card">
          <div class="label">MalScore</div>
          <div class="value" id="liveMalScore">—</div>
        </div>
        <div class="stat-card">
          <div class="label">Duration</div>
          <div class="value" id="liveDuration">0s</div>
        </div>
        <div class="stat-card">
          <div class="label">Processes</div>
          <div class="value" id="liveProcesses">0</div>
        </div>
        <div class="stat-card">
          <div class="label">Network Events</div>
          <div class="value" id="liveNetwork">0</div>
        </div>
        <div class="stat-card">
          <div class="label">File Events</div>
          <div class="value" id="liveFiles">0</div>
        </div>
        <div class="stat-card">
          <div class="label">MITRE Techniques</div>
          <div class="value" id="liveMitre">0</div>
        </div>
      </div>

      <!-- Main Dashboard Grid -->
      <div class="dashboard-grid">
        <!-- Process Tree Panel -->
        <div class="dashboard-panel" style="grid-column: span 2;">
          <div class="panel-header">
            <h3>Process Tree</h3>
            <div class="panel-actions">
              <button class="btn btn-sm" id="expandProcessTree">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M15 3h6v6"></path>
                  <path d="M9 21H3v-6"></path>
                  <line x1="21" y1="3" x2="14" y2="10"></line>
                  <line x1="3" y1="21" x2="10" y2="14"></line>
                </svg>
              </button>
            </div>
          </div>
          <div class="panel-body" style="height: 400px; overflow: auto;" id="processTreeContainer">
            <div id="processTree">${UI.showLoading()}</div>
          </div>
        </div>

        <!-- Timeline Panel -->
        <div class="dashboard-panel" style="grid-column: span 2;">
          <div class="panel-header">
            <h3>Event Timeline</h3>
            <div class="panel-actions">
              <select id="timelineFilter" style="font-size: 12px; padding: 0.25rem;">
                <option value="all">All Events</option>
                <option value="process">Process</option>
                <option value="network">Network</option>
                <option value="file">File</option>
                <option value="registry">Registry</option>
                <option value="api">API Calls</option>
              </select>
            </div>
          </div>
          <div class="panel-body" style="height: 400px; overflow: auto;" id="timelineContainer">
            <div id="eventTimeline">${UI.showLoading()}</div>
          </div>
        </div>

        <!-- Network Graph Panel -->
        <div class="dashboard-panel" style="grid-column: span 2;">
          <div class="panel-header">
            <h3>Network Connections</h3>
            <div class="panel-actions">
              <button class="btn btn-sm" id="exportPcap">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                  <polyline points="17 8 12 3 7 8"></path>
                  <line x1="12" y1="3" x2="12" y2="15"></line>
                </svg>
                PCAP
              </button>
            </div>
          </div>
          <div class="panel-body" style="height: 300px;" id="networkGraphContainer">
            <canvas id="networkCanvas" style="width: 100%; height: 100%;"></canvas>
            <div id="networkList" style="display: none; height: 100%; overflow: auto;"></div>
          </div>
        </div>

        <!-- MITRE ATT&CK Heatmap Panel -->
        <div class="dashboard-panel" style="grid-column: span 2;">
          <div class="panel-header">
            <h3>MITRE ATT&CK Techniques</h3>
          </div>
          <div class="panel-body" style="height: 300px; overflow: auto;" id="mitreContainer">
            <div id="mitreHeatmap">${UI.showLoading()}</div>
          </div>
        </div>

        <!-- Signatures/Alerts Panel -->
        <div class="dashboard-panel" style="grid-column: span 2;">
          <div class="panel-header">
            <h3>Signatures & Alerts</h3>
          </div>
          <div class="panel-body" style="height: 300px; overflow: auto;" id="signaturesContainer">
            <div id="signaturesList">${UI.showLoading()}</div>
          </div>
        </div>

        <!-- Dropped Files Panel -->
        <div class="dashboard-panel" style="grid-column: span 2;">
          <div class="panel-header">
            <h3>Dropped Files</h3>
          </div>
          <div class="panel-body" style="height: 250px; overflow: auto;" id="droppedFilesContainer">
            <div id="droppedFilesList">${UI.showLoading()}</div>
          </div>
        </div>

        <!-- Screenshots Panel -->
        <div class="dashboard-panel" style="grid-column: span 2;">
          <div class="panel-header">
            <h3>Screenshots</h3>
          </div>
          <div class="panel-body" style="height: 250px; overflow: auto;" id="screenshotsContainer">
            <div id="screenshotsGallery" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 1rem;">
              ${UI.showLoading()}
            </div>
          </div>
        </div>
      </div>

      <!-- WebSocket Status Indicator -->
      <div id="wsStatus" class="ws-status disconnected" style="position: fixed; bottom: 1rem; right: 1rem; z-index: 1000;">
        <span class="ws-dot"></span>
        <span>Disconnected</span>
      </div>
    `;
  },

  setupEventListeners() {
    // Task selector
    document.getElementById('goToLiveBtn')?.addEventListener('click', () => {
      const taskId = document.getElementById('taskSelector').value;
      if (taskId) {
        window.location.hash = `live-analysis/${taskId}`;
      }
    });

    document.getElementById('taskSelector')?.addEventListener('change', (e) => {
      document.getElementById('goToLiveBtn').disabled = !e.target.value;
    });

    // Live dashboard actions
    document.getElementById('refreshLiveBtn')?.addEventListener('click', () => this.loadTaskData());
    document.getElementById('viewReportBtn')?.addEventListener('click', () => {
      if (this.currentTaskId) {
        window.open(`/api/vm/tasks/${this.currentTaskId}/report?format=html`, '_blank');
      }
    });

    document.getElementById('expandProcessTree')?.addEventListener('click', () => {
      this.renderProcessTree(this.taskData, true);
    });

    document.getElementById('timelineFilter')?.addEventListener('change', (e) => {
      this.renderTimeline(this.taskData, e.target.value);
    });

    document.getElementById('exportPcap')?.addEventListener('click', () => {
      if (this.currentTaskId) {
        window.open(`/api/vm/tasks/${this.currentTaskId}/pcap`, '_blank');
      }
    });
  },

  async loadTasksForSelector() {
    try {
      const tasks = await API.getVMTasks({ limit: 50 });
      const select = document.getElementById('taskSelector');
      if (select) {
        select.innerHTML = '<option value="">Select a task...</option>';
        tasks.forEach(t => {
          const opt = document.createElement('option');
          opt.value = t.id;
          const status = t.state;
          opt.textContent = `${t.id.slice(0,8)}... | ${status} | ${t.malscore}/100 | ${UI.formatDate(t.created_at)}`;
          select.appendChild(opt);
        });
      }
    } catch (error) {
      console.error('Failed to load tasks:', error);
    }
  },

  async loadTaskData() {
    if (!this.currentTaskId) return;
    
    try {
      const task = await API.getVMTask(this.currentTaskId);
      this.taskData = task;
      this.updateDashboard(task);
    } catch (error) {
      console.error('Failed to load task data:', error);
      UI.toast('Failed to load task data', 'error');
    }
  },

  updateDashboard(task) {
    // Update status bar
    const statusEl = document.getElementById('liveStatus');
    const progressEl = document.getElementById('liveProgress');
    const malScoreEl = document.getElementById('liveMalScore');
    const durationEl = document.getElementById('liveDuration');
    const processesEl = document.getElementById('liveProcesses');
    const networkEl = document.getElementById('liveNetwork');
    const filesEl = document.getElementById('liveFiles');
    const mitreEl = document.getElementById('liveMitre');

    if (statusEl) {
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
      const s = states[task.state] || { label: task.state, class: 'info' };
      statusEl.innerHTML = `<span class="pill ${s.class}">${s.label}</span>`;
    }

    if (progressEl) progressEl.textContent = `${task.progress || 0}%`;
    if (malScoreEl) {
      const cls = task.malscore >= 80 ? 'danger' : task.malscore >= 40 ? 'warn' : task.malscore >= 20 ? 'info' : 'safe';
      malScoreEl.innerHTML = `<span style="color: var(--${cls}); font-weight: 600;">${task.malscore}/100</span>`;
    }
    
    if (durationEl && task.started_at) {
      const start = new Date(task.started_at).getTime();
      const end = task.completed_at ? new Date(task.completed_at).getTime() : Date.now();
      const duration = Math.round((end - start) / 1000);
      durationEl.textContent = `${duration}s`;
    }

    if (processesEl) processesEl.textContent = task.processes_count || 0;
    if (networkEl) networkEl.textContent = task.network_events_count || 0;
    if (filesEl) filesEl.textContent = task.file_events_count || 0;
    if (mitreEl) mitreEl.textContent = task.mitre_techniques?.length || 0;

    // Update panels
    this.renderProcessTree(task);
    this.renderTimeline(task);
    this.renderNetworkGraph(task);
    this.renderMitreHeatmap(task);
    this.renderSignatures(task);
    this.renderDroppedFiles(task);
    this.renderScreenshots(task);

    // Update subtitle
    const subtitle = document.getElementById('taskSubtitle');
    if (subtitle) {
      subtitle.textContent = `Task: ${task.id.slice(0,8)}... | Sample: ${task.sample_id?.slice(0,8)}... | ${task.state}`;
    }

    // Enable/disable refresh
    const refreshBtn = document.getElementById('refreshLiveBtn');
    if (refreshBtn) {
      refreshBtn.disabled = ['completed', 'failed'].includes(task.state);
    }
  },

  renderProcessTree(task, expanded = false) {
    const container = document.getElementById('processTree');
    if (!container) return;

    const processes = task.process_tree || [];
    if (processes.length === 0) {
      container.innerHTML = UI.showEmptyState('', 'No process data yet', '🔄');
      return;
    }

    // Build tree structure
    const processMap = new Map();
    const roots = [];

    processes.forEach(p => {
      processMap.set(p.pid, { ...p, children: [] });
    });

    processes.forEach(p => {
      const node = processMap.get(p.pid);
      if (p.ppid && processMap.has(p.ppid)) {
        processMap.get(p.ppid).children.push(node);
      } else {
        roots.push(node);
      }
    });

    const renderNode = (node, depth = 0) => {
      const hasChildren = node.children.length > 0;
      const indent = depth * 20;
      const duration = node.end_time ? 
        Math.round((new Date(node.end_time).getTime() - new Date(node.start_time).getTime()) / 1000) : 
        Math.round((Date.now() - new Date(node.start_time).getTime()) / 1000);
      
      return `
        <div class="process-node" style="padding-left: ${indent}px;">
          <div class="process-row" style="display: flex; align-items: center; gap: 0.5rem; padding: 0.25rem 0;">
            ${hasChildren ? `
              <button class="tree-toggle" data-pid="${node.pid}" style="background: none; border: none; cursor: pointer; padding: 0.25rem; color: var(--text-muted);">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
              </button>
            ` : '<span style="width: 20px;"></span>'}
            <span class="mono" style="font-size: 12px; color: var(--text-muted); min-width: 60px;">PID ${node.pid}</span>
            <strong style="flex: 1;">${node.name}</strong>
            <span class="mono" style="font-size: 11px; color: var(--text-muted);">${node.path || 'unknown'}</span>
            <span style="font-size: 11px; color: var(--text-muted);">${duration}s</span>
            ${node.cmdline ? `<span class="mono" style="font-size: 10px; color: var(--text-muted); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${node.cmdline}</span>` : ''}
          </div>
          ${hasChildren ? `
            <div class="process-children" id="children-${node.pid}" style="display: block;">
              ${node.children.map(c => renderNode(c, depth + 1)).join('')}
            </div>
          ` : ''}
        </div>
      `;
    };

    container.innerHTML = roots.map(r => renderNode(r)).join('');

    // Add toggle handlers
    container.querySelectorAll('.tree-toggle').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const pid = e.currentTarget.dataset.pid;
        const children = document.getElementById(`children-${pid}`);
        const icon = e.currentTarget.querySelector('svg');
        if (children.style.display === 'none') {
          children.style.display = 'block';
          icon.style.transform = 'rotate(0deg)';
        } else {
          children.style.display = 'none';
          icon.style.transform = 'rotate(-90deg)';
        }
      });
    });
  },

  renderTimeline(task, filter = 'all') {
    const container = document.getElementById('eventTimeline');
    if (!container) return;

    const events = [];
    
    // Process events
    if (filter === 'all' || filter === 'process') {
      (task.process_tree || []).forEach(p => {
        events.push({
          time: p.start_time,
          type: 'process_create',
          icon: '🔄',
          title: `Process Started: ${p.name}`,
          detail: `PID ${p.pid} (PPID ${p.ppid}) - ${p.path || 'unknown'}`,
          pid: p.pid
        });
        if (p.end_time) {
          events.push({
            time: p.end_time,
            type: 'process_terminate',
            icon: '⏹️',
            title: `Process Terminated: ${p.name}`,
            detail: `PID ${p.pid} exited`,
            pid: p.pid
          });
        }
      });
    }

    // Network events
    if (filter === 'all' || filter === 'network') {
      (task.network_events || []).forEach(n => {
        events.push({
          time: n.timestamp,
          type: 'network',
          icon: n.event_type === 'connect' ? '🔗' : '🔌',
          title: `Network ${n.event_type}: ${n.process_name}`,
          detail: `${n.src_ip}:${n.src_port} → ${n.dst_ip}:${n.dst_port} (${n.protocol})`,
          pid: n.pid
        });
      });
    }

    // File events
    if (filter === 'all' || filter === 'file') {
      (task.file_events || []).slice(0, 100).forEach(f => {
        events.push({
          time: f.timestamp,
          type: 'file',
          icon: f.event_type === 'create' ? '📄' : f.event_type === 'modify' ? '✏️' : '🗑️',
          title: `File ${f.event_type}: ${f.process_name}`,
          detail: `${f.path} (${f.size} bytes)`,
          pid: f.pid
        });
      });
    }

    // Registry events
    if (filter === 'all' || filter === 'registry') {
      (task.registry_events || []).forEach(r => {
        events.push({
          time: r.timestamp,
          type: 'registry',
          icon: '📋',
          title: `Registry ${r.event_type}: ${r.process_name}`,
          detail: `${r.key}\\${r.value_name} = ${r.value_data?.slice(0,50)}`,
          pid: r.pid
        });
      });
    }

    // API calls
    if (filter === 'all' || filter === 'api') {
      (task.api_calls || []).slice(0, 100).forEach(a => {
        events.push({
          time: a.timestamp,
          type: 'api',
          icon: '⚙️',
          title: `API Call: ${a.api}`,
          detail: `${a.process_name} (PID ${a.pid}) - ${a.module}`,
          pid: a.pid
        });
      });
    }

    // Sort by time
    events.sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime());

    if (events.length === 0) {
      container.innerHTML = UI.showEmptyState('', 'No events yet', '📋');
      return;
    }

    const typeColors = {
      process: 'var(--saffron)',
      network: 'var(--danger)',
      file: 'var(--info)',
      registry: 'var(--safe)',
      api: 'var(--purple)'
    };

    container.innerHTML = `
      <div class="timeline">
        ${events.map(e => `
          <div class="timeline-item" style="border-left-color: ${typeColors[e.type] || 'var(--line)'};">
            <div class="timeline-time">${UI.formatDate(e.time)}</div>
            <div class="timeline-content">
              <div class="timeline-title">
                <span class="timeline-icon">${e.icon}</span>
                <strong>${e.title}</strong>
              </div>
              <div class="timeline-detail mono" style="font-size: 11px; color: var(--text-muted);">${e.detail}</div>
            </div>
          </div>
        `).join('')}
      </div>
    `;
  },

  renderNetworkGraph(task) {
    const container = document.getElementById('networkList');
    const canvas = document.getElementById('networkCanvas');
    
    const connections = task.network_events || [];
    if (connections.length === 0) {
      if (container) container.innerHTML = UI.showEmptyState('', 'No network connections yet', '🌐');
      return;
    }

    // Group by destination
    const destMap = new Map();
    connections.forEach(c => {
      const key = `${c.dst_ip}:${c.dst_port}`;
      if (!destMap.has(key)) {
        destMap.set(key, {
          ip: c.dst_ip,
          port: c.dst_port,
          protocol: c.protocol,
          processes: new Set(),
          count: 0,
          status: c.status
        });
      }
      const entry = destMap.get(key);
      entry.processes.add(c.process_name);
      entry.count++;
    });

    // Simple list view (canvas graph would need a library)
    if (container) {
      container.style.display = 'block';
      if (canvas) canvas.style.display = 'none';
      
      container.innerHTML = `
        <table style="width: 100%; font-size: 12px;">
          <thead>
            <tr style="border-bottom: 1px solid var(--line);">
              <th style="text-align: left; padding: 0.5rem;">Destination</th>
              <th style="text-align: left; padding: 0.5rem;">Port</th>
              <th style="text-align: left; padding: 0.5rem;">Protocol</th>
              <th style="text-align: left; padding: 0.5rem;">Processes</th>
              <th style="text-align: left; padding: 0.5rem;">Connections</th>
              <th style="text-align: left; padding: 0.5rem;">Status</th>
            </tr>
          </thead>
          <tbody>
            ${Array.from(destMap.entries()).map(([key, v]) => `
              <tr style="border-bottom: 1px solid var(--line);">
                <td style="padding: 0.5rem;"><code class="mono">${v.ip}</code></td>
                <td style="padding: 0.5rem;">${v.port}</td>
                <td style="padding: 0.5rem;"><span class="pill info">${v.protocol}</span></td>
                <td style="padding: 0.5rem;">${Array.from(v.processes).join(', ')}</td>
                <td style="padding: 0.5rem;">${v.count}</td>
                <td style="padding: 0.5rem;"><span class="pill ${v.status === 'ESTABLISHED' ? 'safe' : 'info'}">${v.status}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }
  },

  renderMitreHeatmap(task) {
    const container = document.getElementById('mitreHeatmap');
    if (!container) return;

    const techniques = task.mitre_techniques || [];
    
    // MITRE technique categories with common techniques
    const categories = {
      'Initial Access': ['T1566', 'T1190', 'T1133', 'T1078'],
      'Execution': ['T1059', 'T1204', 'T1559', 'T1106'],
      'Persistence': ['T1547', 'T1053', 'T1543', 'T1556'],
      'Privilege Escalation': ['T1068', 'T1055', 'T1548', 'T1484'],
      'Defense Evasion': ['T1027', 'T1055', 'T1070', 'T1112'],
      'Credential Access': ['T1003', 'T1555', 'T1552', 'T1212'],
      'Discovery': ['T1083', 'T1018', 'T1057', 'T1012'],
      'Lateral Movement': ['T1021', 'T1550', 'T1210', 'T1563'],
      'Collection': ['T1005', 'T1119', 'T1114', 'T1039'],
      'Command and Control': ['T1071', 'T1573', 'T1105', 'T1008'],
      'Exfiltration': ['T1041', 'T1020', 'T1048', 'T1567'],
      'Impact': ['T1486', 'T1485', 'T1491', 'T1529']
    };

    const techniqueNames = {
      'T1566': 'Phishing', 'T1190': 'Exploit Public-Facing App', 'T1133': 'External Remote Services',
      'T1078': 'Valid Accounts', 'T1059': 'Command & Scripting', 'T1204': 'User Execution',
      'T1559': 'Inter-Process Communication', 'T1106': 'Native API', 'T1547': 'Boot/Logon Autostart',
      'T1053': 'Scheduled Task', 'T1543': 'Create/Modify System Process', 'T1556': 'Modify Authentication',
      'T1068': 'Exploitation for Privilege Escalation', 'T1055': 'Process Injection', 'T1548': 'Abuse Elevation Control',
      'T1484': 'Domain Policy Modification', 'T1027': 'Obfuscated Files/Info', 'T1070': 'Indicator Removal',
      'T1112': 'Modify Registry', 'T1003': 'OS Credential Dumping', 'T1555': 'Credentials from Password Stores',
      'T1552': 'Unsecured Credentials', 'T1212': 'Exploitation for Credential Access', 'T1083': 'File & Directory Discovery',
      'T1018': 'Remote System Discovery', 'T1057': 'Process Discovery', 'T1012': 'Query Registry',
      'T1021': 'Remote Services', 'T1550': 'Use Alternate Authentication', 'T1210': 'Exploitation for Lateral Movement',
      'T1563': 'Remote Service Session Hijacking', 'T1005': 'Data from Local System', 'T1119': 'Automated Collection',
      'T1114': 'Email Collection', 'T1039': 'Data from Network Shares', 'T1071': 'Application Layer Protocol',
      'T1573': 'Encrypted Channel', 'T1105': 'Ingress Tool Transfer', 'T1008': 'Fallback Channels',
      'T1041': 'Exfiltration Over C2 Channel', 'T1020': 'Automated Exfiltration', 'T1048': 'Exfiltration Over Alternative Protocol',
      'T1567': 'Exfiltration Over Web Service', 'T1486': 'Data Encrypted for Impact', 'T1485': 'Data Destruction',
      'T1491': 'Defacement', 'T1529': 'System Shutdown/Reboot'
    };

    container.innerHTML = `
      <div class="mitre-heatmap">
        ${Object.entries(categories).map(([category, techs]) => `
          <div class="mitre-category">
            <h4 style="color: var(--text-muted); font-size: 11px; text-transform: uppercase; margin-bottom: 0.5rem;">${category}</h4>
            <div class="mitre-technique-grid" style="display: flex; flex-wrap: wrap; gap: 0.25rem;">
              ${techs.map(t => `
                <div class="mitre-technique ${techniques.includes(t) ? 'detected' : ''}" 
                     title="${techniqueNames[t] || t}"
                     style="
                       padding: 0.25rem 0.5rem; 
                       border-radius: 4px; 
                       font-size: 10px; 
                       font-weight: 600;
                       background: ${techniques.includes(t) ? 'var(--danger)' : 'var(--line)'};
                       color: ${techniques.includes(t) ? 'white' : 'var(--text-muted)'};
                       cursor: help;
                     ">
                ${t}
              </div>
              `).join('')}
            </div>
          </div>
        `).join('')}
        ${techniques.length === 0 ? '<p style="color: var(--text-muted); text-align: center; padding: 2rem;">No MITRE techniques detected yet</p>' : ''}
      </div>
    `;
  },

  renderSignatures(task) {
    const container = document.getElementById('signaturesList');
    if (!container) return;

    const signatures = task.signatures || [];
    if (signatures.length === 0) {
      container.innerHTML = UI.showEmptyState('', 'No signatures triggered yet', '🛡️');
      return;
    }

    const severityColors = {
      'critical': 'danger',
      'high': 'danger',
      'medium': 'warn',
      'low': 'info'
    };

    container.innerHTML = signatures.map(s => `
      <div class="signature-item" style="background: var(--card); border: 1px solid var(--line); border-radius: var(--radius); padding: 1rem; margin-bottom: 0.5rem;">
        <div style="display: flex; align-items: flex-start; gap: 1rem;">
          <div style="flex: 1;">
            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
              <strong>${s.description || 'Unknown signature'}</strong>
              <span class="pill ${severityColors[s.severity] || 'info'}">${s.severity || 'unknown'}</span>
            </div>
            <div class="mono" style="font-size: 11px; color: var(--text-muted);">
              ${s.mitre && s.mitre.length > 0 ? s.mitre.map(t => `<span class="pill info" style="font-size: 9px;">${t}</span>`).join(' ') : 'No MITRE mapping'}
            </div>
          </div>
        </div>
      </div>
    `).join('');
  },

  renderDroppedFiles(task) {
    const container = document.getElementById('droppedFilesList');
    if (!container) return;

    const files = task.dropped_files || [];
    if (files.length === 0) {
      container.innerHTML = UI.showEmptyState('', 'No dropped files detected', '📁');
      return;
    }

    container.innerHTML = `
      <table style="width: 100%; font-size: 12px;">
        <thead>
          <tr style="border-bottom: 1px solid var(--line);">
            <th style="text-align: left; padding: 0.5rem;">File</th>
            <th style="text-align: left; padding: 0.5rem;">Hash (SHA256)</th>
            <th style="text-align: left; padding: 0.5rem;">Size</th>
            <th style="text-align: left; padding: 0.5rem;">Time</th>
          </tr>
        </thead>
        <tbody>
          ${files.map(f => `
            <tr style="border-bottom: 1px solid var(--line);">
              <td style="padding: 0.5rem;"><code class="mono">${f.path.split('\\').pop() || f.path.split('/').pop()}</code></td>
              <td style="padding: 0.5rem;"><code class="mono" style="font-size: 10px;">${f.hash?.slice(0,16)}...</code></td>
              <td style="padding: 0.5rem;">${UI.formatBytes(f.size)}</td>
              <td style="padding: 0.5rem;">${UI.formatDate(f.timestamp)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  },

  renderScreenshots(task) {
    const container = document.getElementById('screenshotsGallery');
    if (!container) return;

    const screenshots = task.screenshots || [];
    if (screenshots.length === 0) {
      container.innerHTML = UI.showEmptyState('', 'No screenshots captured yet', '📸');
      return;
    }

    container.innerHTML = screenshots.map((s, i) => `
      <div class="screenshot-item" style="background: var(--card); border: 1px solid var(--line); border-radius: var(--radius); overflow: hidden;">
        <img src="data:image/${s.format || 'png'};base64,${s.data_b64}" 
             alt="Screenshot ${i+1}" 
             style="width: 100%; height: 150px; object-fit: cover;"
             onclick="window.open(this.src, '_blank')">
        <div style="padding: 0.5rem; font-size: 11px; color: var(--text-muted);">
          ${UI.formatDate(s.timestamp)} ${s.final ? ' <span class="pill safe">Final</span>' : ''}
        </div>
      </div>
    `).join('');
  },

  connectWebSocket() {
    if (!window.location.protocol.startsWith('http')) return;
    if (this.ws) return;

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}/api/vm/ws/${this.currentTaskId}`;

    this.ws = new WebSocket(wsUrl);
    this.updateWSStatus('connecting');

    this.ws.onopen = () => {
      console.log('[LiveAnalysis] WebSocket connected');
      this.updateWSStatus('connected');
      
      // Authenticate
      if (API.getToken()) {
        this.ws.send(JSON.stringify({
          type: 'auth',
          token: API.getToken()
        }));
      }
    };

    this.ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        this.handleWSMessage(message);
      } catch (error) {
        console.error('[LiveAnalysis] WS message parse error:', error);
      }
    };

    this.ws.onclose = () => {
      console.log('[LiveAnalysis] WebSocket disconnected');
      this.updateWSStatus('disconnected');
      // Reconnect after 5 seconds
      setTimeout(() => {
        this.ws = null;
        this.connectWebSocket();
      }, 5000);
    };

    this.ws.onerror = (error) => {
      console.error('[LiveAnalysis] WebSocket error:', error);
      this.updateWSStatus('error');
    };
  },

  handleWSMessage(message) {
    switch (message.type) {
      case 'task_update':
        if (message.data) {
          this.taskData = { ...this.taskData, ...message.data };
          this.updateDashboard(this.taskData);
        }
        break;
      case 'analysis_update':
        // Real-time analysis update from backend
        if (message.data) {
          this.mergeTaskData(message.data);
          this.updateDashboard(this.taskData);
        }
        break;
      case 'initial_state':
        if (message.task) {
          this.taskData = message.task;
          this.updateDashboard(this.taskData);
        }
        break;
    }
  },

  mergeTaskData(newData) {
    if (!this.taskData) this.taskData = {};
    
    // Merge arrays
    ['process_tree', 'api_calls', 'network_events', 'file_events', 'registry_events', 'dropped_files', 'screenshots', 'memory_dumps', 'signatures', 'mitre_techniques'].forEach(key => {
      if (newData[key]) {
        this.taskData[key] = [...(this.taskData[key] || []), ...newData[key]];
      }
    });
    
    // Update scalar values
    ['state', 'progress', 'malscore', 'error', 'completed_at'].forEach(key => {
      if (newData[key] !== undefined) {
        this.taskData[key] = newData[key];
      }
    });
  },

  updateWSStatus(status) {
    const el = document.getElementById('wsStatus');
    if (!el) return;
    
    el.className = `ws-status ${status}`;
    const statusText = {
      'connecting': 'Connecting...',
      'connected': 'Live',
      'disconnected': 'Disconnected',
      'error': 'Error'
    };
    el.querySelector('span:last-child').textContent = statusText[status] || status;
  },

  startPeriodicUpdates() {
    // Poll for updates every 10 seconds as fallback
    this.updateInterval = setInterval(() => {
      if (this.currentTaskId && this.ws?.readyState !== WebSocket.OPEN) {
        this.loadTaskData();
      }
    }, 10000);
  },

  stopPeriodicUpdates() {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
  }
};

// Add to pages registry in app.js
// import { LiveAnalysisPage } from './pages/live-analysis.js';
// pages['live-analysis'] = LiveAnalysisPage;