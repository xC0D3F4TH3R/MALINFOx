// MALINFO UI Utilities
// Common UI components, helpers, and interaction patterns

export const UI = {
  // Format bytes to human readable
  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(i === 0 ? 0 : 1)) + ' ' + sizes[i];
  },

  // Format date
  formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  },

  // Format relative time
  formatRelativeTime(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;
    
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (seconds < 60) return 'just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    if (days < 7) return `${days}d ago`;
    return this.formatDate(dateString);
  },

  // Escape HTML
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  },

  // Show toast notification
  toast(message, type = 'info', duration = 5000) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const icons = {
      success: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>',
      error: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>',
      warning: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>',
      info: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>',
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <div class="toast-icon">${icons[type] || icons.info}</div>
      <div class="toast-content">
        <div class="toast-title">${type.charAt(0).toUpperCase() + type.slice(1)}</div>
        <div class="toast-message">${this.escapeHtml(message)}</div>
      </div>
      <button class="toast-close" aria-label="Dismiss">&times;</button>
    `;

    toast.querySelector('.toast-close').addEventListener('click', () => {
      toast.remove();
    });

    container.appendChild(toast);

    // Auto-remove
    setTimeout(() => {
      toast.style.animation = 'slideIn 0.3s ease reverse';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  },

  // Show modal
  showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.add('open');
      document.body.style.overflow = 'hidden';
      // Focus first focusable element
      const focusable = modal.querySelector('button, input, select, textarea, [tabindex]:not([tabindex="-1"])');
      focusable?.focus();
    }
  },

  // Close modal
  closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.remove('open');
      document.body.style.overflow = '';
    }
  },

  // Close all modals
  closeAllModals() {
    document.querySelectorAll('.modal-overlay.open').forEach(modal => {
      modal.classList.remove('open');
    });
    document.body.style.overflow = '';
  },

  // Show loading spinner in element
  showLoading(element, text = 'Loading...') {
    if (typeof element === 'string') {
      element = document.getElementById(element);
    }
    if (!element) return;
    
    element.dataset.originalContent = element.innerHTML;
    element.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:center;gap:0.5rem;padding:2rem;">
        <div class="spinner"></div>
        <span>${this.escapeHtml(text)}</span>
      </div>
    `;
  },

  // Hide loading spinner
  hideLoading(element) {
    if (typeof element === 'string') {
      element = document.getElementById(element);
    }
    if (!element) return;
    
    if (element.dataset.originalContent) {
      element.innerHTML = element.dataset.originalContent;
      delete element.dataset.originalContent;
    }
  },

  // Create verdict badge
  createVerdictBadge(verdict, size = 'normal') {
    const className = `verdict-hex${size === 'small' ? '-sm' : ''} ${verdict}`;
    const label = verdict.charAt(0).toUpperCase() + verdict.slice(1);
    return `<div class="${className}">${label}</div>`;
  },

  // Create pill badge
  createPill(text, variant = 'unknown') {
    return `<span class="pill ${variant}">${this.escapeHtml(text)}</span>`;
  },

  // Create tag badge
  createTag(text) {
    return `<span class="badge-tag">${this.escapeHtml(text)}</span>`;
  },

  // Render table from data
  renderTable(columns, rows, options = {}) {
    const { clickable = false, keyField = 'id', onRowClick = null } = options;
    
    let html = '<div class="table-container"><table class="data">';
    html += '<thead><tr>';
    columns.forEach(col => {
      html += `<th>${this.escapeHtml(col.label)}</th>`;
    });
    html += '</tr></thead><tbody>';
    
    if (rows.length === 0) {
      html += `<tr><td colspan="${columns.length}"><div class="empty-state"><div class="icon">&#9679;</div>${options.emptyMessage || 'No data available'}</div></td></tr>`;
    } else {
      rows.forEach(row => {
        const rowClass = clickable ? 'clickable' : '';
        const rowId = row[keyField];
        const onclick = clickable && onRowClick ? `onclick="MALINFO.pages.${MALINFO.currentPage}.onRowClick?.('${rowId}')"` : '';
        
        html += `<tr class="${rowClass}" ${onclick}>`;
        columns.forEach(col => {
          let value = row[col.field];
          
          if (col.render) {
            value = col.render(value, row);
          } else if (value instanceof Date) {
            value = this.formatDate(value.toISOString());
          } else if (typeof value === 'object' && value !== null) {
            value = JSON.stringify(value);
          }
          
          const truncateClass = col.truncate ? 'truncate' : '';
          html += `<td class="${truncateClass}">${value !== null && value !== undefined ? this.escapeHtml(String(value)) : '<span style="color:var(--text-muted)">—</span>'}</td>`;
        });
        html += '</tr>';
      });
    }
    
    html += '</tbody></table></div>';
    return html;
  },

  // Show empty state
  showEmptyState(container, message, icon = '&#9679;') {
    if (typeof container === 'string') {
      container = document.getElementById(container);
    }
    if (!container) return;
    
    container.innerHTML = `
      <div class="empty-state">
        <div class="icon">${icon}</div>
        <p>${this.escapeHtml(message)}</p>
      </div>
    `;
  },

  // Show search results dropdown
  showSearchResults(results, query) {
    // Remove existing dropdown
    const existing = document.getElementById('searchResultsDropdown');
    if (existing) existing.remove();

    if (!results || results.length === 0) return;

    const dropdown = document.createElement('div');
    dropdown.id = 'searchResultsDropdown';
    dropdown.style.cssText = `
      position: absolute;
      top: 100%;
      left: 0;
      right: 0;
      margin-top: 4px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius-lg);
      box-shadow: 0 10px 40px rgba(0,0,0,0.4);
      z-index: 1000;
      max-height: 400px;
      overflow-y: auto;
    `;

    dropdown.innerHTML = results.map(r => `
      <a href="#${r.type}/${r.id}" class="dropdown-item" style="display:flex;align-items:center;gap:0.75rem;padding:0.75rem 1rem;color:var(--text-secondary);">
        <span style="font-weight:500">${this.escapeHtml(r.title)}</span>
        <span style="font-size:11px;color:var(--text-muted);margin-left:auto">${r.type}</span>
      </a>
    `).join('');

    const searchContainer = document.querySelector('.header-search');
    if (searchContainer) {
      searchContainer.style.position = 'relative';
      searchContainer.appendChild(dropdown);
    }

    // Close on outside click
    const closeDropdown = (e) => {
      if (!dropdown.contains(e.target) && !searchContainer.contains(e.target)) {
        dropdown.remove();
        document.removeEventListener('click', closeDropdown);
      }
    };
    setTimeout(() => document.addEventListener('click', closeDropdown), 0);
  },

  // Debounce function
  debounce(fn, delay) {
    let timeoutId;
    return (...args) => {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => fn(...args), delay);
    };
  },

  // Throttle function
  throttle(fn, limit) {
    let inThrottle;
    return (...args) => {
      if (!inThrottle) {
        fn(...args);
        inThrottle = true;
        setTimeout(() => inThrottle = false, limit);
      }
    };
  },

  // Initialize UI
  init() {
    // Close modals on overlay click
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
          this.closeAllModals();
        }
      });
    });

    // Close modals on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        this.closeAllModals();
      }
    });

    console.log('[UI] Initialized');
  },

  // Update user display
  updateUserDisplay(user) {
    const avatar = document.getElementById('userAvatar');
    const name = document.getElementById('userName');
    const dropdownName = document.getElementById('dropdownUserName');
    const dropdownRole = document.getElementById('dropdownUserRole');
    
    if (avatar) {
      avatar.textContent = user.full_name?.split(' ').map(n => n[0]).join('').toUpperCase() || 'MI';
    }
    if (name) name.textContent = user.full_name || user.username;
    if (dropdownName) dropdownName.textContent = user.full_name || user.username;
    if (dropdownRole) dropdownRole.textContent = user.role;
  },
};