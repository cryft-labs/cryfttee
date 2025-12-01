// Status Page - Node overview and control

(function() {
    const { formatBytes, showToast, loadSettings, saveSettings } = window.IPFSUtils;
    
    let currentMode = 'full';
    let nodeRunning = false;
    let pollInterval = null;
    
    function render() {
        const container = document.getElementById('page-status');
        container.innerHTML = `
            <div class="page-header">
                <h1>Node Status</h1>
                <div class="header-actions">
                    <button class="btn ${nodeRunning ? 'btn-danger' : 'btn-primary'}" id="btn-toggle-node">
                        <span class="btn-icon">${nodeRunning ? '⏹️' : '▶️'}</span>
                        ${nodeRunning ? 'Stop Node' : 'Start Node'}
                    </button>
                </div>
            </div>
            
            <!-- Node Mode Selector -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Node Mode</h2>
                </div>
                <div class="card-body">
                    <div class="mode-selector">
                        <div class="mode-option ${currentMode === 'full' ? 'selected' : ''}" data-mode="full">
                            <div class="mode-icon">🖥️</div>
                            <div class="mode-info">
                                <div class="mode-name">Full Node</div>
                                <div class="mode-desc">Complete DHT participation, serves and announces content</div>
                            </div>
                            <div class="mode-check">✓</div>
                        </div>
                        <div class="mode-option ${currentMode === 'light' ? 'selected' : ''}" data-mode="light">
                            <div class="mode-icon">📱</div>
                            <div class="mode-info">
                                <div class="mode-name">Light Node</div>
                                <div class="mode-desc">Minimal DHT, request-only, lower resource usage</div>
                            </div>
                            <div class="mode-check">✓</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Stats Grid -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon">👥</div>
                    <div class="stat-content">
                        <div class="stat-value" id="stat-peers">0</div>
                        <div class="stat-label">Connected Peers</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">📦</div>
                    <div class="stat-content">
                        <div class="stat-value" id="stat-blocks">0</div>
                        <div class="stat-label">Blocks</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">📌</div>
                    <div class="stat-content">
                        <div class="stat-value" id="stat-pins">0</div>
                        <div class="stat-label">Pinned Items</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">💾</div>
                    <div class="stat-content">
                        <div class="stat-value" id="stat-storage">0 B</div>
                        <div class="stat-label">Storage Used</div>
                    </div>
                </div>
            </div>
            
            <!-- Node Info -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Node Information</h2>
                    <span class="badge ${nodeRunning ? 'ok' : 'warn'}" id="node-mode-badge">
                        ${currentMode === 'full' ? 'Full Node' : 'Light Node'}
                    </span>
                </div>
                <div class="card-body">
                    <div class="node-info-grid">
                        <div class="info-row">
                            <span class="info-label">Peer ID</span>
                            <span class="info-value monospace" id="info-peer-id">—</span>
                            <button class="btn-icon-small" onclick="IPFSUtils.copyToClipboard(document.getElementById('info-peer-id').textContent)">📋</button>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Protocol Version</span>
                            <span class="info-value" id="info-protocol">—</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Agent Version</span>
                            <span class="info-value" id="info-agent">—</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Listen Addresses</span>
                            <span class="info-value monospace" id="info-addresses">—</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Bandwidth Stats -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Bandwidth</h2>
                </div>
                <div class="card-body">
                    <div class="bandwidth-stats">
                        <div class="bandwidth-item">
                            <div class="bandwidth-icon upload">↑</div>
                            <div class="bandwidth-info">
                                <div class="bandwidth-label">Upload</div>
                                <div class="bandwidth-value" id="bw-upload">0 B/s</div>
                                <div class="bandwidth-total" id="bw-upload-total">Total: 0 B</div>
                            </div>
                        </div>
                        <div class="bandwidth-item">
                            <div class="bandwidth-icon download">↓</div>
                            <div class="bandwidth-info">
                                <div class="bandwidth-label">Download</div>
                                <div class="bandwidth-value" id="bw-download">0 B/s</div>
                                <div class="bandwidth-total" id="bw-download-total">Total: 0 B</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        attachEventListeners();
    }
    
    function attachEventListeners() {
        // Toggle node button
        const toggleBtn = document.getElementById('btn-toggle-node');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', toggleNode);
        }
        
        // Mode selection
        document.querySelectorAll('.mode-option').forEach(option => {
            option.addEventListener('click', () => selectMode(option.dataset.mode));
        });
    }
    
    async function toggleNode() {
        const btn = document.getElementById('btn-toggle-node');
        btn.disabled = true;
        
        try {
            if (nodeRunning) {
                await IPFS_API.stopNode();
                showToast('Node stopped', 'info');
                nodeRunning = false;
            } else {
                await IPFS_API.startNode(currentMode);
                showToast('Node started', 'success');
                nodeRunning = true;
            }
            
            render();
            updateStatus();
            updateSidebarStatus();
        } catch (error) {
            showToast(`Failed: ${error.message}`, 'error');
        } finally {
            btn.disabled = false;
        }
    }
    
    function selectMode(mode) {
        if (nodeRunning) {
            showToast('Stop the node first to change mode', 'warning');
            return;
        }
        
        currentMode = mode;
        const settings = loadSettings();
        settings.nodeMode = mode;
        saveSettings(settings);
        
        document.querySelectorAll('.mode-option').forEach(opt => {
            opt.classList.toggle('selected', opt.dataset.mode === mode);
        });
        
        const badge = document.getElementById('node-mode-badge');
        if (badge) {
            badge.textContent = mode === 'full' ? 'Full Node' : 'Light Node';
        }
    }
    
    async function updateStatus() {
        try {
            const status = await IPFS_API.getStatus();
            
            nodeRunning = status.running || false;
            
            // Update stats
            document.getElementById('stat-peers').textContent = status.peers || 0;
            document.getElementById('stat-blocks').textContent = status.blocks || 0;
            document.getElementById('stat-pins').textContent = status.pins || 0;
            document.getElementById('stat-storage').textContent = formatBytes(status.storage_used || 0);
            
            // Update node info
            if (status.peer_id) {
                document.getElementById('info-peer-id').textContent = status.peer_id;
            }
            if (status.protocol_version) {
                document.getElementById('info-protocol').textContent = status.protocol_version;
            }
            if (status.agent_version) {
                document.getElementById('info-agent').textContent = status.agent_version;
            }
            if (status.addresses && status.addresses.length > 0) {
                document.getElementById('info-addresses').textContent = status.addresses.join('\n');
            }
            
            // Update bandwidth
            if (status.bandwidth) {
                document.getElementById('bw-upload').textContent = formatBytes(status.bandwidth.rate_out || 0) + '/s';
                document.getElementById('bw-download').textContent = formatBytes(status.bandwidth.rate_in || 0) + '/s';
                document.getElementById('bw-upload-total').textContent = 'Total: ' + formatBytes(status.bandwidth.total_out || 0);
                document.getElementById('bw-download-total').textContent = 'Total: ' + formatBytes(status.bandwidth.total_in || 0);
            }
            
            // Update storage indicator
            updateStorageIndicator(status.storage_used || 0, status.storage_max || 10737418240);
            
            // Update toggle button
            const toggleBtn = document.getElementById('btn-toggle-node');
            if (toggleBtn) {
                toggleBtn.innerHTML = `
                    <span class="btn-icon">${nodeRunning ? '⏹️' : '▶️'}</span>
                    ${nodeRunning ? 'Stop Node' : 'Start Node'}
                `;
                toggleBtn.className = `btn ${nodeRunning ? 'btn-danger' : 'btn-primary'}`;
            }
            
            updateSidebarStatus();
            
        } catch (error) {
            console.error('Failed to fetch status:', error);
        }
    }
    
    function updateStorageIndicator(used, max) {
        const percent = max > 0 ? Math.min(100, (used / max) * 100) : 0;
        
        document.getElementById('storage-percent').textContent = percent.toFixed(1) + '%';
        document.getElementById('storage-fill').style.width = percent + '%';
        document.getElementById('storage-text').textContent = `${formatBytes(used)} / ${formatBytes(max)}`;
    }
    
    function updateSidebarStatus() {
        const statusEl = document.getElementById('sidebar-node-status');
        if (statusEl) {
            const dot = statusEl.querySelector('.status-dot');
            const text = statusEl.querySelector('.status-text');
            
            dot.className = 'status-dot ' + (nodeRunning ? 'online' : 'offline');
            text.textContent = nodeRunning ? 'Online' : 'Offline';
        }
    }
    
    function startPolling() {
        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(updateStatus, IPFS_CONFIG.POLL_INTERVAL);
    }
    
    function stopPolling() {
        if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
        }
    }
    
    // Initialize
    function init() {
        const settings = loadSettings();
        currentMode = settings.nodeMode || 'full';
        
        render();
        updateStatus();
        startPolling();
    }
    
    // Expose for app.js
    window.StatusPage = {
        init,
        render,
        updateStatus,
        startPolling,
        stopPolling
    };
})();
