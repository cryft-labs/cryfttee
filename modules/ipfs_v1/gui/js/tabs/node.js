/**
 * Node Control Tab
 */

function renderNodeTab() {
    const container = document.getElementById('tab-node');
    container.innerHTML = `
        <div class="info-banner" id="node-status-banner">
            <span class="icon" id="node-banner-icon">⏳</span>
            <div>
                <strong id="node-banner-title">Checking node status...</strong>
                <div id="node-banner-detail" style="font-size: 0.85rem; color: var(--text-secondary);"></div>
            </div>
        </div>
        
        <!-- Node Control Card -->
        <div class="card">
            <div class="card-header">
                <div>
                    <span class="card-title">🚀 Node Control</span>
                    <div class="card-subtitle">Start, stop, and configure your embedded IPFS node</div>
                </div>
                <button class="btn btn-sm btn-secondary" onclick="refreshNodeStatus()">↻ Refresh</button>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" id="stat-uptime">--</div>
                    <div class="stat-label">Uptime</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-peers">0</div>
                    <div class="stat-label">Connected Peers</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-bandwidth">0 KB/s</div>
                    <div class="stat-label">Bandwidth</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-blocks">0</div>
                    <div class="stat-label">Blocks Stored</div>
                </div>
            </div>
            
            <div class="btn-group">
                <button class="btn btn-lg btn-success" id="btn-start" onclick="handleStartNode()">
                    ▶️ Start Node
                </button>
                <button class="btn btn-lg btn-danger" id="btn-stop" onclick="handleStopNode()" disabled>
                    ⏹️ Stop Node
                </button>
                <button class="btn btn-secondary" onclick="handleRestartNode()">
                    🔄 Restart
                </button>
            </div>
        </div>
        
        <!-- Node Identity Card -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">🆔 Node Identity</span>
            </div>
            <div class="node-info">
                <div class="node-info-item">
                    <div class="node-info-label">Peer ID</div>
                    <div class="node-info-value" id="info-peer-id">-</div>
                </div>
                <div class="node-info-item">
                    <div class="node-info-label">Node Mode</div>
                    <div class="node-info-value" id="info-mode">-</div>
                </div>
                <div class="node-info-item">
                    <div class="node-info-label">Protocol Version</div>
                    <div class="node-info-value" id="info-protocol">-</div>
                </div>
                <div class="node-info-item">
                    <div class="node-info-label">Agent Version</div>
                    <div class="node-info-value" id="info-agent">cryfttee-ipfs/2.0.0</div>
                </div>
            </div>
        </div>
        
        <!-- Listen Addresses Card -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">📡 Listen Addresses</span>
            </div>
            <div id="listen-addresses">
                <div style="color: var(--text-secondary);">Node not running</div>
            </div>
        </div>
        
        <!-- Storage Card -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">💾 Storage</span>
            </div>
            <div class="form-row" style="margin-bottom: 16px;">
                <div>
                    <div class="node-info-label">Used</div>
                    <div style="font-size: 1.4rem; font-weight: 600;" id="storage-used-display">0 MB</div>
                </div>
                <div>
                    <div class="node-info-label">Limit</div>
                    <div style="font-size: 1.4rem; font-weight: 600;" id="storage-limit-display">50 GB</div>
                </div>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" id="storage-progress" style="width: 0%;"></div>
            </div>
            <div style="margin-top: 12px;">
                <button class="btn btn-sm btn-secondary" onclick="runGarbageCollection()">
                    🗑️ Run Garbage Collection
                </button>
            </div>
        </div>
    `;
}

async function refreshNodeStatus() {
    const result = await api.getNodeStatus();
    updateNodeStatusUI(result);
}

function updateNodeStatusUI(status) {
    const banner = document.getElementById('node-status-banner');
    const bannerIcon = document.getElementById('node-banner-icon');
    const bannerTitle = document.getElementById('node-banner-title');
    const bannerDetail = document.getElementById('node-banner-detail');
    const btnStart = document.getElementById('btn-start');
    const btnStop = document.getElementById('btn-stop');
    const nodeStatusDot = document.getElementById('node-status');
    const dhtStatusDot = document.getElementById('dht-status');
    
    if (status.error) {
        banner.className = 'info-banner error';
        bannerIcon.textContent = '❌';
        bannerTitle.textContent = 'Node Error';
        bannerDetail.textContent = status.error;
        nodeStatusDot.className = 'status-dot offline';
        dhtStatusDot.className = 'status-dot offline';
        btnStart.disabled = false;
        btnStop.disabled = true;
        return;
    }
    
    nodeState.running = status.running || status.online;
    nodeState.peerId = status.peer_id || status.peerId;
    nodeState.mode = status.mode || nodeState.mode;
    
    if (nodeState.running) {
        banner.className = 'info-banner success';
        bannerIcon.textContent = '✅';
        bannerTitle.textContent = 'Node is running';
        bannerDetail.textContent = nodeState.peerId ? `Peer ID: ${truncatePeerId(nodeState.peerId, 24)}` : '';
        nodeStatusDot.className = 'status-dot online';
        dhtStatusDot.className = 'status-dot online';
        btnStart.disabled = true;
        btnStop.disabled = false;
        
        // Update stats
        document.getElementById('stat-uptime').textContent = formatDuration(status.uptime || 0);
        document.getElementById('stat-peers').textContent = status.peers || 0;
        document.getElementById('stat-bandwidth').textContent = formatBytes(status.bandwidth || 0) + '/s';
        document.getElementById('stat-blocks').textContent = status.blocks || 0;
        
        // Update identity
        document.getElementById('info-peer-id').textContent = nodeState.peerId || '-';
        document.getElementById('info-mode').textContent = nodeState.mode === 'full' ? 'Full Node' : 'Light Node';
        document.getElementById('info-protocol').textContent = status.protocol_version || 'ipfs/0.1.0';
        
        // Update node peer id in status bar
        document.getElementById('node-peer-id').textContent = truncatePeerId(nodeState.peerId, 12);
        document.getElementById('dht-peers').textContent = `${status.peers || 0} peers`;
        
        // Update storage
        const used = status.storage_used || 0;
        const limit = status.storage_limit || (50 * 1024 * 1024 * 1024);
        document.getElementById('storage-used-display').textContent = formatBytes(used);
        document.getElementById('storage-limit-display').textContent = formatBytes(limit);
        document.getElementById('storage-progress').style.width = `${(used / limit) * 100}%`;
        document.getElementById('storage-used').textContent = formatBytes(used);
        
        // Update listen addresses
        const addrsContainer = document.getElementById('listen-addresses');
        if (status.addresses && status.addresses.length > 0) {
            addrsContainer.innerHTML = status.addresses.map(addr => {
                const { protocol } = parseMultiaddr(addr);
                return `
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px; background: var(--bg-tertiary); border-radius: 4px; margin-bottom: 4px; font-family: monospace; font-size: 0.85rem;">
                        <span>${escapeHtml(addr)}</span>
                        <span class="badge info">${protocol}</span>
                    </div>
                `;
            }).join('');
        } else {
            addrsContainer.innerHTML = '<div style="color: var(--text-secondary);">No listen addresses</div>';
        }
    } else {
        banner.className = 'info-banner warning';
        bannerIcon.textContent = '⚠️';
        bannerTitle.textContent = 'Node is stopped';
        bannerDetail.textContent = 'Click "Start Node" to begin';
        nodeStatusDot.className = 'status-dot offline';
        dhtStatusDot.className = 'status-dot offline';
        btnStart.disabled = false;
        btnStop.disabled = true;
        
        document.getElementById('node-peer-id').textContent = 'Offline';
        document.getElementById('dht-peers').textContent = '0 peers';
        document.getElementById('stat-uptime').textContent = '--';
        document.getElementById('stat-peers').textContent = '0';
    }
}

async function handleStartNode() {
    const btnStart = document.getElementById('btn-start');
    btnStart.disabled = true;
    btnStart.innerHTML = '<span class="loading"></span> Starting...';
    
    showToast('Starting IPFS node...', 'info');
    
    const result = await api.startNode();
    
    if (result.error) {
        showToast('Failed to start node: ' + result.error, 'error');
        btnStart.disabled = false;
        btnStart.innerHTML = '▶️ Start Node';
    } else {
        showToast('Node started successfully!', 'success');
        await refreshNodeStatus();
    }
}

async function handleStopNode() {
    const btnStop = document.getElementById('btn-stop');
    btnStop.disabled = true;
    btnStop.innerHTML = '<span class="loading"></span> Stopping...';
    
    showToast('Stopping IPFS node...', 'info');
    
    const result = await api.stopNode();
    
    if (result.error) {
        showToast('Failed to stop node: ' + result.error, 'error');
        btnStop.disabled = false;
        btnStop.innerHTML = '⏹️ Stop Node';
    } else {
        showToast('Node stopped', 'success');
        await refreshNodeStatus();
    }
}

async function handleRestartNode() {
    showToast('Restarting node...', 'info');
    await api.stopNode();
    await new Promise(r => setTimeout(r, 1000));
    await api.startNode();
    await refreshNodeStatus();
    showToast('Node restarted', 'success');
}

async function runGarbageCollection() {
    showToast('Running garbage collection...', 'info');
    const result = await api.callModule('gc_run', {});
    if (result.error) {
        showToast('GC failed: ' + result.error, 'error');
    } else {
        showToast(`Freed ${formatBytes(result.freed || 0)}`, 'success');
        await refreshNodeStatus();
    }
}

// Export
window.renderNodeTab = renderNodeTab;
window.refreshNodeStatus = refreshNodeStatus;
window.handleStartNode = handleStartNode;
window.handleStopNode = handleStopNode;
window.handleRestartNode = handleRestartNode;
window.runGarbageCollection = runGarbageCollection;
