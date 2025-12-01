/**
 * Peers Tab
 */

let currentPeers = [];

function renderPeersTab() {
    const container = document.getElementById('tab-peers');
    container.innerHTML = `
        <!-- Peer Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="peer-stat-connected">0</div>
                <div class="stat-label">Connected Peers</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="peer-stat-inbound">0</div>
                <div class="stat-label">Inbound</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="peer-stat-outbound">0</div>
                <div class="stat-label">Outbound</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="peer-stat-dht">0</div>
                <div class="stat-label">DHT Peers</div>
            </div>
        </div>
        
        <!-- Connected Peers Card -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">👥 Connected Peers</span>
                <button class="btn btn-sm btn-secondary" onclick="refreshPeersHandler()">↻ Refresh</button>
            </div>
            
            <div class="search-container">
                <input type="text" class="search-input" id="peer-search" placeholder="Filter by Peer ID or address...">
            </div>
            
            <div id="peers-list">
                <div style="text-align: center; color: var(--text-secondary); padding: 40px;">
                    Loading peers...
                </div>
            </div>
            
            <div class="empty-state" id="peers-empty" style="display: none;">
                <div class="empty-state-icon">👤</div>
                <p>No peers connected</p>
                <p style="font-size: 0.9rem; margin-top: 8px;">Your node will automatically discover and connect to peers</p>
            </div>
        </div>
        
        <!-- Connect to Peer Card -->
        <div class="card">
            <div class="card-title" style="margin-bottom: 16px;">🔗 Connect to Peer</div>
            <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem;">
                Manually connect to a specific peer using their multiaddr.
            </p>
            <div class="form-group">
                <label>Multiaddr</label>
                <input type="text" id="connect-addr" placeholder="/ip4/1.2.3.4/tcp/4001/p2p/QmPeerID...">
                <div class="form-hint">Format: /ip4/IP/tcp/PORT/p2p/PEER_ID</div>
            </div>
            <button class="btn btn-primary" onclick="connectToPeer()">🔗 Connect</button>
        </div>
        
        <!-- Find Peer Card -->
        <div class="card">
            <div class="card-title" style="margin-bottom: 16px;">🔍 Find Peer</div>
            <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem;">
                Find a peer's addresses using DHT lookup.
            </p>
            <div class="form-group">
                <label>Peer ID</label>
                <input type="text" id="find-peer-id" placeholder="QmPeerID...">
            </div>
            <button class="btn btn-secondary" onclick="findPeerHandler()">🔍 Find</button>
            
            <div id="find-peer-result" style="display: none; margin-top: 16px;"></div>
        </div>
        
        <!-- Find Providers Card -->
        <div class="card">
            <div class="card-title" style="margin-bottom: 16px;">🔎 Find Content Providers</div>
            <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem;">
                Find peers that are providing specific content.
            </p>
            <div class="form-row">
                <div class="form-group">
                    <label>CID</label>
                    <input type="text" id="find-providers-cid" placeholder="Qm... or bafy...">
                </div>
                <div class="form-group">
                    <label>Limit</label>
                    <input type="number" id="find-providers-limit" value="20" min="1" max="100">
                </div>
            </div>
            <button class="btn btn-secondary" onclick="findProvidersHandler()">🔎 Find Providers</button>
            
            <div id="find-providers-result" style="display: none; margin-top: 16px;"></div>
        </div>
    `;
    
    // Add search filter
    document.getElementById('peer-search').addEventListener('input', debounce(filterPeers, 300));
    
    // Load peers
    refreshPeersHandler();
}

async function refreshPeersHandler() {
    const result = await api.listPeers();
    
    if (result.error) {
        showToast('Failed to load peers: ' + result.error, 'error');
        return;
    }
    
    currentPeers = result.peers || result || [];
    renderPeersList(currentPeers);
    updatePeerStats(currentPeers);
}

function updatePeerStats(peers) {
    const inbound = peers.filter(p => p.direction === 'inbound').length;
    const outbound = peers.filter(p => p.direction === 'outbound').length;
    
    document.getElementById('peer-stat-connected').textContent = peers.length;
    document.getElementById('peer-stat-inbound').textContent = inbound;
    document.getElementById('peer-stat-outbound').textContent = outbound;
    document.getElementById('peer-stat-dht').textContent = peers.filter(p => p.protocols?.includes('/ipfs/kad/')).length;
}

function renderPeersList(peers) {
    const container = document.getElementById('peers-list');
    const emptyState = document.getElementById('peers-empty');
    
    if (!Array.isArray(peers) || peers.length === 0) {
        container.innerHTML = '';
        emptyState.style.display = 'block';
        return;
    }
    
    emptyState.style.display = 'none';
    
    container.innerHTML = peers.map(peer => `
        <div class="peer-item">
            <div>
                <div class="peer-id" title="${peer.peer || peer.id}">${truncatePeerId(peer.peer || peer.id, 24)}</div>
                <div class="peer-addr">${escapeHtml(peer.addr || peer.addresses?.[0] || 'Unknown address')}</div>
            </div>
            <div style="display: flex; align-items: center; gap: 12px;">
                ${peer.latency ? `<span class="peer-latency">${peer.latency}ms</span>` : ''}
                <span class="badge ${peer.direction === 'inbound' ? 'info' : 'success'}">${peer.direction || 'unknown'}</span>
                <div class="btn-group">
                    <button class="btn btn-sm btn-secondary" onclick="copyToClipboard('${peer.peer || peer.id}')" title="Copy Peer ID">📋</button>
                    <button class="btn btn-sm btn-danger" onclick="disconnectPeerHandler('${peer.peer || peer.id}')" title="Disconnect">✖️</button>
                </div>
            </div>
        </div>
    `).join('');
}

function filterPeers() {
    const query = document.getElementById('peer-search').value.toLowerCase().trim();
    
    if (!query) {
        renderPeersList(currentPeers);
        return;
    }
    
    const filtered = currentPeers.filter(peer => 
        (peer.peer || peer.id || '').toLowerCase().includes(query) ||
        (peer.addr || '').toLowerCase().includes(query)
    );
    
    renderPeersList(filtered);
}

async function connectToPeer() {
    const addr = document.getElementById('connect-addr').value.trim();
    
    if (!addr) {
        showToast('Please enter a multiaddr', 'error');
        return;
    }
    
    showToast('Connecting to peer...', 'info');
    
    const result = await api.connectPeer(addr);
    
    if (result.error) {
        showToast('Connection failed: ' + result.error, 'error');
    } else {
        showToast('Connected to peer!', 'success');
        document.getElementById('connect-addr').value = '';
        refreshPeersHandler();
    }
}

async function disconnectPeerHandler(peerId) {
    if (!confirm(`Disconnect from peer ${truncatePeerId(peerId)}?`)) {
        return;
    }
    
    const result = await api.disconnectPeer(peerId);
    
    if (result.error) {
        showToast('Disconnect failed: ' + result.error, 'error');
    } else {
        showToast('Disconnected from peer', 'success');
        refreshPeersHandler();
    }
}

async function findPeerHandler() {
    const peerId = document.getElementById('find-peer-id').value.trim();
    const resultContainer = document.getElementById('find-peer-result');
    
    if (!peerId) {
        showToast('Please enter a Peer ID', 'error');
        return;
    }
    
    showToast('Looking up peer...', 'info');
    resultContainer.innerHTML = '<div class="loading"></div>';
    resultContainer.style.display = 'block';
    
    const result = await api.findPeer(peerId);
    
    if (result.error) {
        resultContainer.innerHTML = `
            <div class="info-banner error">
                <span class="icon">❌</span>
                <div>Peer not found: ${escapeHtml(result.error)}</div>
            </div>
        `;
    } else {
        const addrs = result.addresses || result.Addrs || [];
        resultContainer.innerHTML = `
            <div class="info-banner success">
                <span class="icon">✅</span>
                <div style="flex: 1;">
                    <strong>Peer Found</strong>
                    <div style="font-size: 0.85rem;">${addrs.length} address(es)</div>
                </div>
            </div>
            ${addrs.map(addr => `
                <div style="padding: 8px; background: var(--bg-tertiary); border-radius: 4px; margin-top: 8px; font-family: monospace; font-size: 0.85rem; display: flex; justify-content: space-between; align-items: center;">
                    <span>${escapeHtml(addr)}</span>
                    <button class="btn btn-sm btn-secondary" onclick="document.getElementById('connect-addr').value='${addr}'; showToast('Address copied to connect field', 'info');">Use</button>
                </div>
            `).join('')}
        `;
    }
}

async function findProvidersHandler() {
    const cid = document.getElementById('find-providers-cid').value.trim();
    const limit = parseInt(document.getElementById('find-providers-limit').value) || 20;
    const resultContainer = document.getElementById('find-providers-result');
    
    if (!cid) {
        showToast('Please enter a CID', 'error');
        return;
    }
    
    showToast('Finding providers...', 'info');
    resultContainer.innerHTML = '<div class="loading"></div>';
    resultContainer.style.display = 'block';
    
    const result = await api.findProviders(cid, limit);
    
    if (result.error) {
        resultContainer.innerHTML = `
            <div class="info-banner error">
                <span class="icon">❌</span>
                <div>Failed: ${escapeHtml(result.error)}</div>
            </div>
        `;
    } else {
        const providers = result.providers || result || [];
        if (providers.length === 0) {
            resultContainer.innerHTML = `
                <div class="info-banner warning">
                    <span class="icon">⚠️</span>
                    <div>No providers found for this CID</div>
                </div>
            `;
        } else {
            resultContainer.innerHTML = `
                <div class="info-banner success">
                    <span class="icon">✅</span>
                    <div><strong>${providers.length}</strong> provider(s) found</div>
                </div>
                ${providers.slice(0, 10).map(p => `
                    <div class="peer-item" style="margin-top: 8px;">
                        <div class="peer-id">${truncatePeerId(p.id || p.ID || p, 24)}</div>
                        <button class="btn btn-sm btn-secondary" onclick="copyToClipboard('${p.id || p.ID || p}')">📋</button>
                    </div>
                `).join('')}
                ${providers.length > 10 ? `<div style="color: var(--text-secondary); margin-top: 8px;">...and ${providers.length - 10} more</div>` : ''}
            `;
        }
    }
}

// Export
window.renderPeersTab = renderPeersTab;
window.refreshPeersHandler = refreshPeersHandler;
window.connectToPeer = connectToPeer;
window.disconnectPeerHandler = disconnectPeerHandler;
window.findPeerHandler = findPeerHandler;
window.findProvidersHandler = findProvidersHandler;
