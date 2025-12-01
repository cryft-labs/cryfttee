// Peers Page - Peer management and network view

(function() {
    const { showToast, truncate } = window.IPFSUtils;
    
    let peers = [];
    let bootstrapPeers = [];
    
    function render() {
        const container = document.getElementById('page-peers');
        container.innerHTML = `
            <div class="page-header">
                <h1>Peers</h1>
                <div class="header-actions">
                    <button class="btn btn-secondary" id="btn-add-peer">
                        <span class="btn-icon">➕</span>
                        Connect to Peer
                    </button>
                    <button class="btn btn-secondary" id="btn-refresh-peers">
                        <span class="btn-icon">🔄</span>
                        Refresh
                    </button>
                </div>
            </div>
            
            <!-- Peer Stats -->
            <div class="peer-stats">
                <div class="peer-stat">
                    <span class="peer-stat-value" id="peers-total">0</span>
                    <span class="peer-stat-label">Connected</span>
                </div>
                <div class="peer-stat">
                    <span class="peer-stat-value" id="peers-inbound">0</span>
                    <span class="peer-stat-label">Inbound</span>
                </div>
                <div class="peer-stat">
                    <span class="peer-stat-value" id="peers-outbound">0</span>
                    <span class="peer-stat-label">Outbound</span>
                </div>
            </div>
            
            <!-- Peer Search -->
            <div class="search-box">
                <span class="search-icon">🔍</span>
                <input type="text" class="search-input" id="peer-search" placeholder="Search peers by ID or address...">
            </div>
            
            <!-- Peer List -->
            <div class="peer-list" id="peer-list">
                <div class="empty-state">
                    <div class="empty-icon">🌍</div>
                    <div class="empty-text">No peers connected</div>
                    <div class="empty-subtext">Start the node to connect to the IPFS network</div>
                </div>
            </div>
            
            <!-- Bootstrap Peers -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Bootstrap Peers</h2>
                    <button class="btn btn-sm btn-secondary" id="btn-reset-bootstrap">Reset to Default</button>
                </div>
                <div class="card-body">
                    <div class="bootstrap-list" id="bootstrap-list"></div>
                    <div class="form-group" style="margin-top: var(--pad-lg);">
                        <label>Add Bootstrap Peer</label>
                        <div class="explore-input-group">
                            <input type="text" class="form-input" id="new-bootstrap" placeholder="/dnsaddr/... or /ip4/...">
                            <button class="btn btn-secondary" id="btn-add-bootstrap">Add</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        attachEventListeners();
        loadPeers();
        loadBootstrapPeers();
    }
    
    function attachEventListeners() {
        document.getElementById('btn-add-peer').addEventListener('click', showConnectDialog);
        document.getElementById('btn-refresh-peers').addEventListener('click', loadPeers);
        document.getElementById('btn-reset-bootstrap').addEventListener('click', resetBootstrap);
        document.getElementById('btn-add-bootstrap').addEventListener('click', addBootstrapPeer);
        
        // Search
        document.getElementById('peer-search').addEventListener('input', 
            IPFSUtils.debounce(filterPeers, 300)
        );
    }
    
    async function loadPeers() {
        try {
            const result = await IPFS_API.listPeers();
            peers = result.peers || [];
            
            // Update stats
            document.getElementById('peers-total').textContent = peers.length;
            
            // Count inbound/outbound (if available)
            const inbound = peers.filter(p => p.direction === 'inbound').length;
            const outbound = peers.filter(p => p.direction === 'outbound').length;
            document.getElementById('peers-inbound').textContent = inbound || Math.floor(peers.length / 2);
            document.getElementById('peers-outbound').textContent = outbound || Math.ceil(peers.length / 2);
            
            renderPeerList();
        } catch (error) {
            console.error('Failed to load peers:', error);
            peers = [];
            renderPeerList();
        }
    }
    
    function renderPeerList(filteredPeers = null) {
        const container = document.getElementById('peer-list');
        const displayPeers = filteredPeers || peers;
        
        if (displayPeers.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">🌍</div>
                    <div class="empty-text">${filteredPeers ? 'No matching peers' : 'No peers connected'}</div>
                    <div class="empty-subtext">${filteredPeers ? 'Try a different search term' : 'Start the node to connect to the IPFS network'}</div>
                </div>
            `;
            return;
        }
        
        container.innerHTML = displayPeers.map(peer => `
            <div class="list-item">
                <div class="list-item-icon">👤</div>
                <div class="list-item-content">
                    <div class="list-item-title">${truncate(peer.peer_id || peer.id, 24)}</div>
                    <div class="list-item-subtitle">${peer.addr || peer.address || 'Unknown address'}</div>
                </div>
                <div class="list-item-actions">
                    ${peer.latency ? `<span class="badge info">${peer.latency}</span>` : ''}
                    <button class="btn btn-sm btn-secondary" onclick="PeersPage.copyPeerId('${peer.peer_id || peer.id}')">📋</button>
                    <button class="btn btn-sm btn-danger" onclick="PeersPage.disconnectPeer('${peer.peer_id || peer.id}')">✕</button>
                </div>
            </div>
        `).join('');
    }
    
    function filterPeers() {
        const search = document.getElementById('peer-search').value.toLowerCase();
        if (!search) {
            renderPeerList();
            return;
        }
        
        const filtered = peers.filter(peer => 
            (peer.peer_id || peer.id || '').toLowerCase().includes(search) ||
            (peer.addr || peer.address || '').toLowerCase().includes(search)
        );
        
        renderPeerList(filtered);
    }
    
    async function loadBootstrapPeers() {
        try {
            const result = await IPFS_API.getBootstrapPeers();
            bootstrapPeers = result.peers || IPFS_CONFIG.BOOTSTRAP_PEERS;
            renderBootstrapList();
        } catch (error) {
            bootstrapPeers = IPFS_CONFIG.BOOTSTRAP_PEERS;
            renderBootstrapList();
        }
    }
    
    function renderBootstrapList() {
        const container = document.getElementById('bootstrap-list');
        
        if (bootstrapPeers.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-text">No bootstrap peers configured</div></div>';
            return;
        }
        
        container.innerHTML = bootstrapPeers.map((addr, idx) => `
            <div class="list-item">
                <div class="list-item-icon">🌐</div>
                <div class="list-item-content">
                    <div class="list-item-subtitle">${truncate(addr, 60)}</div>
                </div>
                <div class="list-item-actions">
                    <button class="btn btn-sm btn-secondary" onclick="PeersPage.connectToBootstrap('${addr}')">Connect</button>
                    <button class="btn btn-sm btn-danger" onclick="PeersPage.removeBootstrap(${idx})">✕</button>
                </div>
            </div>
        `).join('');
    }
    
    function showConnectDialog() {
        const addr = prompt('Enter peer multiaddress:\n\nExample: /ip4/104.131.131.82/tcp/4001/p2p/QmaCpDM...');
        if (addr) {
            connectToPeer(addr);
        }
    }
    
    async function connectToPeer(multiaddr) {
        try {
            await IPFS_API.connectPeer(multiaddr);
            showToast('Connected to peer', 'success');
            loadPeers();
        } catch (error) {
            showToast(`Failed to connect: ${error.message}`, 'error');
        }
    }
    
    async function disconnectPeer(peerId) {
        try {
            await IPFS_API.disconnectPeer(peerId);
            showToast('Disconnected from peer', 'info');
            loadPeers();
        } catch (error) {
            showToast(`Failed to disconnect: ${error.message}`, 'error');
        }
    }
    
    function copyPeerId(peerId) {
        IPFSUtils.copyToClipboard(peerId);
    }
    
    async function connectToBootstrap(addr) {
        await connectToPeer(addr);
    }
    
    async function addBootstrapPeer() {
        const input = document.getElementById('new-bootstrap');
        const addr = input.value.trim();
        
        if (!addr) {
            showToast('Please enter a multiaddress', 'warning');
            return;
        }
        
        try {
            await IPFS_API.addBootstrapPeer(addr);
            showToast('Bootstrap peer added', 'success');
            input.value = '';
            loadBootstrapPeers();
        } catch (error) {
            showToast(`Failed to add: ${error.message}`, 'error');
        }
    }
    
    async function removeBootstrap(index) {
        const addr = bootstrapPeers[index];
        if (!addr) return;
        
        try {
            await IPFS_API.removeBootstrapPeer(addr);
            showToast('Bootstrap peer removed', 'info');
            loadBootstrapPeers();
        } catch (error) {
            showToast(`Failed to remove: ${error.message}`, 'error');
        }
    }
    
    async function resetBootstrap() {
        if (!confirm('Reset bootstrap peers to defaults?')) return;
        
        try {
            await IPFS_API.resetBootstrapPeers();
            showToast('Bootstrap peers reset', 'success');
            loadBootstrapPeers();
        } catch (error) {
            showToast(`Failed to reset: ${error.message}`, 'error');
        }
    }
    
    // Initialize
    function init() {
        render();
    }
    
    // Expose for app.js
    window.PeersPage = {
        init,
        render,
        copyPeerId,
        disconnectPeer,
        connectToBootstrap,
        removeBootstrap
    };
})();
