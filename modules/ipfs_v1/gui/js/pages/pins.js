// Pins Page - Pin management

(function() {
    const { formatBytes, showToast, truncate, isValidCID } = window.IPFSUtils;
    
    let pins = [];
    
    function render() {
        const container = document.getElementById('page-pins');
        container.innerHTML = `
            <div class="page-header">
                <h1>Pinned Content</h1>
                <div class="header-actions">
                    <button class="btn btn-primary" id="btn-add-pin">
                        <span class="btn-icon">📌</span>
                        Pin by CID
                    </button>
                </div>
            </div>
            
            <!-- Pin Stats -->
            <div class="pin-stats">
                <div class="pin-stat">
                    <span class="pin-stat-value" id="pins-recursive">0</span>
                    <span class="pin-stat-label">Recursive</span>
                </div>
                <div class="pin-stat">
                    <span class="pin-stat-value" id="pins-direct">0</span>
                    <span class="pin-stat-label">Direct</span>
                </div>
                <div class="pin-stat">
                    <span class="pin-stat-value" id="pins-size">0 B</span>
                    <span class="pin-stat-label">Total Size</span>
                </div>
            </div>
            
            <!-- Pin Search -->
            <div class="search-box">
                <span class="search-icon">🔍</span>
                <input type="text" class="search-input" id="pin-search" placeholder="Search pins by CID or name...">
            </div>
            
            <!-- Pin Filter -->
            <div class="btn-group" style="margin-bottom: var(--pad-lg);">
                <button class="btn btn-sm filter-btn active" data-type="all">All</button>
                <button class="btn btn-sm filter-btn" data-type="recursive">Recursive</button>
                <button class="btn btn-sm filter-btn" data-type="direct">Direct</button>
            </div>
            
            <!-- Pin List -->
            <div class="pin-list" id="pin-list">
                <div class="empty-state">
                    <div class="empty-icon">📌</div>
                    <div class="empty-text">No pinned content</div>
                    <div class="empty-subtext">Pin content to keep it available on your node</div>
                </div>
            </div>
        `;
        
        attachEventListeners();
        loadPins();
    }
    
    function attachEventListeners() {
        document.getElementById('btn-add-pin').addEventListener('click', showPinDialog);
        
        // Search
        document.getElementById('pin-search').addEventListener('input',
            IPFSUtils.debounce(filterPins, 300)
        );
        
        // Filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                loadPins(btn.dataset.type);
            });
        });
    }
    
    async function loadPins(type = 'all') {
        try {
            const result = await IPFS_API.listPins(type);
            pins = result.pins || [];
            
            // Update stats
            const recursive = pins.filter(p => p.type === 'recursive').length;
            const direct = pins.filter(p => p.type === 'direct').length;
            const totalSize = pins.reduce((sum, p) => sum + (p.size || 0), 0);
            
            document.getElementById('pins-recursive').textContent = recursive;
            document.getElementById('pins-direct').textContent = direct;
            document.getElementById('pins-size').textContent = formatBytes(totalSize);
            
            renderPinList();
        } catch (error) {
            console.error('Failed to load pins:', error);
            pins = [];
            renderPinList();
        }
    }
    
    function renderPinList(filteredPins = null) {
        const container = document.getElementById('pin-list');
        const displayPins = filteredPins || pins;
        
        if (displayPins.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">📌</div>
                    <div class="empty-text">${filteredPins ? 'No matching pins' : 'No pinned content'}</div>
                    <div class="empty-subtext">${filteredPins ? 'Try a different search term' : 'Pin content to keep it available on your node'}</div>
                </div>
            `;
            return;
        }
        
        container.innerHTML = displayPins.map(pin => `
            <div class="list-item">
                <div class="list-item-icon">📌</div>
                <div class="list-item-content">
                    <div class="list-item-title">${pin.name || truncate(pin.cid, 24)}</div>
                    <div class="list-item-subtitle">
                        ${truncate(pin.cid, 30)} 
                        ${pin.size ? `• ${formatBytes(pin.size)}` : ''}
                    </div>
                </div>
                <div class="list-item-actions">
                    <span class="badge ${pin.type === 'recursive' ? 'ok' : 'info'}">${pin.type}</span>
                    <button class="btn btn-sm btn-secondary" onclick="PinsPage.copyPinCid('${pin.cid}')">📋</button>
                    <button class="btn btn-sm btn-secondary" onclick="PinsPage.openPin('${pin.cid}')">🌐</button>
                    <button class="btn btn-sm btn-danger" onclick="PinsPage.unpinContent('${pin.cid}')">✕</button>
                </div>
            </div>
        `).join('');
    }
    
    function filterPins() {
        const search = document.getElementById('pin-search').value.toLowerCase();
        if (!search) {
            renderPinList();
            return;
        }
        
        const filtered = pins.filter(pin =>
            (pin.cid || '').toLowerCase().includes(search) ||
            (pin.name || '').toLowerCase().includes(search)
        );
        
        renderPinList(filtered);
    }
    
    function showPinDialog() {
        const cid = prompt('Enter CID to pin:');
        if (cid) {
            pinContent(cid);
        }
    }
    
    async function pinContent(cid) {
        if (!isValidCID(cid)) {
            showToast('Invalid CID format', 'error');
            return;
        }
        
        try {
            await IPFS_API.addPin(cid, true);
            showToast('Content pinned', 'success');
            loadPins();
        } catch (error) {
            showToast(`Failed to pin: ${error.message}`, 'error');
        }
    }
    
    async function unpinContent(cid) {
        if (!confirm(`Unpin ${truncate(cid, 20)}?\n\nThis will remove the pin but the content may still be available if referenced elsewhere.`)) {
            return;
        }
        
        try {
            await IPFS_API.removePin(cid, true);
            showToast('Content unpinned', 'info');
            loadPins();
        } catch (error) {
            showToast(`Failed to unpin: ${error.message}`, 'error');
        }
    }
    
    function copyPinCid(cid) {
        IPFSUtils.copyToClipboard(cid);
    }
    
    function openPin(cid) {
        const settings = IPFSUtils.loadSettings();
        const url = `${settings.gateway}/ipfs/${cid}`;
        window.open(url, '_blank');
    }
    
    // Initialize
    function init() {
        render();
    }
    
    // Expose for app.js
    window.PinsPage = {
        init,
        render,
        copyPinCid,
        openPin,
        unpinContent
    };
})();
