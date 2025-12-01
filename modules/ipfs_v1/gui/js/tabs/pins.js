/**
 * Pins Tab
 */

let currentPins = [];

function renderPinsTab() {
    const container = document.getElementById('tab-pins');
    container.innerHTML = `
        <div class="search-container">
            <input type="text" class="search-input" id="pin-search" placeholder="Search by CID, name, or tag...">
            <select id="pin-type-filter" style="width: auto; padding: 10px 12px; background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-primary);">
                <option value="all">All Types</option>
                <option value="recursive" selected>Recursive</option>
                <option value="direct">Direct</option>
            </select>
            <button class="btn btn-primary" onclick="searchPinsHandler()">Search</button>
        </div>
        
        <div class="card">
            <div class="card-header">
                <span class="card-title">📌 Pinned Content</span>
                <div class="btn-group">
                    <button class="btn btn-sm btn-secondary" onclick="refreshPinsHandler()">↻ Refresh</button>
                    <button class="btn btn-sm btn-secondary" onclick="exportPins()">📥 Export</button>
                </div>
            </div>
            
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>CID</th>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Size</th>
                            <th>Pinned At</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="pins-table-body">
                        <tr><td colspan="6" style="text-align: center; color: var(--text-secondary);">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
            
            <div class="empty-state" id="pins-empty" style="display: none;">
                <div class="empty-state-icon">📭</div>
                <p>No pinned content found</p>
                <p style="font-size: 0.9rem; margin-top: 8px;">Add content to your node and pin it to keep it available</p>
            </div>
        </div>
        
        <!-- Quick Pin Card -->
        <div class="card">
            <div class="card-title" style="margin-bottom: 16px;">📌 Quick Pin</div>
            <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem;">
                Pin content from the IPFS network to your local node.
            </p>
            <div class="form-row">
                <div class="form-group">
                    <label>CID</label>
                    <input type="text" id="quick-pin-cid" placeholder="Qm... or bafy...">
                </div>
                <div class="form-group">
                    <label>Name (optional)</label>
                    <input type="text" id="quick-pin-name" placeholder="my-file.txt">
                </div>
            </div>
            <div class="form-group">
                <label class="checkbox-label">
                    <input type="checkbox" id="quick-pin-recursive" checked>
                    Recursive (include linked content)
                </label>
            </div>
            <button class="btn btn-primary" onclick="quickPinHandler()">📌 Pin Content</button>
        </div>
    `;
    
    // Add search event listener
    document.getElementById('pin-search').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') searchPinsHandler();
    });
    
    // Load initial pins
    refreshPinsHandler();
}

async function refreshPinsHandler() {
    const type = document.getElementById('pin-type-filter')?.value || 'recursive';
    const result = await api.listPins(type);
    
    if (result.error) {
        showToast('Failed to load pins: ' + result.error, 'error');
        return;
    }
    
    currentPins = result.pins || result || [];
    renderPinsTable(currentPins);
}

async function searchPinsHandler() {
    const query = document.getElementById('pin-search').value.trim();
    
    if (!query) {
        refreshPinsHandler();
        return;
    }
    
    const result = await api.searchPins(query);
    
    if (result.error) {
        showToast('Search failed: ' + result.error, 'error');
        return;
    }
    
    currentPins = result.pins || result || [];
    renderPinsTable(currentPins);
}

function renderPinsTable(pins) {
    const tbody = document.getElementById('pins-table-body');
    const emptyState = document.getElementById('pins-empty');
    const pinCountEl = document.getElementById('pin-count');
    
    if (!Array.isArray(pins) || pins.length === 0) {
        tbody.innerHTML = '';
        emptyState.style.display = 'block';
        pinCountEl.textContent = '0';
        return;
    }
    
    emptyState.style.display = 'none';
    pinCountEl.textContent = pins.length;
    
    tbody.innerHTML = pins.map(pin => `
        <tr data-cid="${escapeHtml(pin.cid)}">
            <td class="cid-cell">
                <a href="${CONFIG.publicGateway}/ipfs/${pin.cid}" target="_blank" title="${pin.cid}">
                    ${truncateCid(pin.cid)}
                </a>
            </td>
            <td>${escapeHtml(pin.name || '-')}</td>
            <td><span class="badge badge-${pin.pinType || 'recursive'}">${pin.pinType || 'recursive'}</span></td>
            <td>${pin.size ? formatBytes(pin.size) : '-'}</td>
            <td>${formatDate(pin.pinnedAt)}</td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-sm btn-secondary" onclick="copyToClipboard('${pin.cid}')" title="Copy CID">📋</button>
                    <button class="btn btn-sm btn-secondary" onclick="openGateway('${pin.cid}')" title="Open in Gateway">🔗</button>
                    <button class="btn btn-sm btn-secondary" onclick="showPinDetails('${pin.cid}')" title="Details">ℹ️</button>
                    <button class="btn btn-sm btn-danger" onclick="unpinHandler('${pin.cid}')" title="Unpin">🗑️</button>
                </div>
            </td>
        </tr>
    `).join('');
}

async function quickPinHandler() {
    const cid = document.getElementById('quick-pin-cid').value.trim();
    const name = document.getElementById('quick-pin-name').value.trim() || undefined;
    const recursive = document.getElementById('quick-pin-recursive').checked;
    
    if (!cid) {
        showToast('Please enter a CID', 'error');
        return;
    }
    
    if (!isValidCid(cid)) {
        showToast('Invalid CID format', 'error');
        return;
    }
    
    showToast('Pinning content...', 'info');
    
    const result = await api.pinCid(cid, { name, recursive });
    
    if (result.error) {
        showToast('Pin failed: ' + result.error, 'error');
    } else {
        showToast('Content pinned successfully!', 'success');
        document.getElementById('quick-pin-cid').value = '';
        document.getElementById('quick-pin-name').value = '';
        refreshPinsHandler();
    }
}

async function unpinHandler(cid) {
    if (!confirm(`Unpin ${truncateCid(cid)}?\n\nThis will remove the content from your local node.`)) {
        return;
    }
    
    const result = await api.unpinCid(cid);
    
    if (result.error) {
        showToast('Unpin failed: ' + result.error, 'error');
    } else {
        showToast('Content unpinned', 'success');
        refreshPinsHandler();
    }
}

async function showPinDetails(cid) {
    const result = await api.statContent(cid);
    
    if (result.error) {
        showToast('Failed to get details: ' + result.error, 'error');
        return;
    }
    
    const details = `
CID: ${cid}
Size: ${formatBytes(result.size || result.CumulativeSize || 0)}
Blocks: ${result.blocks || result.NumLinks || 0}
Type: ${result.type || result.Type || 'unknown'}
    `.trim();
    
    alert(details);
}

function exportPins() {
    if (!currentPins || currentPins.length === 0) {
        showToast('No pins to export', 'warning');
        return;
    }
    
    const data = JSON.stringify(currentPins, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `ipfs-pins-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    
    URL.revokeObjectURL(url);
    showToast('Pins exported', 'success');
}

// Export
window.renderPinsTab = renderPinsTab;
window.refreshPinsHandler = refreshPinsHandler;
window.searchPinsHandler = searchPinsHandler;
window.quickPinHandler = quickPinHandler;
window.unpinHandler = unpinHandler;
window.showPinDetails = showPinDetails;
window.exportPins = exportPins;
