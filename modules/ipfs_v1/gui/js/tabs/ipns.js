/**
 * IPNS Tab
 */

let ipnsKeys = [];

function renderIpnsTab() {
    const container = document.getElementById('tab-ipns');
    container.innerHTML = `
        <!-- IPNS Keys Card -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">🔑 IPNS Keys</span>
                <button class="btn btn-sm btn-secondary" onclick="refreshKeysHandler()">↻ Refresh</button>
            </div>
            <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem;">
                IPNS keys allow you to create mutable pointers to IPFS content.
            </p>
            
            <div id="keys-list">
                <div style="color: var(--text-secondary); text-align: center; padding: 20px;">Loading keys...</div>
            </div>
            
            <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border-color);">
                <div class="form-row">
                    <div class="form-group">
                        <label>New Key Name</label>
                        <input type="text" id="new-key-name" placeholder="my-key">
                    </div>
                    <div class="form-group">
                        <label>Key Type</label>
                        <select id="new-key-type">
                            <option value="ed25519">Ed25519 (recommended)</option>
                            <option value="rsa">RSA 2048</option>
                            <option value="secp256k1">secp256k1</option>
                        </select>
                    </div>
                </div>
                <button class="btn btn-secondary" onclick="generateKeyHandler()">🔑 Generate Key</button>
            </div>
        </div>
        
        <!-- Publish to IPNS Card -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">📤 Publish to IPNS</span>
            </div>
            <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem;">
                Publish an IPFS CID to an IPNS name. The IPNS name will resolve to this CID.
            </p>
            <div class="form-row">
                <div class="form-group">
                    <label>CID to Publish</label>
                    <input type="text" id="publish-cid" placeholder="Qm... or bafy...">
                </div>
                <div class="form-group">
                    <label>Key</label>
                    <select id="publish-key">
                        <option value="self">self (default)</option>
                    </select>
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>TTL (seconds)</label>
                    <input type="number" id="publish-ttl" value="3600" min="60">
                    <div class="form-hint">How long resolvers should cache this record</div>
                </div>
                <div class="form-group">
                    <label>Lifetime (seconds)</label>
                    <input type="number" id="publish-lifetime" value="86400" min="3600">
                    <div class="form-hint">How long until this record expires</div>
                </div>
            </div>
            <button class="btn btn-primary" onclick="publishIpnsHandler()">📤 Publish</button>
            
            <div id="publish-result" style="display: none; margin-top: 16px;"></div>
        </div>
        
        <!-- Resolve IPNS Card -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">🔍 Resolve IPNS Name</span>
            </div>
            <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem;">
                Resolve an IPNS name to its current IPFS CID.
            </p>
            <div class="form-row">
                <div class="form-group" style="flex: 2;">
                    <label>IPNS Name</label>
                    <input type="text" id="resolve-name" placeholder="k51qzi5uqu5... or /ipns/domain.com">
                    <div class="form-hint">Peer ID, CID, or domain name</div>
                </div>
                <div class="form-group" style="display: flex; align-items: flex-end;">
                    <button class="btn btn-secondary" onclick="resolveIpnsHandler()">🔍 Resolve</button>
                </div>
            </div>
            
            <div id="resolve-result" style="display: none; margin-top: 16px;"></div>
        </div>
        
        <!-- IPNS Info Card -->
        <div class="card">
            <div class="card-title" style="margin-bottom: 16px;">📚 About IPNS</div>
            <div style="color: var(--text-secondary); font-size: 0.9rem; line-height: 1.8;">
                <p><strong>IPNS (InterPlanetary Name System)</strong> provides mutable pointers to IPFS content.</p>
                <ul style="margin: 12px 0; padding-left: 20px;">
                    <li><strong>Mutable:</strong> Unlike CIDs, IPNS names can be updated to point to new content</li>
                    <li><strong>Cryptographic:</strong> IPNS names are derived from public keys, ensuring authenticity</li>
                    <li><strong>Human-readable:</strong> IPNS names can be linked to DNS names via DNSLink</li>
                    <li><strong>DHT-based:</strong> IPNS records are stored and resolved through the DHT</li>
                </ul>
                <p>Example: <code>/ipns/k51qzi5uqu5...</code> → <code>/ipfs/Qm...</code></p>
            </div>
        </div>
    `;
    
    // Load keys
    refreshKeysHandler();
}

async function refreshKeysHandler() {
    const result = await api.listKeys();
    
    if (result.error) {
        showToast('Failed to load keys: ' + result.error, 'error');
        return;
    }
    
    ipnsKeys = result.Keys || result.keys || result || [];
    renderKeysList(ipnsKeys);
    updateKeySelect(ipnsKeys);
}

function renderKeysList(keys) {
    const container = document.getElementById('keys-list');
    
    if (!Array.isArray(keys) || keys.length === 0) {
        container.innerHTML = '<div style="color: var(--text-secondary); text-align: center; padding: 20px;">No keys found</div>';
        return;
    }
    
    container.innerHTML = keys.map(key => `
        <div class="key-item">
            <div>
                <div class="key-name">${escapeHtml(key.Name || key.name)}</div>
                <div class="key-id">${key.Id || key.id}</div>
            </div>
            <div class="btn-group">
                <button class="btn btn-sm btn-secondary" onclick="copyToClipboard('${key.Id || key.id}')" title="Copy Key ID">📋</button>
                <button class="btn btn-sm btn-secondary" onclick="copyIpnsUrl('${key.Id || key.id}')" title="Copy IPNS URL">🔗</button>
                ${(key.Name || key.name) !== 'self' ? `
                    <button class="btn btn-sm btn-danger" onclick="removeKeyHandler('${key.Name || key.name}')" title="Remove Key">🗑️</button>
                ` : ''}
            </div>
        </div>
    `).join('');
}

function updateKeySelect(keys) {
    const select = document.getElementById('publish-key');
    select.innerHTML = keys.map(key => 
        `<option value="${key.Name || key.name}">${key.Name || key.name}</option>`
    ).join('');
}

async function generateKeyHandler() {
    const name = document.getElementById('new-key-name').value.trim();
    const type = document.getElementById('new-key-type').value;
    
    if (!name) {
        showToast('Please enter a key name', 'error');
        return;
    }
    
    if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
        showToast('Key name can only contain letters, numbers, dashes, and underscores', 'error');
        return;
    }
    
    showToast('Generating key...', 'info');
    
    const result = await api.generateKey(name, type);
    
    if (result.error) {
        showToast('Failed to generate key: ' + result.error, 'error');
    } else {
        showToast('Key generated successfully!', 'success');
        document.getElementById('new-key-name').value = '';
        refreshKeysHandler();
    }
}

async function removeKeyHandler(name) {
    if (!confirm(`Remove key "${name}"?\n\nThis cannot be undone. Any IPNS records published with this key will become inaccessible.`)) {
        return;
    }
    
    const result = await api.callModule('ipns_keys', { remove: name });
    
    if (result.error) {
        showToast('Failed to remove key: ' + result.error, 'error');
    } else {
        showToast('Key removed', 'success');
        refreshKeysHandler();
    }
}

function copyIpnsUrl(keyId) {
    const url = `${CONFIG.publicGateway}/ipns/${keyId}`;
    copyToClipboard(url);
}

async function publishIpnsHandler() {
    const cid = document.getElementById('publish-cid').value.trim();
    const key = document.getElementById('publish-key').value;
    const ttl = parseInt(document.getElementById('publish-ttl').value) || 3600;
    const lifetime = parseInt(document.getElementById('publish-lifetime').value) || 86400;
    const resultContainer = document.getElementById('publish-result');
    
    if (!cid) {
        showToast('Please enter a CID', 'error');
        return;
    }
    
    if (!isValidCid(cid)) {
        showToast('Invalid CID format', 'error');
        return;
    }
    
    showToast('Publishing to IPNS...', 'info');
    resultContainer.innerHTML = '<div class="loading"></div>';
    resultContainer.style.display = 'block';
    
    const result = await api.publishIpns(cid, { key, ttl, lifetime });
    
    if (result.error) {
        resultContainer.innerHTML = `
            <div class="info-banner error">
                <span class="icon">❌</span>
                <div>Publish failed: ${escapeHtml(result.error)}</div>
            </div>
        `;
    } else {
        const ipnsName = result.name || result.Name || key;
        resultContainer.innerHTML = `
            <div class="info-banner success">
                <span class="icon">✅</span>
                <div style="flex: 1;">
                    <strong>Published Successfully!</strong>
                    <div style="font-size: 0.85rem; margin-top: 4px;">
                        <div>IPNS: <code>${ipnsName}</code></div>
                        <div>Value: <code>${cid}</code></div>
                    </div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-sm btn-secondary" onclick="copyToClipboard('/ipns/${ipnsName}')">📋</button>
                    <button class="btn btn-sm btn-secondary" onclick="window.open('${CONFIG.publicGateway}/ipns/${ipnsName}', '_blank')">🔗</button>
                </div>
            </div>
        `;
        showToast('Published to IPNS!', 'success');
    }
}

async function resolveIpnsHandler() {
    const name = document.getElementById('resolve-name').value.trim();
    const resultContainer = document.getElementById('resolve-result');
    
    if (!name) {
        showToast('Please enter an IPNS name', 'error');
        return;
    }
    
    showToast('Resolving IPNS name...', 'info');
    resultContainer.innerHTML = '<div class="loading"></div>';
    resultContainer.style.display = 'block';
    
    const result = await api.resolveIpns(name);
    
    if (result.error) {
        resultContainer.innerHTML = `
            <div class="info-banner error">
                <span class="icon">❌</span>
                <div>Resolution failed: ${escapeHtml(result.error)}</div>
            </div>
        `;
    } else {
        const resolvedPath = result.path || result.Path || result.cid || result;
        const cleanCid = typeof resolvedPath === 'string' ? resolvedPath.replace('/ipfs/', '') : resolvedPath;
        
        resultContainer.innerHTML = `
            <div class="ipns-record">
                <div style="flex: 1;">
                    <div class="ipns-name">/ipns/${escapeHtml(name)}</div>
                    <div class="ipns-value" style="margin-top: 4px;">→ ${escapeHtml(resolvedPath)}</div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-sm btn-secondary" onclick="copyToClipboard('${cleanCid}')">📋 Copy CID</button>
                    <button class="btn btn-sm btn-secondary" onclick="openGateway('${cleanCid}')">🔗 Open</button>
                </div>
            </div>
        `;
    }
}

// Export
window.renderIpnsTab = renderIpnsTab;
window.refreshKeysHandler = refreshKeysHandler;
window.generateKeyHandler = generateKeyHandler;
window.removeKeyHandler = removeKeyHandler;
window.copyIpnsUrl = copyIpnsUrl;
window.publishIpnsHandler = publishIpnsHandler;
window.resolveIpnsHandler = resolveIpnsHandler;
