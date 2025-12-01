// IPNS Page - Key management and name publishing

(function() {
    const { showToast, truncate, isValidCID, parseIPFSPath } = window.IPFSUtils;
    
    let keys = [];
    
    function render() {
        const container = document.getElementById('page-ipns');
        container.innerHTML = `
            <div class="page-header">
                <h1>IPNS Keys</h1>
                <div class="header-actions">
                    <button class="btn btn-primary" id="btn-generate-key">
                        <span class="btn-icon">🔑</span>
                        Generate Key
                    </button>
                </div>
            </div>
            
            <!-- Key List -->
            <div class="key-list" id="key-list">
                <div class="empty-state">
                    <div class="empty-icon">🔑</div>
                    <div class="empty-text">No IPNS keys</div>
                    <div class="empty-subtext">Generate a key to publish content to IPNS</div>
                </div>
            </div>
            
            <!-- Publish Section -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Publish to IPNS</h2>
                </div>
                <div class="card-body">
                    <div class="form-group">
                        <label>Select Key</label>
                        <select class="form-select" id="publish-key">
                            <option value="">Select a key...</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Content CID or Path</label>
                        <input type="text" class="form-input" id="publish-cid" placeholder="/ipfs/Qm...">
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Lifetime</label>
                            <input type="text" class="form-input" id="publish-lifetime" value="24h" placeholder="24h">
                        </div>
                        <div class="form-group">
                            <label>TTL</label>
                            <input type="text" class="form-input" id="publish-ttl" value="1h" placeholder="1h">
                        </div>
                    </div>
                    <button class="btn btn-primary" id="btn-publish">
                        <span class="btn-icon">📢</span>
                        Publish
                    </button>
                </div>
            </div>
            
            <!-- Resolve Section -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Resolve IPNS Name</h2>
                </div>
                <div class="card-body">
                    <div class="form-group">
                        <label>IPNS Name</label>
                        <input type="text" class="form-input" id="resolve-name" placeholder="/ipns/k51... or /ipns/domain.eth">
                    </div>
                    <button class="btn btn-secondary" id="btn-resolve">
                        <span class="btn-icon">🔍</span>
                        Resolve
                    </button>
                    <div class="resolve-result" id="resolve-result" style="display: none;">
                        <div class="resolve-label">Resolved to:</div>
                        <div class="resolve-value" id="resolve-value"></div>
                    </div>
                </div>
            </div>
        `;
        
        attachEventListeners();
        loadKeys();
    }
    
    function attachEventListeners() {
        document.getElementById('btn-generate-key').addEventListener('click', showGenerateDialog);
        document.getElementById('btn-publish').addEventListener('click', publish);
        document.getElementById('btn-resolve').addEventListener('click', resolve);
    }
    
    async function loadKeys() {
        try {
            const result = await IPFS_API.listKeys();
            keys = result.keys || [];
            renderKeyList();
            updateKeySelect();
        } catch (error) {
            console.error('Failed to load keys:', error);
            keys = [];
            renderKeyList();
        }
    }
    
    function renderKeyList() {
        const container = document.getElementById('key-list');
        
        if (keys.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">🔑</div>
                    <div class="empty-text">No IPNS keys</div>
                    <div class="empty-subtext">Generate a key to publish content to IPNS</div>
                </div>
            `;
            return;
        }
        
        container.innerHTML = keys.map(key => `
            <div class="list-item">
                <div class="list-item-icon">🔑</div>
                <div class="list-item-content">
                    <div class="list-item-title">${key.name}</div>
                    <div class="list-item-subtitle">${truncate(key.id, 30)}</div>
                </div>
                <div class="list-item-actions">
                    <button class="btn btn-sm btn-secondary" onclick="IPNSPage.copyKeyId('${key.id}')">📋</button>
                    <button class="btn btn-sm btn-secondary" onclick="IPNSPage.renameKey('${key.name}')">✏️</button>
                    ${key.name !== 'self' ? `<button class="btn btn-sm btn-danger" onclick="IPNSPage.deleteKey('${key.name}')">🗑️</button>` : ''}
                </div>
            </div>
        `).join('');
    }
    
    function updateKeySelect() {
        const select = document.getElementById('publish-key');
        select.innerHTML = '<option value="">Select a key...</option>' +
            keys.map(key => `<option value="${key.name}">${key.name}</option>`).join('');
    }
    
    function showGenerateDialog() {
        const name = prompt('Enter key name:');
        if (name) {
            generateKey(name);
        }
    }
    
    async function generateKey(name) {
        if (!name || name.trim() === '') {
            showToast('Key name is required', 'warning');
            return;
        }
        
        try {
            await IPFS_API.generateKey(name, 'ed25519');
            showToast(`Key "${name}" generated`, 'success');
            loadKeys();
        } catch (error) {
            showToast(`Failed to generate key: ${error.message}`, 'error');
        }
    }
    
    async function renameKey(oldName) {
        if (oldName === 'self') {
            showToast('Cannot rename the "self" key', 'warning');
            return;
        }
        
        const newName = prompt(`Rename key "${oldName}" to:`, oldName);
        if (!newName || newName === oldName) return;
        
        try {
            await IPFS_API.renameKey(oldName, newName);
            showToast(`Key renamed to "${newName}"`, 'success');
            loadKeys();
        } catch (error) {
            showToast(`Failed to rename: ${error.message}`, 'error');
        }
    }
    
    async function deleteKey(name) {
        if (!confirm(`Delete key "${name}"?\n\nThis cannot be undone and any IPNS names using this key will become invalid.`)) {
            return;
        }
        
        try {
            await IPFS_API.removeKey(name);
            showToast(`Key "${name}" deleted`, 'info');
            loadKeys();
        } catch (error) {
            showToast(`Failed to delete: ${error.message}`, 'error');
        }
    }
    
    function copyKeyId(id) {
        IPFSUtils.copyToClipboard(id);
    }
    
    async function publish() {
        const keyName = document.getElementById('publish-key').value;
        const cid = document.getElementById('publish-cid').value.trim();
        const lifetime = document.getElementById('publish-lifetime').value || '24h';
        const ttl = document.getElementById('publish-ttl').value || '1h';
        
        if (!keyName) {
            showToast('Please select a key', 'warning');
            return;
        }
        
        if (!cid) {
            showToast('Please enter a CID or path', 'warning');
            return;
        }
        
        // Parse and validate
        const parsed = parseIPFSPath(cid);
        const resolvedCid = parsed?.cid || (isValidCID(cid) ? cid : null);
        
        if (!resolvedCid) {
            showToast('Invalid CID or path', 'error');
            return;
        }
        
        const btn = document.getElementById('btn-publish');
        btn.disabled = true;
        btn.innerHTML = '<span class="loading"></span> Publishing...';
        
        try {
            const result = await IPFS_API.ipnsPublish(resolvedCid, {
                key: keyName,
                lifetime,
                ttl
            });
            
            showToast('Published to IPNS!', 'success');
            
            if (result.name) {
                alert(`Published!\n\nIPNS Name: ${result.name}\nValue: ${result.value || cid}`);
            }
        } catch (error) {
            showToast(`Failed to publish: ${error.message}`, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<span class="btn-icon">📢</span> Publish';
        }
    }
    
    async function resolve() {
        const name = document.getElementById('resolve-name').value.trim();
        const resultDiv = document.getElementById('resolve-result');
        const valueEl = document.getElementById('resolve-value');
        
        if (!name) {
            showToast('Please enter an IPNS name', 'warning');
            return;
        }
        
        resultDiv.style.display = 'none';
        
        const btn = document.getElementById('btn-resolve');
        btn.disabled = true;
        btn.innerHTML = '<span class="loading"></span> Resolving...';
        
        try {
            const result = await IPFS_API.ipnsResolve(name);
            
            valueEl.textContent = result.path || result.value || 'Unknown';
            resultDiv.style.display = 'block';
            
        } catch (error) {
            showToast(`Failed to resolve: ${error.message}`, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<span class="btn-icon">🔍</span> Resolve';
        }
    }
    
    // Initialize
    function init() {
        render();
    }
    
    // Expose for app.js
    window.IPNSPage = {
        init,
        render,
        copyKeyId,
        renameKey,
        deleteKey
    };
})();
