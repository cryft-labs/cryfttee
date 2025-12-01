// Settings Page - Configuration options

(function() {
    const { showToast, loadSettings, saveSettings, formatBytes, toBytes } = window.IPFSUtils;
    
    function render() {
        const settings = loadSettings();
        const container = document.getElementById('page-settings');
        
        container.innerHTML = `
            <div class="page-header">
                <h1>Settings</h1>
            </div>
            
            <!-- Network Settings -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Network</h2>
                </div>
                <div class="card-body">
                    <div class="setting-item">
                        <div class="setting-info">
                            <div class="setting-label">Enable DHT Server</div>
                            <div class="setting-desc">Participate fully in DHT operations (Full Node only)</div>
                        </div>
                        <label class="toggle">
                            <input type="checkbox" id="setting-dht-server" ${settings.dhtServer ? 'checked' : ''}>
                            <span class="toggle-slider"></span>
                        </label>
                    </div>
                    <div class="setting-item">
                        <div class="setting-info">
                            <div class="setting-label">Enable Relay</div>
                            <div class="setting-desc">Allow connections through relay nodes</div>
                        </div>
                        <label class="toggle">
                            <input type="checkbox" id="setting-relay" ${settings.relay ? 'checked' : ''}>
                            <span class="toggle-slider"></span>
                        </label>
                    </div>
                    <div class="setting-item">
                        <div class="setting-info">
                            <div class="setting-label">Enable AutoNAT</div>
                            <div class="setting-desc">Automatic NAT traversal detection</div>
                        </div>
                        <label class="toggle">
                            <input type="checkbox" id="setting-autonat" ${settings.autonat ? 'checked' : ''}>
                            <span class="toggle-slider"></span>
                        </label>
                    </div>
                </div>
            </div>
            
            <!-- Storage Settings -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Storage</h2>
                </div>
                <div class="card-body">
                    <div class="form-group">
                        <label>Storage Limit</label>
                        <div class="input-with-unit">
                            <input type="number" class="form-input" id="setting-storage-limit" 
                                   value="${settings.storageLimit}" min="1">
                            <select class="form-select unit-select" id="setting-storage-unit">
                                <option value="MB" ${settings.storageUnit === 'MB' ? 'selected' : ''}>MB</option>
                                <option value="GB" ${settings.storageUnit === 'GB' ? 'selected' : ''}>GB</option>
                                <option value="TB" ${settings.storageUnit === 'TB' ? 'selected' : ''}>TB</option>
                            </select>
                        </div>
                    </div>
                    <div class="setting-item">
                        <div class="setting-info">
                            <div class="setting-label">Enable Garbage Collection</div>
                            <div class="setting-desc">Automatically remove unpinned blocks when storage is full</div>
                        </div>
                        <label class="toggle">
                            <input type="checkbox" id="setting-gc" ${settings.gcEnabled ? 'checked' : ''}>
                            <span class="toggle-slider"></span>
                        </label>
                    </div>
                    <div class="form-group">
                        <label>GC Watermark (%)</label>
                        <div style="display: flex; align-items: center; gap: var(--pad-md);">
                            <input type="range" class="form-range" id="setting-gc-watermark" 
                                   min="50" max="95" value="${settings.gcWatermark}">
                            <span class="range-value" id="gc-watermark-value">${settings.gcWatermark}%</span>
                        </div>
                        <div class="form-hint">Run GC when storage exceeds this percentage</div>
                    </div>
                </div>
            </div>
            
            <!-- Gateway Settings -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Gateway</h2>
                </div>
                <div class="card-body">
                    <div class="form-group">
                        <label>Public Gateway</label>
                        <select class="form-select" id="setting-gateway">
                            ${IPFS_CONFIG.GATEWAYS.map(gw => 
                                `<option value="${gw.url}" ${settings.gateway === gw.url ? 'selected' : ''}>${gw.name}</option>`
                            ).join('')}
                            <option value="custom" ${!IPFS_CONFIG.GATEWAYS.find(g => g.url === settings.gateway) ? 'selected' : ''}>Custom...</option>
                        </select>
                    </div>
                    <div class="form-group" id="custom-gateway-group" 
                         style="display: ${!IPFS_CONFIG.GATEWAYS.find(g => g.url === settings.gateway) ? 'block' : 'none'};">
                        <label>Custom Gateway URL</label>
                        <input type="text" class="form-input" id="setting-custom-gateway" 
                               value="${settings.gateway}" placeholder="https://...">
                    </div>
                </div>
            </div>
            
            <!-- Advanced Settings -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Advanced</h2>
                </div>
                <div class="card-body">
                    <div class="form-row">
                        <div class="form-group">
                            <label>Connection Manager Low Watermark</label>
                            <input type="number" class="form-input" id="setting-connmgr-low" 
                                   value="${settings.connmgrLow}" min="10">
                            <div class="form-hint">Minimum connections to maintain</div>
                        </div>
                        <div class="form-group">
                            <label>Connection Manager High Watermark</label>
                            <input type="number" class="form-input" id="setting-connmgr-high" 
                                   value="${settings.connmgrHigh}" min="50">
                            <div class="form-hint">Maximum connections before pruning</div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Connection Manager Grace Period</label>
                        <input type="text" class="form-input" id="setting-connmgr-grace" 
                               value="${settings.connmgrGrace}" placeholder="30s">
                        <div class="form-hint">Time before new connections can be pruned</div>
                    </div>
                    <div class="btn-group" style="margin-top: var(--pad-xl);">
                        <button class="btn btn-secondary" id="btn-reset-settings">
                            Reset to Defaults
                        </button>
                        <button class="btn btn-primary" id="btn-save-settings">
                            Save Settings
                        </button>
                    </div>
                </div>
            </div>
            
            <!-- Danger Zone -->
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title" style="color: var(--bad);">Danger Zone</h2>
                </div>
                <div class="card-body">
                    <div class="setting-item" style="border: 1px solid var(--bad); border-radius: var(--radius-lg);">
                        <div class="setting-info">
                            <div class="setting-label">Run Garbage Collection</div>
                            <div class="setting-desc">Remove all unpinned blocks from the datastore</div>
                        </div>
                        <button class="btn btn-danger" id="btn-run-gc">Run GC</button>
                    </div>
                </div>
            </div>
        `;
        
        attachEventListeners();
    }
    
    function attachEventListeners() {
        // GC watermark slider
        const gcSlider = document.getElementById('setting-gc-watermark');
        const gcValue = document.getElementById('gc-watermark-value');
        gcSlider.addEventListener('input', () => {
            gcValue.textContent = gcSlider.value + '%';
        });
        
        // Gateway select
        const gatewaySelect = document.getElementById('setting-gateway');
        const customGroup = document.getElementById('custom-gateway-group');
        gatewaySelect.addEventListener('change', () => {
            customGroup.style.display = gatewaySelect.value === 'custom' ? 'block' : 'none';
        });
        
        // Save button
        document.getElementById('btn-save-settings').addEventListener('click', saveCurrentSettings);
        
        // Reset button
        document.getElementById('btn-reset-settings').addEventListener('click', resetSettings);
        
        // Run GC button
        document.getElementById('btn-run-gc').addEventListener('click', runGarbageCollection);
    }
    
    function saveCurrentSettings() {
        const gatewaySelect = document.getElementById('setting-gateway');
        
        const newSettings = {
            dhtServer: document.getElementById('setting-dht-server').checked,
            relay: document.getElementById('setting-relay').checked,
            autonat: document.getElementById('setting-autonat').checked,
            storageLimit: parseInt(document.getElementById('setting-storage-limit').value) || 10,
            storageUnit: document.getElementById('setting-storage-unit').value,
            gcEnabled: document.getElementById('setting-gc').checked,
            gcWatermark: parseInt(document.getElementById('setting-gc-watermark').value) || 90,
            gateway: gatewaySelect.value === 'custom' 
                ? document.getElementById('setting-custom-gateway').value 
                : gatewaySelect.value,
            connmgrLow: parseInt(document.getElementById('setting-connmgr-low').value) || 100,
            connmgrHigh: parseInt(document.getElementById('setting-connmgr-high').value) || 400,
            connmgrGrace: document.getElementById('setting-connmgr-grace').value || '30s'
        };
        
        // Validate
        if (newSettings.connmgrLow >= newSettings.connmgrHigh) {
            showToast('Low watermark must be less than high watermark', 'error');
            return;
        }
        
        if (newSettings.storageLimit < 1) {
            showToast('Storage limit must be at least 1', 'error');
            return;
        }
        
        if (saveSettings(newSettings)) {
            showToast('Settings saved', 'success');
            
            // Try to apply settings to running node
            applySettings(newSettings);
        } else {
            showToast('Failed to save settings', 'error');
        }
    }
    
    async function applySettings(settings) {
        // Try to apply settings to the running node
        try {
            await IPFS_API.setConfig('Datastore.StorageMax', 
                `${settings.storageLimit}${settings.storageUnit}`
            );
        } catch (e) {
            console.log('Could not apply storage setting to running node');
        }
    }
    
    function resetSettings() {
        if (!confirm('Reset all settings to defaults?\n\nThis will not affect your stored content.')) {
            return;
        }
        
        saveSettings(IPFS_CONFIG.DEFAULTS);
        showToast('Settings reset to defaults', 'info');
        render();
    }
    
    async function runGarbageCollection() {
        if (!confirm('Run garbage collection?\n\nThis will remove all unpinned blocks from storage.')) {
            return;
        }
        
        const btn = document.getElementById('btn-run-gc');
        btn.disabled = true;
        btn.innerHTML = '<span class="loading"></span> Running...';
        
        try {
            const result = await IPFS_API.repoGc();
            const freed = result.freed || 0;
            showToast(`GC complete. Freed ${formatBytes(freed)}`, 'success');
        } catch (error) {
            showToast(`GC failed: ${error.message}`, 'error');
        } finally {
            btn.disabled = false;
            btn.textContent = 'Run GC';
        }
    }
    
    // Initialize
    function init() {
        render();
    }
    
    // Expose for app.js
    window.SettingsPage = {
        init,
        render
    };
})();
