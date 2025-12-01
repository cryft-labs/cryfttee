/**
 * Settings Tab
 */

function renderSettingsTab() {
    const container = document.getElementById('tab-settings');
    container.innerHTML = `
        <!-- Node Mode Card -->
        <div class="card">
            <div class="card-title" style="margin-bottom: 16px;">🎛️ Node Mode</div>
            <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem;">
                Select how your IPFS node operates. Changes require a node restart.
            </p>
            <div class="form-group">
                <label>Mode</label>
                <select id="config-node-mode">
                    <option value="full">Full Node - Complete DHT, serves blocks, announces content</option>
                    <option value="light">Light Node - Minimal DHT, request-only, low resources</option>
                </select>
            </div>
            <div class="info-banner" style="margin-top: 16px;">
                <span class="icon">💡</span>
                <div>
                    <strong>Full Node</strong> is recommended for servers and always-on machines.<br>
                    <strong>Light Node</strong> is ideal for laptops, mobile devices, or limited bandwidth situations.
                </div>
            </div>
        </div>
        
        <!-- Storage Settings Card -->
        <div class="card">
            <div class="card-title" style="margin-bottom: 16px;">💾 Storage</div>
            <div class="form-row">
                <div class="form-group">
                    <label>Repository Path</label>
                    <input type="text" id="config-repo-path" value="~/.cryfttee/ipfs" readonly>
                    <div class="form-hint">Location of the IPFS repository</div>
                </div>
                <div class="form-group">
                    <label>Storage Limit (GB)</label>
                    <input type="number" id="config-storage-limit" value="50" min="1" max="10000">
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>GC High Watermark (%)</label>
                    <input type="number" id="config-gc-high" value="90" min="50" max="99">
                    <div class="form-hint">Start GC when storage exceeds this %</div>
                </div>
                <div class="form-group">
                    <label>GC Low Watermark (%)</label>
                    <input type="number" id="config-gc-low" value="70" min="10" max="90">
                    <div class="form-hint">Stop GC when storage falls below this %</div>
                </div>
            </div>
        </div>
        
        <!-- Network Settings Card -->
        <div class="card">
            <div class="card-title" style="margin-bottom: 16px;">🌐 Network</div>
            <div class="form-row">
                <div class="form-group">
                    <label>Max Connections</label>
                    <input type="number" id="config-max-conns" value="900" min="10" max="5000">
                </div>
                <div class="form-group">
                    <label>Min Connections</label>
                    <input type="number" id="config-min-conns" value="50" min="1" max="500">
                </div>
            </div>
            <div class="form-group">
                <label>Listen Addresses</label>
                <textarea id="config-listen-addrs" style="font-family: monospace; font-size: 0.85rem;">/ip4/0.0.0.0/tcp/4001
/ip6/::/tcp/4001
/ip4/0.0.0.0/udp/4001/quic-v1
/ip6/::/udp/4001/quic-v1</textarea>
                <div class="form-hint">One address per line</div>
            </div>
            <div class="form-group">
                <label>Bootstrap Peers</label>
                <textarea id="config-bootstrap" style="font-family: monospace; font-size: 0.85rem;">/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN
/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa
/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb
/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt</textarea>
                <div class="form-hint">Peers to connect to on startup</div>
            </div>
        </div>
        
        <!-- Gateway Settings Card -->
        <div class="card">
            <div class="card-title" style="margin-bottom: 16px;">🚪 Gateway</div>
            <div class="form-row">
                <div class="form-group">
                    <label class="checkbox-label">
                        <input type="checkbox" id="config-gateway-enabled" checked>
                        Enable Local Gateway
                    </label>
                </div>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>Gateway Listen Address</label>
                    <input type="text" id="config-gateway-addr" value="127.0.0.1:8080">
                </div>
                <div class="form-group">
                    <label>Public Gateway (for links)</label>
                    <input type="text" id="config-public-gateway" value="https://gateway.cryft.network">
                </div>
            </div>
            <div class="form-group">
                <label>Fallback Gateways</label>
                <textarea id="config-fallback-gateways" style="font-family: monospace; font-size: 0.85rem;">https://ipfs.io
https://dweb.link
https://cloudflare-ipfs.com</textarea>
                <div class="form-hint">Used when content is not available locally</div>
            </div>
        </div>
        
        <!-- API Settings Card -->
        <div class="card">
            <div class="card-title" style="margin-bottom: 16px;">🔌 API</div>
            <div class="form-row">
                <div class="form-group">
                    <label>API Listen Address</label>
                    <input type="text" id="config-api-addr" value="127.0.0.1:5001">
                </div>
                <div class="form-group">
                    <label>Request Timeout (seconds)</label>
                    <input type="number" id="config-timeout" value="60" min="10" max="600">
                </div>
            </div>
            <div class="form-group">
                <label>CORS Origins</label>
                <input type="text" id="config-cors" value="*">
                <div class="form-hint">Comma-separated list of allowed origins, or * for all</div>
            </div>
        </div>
        
        <!-- IPNS Settings Card -->
        <div class="card">
            <div class="card-title" style="margin-bottom: 16px;">🔗 IPNS</div>
            <div class="form-row">
                <div class="form-group">
                    <label>Cache TTL (seconds)</label>
                    <input type="number" id="config-ipns-cache-ttl" value="3600" min="60">
                </div>
                <div class="form-group">
                    <label>Republish Interval (hours)</label>
                    <input type="number" id="config-ipns-republish" value="12" min="1" max="72">
                </div>
            </div>
        </div>
        
        <!-- Save Button -->
        <div class="btn-group">
            <button class="btn btn-lg btn-primary" onclick="saveSettingsHandler()">💾 Save Configuration</button>
            <button class="btn btn-lg btn-secondary" onclick="resetSettingsHandler()">↩️ Reset to Defaults</button>
            <button class="btn btn-lg btn-secondary" onclick="exportConfigHandler()">📥 Export Config</button>
        </div>
    `;
    
    // Load current config
    loadCurrentConfig();
}

async function loadCurrentConfig() {
    const result = await api.getNodeConfig();
    
    if (result.error) {
        console.error('Failed to load config:', result.error);
        return;
    }
    
    const config = result.config || result;
    
    // Populate form fields
    if (config.node?.mode) {
        document.getElementById('config-node-mode').value = config.node.mode;
    }
    
    if (config.storage) {
        if (config.storage.repo_path) {
            document.getElementById('config-repo-path').value = config.storage.repo_path;
        }
        if (config.storage.max_storage_gb) {
            document.getElementById('config-storage-limit').value = config.storage.max_storage_gb;
        }
        if (config.storage.gc_watermark_high) {
            document.getElementById('config-gc-high').value = Math.round(config.storage.gc_watermark_high * 100);
        }
        if (config.storage.gc_watermark_low) {
            document.getElementById('config-gc-low').value = Math.round(config.storage.gc_watermark_low * 100);
        }
    }
    
    if (config.network) {
        if (config.network.max_connections) {
            document.getElementById('config-max-conns').value = config.network.max_connections;
        }
        if (config.network.min_connections) {
            document.getElementById('config-min-conns').value = config.network.min_connections;
        }
        if (config.network.listen_addrs) {
            document.getElementById('config-listen-addrs').value = config.network.listen_addrs.join('\n');
        }
        if (config.network.bootstrap_peers) {
            document.getElementById('config-bootstrap').value = config.network.bootstrap_peers.join('\n');
        }
    }
    
    if (config.gateway) {
        document.getElementById('config-gateway-enabled').checked = config.gateway.enabled !== false;
        if (config.gateway.listen_addr) {
            document.getElementById('config-gateway-addr').value = config.gateway.listen_addr;
        }
        if (config.gateway.public_gateways?.[0]) {
            document.getElementById('config-public-gateway').value = config.gateway.public_gateways[0];
        }
        if (config.gateway.public_gateways) {
            document.getElementById('config-fallback-gateways').value = config.gateway.public_gateways.slice(1).join('\n');
        }
    }
    
    if (config.api) {
        if (config.api.listen_addr) {
            document.getElementById('config-api-addr').value = config.api.listen_addr;
        }
    }
    
    if (config.limits?.request_timeout_secs) {
        document.getElementById('config-timeout').value = config.limits.request_timeout_secs;
    }
    
    if (config.ipns) {
        if (config.ipns.cache_ttl_secs) {
            document.getElementById('config-ipns-cache-ttl').value = config.ipns.cache_ttl_secs;
        }
        if (config.ipns.republish_interval_hours) {
            document.getElementById('config-ipns-republish').value = config.ipns.republish_interval_hours;
        }
    }
}

async function saveSettingsHandler() {
    const config = {
        node: {
            mode: document.getElementById('config-node-mode').value
        },
        storage: {
            max_storage_gb: parseInt(document.getElementById('config-storage-limit').value),
            gc_watermark_high: parseInt(document.getElementById('config-gc-high').value) / 100,
            gc_watermark_low: parseInt(document.getElementById('config-gc-low').value) / 100
        },
        network: {
            max_connections: parseInt(document.getElementById('config-max-conns').value),
            min_connections: parseInt(document.getElementById('config-min-conns').value),
            listen_addrs: document.getElementById('config-listen-addrs').value.split('\n').filter(a => a.trim()),
            bootstrap_peers: document.getElementById('config-bootstrap').value.split('\n').filter(a => a.trim())
        },
        gateway: {
            enabled: document.getElementById('config-gateway-enabled').checked,
            listen_addr: document.getElementById('config-gateway-addr').value,
            public_gateways: [
                document.getElementById('config-public-gateway').value,
                ...document.getElementById('config-fallback-gateways').value.split('\n').filter(a => a.trim())
            ]
        },
        api: {
            listen_addr: document.getElementById('config-api-addr').value,
            cors_origins: document.getElementById('config-cors').value.split(',').map(o => o.trim())
        },
        limits: {
            request_timeout_secs: parseInt(document.getElementById('config-timeout').value)
        },
        ipns: {
            cache_ttl_secs: parseInt(document.getElementById('config-ipns-cache-ttl').value),
            republish_interval_hours: parseInt(document.getElementById('config-ipns-republish').value)
        }
    };
    
    showToast('Saving configuration...', 'info');
    
    const result = await api.setNodeConfig(config);
    
    if (result.error) {
        showToast('Failed to save: ' + result.error, 'error');
    } else {
        showToast('Configuration saved! Restart node for changes to take effect.', 'success');
        
        // Update global config
        CONFIG.publicGateway = config.gateway.public_gateways[0];
        
        // Update node mode badge if changed
        if (config.node.mode !== nodeState.mode) {
            updateNodeModeBadge(config.node.mode);
        }
    }
}

function resetSettingsHandler() {
    if (!confirm('Reset all settings to defaults?\n\nThis will not affect stored data or keys.')) {
        return;
    }
    
    // Reset form to defaults
    document.getElementById('config-node-mode').value = 'full';
    document.getElementById('config-storage-limit').value = '50';
    document.getElementById('config-gc-high').value = '90';
    document.getElementById('config-gc-low').value = '70';
    document.getElementById('config-max-conns').value = '900';
    document.getElementById('config-min-conns').value = '50';
    document.getElementById('config-listen-addrs').value = `/ip4/0.0.0.0/tcp/4001
/ip6/::/tcp/4001
/ip4/0.0.0.0/udp/4001/quic-v1
/ip6/::/udp/4001/quic-v1`;
    document.getElementById('config-bootstrap').value = `/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN
/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa
/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb
/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt`;
    document.getElementById('config-gateway-enabled').checked = true;
    document.getElementById('config-gateway-addr').value = '127.0.0.1:8080';
    document.getElementById('config-public-gateway').value = 'https://gateway.cryft.network';
    document.getElementById('config-fallback-gateways').value = `https://ipfs.io
https://dweb.link
https://cloudflare-ipfs.com`;
    document.getElementById('config-api-addr').value = '127.0.0.1:5001';
    document.getElementById('config-timeout').value = '60';
    document.getElementById('config-cors').value = '*';
    document.getElementById('config-ipns-cache-ttl').value = '3600';
    document.getElementById('config-ipns-republish').value = '12';
    
    showToast('Settings reset to defaults. Click Save to apply.', 'info');
}

async function exportConfigHandler() {
    const result = await api.getNodeConfig();
    
    if (result.error) {
        showToast('Failed to export: ' + result.error, 'error');
        return;
    }
    
    const config = result.config || result;
    const data = JSON.stringify(config, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `ipfs-config-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    
    URL.revokeObjectURL(url);
    showToast('Configuration exported', 'success');
}

function updateNodeModeBadge(mode) {
    const badge = document.getElementById('node-mode-badge');
    if (mode === 'light') {
        badge.textContent = 'LIGHT NODE';
        badge.classList.add('light');
    } else {
        badge.textContent = 'FULL NODE';
        badge.classList.remove('light');
    }
}

// Export
window.renderSettingsTab = renderSettingsTab;
window.saveSettingsHandler = saveSettingsHandler;
window.resetSettingsHandler = resetSettingsHandler;
window.exportConfigHandler = exportConfigHandler;
window.updateNodeModeBadge = updateNodeModeBadge;
