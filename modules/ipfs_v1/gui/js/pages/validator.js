// Validator Page - Node validator configuration and status
window.ValidatorPage = {
    status: null,
    config: null,
    
    init() {
        this.render();
        this.loadStatus();
    },
    
    render() {
        const page = document.getElementById('page-validator');
        page.innerHTML = `
            <div class="page-header">
                <h1>🏆 Validator Node</h1>
                <p class="subtitle">Configure and manage your IPFS validator</p>
            </div>
            
            <!-- Validator Status -->
            <div class="card status-card">
                <div class="card-header">
                    <h2>Validator Status</h2>
                    <span class="status-indicator" id="validator-status-indicator">
                        <span class="dot"></span>
                        <span class="label">Checking...</span>
                    </span>
                </div>
                <div class="card-body">
                    <div class="status-grid" id="validator-status-grid">
                        <div class="loading">Loading validator status...</div>
                    </div>
                </div>
            </div>
            
            <!-- Quick Actions -->
            <div class="actions-grid">
                <button class="action-card" id="btn-register-validator" disabled>
                    <span class="action-icon">📝</span>
                    <span class="action-title">Register</span>
                    <span class="action-desc">Register as validator</span>
                </button>
                <button class="action-card" id="btn-update-config">
                    <span class="action-icon">⚙️</span>
                    <span class="action-title">Configure</span>
                    <span class="action-desc">Update settings</span>
                </button>
                <button class="action-card" id="btn-view-proofs">
                    <span class="action-icon">🔐</span>
                    <span class="action-title">Proofs</span>
                    <span class="action-desc">View proof history</span>
                </button>
                <button class="action-card" id="btn-claim-rewards">
                    <span class="action-icon">💰</span>
                    <span class="action-title">Claim</span>
                    <span class="action-desc">Claim rewards</span>
                </button>
            </div>
            
            <!-- Configuration -->
            <div class="card">
                <div class="card-header">
                    <h2>Configuration</h2>
                    <button class="btn btn-sm" id="btn-save-config">💾 Save</button>
                </div>
                <div class="card-body">
                    <form id="validator-config-form">
                        <div class="form-row">
                            <div class="form-group">
                                <label>Validator Wallet Address</label>
                                <input type="text" id="config-wallet" placeholder="0x...">
                                <span class="help-text">Rewards will be sent to this address</span>
                            </div>
                            <div class="form-group">
                                <label>Storage Allocation</label>
                                <input type="number" id="config-storage-gb" value="100" min="1">
                                <span class="help-text">Maximum GB for incentivized pins</span>
                            </div>
                        </div>
                        <div class="form-row">
                            <div class="form-group">
                                <label>Min Reward Rate (nCRYFT/epoch)</label>
                                <input type="number" id="config-min-reward" value="100000" min="0">
                                <span class="help-text">Only pin content above this reward rate</span>
                            </div>
                            <div class="form-group">
                                <label>Auto-pin Tiers</label>
                                <select id="config-auto-tiers" multiple>
                                    <option value="critical" selected>Critical (10x)</option>
                                    <option value="priority" selected>Priority (5x)</option>
                                    <option value="standard">Standard (2x)</option>
                                    <option value="basic">Basic (1x)</option>
                                </select>
                                <span class="help-text">Automatically pin content from these tiers</span>
                            </div>
                        </div>
                        <div class="form-row">
                            <div class="form-group checkbox-group">
                                <label>
                                    <input type="checkbox" id="config-auto-claim" checked>
                                    Auto-claim rewards (when > 1 CRYFT)
                                </label>
                            </div>
                            <div class="form-group checkbox-group">
                                <label>
                                    <input type="checkbox" id="config-auto-respond" checked>
                                    Auto-respond to challenges
                                </label>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
            
            <!-- Performance Metrics -->
            <div class="card">
                <div class="card-header">
                    <h2>Performance Metrics</h2>
                </div>
                <div class="card-body">
                    <div class="metrics-grid" id="metrics-grid">
                        <div class="metric-item">
                            <span class="metric-icon">✅</span>
                            <span class="metric-value" id="metric-proofs-submitted">0</span>
                            <span class="metric-label">Proofs Submitted</span>
                        </div>
                        <div class="metric-item">
                            <span class="metric-icon">💯</span>
                            <span class="metric-value" id="metric-success-rate">0%</span>
                            <span class="metric-label">Success Rate</span>
                        </div>
                        <div class="metric-item">
                            <span class="metric-icon">⏱️</span>
                            <span class="metric-value" id="metric-avg-response">0ms</span>
                            <span class="metric-label">Avg Response Time</span>
                        </div>
                        <div class="metric-item">
                            <span class="metric-icon">📦</span>
                            <span class="metric-value" id="metric-storage-used">0 GB</span>
                            <span class="metric-label">Storage Used</span>
                        </div>
                        <div class="metric-item">
                            <span class="metric-icon">🔗</span>
                            <span class="metric-value" id="metric-active-pins">0</span>
                            <span class="metric-label">Active Pins</span>
                        </div>
                        <div class="metric-item">
                            <span class="metric-icon">💎</span>
                            <span class="metric-value" id="metric-total-earned">0</span>
                            <span class="metric-label">Total Earned (CRYFT)</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Recent Activity -->
            <div class="card">
                <div class="card-header">
                    <h2>Recent Activity</h2>
                </div>
                <div class="card-body">
                    <div class="activity-list" id="activity-list">
                        <div class="loading">Loading activity...</div>
                    </div>
                </div>
            </div>
        `;
        
        this.bindEvents();
    },
    
    bindEvents() {
        document.getElementById('btn-register-validator').addEventListener('click', () => this.registerValidator());
        document.getElementById('btn-update-config').addEventListener('click', () => this.showConfigModal());
        document.getElementById('btn-view-proofs').addEventListener('click', () => window.App.navigate('rewards'));
        document.getElementById('btn-claim-rewards').addEventListener('click', () => this.claimRewards());
        document.getElementById('btn-save-config').addEventListener('click', () => this.saveConfig());
    },
    
    async loadStatus() {
        try {
            const response = await window.API.call('validator_status');
            this.status = response;
            this.renderStatus();
            this.loadMetrics();
            this.loadActivity();
        } catch (e) {
            console.error('Failed to load validator status:', e);
            this.renderNotRegistered();
        }
    },
    
    renderStatus() {
        const indicator = document.getElementById('validator-status-indicator');
        const grid = document.getElementById('validator-status-grid');
        
        if (!this.status || !this.status.registered) {
            this.renderNotRegistered();
            return;
        }
        
        // Update indicator
        indicator.innerHTML = `
            <span class="dot ${this.status.online ? 'online' : 'offline'}"></span>
            <span class="label">${this.status.online ? 'Online' : 'Offline'}</span>
        `;
        
        // Disable register button if already registered
        document.getElementById('btn-register-validator').disabled = true;
        
        grid.innerHTML = `
            <div class="status-item">
                <span class="status-label">Validator ID</span>
                <span class="status-value"><code>${this.status.validatorId || 'Unknown'}</code></span>
            </div>
            <div class="status-item">
                <span class="status-label">Wallet</span>
                <span class="status-value"><code>${this.truncateAddress(this.status.wallet)}</code></span>
            </div>
            <div class="status-item">
                <span class="status-label">Stake</span>
                <span class="status-value">${this.formatCryft(this.status.stake)} CRYFT</span>
            </div>
            <div class="status-item">
                <span class="status-label">Pending Rewards</span>
                <span class="status-value">${this.formatCryft(this.status.pendingRewards)} CRYFT</span>
            </div>
            <div class="status-item">
                <span class="status-label">Registered Since</span>
                <span class="status-value">${this.formatDate(this.status.registeredAt)}</span>
            </div>
            <div class="status-item">
                <span class="status-label">Last Proof</span>
                <span class="status-value">${this.formatDate(this.status.lastProof)}</span>
            </div>
        `;
        
        // Store validator ID globally for other pages
        window.validatorId = this.status.validatorId;
        
        // Load config
        if (this.status.config) {
            this.config = this.status.config;
            this.populateConfigForm();
        }
    },
    
    renderNotRegistered() {
        const indicator = document.getElementById('validator-status-indicator');
        const grid = document.getElementById('validator-status-grid');
        
        indicator.innerHTML = `
            <span class="dot offline"></span>
            <span class="label">Not Registered</span>
        `;
        
        // Enable register button
        document.getElementById('btn-register-validator').disabled = false;
        
        grid.innerHTML = `
            <div class="not-registered-message">
                <span class="icon">🏆</span>
                <h3>Become a Validator</h3>
                <p>Register your node to start earning CRYFT rewards for pinning incentivized content.</p>
                <button class="btn btn-primary" onclick="ValidatorPage.registerValidator()">
                    Register as Validator
                </button>
            </div>
        `;
    },
    
    async registerValidator() {
        window.Utils.showModal('Register as Validator', `
            <form id="register-form">
                <div class="form-group">
                    <label>Wallet Address *</label>
                    <input type="text" id="register-wallet" placeholder="0x..." required>
                    <span class="help-text">Your CRYFT wallet address for receiving rewards</span>
                </div>
                <div class="form-group">
                    <label>Initial Storage Allocation (GB)</label>
                    <input type="number" id="register-storage" value="100" min="10">
                </div>
                <div class="info-box">
                    <strong>Note:</strong> Registration requires signing a message with your wallet to prove ownership.
                </div>
            </form>
        `, `
            <button class="btn" onclick="Utils.hideModal()">Cancel</button>
            <button class="btn btn-primary" onclick="ValidatorPage.submitRegistration()">
                🏆 Register
            </button>
        `);
    },
    
    async submitRegistration() {
        const wallet = document.getElementById('register-wallet').value.trim();
        const storage = parseInt(document.getElementById('register-storage').value);
        
        if (!wallet) {
            window.Utils.showToast('Wallet address is required', 'error');
            return;
        }
        
        try {
            const response = await window.API.call('validator_register', {
                wallet,
                storageGb: storage
            });
            
            window.Utils.hideModal();
            window.Utils.showToast('🎉 Successfully registered as validator!', 'success');
            this.loadStatus();
        } catch (e) {
            window.Utils.showToast('Registration failed: ' + e.message, 'error');
        }
    },
    
    populateConfigForm() {
        if (!this.config) return;
        
        if (this.config.wallet) {
            document.getElementById('config-wallet').value = this.config.wallet;
        }
        if (this.config.storageGb) {
            document.getElementById('config-storage-gb').value = this.config.storageGb;
        }
        if (this.config.minReward) {
            document.getElementById('config-min-reward').value = this.config.minReward;
        }
        if (this.config.autoClaim !== undefined) {
            document.getElementById('config-auto-claim').checked = this.config.autoClaim;
        }
        if (this.config.autoRespond !== undefined) {
            document.getElementById('config-auto-respond').checked = this.config.autoRespond;
        }
    },
    
    async saveConfig() {
        const config = {
            wallet: document.getElementById('config-wallet').value.trim(),
            storageGb: parseInt(document.getElementById('config-storage-gb').value),
            minReward: parseInt(document.getElementById('config-min-reward').value),
            autoClaim: document.getElementById('config-auto-claim').checked,
            autoRespond: document.getElementById('config-auto-respond').checked,
            autoTiers: Array.from(document.getElementById('config-auto-tiers').selectedOptions).map(o => o.value)
        };
        
        try {
            await window.API.call('validator_update_config', config);
            window.Utils.showToast('Configuration saved!', 'success');
        } catch (e) {
            window.Utils.showToast('Failed to save config: ' + e.message, 'error');
        }
    },
    
    async loadMetrics() {
        try {
            const metrics = await window.API.call('validator_metrics');
            
            if (metrics) {
                document.getElementById('metric-proofs-submitted').textContent = metrics.proofsSubmitted || 0;
                document.getElementById('metric-success-rate').textContent = (metrics.successRate || 0).toFixed(1) + '%';
                document.getElementById('metric-avg-response').textContent = (metrics.avgResponseMs || 0) + 'ms';
                document.getElementById('metric-storage-used').textContent = this.formatSize(metrics.storageUsed || 0);
                document.getElementById('metric-active-pins').textContent = metrics.activePins || 0;
                document.getElementById('metric-total-earned').textContent = this.formatCryft(metrics.totalEarned || 0);
            }
        } catch (e) {
            console.error('Failed to load metrics:', e);
        }
    },
    
    async loadActivity() {
        const container = document.getElementById('activity-list');
        
        try {
            const activity = await window.API.call('validator_activity');
            
            if (!activity || activity.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <p>No recent activity</p>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = activity.slice(0, 20).map(item => `
                <div class="activity-item ${item.type}">
                    <span class="activity-icon">${this.getActivityIcon(item.type)}</span>
                    <div class="activity-details">
                        <span class="activity-title">${item.title}</span>
                        <span class="activity-time">${this.formatDate(item.timestamp)}</span>
                    </div>
                    ${item.amount ? `<span class="activity-amount">${this.formatCryft(item.amount)} CRYFT</span>` : ''}
                </div>
            `).join('');
        } catch (e) {
            console.error('Failed to load activity:', e);
            container.innerHTML = `<div class="error-state">Failed to load activity</div>`;
        }
    },
    
    async claimRewards() {
        if (!this.status || !this.status.pendingRewards || this.status.pendingRewards <= 0) {
            window.Utils.showToast('No rewards to claim', 'warning');
            return;
        }
        
        try {
            const result = await window.API.call('validator_claim_rewards', {
                wallet: this.status.wallet
            });
            
            window.Utils.showToast(`🎉 Claimed ${this.formatCryft(result.amount)} CRYFT!`, 'success');
            this.loadStatus();
        } catch (e) {
            window.Utils.showToast('Failed to claim: ' + e.message, 'error');
        }
    },
    
    getActivityIcon(type) {
        const icons = {
            'proof': '🔐',
            'reward': '💰',
            'pin': '📌',
            'unpin': '📤',
            'challenge': '⚡',
            'registration': '📝',
            'claim': '💎'
        };
        return icons[type] || '📋';
    },
    
    formatCryft(nCryft) {
        if (!nCryft) return '0';
        // Convert from nCRYFT to CRYFT (assuming 9 decimals)
        const cryft = nCryft / 1e9;
        if (cryft >= 1000000) return (cryft / 1e6).toFixed(2) + 'M';
        if (cryft >= 1000) return (cryft / 1e3).toFixed(2) + 'K';
        return cryft.toFixed(4);
    },
    
    formatSize(bytes) {
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let i = 0;
        while (bytes >= 1024 && i < units.length - 1) {
            bytes /= 1024;
            i++;
        }
        return bytes.toFixed(1) + ' ' + units[i];
    },
    
    formatDate(timestamp) {
        if (!timestamp) return 'Never';
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        
        if (diff < 60000) return 'Just now';
        if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
        if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
        return date.toLocaleDateString();
    },
    
    truncateAddress(addr) {
        if (!addr) return 'Not set';
        if (addr.length > 20) {
            return addr.substring(0, 10) + '...' + addr.substring(addr.length - 6);
        }
        return addr;
    },
    
    refresh() {
        this.loadStatus();
    }
};
