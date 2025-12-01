// Incentivized Pins Page - Network-wide incentivized content
window.IncentivizedPage = {
    pins: [],
    
    init() {
        this.render();
        this.loadIncentivized();
    },
    
    render() {
        const page = document.getElementById('page-incentivized');
        page.innerHTML = `
            <div class="page-header">
                <h1>⭐ Incentivized Pins</h1>
                <p class="subtitle">Network-wide content with CRYFT rewards for pinners</p>
            </div>
            
            <!-- Actions -->
            <div class="actions-bar">
                <button class="btn btn-primary" id="btn-incentivize-new">
                    ➕ Incentivize Content
                </button>
                <button class="btn" id="btn-refresh-incentivized">
                    🔄 Refresh
                </button>
            </div>
            
            <!-- Stats -->
            <div class="stats-row">
                <div class="stat-mini">
                    <span class="stat-value" id="incentivized-count">0</span>
                    <span class="stat-label">Active Incentives</span>
                </div>
                <div class="stat-mini">
                    <span class="stat-value" id="incentivized-pool">0</span>
                    <span class="stat-label">Total Reward Pool</span>
                </div>
                <div class="stat-mini">
                    <span class="stat-value" id="incentivized-pinned">0</span>
                    <span class="stat-label">You're Pinning</span>
                </div>
            </div>
            
            <!-- Incentivized Pins List -->
            <div class="card">
                <div class="card-header">
                    <h2>Available Incentives</h2>
                    <div class="filter-tabs">
                        <button class="filter-tab active" data-filter="all">All</button>
                        <button class="filter-tab" data-filter="pinned">Pinned</button>
                        <button class="filter-tab" data-filter="available">Available</button>
                    </div>
                </div>
                <div class="card-body">
                    <div class="incentivized-list" id="incentivized-list">
                        <div class="loading">Loading incentivized pins...</div>
                    </div>
                </div>
            </div>
        `;
        
        this.bindEvents();
    },
    
    bindEvents() {
        document.getElementById('btn-incentivize-new').addEventListener('click', () => this.showIncentivizeModal());
        document.getElementById('btn-refresh-incentivized').addEventListener('click', () => this.loadIncentivized());
        
        document.querySelectorAll('.filter-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                document.querySelectorAll('.filter-tab').forEach(t => t.classList.remove('active'));
                e.target.classList.add('active');
                this.renderList(e.target.dataset.filter);
            });
        });
    },
    
    async loadIncentivized() {
        try {
            const response = await window.API.call('list_incentivized');
            if (Array.isArray(response)) {
                this.pins = response;
                this.updateStats();
                this.renderList('all');
            }
        } catch (e) {
            console.error('Failed to load incentivized pins:', e);
            document.getElementById('incentivized-list').innerHTML = `
                <div class="error-state">
                    <span class="error-icon">❌</span>
                    <p>Failed to load incentivized pins</p>
                </div>
            `;
        }
    },
    
    updateStats() {
        document.getElementById('incentivized-count').textContent = this.pins.length;
        
        const totalPool = this.pins.reduce((sum, p) => sum + (p.rewardPool || 0), 0);
        document.getElementById('incentivized-pool').textContent = this.formatCryft(totalPool);
        
        // Count how many we're pinning (would need to cross-reference with local pins)
        const pinned = this.pins.filter(p => p.pinners && p.pinners.includes(window.validatorId)).length;
        document.getElementById('incentivized-pinned').textContent = pinned;
    },
    
    renderList(filter = 'all') {
        const container = document.getElementById('incentivized-list');
        
        let filtered = this.pins;
        if (filter === 'pinned') {
            filtered = this.pins.filter(p => p.pinners && p.pinners.includes(window.validatorId));
        } else if (filter === 'available') {
            filtered = this.pins.filter(p => !p.pinners || !p.pinners.includes(window.validatorId));
        }
        
        if (filtered.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <span class="empty-icon">⭐</span>
                    <p>No incentivized pins found</p>
                    <button class="btn btn-primary" onclick="IncentivizedPage.showIncentivizeModal()">
                        Create First Incentive
                    </button>
                </div>
            `;
            return;
        }
        
        container.innerHTML = filtered.map(pin => `
            <div class="incentivized-item ${this.getTierClass(pin.tier)}">
                <div class="incentivized-header">
                    <div class="incentivized-cid">
                        <code title="${pin.cid}">${this.truncateCid(pin.cid)}</code>
                        <button class="btn-icon" onclick="navigator.clipboard.writeText('${pin.cid}')">📋</button>
                    </div>
                    <span class="tier-badge ${pin.tier}">${pin.tier || 'standard'}</span>
                </div>
                <div class="incentivized-details">
                    <div class="detail-row">
                        <span class="label">Reward/Epoch:</span>
                        <span class="value">${this.formatCryft(pin.rewardPerEpoch)} nCRYFT</span>
                    </div>
                    <div class="detail-row">
                        <span class="label">Pool Remaining:</span>
                        <span class="value">${this.formatCryft(pin.rewardPool)} nCRYFT</span>
                    </div>
                    <div class="detail-row">
                        <span class="label">Replicas:</span>
                        <span class="value">${pin.currentReplicas || 0} / ${pin.minReplicas || 3}</span>
                    </div>
                    <div class="detail-row">
                        <span class="label">Size:</span>
                        <span class="value">${this.formatSize(pin.size || 0)}</span>
                    </div>
                </div>
                <div class="incentivized-actions">
                    <button class="btn btn-primary btn-sm" onclick="IncentivizedPage.pinContent('${pin.cid}')">
                        📌 Pin & Earn
                    </button>
                    <button class="btn btn-sm" onclick="IncentivizedPage.viewDetails('${pin.cid}')">
                        ℹ️ Details
                    </button>
                </div>
            </div>
        `).join('');
    },
    
    showIncentivizeModal() {
        window.Utils.showModal('Incentivize Content', `
            <form id="incentivize-form">
                <div class="form-group">
                    <label>Content CID</label>
                    <input type="text" id="incentivize-cid" placeholder="bafy... or Qm..." required>
                </div>
                <div class="form-group">
                    <label>Reward Tier</label>
                    <select id="incentivize-tier">
                        <option value="basic">Basic (1x multiplier)</option>
                        <option value="standard" selected>Standard (2x multiplier)</option>
                        <option value="priority">Priority (5x multiplier)</option>
                        <option value="critical">Critical (10x multiplier)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Minimum Replicas</label>
                    <input type="number" id="incentivize-replicas" value="3" min="1" max="100">
                </div>
                <div class="form-group">
                    <label>Reward per Epoch (nCRYFT)</label>
                    <input type="number" id="incentivize-reward" value="1000000" min="1">
                    <span class="help-text">Paid to each validator per hour</span>
                </div>
                <div class="form-group">
                    <label>Total Reward Pool (nCRYFT)</label>
                    <input type="number" id="incentivize-pool" value="100000000" min="1">
                    <span class="help-text">Total budget for this incentive</span>
                </div>
            </form>
        `, `
            <button class="btn" onclick="Utils.hideModal()">Cancel</button>
            <button class="btn btn-primary" onclick="IncentivizedPage.submitIncentive()">
                💎 Create Incentive
            </button>
        `);
    },
    
    async submitIncentive() {
        const cid = document.getElementById('incentivize-cid').value.trim();
        const tier = document.getElementById('incentivize-tier').value;
        const minReplicas = parseInt(document.getElementById('incentivize-replicas').value);
        const rewardPerEpoch = parseInt(document.getElementById('incentivize-reward').value);
        const rewardPool = parseInt(document.getElementById('incentivize-pool').value);
        
        if (!cid) {
            window.Utils.showToast('Please enter a CID', 'error');
            return;
        }
        
        try {
            await window.API.call('incentivize', {
                cid,
                tier,
                minReplicas,
                rewardPerEpoch,
                rewardPool
            });
            
            window.Utils.hideModal();
            window.Utils.showToast('Incentive created successfully!', 'success');
            this.loadIncentivized();
        } catch (e) {
            window.Utils.showToast('Failed to create incentive: ' + e.message, 'error');
        }
    },
    
    async pinContent(cid) {
        try {
            await window.API.call('pin', {
                cid,
                incentivize: true
            });
            window.Utils.showToast(`📌 Pinned ${this.truncateCid(cid)} - you'll earn rewards!`, 'success');
            this.loadIncentivized();
        } catch (e) {
            window.Utils.showToast('Failed to pin: ' + e.message, 'error');
        }
    },
    
    viewDetails(cid) {
        const pin = this.pins.find(p => p.cid === cid);
        if (!pin) return;
        
        window.Utils.showModal('Incentive Details', `
            <div class="detail-view">
                <div class="detail-section">
                    <h4>Content</h4>
                    <div class="detail-item">
                        <span class="label">CID:</span>
                        <code class="value">${pin.cid}</code>
                    </div>
                    <div class="detail-item">
                        <span class="label">Size:</span>
                        <span class="value">${this.formatSize(pin.size || 0)}</span>
                    </div>
                </div>
                <div class="detail-section">
                    <h4>Rewards</h4>
                    <div class="detail-item">
                        <span class="label">Tier:</span>
                        <span class="value tier-badge ${pin.tier}">${pin.tier}</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Per Epoch:</span>
                        <span class="value">${this.formatCryft(pin.rewardPerEpoch)} nCRYFT</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Pool:</span>
                        <span class="value">${this.formatCryft(pin.rewardPool)} nCRYFT</span>
                    </div>
                </div>
                <div class="detail-section">
                    <h4>Replication</h4>
                    <div class="detail-item">
                        <span class="label">Current:</span>
                        <span class="value">${pin.currentReplicas || 0}</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Minimum:</span>
                        <span class="value">${pin.minReplicas}</span>
                    </div>
                    <div class="detail-item">
                        <span class="label">Sponsor:</span>
                        <span class="value">${pin.sponsor || 'Unknown'}</span>
                    </div>
                </div>
                ${pin.pinners && pin.pinners.length > 0 ? `
                <div class="detail-section">
                    <h4>Current Pinners (${pin.pinners.length})</h4>
                    <ul class="pinners-list">
                        ${pin.pinners.map(p => `<li><code>${p}</code></li>`).join('')}
                    </ul>
                </div>
                ` : ''}
            </div>
        `, `
            <button class="btn" onclick="Utils.hideModal()">Close</button>
            <button class="btn btn-primary" onclick="IncentivizedPage.pinContent('${pin.cid}'); Utils.hideModal();">
                📌 Pin This Content
            </button>
        `);
    },
    
    getTierClass(tier) {
        return `tier-${tier || 'standard'}`;
    },
    
    formatCryft(nCryft) {
        if (nCryft >= 1e9) {
            return (nCryft / 1e9).toFixed(2);
        } else if (nCryft >= 1e6) {
            return (nCryft / 1e6).toFixed(2) + 'M';
        } else if (nCryft >= 1e3) {
            return (nCryft / 1e3).toFixed(1) + 'K';
        }
        return nCryft.toString();
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
    
    truncateCid(cid) {
        if (cid && cid.length > 20) {
            return cid.substring(0, 10) + '...' + cid.substring(cid.length - 6);
        }
        return cid || '';
    },
    
    refresh() {
        this.loadIncentivized();
    }
};
