// Rewards Page - Validator rewards tracking and claiming
window.RewardsPage = {
    stats: null,
    proofs: [],
    
    init() {
        this.render();
        this.loadStats();
    },
    
    render() {
        const page = document.getElementById('page-rewards');
        page.innerHTML = `
            <div class="page-header">
                <h1>💰 Validator Rewards</h1>
                <p class="subtitle">Track your storage rewards and claim earnings</p>
            </div>
            
            <!-- Rewards Overview -->
            <div class="stats-grid rewards-stats">
                <div class="stat-card accent">
                    <div class="stat-icon">💎</div>
                    <div class="stat-content">
                        <div class="stat-value" id="rewards-pending">0</div>
                        <div class="stat-label">Pending Rewards (nCRYFT)</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">🏆</div>
                    <div class="stat-content">
                        <div class="stat-value" id="rewards-total">0</div>
                        <div class="stat-label">Total Earned (nCRYFT)</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">✅</div>
                    <div class="stat-content">
                        <div class="stat-value" id="rewards-challenges-passed">0</div>
                        <div class="stat-label">Challenges Passed</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">⭐</div>
                    <div class="stat-content">
                        <div class="stat-value" id="rewards-incentivized-pins">0</div>
                        <div class="stat-label">Incentivized Pins</div>
                    </div>
                </div>
            </div>
            
            <!-- Claim Section -->
            <div class="card claim-section">
                <div class="card-header">
                    <h2>Claim Rewards</h2>
                </div>
                <div class="card-body">
                    <div class="claim-info">
                        <div class="claim-amount">
                            <span class="label">Available to Claim:</span>
                            <span class="value" id="claim-amount">0 nCRYFT</span>
                        </div>
                        <div class="claim-details">
                            <p>Rewards are calculated based on:</p>
                            <ul>
                                <li>Number of incentivized pins you're hosting</li>
                                <li>Storage challenges passed successfully</li>
                                <li>Reward tier multipliers</li>
                            </ul>
                        </div>
                    </div>
                    <button class="btn btn-primary btn-large" id="btn-claim-rewards" disabled>
                        💎 Claim All Rewards
                    </button>
                </div>
            </div>
            
            <!-- Challenge Stats -->
            <div class="card">
                <div class="card-header">
                    <h2>Storage Challenges</h2>
                    <span class="badge" id="challenge-success-rate">0%</span>
                </div>
                <div class="card-body">
                    <div class="challenge-stats">
                        <div class="challenge-stat">
                            <span class="challenge-value" id="challenges-received">0</span>
                            <span class="challenge-label">Received</span>
                        </div>
                        <div class="challenge-stat success">
                            <span class="challenge-value" id="challenges-passed">0</span>
                            <span class="challenge-label">Passed</span>
                        </div>
                        <div class="challenge-stat error">
                            <span class="challenge-value" id="challenges-failed">0</span>
                            <span class="challenge-label">Failed</span>
                        </div>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill success" id="challenge-progress" style="width: 0%"></div>
                    </div>
                </div>
            </div>
            
            <!-- Pending Proofs -->
            <div class="card">
                <div class="card-header">
                    <h2>Pending Proofs</h2>
                    <button class="btn btn-sm" id="btn-refresh-proofs">🔄 Refresh</button>
                </div>
                <div class="card-body">
                    <div class="proofs-list" id="proofs-list">
                        <div class="empty-state">
                            <span class="empty-icon">📝</span>
                            <p>No pending proofs</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Reward Tiers Info -->
            <div class="card">
                <div class="card-header">
                    <h2>Reward Tiers</h2>
                </div>
                <div class="card-body">
                    <div class="tiers-grid">
                        <div class="tier-card basic">
                            <div class="tier-name">Basic</div>
                            <div class="tier-multiplier">1x</div>
                            <div class="tier-desc">Standard storage rewards</div>
                        </div>
                        <div class="tier-card standard">
                            <div class="tier-name">Standard</div>
                            <div class="tier-multiplier">2x</div>
                            <div class="tier-desc">Important data rewards</div>
                        </div>
                        <div class="tier-card priority">
                            <div class="tier-name">Priority</div>
                            <div class="tier-multiplier">5x</div>
                            <div class="tier-desc">High-availability rewards</div>
                        </div>
                        <div class="tier-card critical">
                            <div class="tier-name">Critical</div>
                            <div class="tier-multiplier">10x</div>
                            <div class="tier-desc">Infrastructure rewards</div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        this.bindEvents();
    },
    
    bindEvents() {
        document.getElementById('btn-claim-rewards').addEventListener('click', () => this.claimRewards());
        document.getElementById('btn-refresh-proofs').addEventListener('click', () => this.loadProofs());
    },
    
    async loadStats() {
        try {
            const response = await window.API.call('validator_stats');
            if (response.success !== false) {
                this.stats = response;
                this.updateUI();
            }
        } catch (e) {
            console.error('Failed to load validator stats:', e);
        }
        
        this.loadProofs();
    },
    
    async loadProofs() {
        try {
            const response = await window.API.call('list_proofs');
            if (Array.isArray(response)) {
                this.proofs = response;
                this.renderProofs();
            }
        } catch (e) {
            console.error('Failed to load proofs:', e);
        }
    },
    
    updateUI() {
        if (!this.stats) return;
        
        const s = this.stats;
        
        // Update stat cards
        document.getElementById('rewards-pending').textContent = this.formatCryft(s.pendingRewards || 0);
        document.getElementById('rewards-total').textContent = this.formatCryft(s.totalRewardsEarned || 0);
        document.getElementById('rewards-challenges-passed').textContent = s.challengesPassed || 0;
        document.getElementById('rewards-incentivized-pins').textContent = s.incentivizedPins || 0;
        
        // Update claim section
        const claimAmount = s.pendingRewards || 0;
        document.getElementById('claim-amount').textContent = this.formatCryft(claimAmount) + ' nCRYFT';
        document.getElementById('btn-claim-rewards').disabled = claimAmount === 0;
        
        // Update sidebar pending rewards
        const pendingEl = document.getElementById('pending-rewards');
        if (pendingEl) {
            pendingEl.textContent = this.formatCryft(claimAmount) + ' nCRYFT';
        }
        
        // Update challenge stats
        const received = s.challengesReceived || 0;
        const passed = s.challengesPassed || 0;
        const failed = s.challengesFailed || 0;
        const successRate = received > 0 ? Math.round((passed / received) * 100) : 0;
        
        document.getElementById('challenges-received').textContent = received;
        document.getElementById('challenges-passed').textContent = passed;
        document.getElementById('challenges-failed').textContent = failed;
        document.getElementById('challenge-success-rate').textContent = successRate + '% Success';
        document.getElementById('challenge-progress').style.width = successRate + '%';
    },
    
    renderProofs() {
        const container = document.getElementById('proofs-list');
        
        if (this.proofs.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <span class="empty-icon">📝</span>
                    <p>No pending proofs</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = this.proofs.map(proof => `
            <div class="proof-item">
                <div class="proof-cid">
                    <span class="label">CID:</span>
                    <code>${this.truncateCid(proof.cid)}</code>
                </div>
                <div class="proof-details">
                    <span class="proof-hash">Hash: ${proof.chunkHash.substring(0, 16)}...</span>
                    <span class="proof-time">${this.formatTime(proof.provenAt)}</span>
                </div>
            </div>
        `).join('');
    },
    
    async claimRewards() {
        const btn = document.getElementById('btn-claim-rewards');
        btn.disabled = true;
        btn.textContent = '⏳ Claiming...';
        
        try {
            const response = await window.API.call('claim_rewards');
            if (response.rewardAmount > 0) {
                window.Utils.showToast(`🎉 Claimed ${this.formatCryft(response.rewardAmount)} nCRYFT!`, 'success');
            } else {
                window.Utils.showToast('No rewards to claim', 'info');
            }
            this.loadStats();
        } catch (e) {
            window.Utils.showToast('Failed to claim rewards: ' + e.message, 'error');
        } finally {
            btn.disabled = false;
            btn.textContent = '💎 Claim All Rewards';
        }
    },
    
    formatCryft(nCryft) {
        if (nCryft >= 1e9) {
            return (nCryft / 1e9).toFixed(2) + ' CRYFT';
        } else if (nCryft >= 1e6) {
            return (nCryft / 1e6).toFixed(2) + 'M';
        } else if (nCryft >= 1e3) {
            return (nCryft / 1e3).toFixed(2) + 'K';
        }
        return nCryft.toString();
    },
    
    truncateCid(cid) {
        if (cid.length > 20) {
            return cid.substring(0, 10) + '...' + cid.substring(cid.length - 6);
        }
        return cid;
    },
    
    formatTime(timestamp) {
        const date = new Date(timestamp * 1000);
        return date.toLocaleString();
    },
    
    refresh() {
        this.loadStats();
    }
};
