/**
 * Redeemable Codes Module - Main Application
 * US Patent Application 20250139608
 */

const App = {
    currentPage: 'dashboard',
    generatedCodes: [],
    settings: {
        rpcUrl: 'http://127.0.0.1:9650',
        managerAddress: '',
        indexLength: 4,
        codeLength: 12,
        groupSize: 4,
    },
    
    /**
     * Initialize the application
     */
    init() {
        this.loadSettings();
        this.bindNavigation();
        this.bindForms();
        this.bindModals();
        this.checkConnection();
        this.loadStats();
        
        // Refresh stats periodically
        setInterval(() => this.loadStats(), 30000);
        
        console.log('Redeemable Codes Module initialized');
    },
    
    // =============================================
    // Navigation
    // =============================================
    
    bindNavigation() {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                const page = item.dataset.page;
                this.navigate(page);
            });
        });
    },
    
    navigate(page) {
        // Update nav
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.page === page);
        });
        
        // Update pages
        document.querySelectorAll('.page').forEach(p => {
            p.classList.toggle('active', p.id === `page-${page}`);
        });
        
        this.currentPage = page;
        
        // Page-specific init
        if (page === 'manage') {
            this.loadCodesList();
        } else if (page === 'history') {
            this.loadHistory();
        }
    },
    
    // =============================================
    // Forms
    // =============================================
    
    bindForms() {
        // Generate form
        const generateForm = document.getElementById('generate-form');
        if (generateForm) {
            generateForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleGenerate();
            });
        }
        
        // Content type change
        const contentType = document.getElementById('gen-content-type');
        if (contentType) {
            contentType.addEventListener('change', () => this.updateContentFields());
            this.updateContentFields();
        }
        
        // Redeem button
        const btnRedeem = document.getElementById('btn-redeem');
        if (btnRedeem) {
            btnRedeem.addEventListener('click', () => this.handleRedeem());
        }
        
        // Verify button
        const btnVerify = document.getElementById('btn-verify');
        if (btnVerify) {
            btnVerify.addEventListener('click', () => this.handleVerify());
        }
        
        // Filter buttons
        const btnFilter = document.getElementById('btn-filter');
        if (btnFilter) {
            btnFilter.addEventListener('click', () => this.loadCodesList());
        }
        
        const btnRefresh = document.getElementById('btn-refresh');
        if (btnRefresh) {
            btnRefresh.addEventListener('click', () => this.loadCodesList());
        }
        
        // Batch actions
        const btnBatchFreeze = document.getElementById('btn-batch-freeze');
        if (btnBatchFreeze) {
            btnBatchFreeze.addEventListener('click', () => this.handleBatchFreeze());
        }
        
        const btnBatchActivate = document.getElementById('btn-batch-activate');
        if (btnBatchActivate) {
            btnBatchActivate.addEventListener('click', () => this.handleBatchActivate());
        }
        
        // Select all checkbox
        const selectAll = document.getElementById('select-all');
        if (selectAll) {
            selectAll.addEventListener('change', (e) => {
                document.querySelectorAll('.code-checkbox').forEach(cb => {
                    cb.checked = e.target.checked;
                });
            });
        }
        
        // Validator form
        const validatorForm = document.getElementById('validator-form');
        if (validatorForm) {
            validatorForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleValidatorRedeem();
            });
        }
        
        // Generate validator form
        const genValidatorForm = document.getElementById('gen-validator-form');
        if (genValidatorForm) {
            genValidatorForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleGenerateValidatorCodes();
            });
        }
        
        // Code input formatting
        const codeInputs = document.querySelectorAll('.code-input');
        codeInputs.forEach(input => {
            input.addEventListener('input', (e) => this.formatCodeInput(e.target));
        });
    },
    
    formatCodeInput(input) {
        // Format as XXXX-XXXX-XXXX-XXXX
        let value = input.value.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
        const parts = [];
        for (let i = 0; i < value.length && i < 16; i += 4) {
            parts.push(value.substr(i, 4));
        }
        input.value = parts.join('-');
    },
    
    updateContentFields() {
        const type = document.getElementById('gen-content-type').value;
        const container = document.getElementById('content-fields');
        
        let html = '';
        
        switch (type) {
            case 'token':
                html = `
                    <div class="form-group">
                        <label>Token Contract Address</label>
                        <input type="text" id="content-token-address" placeholder="0x..." class="form-input">
                    </div>
                    <div class="form-group">
                        <label>Amount</label>
                        <input type="text" id="content-token-amount" placeholder="100.0" class="form-input">
                    </div>
                `;
                break;
                
            case 'wallet_access':
                html = `
                    <div class="form-group">
                        <label>Wallet Address (to be accessed)</label>
                        <input type="text" id="content-wallet" placeholder="0x..." class="form-input">
                    </div>
                `;
                break;
                
            case 'validator_registration':
                html = `
                    <div class="form-row">
                        <div class="form-group">
                            <label>Stake Amount (CRYFT)</label>
                            <input type="number" id="content-stake" placeholder="2000" class="form-input">
                        </div>
                        <div class="form-group">
                            <label>Delegation Fee (%)</label>
                            <input type="number" id="content-fee" placeholder="2" class="form-input">
                        </div>
                    </div>
                `;
                break;
                
            case 'experience':
                html = `
                    <div class="form-group">
                        <label>API Endpoint</label>
                        <input type="text" id="content-api" placeholder="https://api.example.com/trigger" class="form-input">
                    </div>
                    <div class="form-group">
                        <label>Experience Data (JSON)</label>
                        <textarea id="content-experience-data" class="form-textarea" placeholder='{"experience_id": "xyz"}'></textarea>
                    </div>
                `;
                break;
                
            case 'custom':
                html = `
                    <div class="form-group">
                        <label>Custom Content (JSON)</label>
                        <textarea id="content-custom" class="form-textarea" placeholder='{"type": "...", "data": {...}}'></textarea>
                    </div>
                `;
                break;
        }
        
        container.innerHTML = html;
    },
    
    // =============================================
    // Handlers
    // =============================================
    
    async handleGenerate() {
        const manager = document.getElementById('gen-manager').value;
        const contentType = document.getElementById('gen-content-type').value;
        const count = parseInt(document.getElementById('gen-count').value) || 1;
        const status = document.getElementById('gen-status').value;
        const metadata = document.getElementById('gen-metadata').value;
        
        if (!manager) {
            this.toast('Please enter a manager address', 'error');
            return;
        }
        
        // Build content based on type
        const content = this.buildContent(contentType);
        
        try {
            // For demo, generate locally
            const codes = [];
            for (let i = 0; i < count; i++) {
                const code = this.generateCodeLocally();
                codes.push({
                    code: code,
                    uid: this.generateUid(manager, i),
                    status: status,
                    contentType: contentType,
                    created: new Date().toISOString(),
                });
            }
            
            this.generatedCodes = codes;
            this.displayGeneratedCodes(codes);
            this.toast(`Generated ${count} code(s) successfully`, 'success');
            
        } catch (error) {
            this.toast(`Generation failed: ${error.message}`, 'error');
        }
    },
    
    buildContent(type) {
        switch (type) {
            case 'token':
                return {
                    type: 'token',
                    token_address: document.getElementById('content-token-address')?.value || '',
                    amount: document.getElementById('content-token-amount')?.value || '0',
                };
            case 'wallet_access':
                return {
                    type: 'wallet_access',
                    wallet_address: document.getElementById('content-wallet')?.value || '',
                };
            case 'validator_registration':
                return {
                    type: 'validator_registration',
                    stake_amount: document.getElementById('content-stake')?.value || '2000',
                    delegation_fee: document.getElementById('content-fee')?.value || '2',
                };
            case 'experience':
                return {
                    type: 'experience',
                    api_endpoint: document.getElementById('content-api')?.value || '',
                    data: JSON.parse(document.getElementById('content-experience-data')?.value || '{}'),
                };
            case 'custom':
                return JSON.parse(document.getElementById('content-custom')?.value || '{}');
            default:
                return { type: type };
        }
    },
    
    generateCodeLocally() {
        // Generate format: XXXX-YYYY-YYYY-YYYY (4 char index + 12 char code)
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Avoiding confusing chars
        let code = '';
        for (let i = 0; i < 16; i++) {
            code += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return code.match(/.{1,4}/g).join('-');
    },
    
    generateUid(manager, index) {
        const indexStr = String(index + 1).padStart(4, '0');
        const shortManager = manager.slice(0, 10);
        return `${shortManager}-${indexStr}`;
    },
    
    displayGeneratedCodes(codes) {
        const card = document.getElementById('generated-codes-card');
        const list = document.getElementById('generated-codes-list');
        
        card.style.display = 'block';
        
        list.innerHTML = codes.map(c => `
            <div class="code-item">
                <code>${c.code}</code>
                <div class="code-actions">
                    <button class="btn btn-sm" onclick="App.copyCode('${c.code}')" title="Copy">
                        📋
                    </button>
                    <span class="status-badge ${c.status}">${c.status}</span>
                </div>
            </div>
        `).join('');
    },
    
    copyCode(code) {
        navigator.clipboard.writeText(code);
        this.toast('Code copied to clipboard', 'success');
    },
    
    async handleRedeem() {
        const code = document.getElementById('redeem-code').value.replace(/-/g, '');
        const wallet = document.getElementById('redeem-wallet').value;
        
        if (!code || code.length !== 16) {
            this.toast('Please enter a valid 16-character code', 'error');
            return;
        }
        
        if (!wallet) {
            this.toast('Please enter your wallet address', 'error');
            return;
        }
        
        try {
            // Demo: simulate redemption
            const resultCard = document.getElementById('redeem-result-card');
            const resultDiv = document.getElementById('redeem-result');
            
            resultCard.style.display = 'block';
            resultDiv.innerHTML = `
                <div class="activity-item">
                    <div class="activity-icon">✅</div>
                    <div class="activity-content">
                        <div class="activity-title">Code Redeemed Successfully!</div>
                        <div class="activity-meta">
                            Content has been delivered to ${wallet.slice(0, 10)}...
                        </div>
                    </div>
                </div>
            `;
            
            this.toast('Code redeemed successfully!', 'success');
            
        } catch (error) {
            this.toast(`Redemption failed: ${error.message}`, 'error');
        }
    },
    
    async handleVerify() {
        const uid = document.getElementById('verify-uid').value;
        const resultDiv = document.getElementById('verify-result');
        
        if (!uid) {
            this.toast('Please enter a UID to verify', 'error');
            return;
        }
        
        try {
            // Demo: show status
            resultDiv.innerHTML = `
                <div class="activity-item" style="margin-top: 1rem;">
                    <div class="activity-icon">📋</div>
                    <div class="activity-content">
                        <div class="activity-title">Code Status: <span class="status-badge active">Active</span></div>
                        <div class="activity-meta">UID: ${uid}</div>
                    </div>
                </div>
            `;
            
        } catch (error) {
            resultDiv.innerHTML = `<p class="error">Error: ${error.message}</p>`;
        }
    },
    
    async handleValidatorRedeem() {
        const code = document.getElementById('val-code').value;
        const nodeId = document.getElementById('val-node-id').value;
        const wallet = document.getElementById('val-wallet').value;
        
        if (!code || !nodeId || !wallet) {
            this.toast('Please fill in all fields', 'error');
            return;
        }
        
        try {
            this.toast('Validator registration initiated!', 'success');
        } catch (error) {
            this.toast(`Registration failed: ${error.message}`, 'error');
        }
    },
    
    async handleGenerateValidatorCodes() {
        const stake = document.getElementById('gen-val-stake').value;
        const fee = document.getElementById('gen-val-fee').value;
        const count = parseInt(document.getElementById('gen-val-count').value) || 1;
        
        try {
            const codes = [];
            for (let i = 0; i < count; i++) {
                codes.push({
                    code: this.generateCodeLocally(),
                    stake: stake,
                    fee: fee,
                });
            }
            
            this.toast(`Generated ${count} validator code(s)`, 'success');
            
            // Switch to generate page to show codes
            this.generatedCodes = codes.map(c => ({
                code: c.code,
                contentType: 'validator_registration',
                status: 'frozen',
            }));
            this.navigate('generate');
            this.displayGeneratedCodes(this.generatedCodes);
            
        } catch (error) {
            this.toast(`Generation failed: ${error.message}`, 'error');
        }
    },
    
    async handleBatchFreeze() {
        const selected = this.getSelectedCodes();
        if (selected.length === 0) {
            this.toast('No codes selected', 'error');
            return;
        }
        
        this.toast(`Frozen ${selected.length} code(s)`, 'success');
        this.loadCodesList();
    },
    
    async handleBatchActivate() {
        const selected = this.getSelectedCodes();
        if (selected.length === 0) {
            this.toast('No codes selected', 'error');
            return;
        }
        
        this.toast(`Activated ${selected.length} code(s)`, 'success');
        this.loadCodesList();
    },
    
    getSelectedCodes() {
        const checkboxes = document.querySelectorAll('.code-checkbox:checked');
        return Array.from(checkboxes).map(cb => cb.dataset.uid);
    },
    
    // =============================================
    // Data Loading
    // =============================================
    
    async loadStats() {
        try {
            // Demo data
            const stats = {
                total: 42,
                active: 28,
                redeemed: 10,
                frozen: 4,
            };
            
            // Update dashboard
            document.getElementById('dash-total').textContent = stats.total;
            document.getElementById('dash-active').textContent = stats.active;
            document.getElementById('dash-redeemed').textContent = stats.redeemed;
            document.getElementById('dash-frozen').textContent = stats.frozen;
            
            // Update sidebar
            document.getElementById('stat-total').textContent = stats.total;
            document.getElementById('stat-active').textContent = stats.active;
            document.getElementById('stat-redeemed').textContent = stats.redeemed;
            
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    },
    
    async loadCodesList() {
        const tbody = document.getElementById('codes-tbody');
        const status = document.getElementById('filter-status').value;
        const manager = document.getElementById('filter-manager').value;
        
        try {
            // Demo data
            const codes = [
                { uid: '0x1234...5678-0001', status: 'active', contentType: 'token', created: '2024-01-15' },
                { uid: '0x1234...5678-0002', status: 'frozen', contentType: 'validator_registration', created: '2024-01-14' },
                { uid: '0x1234...5678-0003', status: 'redeemed', contentType: 'experience', created: '2024-01-13' },
                { uid: '0x1234...5678-0004', status: 'active', contentType: 'wallet_access', created: '2024-01-12' },
            ];
            
            // Filter
            const filtered = codes.filter(c => {
                if (status && c.status !== status) return false;
                return true;
            });
            
            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">No codes found</td></tr>';
                return;
            }
            
            tbody.innerHTML = filtered.map(c => `
                <tr>
                    <td><input type="checkbox" class="code-checkbox" data-uid="${c.uid}"></td>
                    <td><code>${c.uid}</code></td>
                    <td><span class="status-badge ${c.status}">${c.status}</span></td>
                    <td>${c.contentType}</td>
                    <td>${c.created}</td>
                    <td>
                        <button class="btn btn-sm" onclick="App.showCodeDetails('${c.uid}')" title="View">👁</button>
                    </td>
                </tr>
            `).join('');
            
        } catch (error) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-cell">Error: ${error.message}</td></tr>`;
        }
    },
    
    async loadHistory() {
        const list = document.getElementById('history-list');
        
        try {
            // Demo data
            const history = [
                { type: 'redeemed', code: 'ABCD-EFGH-IJKL-MNOP', wallet: '0x1234...5678', time: '2 hours ago' },
                { type: 'activated', code: 'QRST-UVWX-YZ12-3456', wallet: '0x8765...4321', time: '1 day ago' },
                { type: 'generated', count: 10, wallet: '0xABCD...EF01', time: '2 days ago' },
            ];
            
            if (history.length === 0) {
                list.innerHTML = `
                    <div class="empty-state">
                        <span class="empty-icon">📜</span>
                        <p>No redemption history</p>
                    </div>
                `;
                return;
            }
            
            list.innerHTML = history.map(h => {
                let icon = '📋';
                let title = '';
                
                switch (h.type) {
                    case 'redeemed':
                        icon = '✅';
                        title = `Redeemed: ${h.code}`;
                        break;
                    case 'activated':
                        icon = '🔓';
                        title = `Activated: ${h.code}`;
                        break;
                    case 'generated':
                        icon = '✨';
                        title = `Generated ${h.count} codes`;
                        break;
                }
                
                return `
                    <div class="history-item">
                        <div class="activity-icon">${icon}</div>
                        <div class="activity-content">
                            <div class="activity-title">${title}</div>
                            <div class="activity-meta">${h.wallet || ''}</div>
                        </div>
                        <div class="activity-time">${h.time}</div>
                    </div>
                `;
            }).join('');
            
        } catch (error) {
            list.innerHTML = `<p class="error">Error: ${error.message}</p>`;
        }
    },
    
    showCodeDetails(uid) {
        this.showModal('Code Details', `
            <div class="form-group">
                <label>UID</label>
                <input type="text" class="form-input" value="${uid}" readonly>
            </div>
            <p>Additional details would be loaded from the blockchain...</p>
        `);
    },
    
    // =============================================
    // Connection
    // =============================================
    
    async checkConnection() {
        const statusEl = document.getElementById('connection-status');
        const dot = statusEl.querySelector('.status-dot');
        const text = statusEl.querySelector('.status-text');
        
        try {
            // Demo: always connected
            dot.classList.remove('offline');
            dot.classList.add('online');
            text.textContent = 'Connected';
        } catch (error) {
            dot.classList.remove('online');
            dot.classList.add('offline');
            text.textContent = 'Disconnected';
        }
    },
    
    // =============================================
    // Settings
    // =============================================
    
    loadSettings() {
        const saved = localStorage.getItem('redeemable_codes_settings');
        if (saved) {
            try {
                this.settings = { ...this.settings, ...JSON.parse(saved) };
            } catch (e) {
                console.error('Failed to load settings:', e);
            }
        }
        
        // Apply to form
        const rpcInput = document.getElementById('setting-rpc');
        if (rpcInput) rpcInput.value = this.settings.rpcUrl;
        
        const managerInput = document.getElementById('setting-manager');
        if (managerInput) managerInput.value = this.settings.managerAddress;
    },
    
    saveSettings() {
        this.settings.rpcUrl = document.getElementById('setting-rpc')?.value || '';
        this.settings.managerAddress = document.getElementById('setting-manager')?.value || '';
        
        localStorage.setItem('redeemable_codes_settings', JSON.stringify(this.settings));
        this.toast('Settings saved', 'success');
    },
    
    // =============================================
    // Modal
    // =============================================
    
    bindModals() {
        const overlay = document.getElementById('modal-overlay');
        const closeBtn = document.getElementById('modal-close');
        
        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.hideModal());
        }
        
        if (overlay) {
            overlay.addEventListener('click', (e) => {
                if (e.target === overlay) this.hideModal();
            });
        }
    },
    
    showModal(title, content, footer = '') {
        document.getElementById('modal-title').textContent = title;
        document.getElementById('modal-body').innerHTML = content;
        document.getElementById('modal-footer').innerHTML = footer;
        document.getElementById('modal-overlay').classList.add('active');
    },
    
    hideModal() {
        document.getElementById('modal-overlay').classList.remove('active');
    },
    
    // =============================================
    // Toast Notifications
    // =============================================
    
    toast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icons = {
            success: '✅',
            error: '❌',
            warning: '⚠️',
            info: 'ℹ️',
        };
        
        toast.innerHTML = `
            <span class="toast-icon">${icons[type] || icons.info}</span>
            <span class="toast-message">${message}</span>
        `;
        
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    },
    
    // =============================================
    // Utilities
    // =============================================
    
    formatDate(dateStr) {
        return new Date(dateStr).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
        });
    },
};

// Download codes as CSV
function downloadCodes() {
    if (App.generatedCodes.length === 0) {
        App.toast('No codes to download', 'error');
        return;
    }
    
    const csv = 'Code,UID,Status,Content Type,Created\n' +
        App.generatedCodes.map(c => 
            `${c.code},${c.uid || ''},${c.status || ''},${c.contentType || ''},${c.created || ''}`
        ).join('\n');
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `redeemable-codes-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => App.init());

// Export for use
window.App = App;
