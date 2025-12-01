// Main Application Entry Point - IPFS Module GUI

(function() {
    // Page registry
    const pages = {
        status: { init: () => window.StatusPage?.init(), name: 'Status' },
        rewards: { init: () => window.RewardsPage?.init(), name: 'Rewards' },
        files: { init: () => window.FilesPage?.init(), name: 'Files' },
        explore: { init: () => window.ExplorePage?.init(), name: 'Explore' },
        peers: { init: () => window.PeersPage?.init(), name: 'Peers' },
        pins: { init: () => window.PinsPage?.init(), name: 'Pins' },
        incentivized: { init: () => window.IncentivizedPage?.init(), name: 'Incentivized' },
        validator: { init: () => window.ValidatorPage?.init(), name: 'Validator' },
        ipns: { init: () => window.IPNSPage?.init(), name: 'IPNS' },
        settings: { init: () => window.SettingsPage?.init(), name: 'Settings' }
    };
    
    let currentPage = 'status';
    let initialized = false;
    
    /**
     * Navigate to a page
     */
    function navigateTo(pageId) {
        if (!pages[pageId]) {
            console.error(`Unknown page: ${pageId}`);
            return;
        }
        
        // Update nav items
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.page === pageId);
        });
        
        // Update pages
        document.querySelectorAll('.page').forEach(page => {
            page.classList.toggle('active', page.id === `page-${pageId}`);
        });
        
        currentPage = pageId;
        
        // Initialize page if needed
        pages[pageId].init();
        
        // Stop status polling when leaving status page
        if (pageId !== 'status' && window.StatusPage?.stopPolling) {
            // Keep status polling for sidebar updates
        }
    }
    
    /**
     * Initialize modal functionality
     */
    function initModal() {
        const overlay = document.getElementById('modal-overlay');
        const closeBtn = document.getElementById('modal-close');
        
        if (closeBtn) {
            closeBtn.addEventListener('click', closeModal);
        }
        
        if (overlay) {
            overlay.addEventListener('click', (e) => {
                if (e.target === overlay) {
                    closeModal();
                }
            });
        }
        
        // Close on Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                closeModal();
            }
        });
    }
    
    /**
     * Show modal dialog
     */
    function showModal(title, content, footer = '') {
        const overlay = document.getElementById('modal-overlay');
        const titleEl = document.getElementById('modal-title');
        const bodyEl = document.getElementById('modal-body');
        const footerEl = document.getElementById('modal-footer');
        
        if (titleEl) titleEl.textContent = title;
        if (bodyEl) bodyEl.innerHTML = content;
        if (footerEl) footerEl.innerHTML = footer;
        if (overlay) overlay.classList.add('active');
    }
    
    /**
     * Close modal dialog
     */
    function closeModal() {
        const overlay = document.getElementById('modal-overlay');
        if (overlay) overlay.classList.remove('active');
    }
    
    /**
     * Initialize navigation
     */
    function initNavigation() {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                const pageId = item.dataset.page;
                if (pageId) {
                    navigateTo(pageId);
                }
            });
        });
    }
    
    /**
     * Update sidebar node status
     */
    function updateSidebarStatus(running) {
        const statusEl = document.getElementById('sidebar-node-status');
        if (statusEl) {
            const dot = statusEl.querySelector('.status-dot');
            const text = statusEl.querySelector('.status-text');
            
            if (dot) dot.className = 'status-dot ' + (running ? 'online' : 'offline');
            if (text) text.textContent = running ? 'Online' : 'Offline';
        }
    }
    
    /**
     * Start global status polling for sidebar
     */
    async function pollGlobalStatus() {
        try {
            const status = await IPFS_API.getStatus();
            updateSidebarStatus(status.running || false);
            
            // Update storage indicator
            if (status.storage_used !== undefined) {
                const used = status.storage_used || 0;
                const max = status.storage_max || 10737418240; // 10GB default
                const percent = max > 0 ? Math.min(100, (used / max) * 100) : 0;
                
                const percentEl = document.getElementById('storage-percent');
                const fillEl = document.getElementById('storage-fill');
                const textEl = document.getElementById('storage-text');
                
                if (percentEl) percentEl.textContent = percent.toFixed(1) + '%';
                if (fillEl) fillEl.style.width = percent + '%';
                if (textEl) textEl.textContent = `${IPFSUtils.formatBytes(used)} / ${IPFSUtils.formatBytes(max)}`;
            }
        } catch (error) {
            updateSidebarStatus(false);
        }
    }
    
    /**
     * Initialize the application
     */
    function init() {
        if (initialized) return;
        initialized = true;
        
        console.log('Initializing IPFS Module GUI...');
        
        // Initialize navigation
        initNavigation();
        
        // Initialize modal
        initModal();
        
        // Initialize the default page (status)
        navigateTo('status');
        
        // Start global status polling
        pollGlobalStatus();
        setInterval(pollGlobalStatus, IPFS_CONFIG.POLL_INTERVAL);
        
        console.log('IPFS Module GUI initialized');
    }
    
    // Expose API for other scripts
    window.IPFSApp = {
        navigateTo,
        showModal,
        closeModal,
        updateSidebarStatus
    };
    
    // Expose simplified aliases for page scripts
    window.App = {
        navigate: navigateTo
    };
    
    window.Utils = {
        showModal,
        hideModal: closeModal,
        showToast: (msg, type) => {
            // Simple toast implementation
            const container = document.getElementById('toast-container');
            if (!container) return;
            const toast = document.createElement('div');
            toast.className = `toast toast-${type || 'info'}`;
            toast.textContent = msg;
            container.appendChild(toast);
            setTimeout(() => toast.remove(), 4000);
        }
    };
    
    window.API = {
        call: async (method, params) => {
            // Route to IPFS_API methods
            if (typeof IPFS_API[method] === 'function') {
                return IPFS_API[method](params);
            }
            // Generic POST for other methods
            return IPFS_API.request(method, params || {});
        }
    };
    
    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
