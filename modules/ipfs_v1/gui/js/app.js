/**
 * Main Application Entry Point
 */

// Tab switching
function initTabs() {
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const tabName = tab.dataset.tab;
            switchTab(tabName);
        });
    });
}

function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`.tab[data-tab="${tabName}"]`)?.classList.add('active');
    
    // Update tab content
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById(`tab-${tabName}`)?.classList.add('active');
}

// Node mode selection
function selectNodeMode(mode) {
    // Update UI
    document.querySelectorAll('.mode-option').forEach(opt => {
        opt.classList.remove('selected');
        if (opt.dataset.mode === mode) {
            opt.classList.add('selected');
        }
    });
    
    // Update badge
    updateNodeModeBadge(mode);
    
    // Store selection
    nodeState.mode = mode;
    
    // If node is running, show restart prompt
    if (nodeState.running) {
        showToast('Restart node for mode change to take effect', 'warning');
    }
}

// Render all tabs
function renderAllTabs() {
    renderNodeTab();
    renderPinsTab();
    renderAddTab();
    renderPeersTab();
    renderIpnsTab();
    renderSettingsTab();
}

// Status refresh
async function refreshAllStatus() {
    await refreshNodeStatus();
    
    // Update stats in status bar
    document.getElementById('pin-count').textContent = nodeState.pins;
    document.getElementById('block-count').textContent = nodeState.blocks;
    document.getElementById('storage-used').textContent = formatBytes(nodeState.storageUsed);
}

// Gateway status check
async function checkGatewayStatus() {
    const gatewayDot = document.getElementById('gateway-status');
    
    try {
        const testCid = 'QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn'; // Empty dir
        const testUrl = `${CONFIG.publicGateway}/ipfs/${testCid}`;
        
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        
        const response = await fetch(testUrl, { 
            method: 'HEAD', 
            mode: 'no-cors',
            signal: controller.signal
        });
        
        clearTimeout(timeout);
        gatewayDot.className = 'status-dot online';
    } catch (error) {
        gatewayDot.className = 'status-dot offline';
    }
}

// Periodic refresh
let refreshInterval;

function startPeriodicRefresh() {
    refreshInterval = setInterval(async () => {
        if (nodeState.running) {
            await refreshNodeStatus();
        }
    }, CONFIG.refreshInterval);
}

function stopPeriodicRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
    }
}

// Initialize application
async function init() {
    console.log('Initializing IPFS Module GUI...');
    
    // Initialize tabs
    initTabs();
    
    // Render all tab content
    renderAllTabs();
    
    // Initial status check
    await refreshAllStatus();
    await checkGatewayStatus();
    
    // Start periodic refresh
    startPeriodicRefresh();
    
    console.log('IPFS Module GUI initialized');
}

// Start when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    stopPeriodicRefresh();
});

// Export
window.switchTab = switchTab;
window.selectNodeMode = selectNodeMode;
window.refreshAllStatus = refreshAllStatus;
