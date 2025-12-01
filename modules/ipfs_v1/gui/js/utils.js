/**
 * Utility functions for IPFS Module GUI
 */

/**
 * Format bytes to human readable string
 */
function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/**
 * Format date to localized string
 */
function formatDate(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/**
 * Truncate CID for display
 */
function truncateCid(cid, prefixLen = 12, suffixLen = 4) {
    if (!cid || cid.length <= prefixLen + suffixLen) return cid;
    return `${cid.substring(0, prefixLen)}...${cid.slice(-suffixLen)}`;
}

/**
 * Truncate Peer ID for display
 */
function truncatePeerId(peerId, len = 16) {
    if (!peerId || peerId.length <= len) return peerId;
    return `${peerId.substring(0, len)}...`;
}

/**
 * Copy text to clipboard
 */
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard', 'info');
    }).catch(err => {
        showToast('Failed to copy', 'error');
        console.error('Copy failed:', err);
    });
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

/**
 * Open CID in public gateway
 */
function openGateway(cid) {
    const url = `${CONFIG.publicGateway}/ipfs/${cid}`;
    window.open(url, '_blank');
}

/**
 * Debounce function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Create HTML element from template string
 */
function htmlToElement(html) {
    const template = document.createElement('template');
    template.innerHTML = html.trim();
    return template.content.firstChild;
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Parse multiaddr to human readable
 */
function parseMultiaddr(addr) {
    if (!addr) return { protocol: 'unknown', address: addr };
    
    const parts = addr.split('/').filter(p => p);
    let protocol = 'tcp';
    let address = addr;
    
    if (parts.includes('quic') || parts.includes('quic-v1')) {
        protocol = 'quic';
    } else if (parts.includes('ws') || parts.includes('wss')) {
        protocol = 'websocket';
    }
    
    return { protocol, address };
}

/**
 * Validate CID format
 */
function isValidCid(cid) {
    if (!cid) return false;
    // Basic validation - starts with Qm (v0) or ba (v1) or has proper length
    return /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|ba[a-z2-7]{57,59}|b[a-z2-7]{58,})$/i.test(cid);
}

/**
 * Format duration in seconds to human readable
 */
function formatDuration(seconds) {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${mins}m`;
}

/**
 * Get status dot class based on state
 */
function getStatusClass(state) {
    switch (state) {
        case 'online':
        case 'running':
        case 'healthy':
            return 'online';
        case 'connecting':
        case 'starting':
            return 'connecting';
        case 'degraded':
        case 'warning':
            return 'degraded';
        case 'offline':
        case 'stopped':
        case 'error':
            return 'offline';
        default:
            return 'unknown';
    }
}

// Export functions
window.formatBytes = formatBytes;
window.formatDate = formatDate;
window.truncateCid = truncateCid;
window.truncatePeerId = truncatePeerId;
window.copyToClipboard = copyToClipboard;
window.showToast = showToast;
window.openGateway = openGateway;
window.debounce = debounce;
window.htmlToElement = htmlToElement;
window.escapeHtml = escapeHtml;
window.parseMultiaddr = parseMultiaddr;
window.isValidCid = isValidCid;
window.formatDuration = formatDuration;
window.getStatusClass = getStatusClass;
