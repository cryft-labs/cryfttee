// Utility functions for IPFS Module

/**
 * Format bytes to human readable string
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Format duration to human readable string
 */
function formatDuration(seconds) {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
    return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`;
}

/**
 * Format date to locale string
 */
function formatDate(date) {
    if (!(date instanceof Date)) {
        date = new Date(date);
    }
    return date.toLocaleString();
}

/**
 * Format timestamp to relative time
 */
function formatRelativeTime(date) {
    if (!(date instanceof Date)) {
        date = new Date(date);
    }
    
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);
    
    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    return formatDate(date);
}

/**
 * Truncate string with ellipsis
 */
function truncate(str, maxLen = 20, position = 'middle') {
    if (!str || str.length <= maxLen) return str;
    
    if (position === 'middle') {
        const halfLen = Math.floor((maxLen - 3) / 2);
        return str.slice(0, halfLen) + '...' + str.slice(-halfLen);
    }
    
    return str.slice(0, maxLen - 3) + '...';
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showToast('Copied to clipboard', 'success');
        return true;
    } catch (err) {
        console.error('Failed to copy:', err);
        showToast('Failed to copy', 'error');
        return false;
    }
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    
    const icons = {
        success: '✓',
        error: '✗',
        warning: '⚠',
        info: 'ℹ'
    };
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <span class="toast-message">${escapeHtml(message)}</span>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideIn 0.3s ease reverse';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

/**
 * Escape HTML entities
 */
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 * Parse CID string to validate format
 */
function isValidCID(str) {
    if (!str) return false;
    // Basic CID validation - starts with Qm (v0) or ba (v1)
    return /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/.test(str) || 
           /^ba[a-z2-7]{57,}$/.test(str) ||
           /^baf[a-z2-7]{50,}$/.test(str);
}

/**
 * Parse IPFS path
 */
function parseIPFSPath(path) {
    if (!path) return null;
    
    // Handle /ipfs/CID format
    const ipfsMatch = path.match(/^\/ipfs\/([^/]+)(\/.*)?$/);
    if (ipfsMatch) {
        return { type: 'ipfs', cid: ipfsMatch[1], subpath: ipfsMatch[2] || '' };
    }
    
    // Handle /ipns/name format
    const ipnsMatch = path.match(/^\/ipns\/([^/]+)(\/.*)?$/);
    if (ipnsMatch) {
        return { type: 'ipns', name: ipnsMatch[1], subpath: ipnsMatch[2] || '' };
    }
    
    // Handle raw CID
    if (isValidCID(path)) {
        return { type: 'ipfs', cid: path, subpath: '' };
    }
    
    return null;
}

/**
 * Generate gateway URL for CID
 */
function getGatewayUrl(cid, gateway = 'https://ipfs.io') {
    return `${gateway}/ipfs/${cid}`;
}

/**
 * Debounce function
 */
function debounce(fn, delay) {
    let timeoutId;
    return function(...args) {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => fn.apply(this, args), delay);
    };
}

/**
 * Throttle function
 */
function throttle(fn, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            fn.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

/**
 * Get file icon based on type/extension
 */
function getFileIcon(filename, isDirectory = false) {
    if (isDirectory) return '📁';
    
    const ext = filename.split('.').pop().toLowerCase();
    const icons = {
        // Images
        jpg: '🖼️', jpeg: '🖼️', png: '🖼️', gif: '🖼️', svg: '🖼️', webp: '🖼️',
        // Videos
        mp4: '🎬', webm: '🎬', avi: '🎬', mov: '🎬', mkv: '🎬',
        // Audio
        mp3: '🎵', wav: '🎵', ogg: '🎵', flac: '🎵', m4a: '🎵',
        // Documents
        pdf: '📄', doc: '📝', docx: '📝', txt: '📝', md: '📝',
        // Code
        js: '📜', ts: '📜', py: '📜', rs: '📜', go: '📜', html: '📜', css: '📜', json: '📜',
        // Archives
        zip: '📦', tar: '📦', gz: '📦', rar: '📦', '7z': '📦'
    };
    
    return icons[ext] || '📄';
}

/**
 * Convert storage size to bytes
 */
function toBytes(value, unit) {
    const units = { B: 1, KB: 1024, MB: 1024**2, GB: 1024**3, TB: 1024**4 };
    return value * (units[unit] || 1);
}

/**
 * Load settings from localStorage
 */
function loadSettings() {
    try {
        const saved = localStorage.getItem('ipfs_settings');
        return saved ? { ...IPFS_CONFIG.DEFAULTS, ...JSON.parse(saved) } : { ...IPFS_CONFIG.DEFAULTS };
    } catch (e) {
        console.error('Failed to load settings:', e);
        return { ...IPFS_CONFIG.DEFAULTS };
    }
}

/**
 * Save settings to localStorage
 */
function saveSettings(settings) {
    try {
        localStorage.setItem('ipfs_settings', JSON.stringify(settings));
        return true;
    } catch (e) {
        console.error('Failed to save settings:', e);
        return false;
    }
}

// Make utilities globally available
window.IPFSUtils = {
    formatBytes,
    formatDuration,
    formatDate,
    formatRelativeTime,
    truncate,
    copyToClipboard,
    showToast,
    escapeHtml,
    isValidCID,
    parseIPFSPath,
    getGatewayUrl,
    debounce,
    throttle,
    getFileIcon,
    toBytes,
    loadSettings,
    saveSettings
};
