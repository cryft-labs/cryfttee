/**
 * API wrapper for IPFS Module
 */

/**
 * Call module operation
 */
async function callModule(operation, data = {}) {
    try {
        const response = await fetch(`${CONFIG.apiBase}/call`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ operation, data })
        });
        
        if (!response.ok) {
            const error = await response.text();
            throw new Error(error || `HTTP ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error(`API error [${operation}]:`, error);
        return { error: error.message };
    }
}

// ==================== Node Operations ====================

async function initNode(mode = 'full') {
    return callModule('node_init', { mode });
}

async function startNode() {
    return callModule('node_start', {});
}

async function stopNode() {
    return callModule('node_stop', {});
}

async function getNodeStatus() {
    return callModule('node_status', {});
}

async function getNodeConfig() {
    return callModule('node_config', { action: 'get' });
}

async function setNodeConfig(config) {
    return callModule('node_config', { action: 'set', config });
}

// ==================== Content Operations ====================

async function addContent(content, options = {}) {
    return callModule('ipfs_add', {
        content,
        base64: options.base64 || false,
        filename: options.filename,
        pin: options.pin !== false,
        cidVersion: options.cidVersion || 1
    });
}

async function catContent(cid) {
    return callModule('ipfs_cat', { cid });
}

async function getContent(cid, outputPath) {
    return callModule('ipfs_get', { cid, outputPath });
}

async function statContent(cid) {
    return callModule('ipfs_stat', { cid });
}

// ==================== Pin Operations ====================

async function pinCid(cid, options = {}) {
    return callModule('ipfs_pin', {
        cid,
        name: options.name,
        recursive: options.recursive !== false
    });
}

async function unpinCid(cid) {
    return callModule('ipfs_unpin', { cid });
}

async function listPins(type = 'recursive') {
    return callModule('ipfs_ls', { pinType: type });
}

async function searchPins(query, limit = 100) {
    return callModule('ipfs_search', { query, limit });
}

// ==================== Peer Operations ====================

async function connectPeer(addr) {
    return callModule('peer_connect', { addr });
}

async function disconnectPeer(peerId) {
    return callModule('peer_disconnect', { peerId });
}

async function listPeers() {
    return callModule('peer_list', {});
}

async function findPeer(peerId) {
    return callModule('dht_find_peer', { peerId });
}

async function findProviders(cid, limit = 20) {
    return callModule('dht_find_providers', { cid, limit });
}

async function provideContent(cid) {
    return callModule('dht_provide', { cid });
}

// ==================== Block Operations ====================

async function getBlock(cid) {
    return callModule('block_get', { cid });
}

async function putBlock(data, options = {}) {
    return callModule('block_put', {
        data,
        format: options.format || 'raw',
        mhtype: options.mhtype || 'sha2-256'
    });
}

async function statBlock(cid) {
    return callModule('block_stat', { cid });
}

// ==================== IPNS Operations ====================

async function publishIpns(cid, options = {}) {
    return callModule('ipns_publish', {
        cid,
        key: options.key || 'self',
        ttl: options.ttl || 3600,
        lifetime: options.lifetime || 86400
    });
}

async function resolveIpns(name) {
    return callModule('ipns_resolve', { name });
}

async function listKeys() {
    return callModule('ipns_keys', {});
}

async function generateKey(name, type = 'ed25519') {
    return callModule('ipns_keys', { generate: name, keyType: type });
}

// Export all API functions
window.api = {
    callModule,
    // Node
    initNode,
    startNode,
    stopNode,
    getNodeStatus,
    getNodeConfig,
    setNodeConfig,
    // Content
    addContent,
    catContent,
    getContent,
    statContent,
    // Pins
    pinCid,
    unpinCid,
    listPins,
    searchPins,
    // Peers
    connectPeer,
    disconnectPeer,
    listPeers,
    findPeer,
    findProviders,
    provideContent,
    // Blocks
    getBlock,
    putBlock,
    statBlock,
    // IPNS
    publishIpns,
    resolveIpns,
    listKeys,
    generateKey
};
