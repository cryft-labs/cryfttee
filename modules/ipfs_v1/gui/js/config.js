/**
 * IPFS Module Configuration
 */
const CONFIG = {
    apiBase: '/api/modules/ipfs_v1',
    publicGateway: 'https://gateway.cryft.network',
    fallbackGateways: [
        'https://ipfs.io',
        'https://dweb.link',
        'https://cloudflare-ipfs.com'
    ],
    defaultNodeMode: 'full',
    refreshInterval: 10000, // 10 seconds
    limits: {
        maxAddSizeMb: 100,
        requestTimeoutSecs: 60
    }
};

// Current node state
const nodeState = {
    mode: 'full',
    running: false,
    peerId: null,
    dhtPeers: 0,
    pins: 0,
    blocks: 0,
    storageUsed: 0
};

// Export for use in other modules
window.CONFIG = CONFIG;
window.nodeState = nodeState;
