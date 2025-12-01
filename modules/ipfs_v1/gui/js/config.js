// IPFS Module Configuration
const CONFIG = {
    MODULE_ID: 'ipfs_v1',
    API_BASE: '/v1/module/ipfs_v1',
    POLL_INTERVAL: 5000,
    
    // Default gateways
    GATEWAYS: [
        { name: 'ipfs.io', url: 'https://ipfs.io' },
        { name: 'dweb.link', url: 'https://dweb.link' },
        { name: 'cloudflare-ipfs.com', url: 'https://cloudflare-ipfs.com' },
        { name: 'pinata.cloud', url: 'https://gateway.pinata.cloud' }
    ],
    
    // Default bootstrap peers
    BOOTSTRAP_PEERS: [
        '/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN',
        '/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa',
        '/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb',
        '/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt',
        '/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ'
    ],
    
    // Node modes
    NODE_MODES: {
        full: {
            name: 'Full Node',
            description: 'Complete DHT participation, serves and announces content',
            icon: '🖥️'
        },
        light: {
            name: 'Light Node', 
            description: 'Minimal DHT, request-only, lower resource usage',
            icon: '📱'
        }
    },
    
    // Default settings
    DEFAULTS: {
        nodeMode: 'full',
        storageLimit: 10,
        storageUnit: 'GB',
        gcEnabled: true,
        gcWatermark: 90,
        dhtServer: true,
        relay: true,
        autonat: true,
        connmgrLow: 100,
        connmgrHigh: 400,
        connmgrGrace: '30s',
        gateway: 'https://ipfs.io'
    }
};

// Make config globally available
window.IPFS_CONFIG = CONFIG;
