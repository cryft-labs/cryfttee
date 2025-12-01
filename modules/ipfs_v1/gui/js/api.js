// IPFS Module API wrapper

const IPFS_API = {
    /**
     * Call the IPFS module with an operation
     */
    async call(operation, params = {}) {
        try {
            const response = await fetch(`${IPFS_CONFIG.API_BASE}/call`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ operation, ...params })
            });
            
            if (!response.ok) {
                const error = await response.text();
                throw new Error(error || `HTTP ${response.status}`);
            }
            
            return await response.json();
        } catch (error) {
            console.error(`IPFS API error (${operation}):`, error);
            throw error;
        }
    },
    
    // ============ Node Operations ============
    
    async getStatus() {
        return this.call('node_status');
    },
    
    async startNode(mode = 'full') {
        return this.call('node_start', { mode });
    },
    
    async stopNode() {
        return this.call('node_stop');
    },
    
    async getNodeInfo() {
        return this.call('node_info');
    },
    
    async getBandwidth() {
        return this.call('bandwidth_stats');
    },
    
    // ============ File Operations ============
    
    async addFile(content, options = {}) {
        return this.call('ipfs_add', { 
            content,
            pin: options.pin !== false,
            wrap_with_directory: options.wrapWithDirectory || false,
            only_hash: options.onlyHash || false
        });
    },
    
    async addDirectory(files) {
        return this.call('ipfs_add_dir', { files });
    },
    
    async cat(cid, options = {}) {
        return this.call('ipfs_cat', {
            cid,
            offset: options.offset,
            length: options.length
        });
    },
    
    async get(cid) {
        return this.call('ipfs_get', { cid });
    },
    
    async ls(cid) {
        return this.call('ipfs_ls', { cid });
    },
    
    // ============ Pin Operations ============
    
    async listPins(type = 'all') {
        return this.call('pin_ls', { type });
    },
    
    async addPin(cid, recursive = true) {
        return this.call('pin_add', { cid, recursive });
    },
    
    async removePin(cid, recursive = true) {
        return this.call('pin_rm', { cid, recursive });
    },
    
    // ============ Peer Operations ============
    
    async listPeers() {
        return this.call('swarm_peers');
    },
    
    async connectPeer(multiaddr) {
        return this.call('swarm_connect', { multiaddr });
    },
    
    async disconnectPeer(peerId) {
        return this.call('swarm_disconnect', { peer_id: peerId });
    },
    
    async getBootstrapPeers() {
        return this.call('bootstrap_list');
    },
    
    async addBootstrapPeer(multiaddr) {
        return this.call('bootstrap_add', { multiaddr });
    },
    
    async removeBootstrapPeer(multiaddr) {
        return this.call('bootstrap_rm', { multiaddr });
    },
    
    async resetBootstrapPeers() {
        return this.call('bootstrap_reset');
    },
    
    // ============ DHT Operations ============
    
    async dhtFindPeer(peerId) {
        return this.call('dht_findpeer', { peer_id: peerId });
    },
    
    async dhtFindProviders(cid, numProviders = 20) {
        return this.call('dht_findprovs', { cid, num_providers: numProviders });
    },
    
    async dhtProvide(cid) {
        return this.call('dht_provide', { cid });
    },
    
    // ============ IPNS Operations ============
    
    async listKeys() {
        return this.call('key_list');
    },
    
    async generateKey(name, type = 'ed25519', size = 2048) {
        return this.call('key_gen', { name, type, size });
    },
    
    async removeKey(name) {
        return this.call('key_rm', { name });
    },
    
    async renameKey(oldName, newName) {
        return this.call('key_rename', { old_name: oldName, new_name: newName });
    },
    
    async ipnsPublish(cid, options = {}) {
        return this.call('ipns_publish', {
            cid,
            key: options.key || 'self',
            lifetime: options.lifetime || '24h',
            ttl: options.ttl || '1h',
            resolve: options.resolve !== false
        });
    },
    
    async ipnsResolve(name, options = {}) {
        return this.call('ipns_resolve', {
            name,
            recursive: options.recursive !== false,
            nocache: options.nocache || false
        });
    },
    
    // ============ Repo Operations ============
    
    async repoStat() {
        return this.call('repo_stat');
    },
    
    async repoGc() {
        return this.call('repo_gc');
    },
    
    // ============ Block Operations ============
    
    async blockStat(cid) {
        return this.call('block_stat', { cid });
    },
    
    async blockGet(cid) {
        return this.call('block_get', { cid });
    },
    
    // ============ Config Operations ============
    
    async getConfig(key) {
        return this.call('config_get', { key });
    },
    
    async setConfig(key, value) {
        return this.call('config_set', { key, value });
    },
    
    // ============ Validator Reward Operations ============
    
    async validator_status() {
        return this.call('validator_status');
    },
    
    async validator_register(params) {
        return this.call('validator_register', params);
    },
    
    async validator_update_config(config) {
        return this.call('validator_update_config', config);
    },
    
    async validator_metrics() {
        return this.call('validator_metrics');
    },
    
    async validator_activity() {
        return this.call('validator_activity');
    },
    
    async validator_claim_rewards(params) {
        return this.call('validator_claim_rewards', params);
    },
    
    async validator_stats() {
        return this.call('validator_stats');
    },
    
    async list_proofs() {
        return this.call('list_proofs');
    },
    
    async claim_rewards() {
        return this.call('claim_rewards');
    },
    
    // ============ Incentivized Pin Operations ============
    
    async list_incentivized() {
        return this.call('list_incentivized');
    },
    
    async incentivize(params) {
        return this.call('incentivize', params);
    },
    
    async pin(params) {
        return this.call('pin', params);
    },
    
    // ============ Generic Request ============
    
    async request(method, params) {
        return this.call(method, params);
    }
};

// Make API globally available
window.IPFS_API = IPFS_API;
