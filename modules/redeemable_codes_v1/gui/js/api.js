/**
 * Redeemable Codes Module - API Layer
 * Handles all communication with the WASM module
 */

const API = {
    baseUrl: '/api/v1/codes',
    
    /**
     * Make an API request
     */
    async request(endpoint, method = 'GET', body = null) {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
            },
        };
        
        if (body) {
            options.body = JSON.stringify(body);
        }
        
        try {
            const response = await fetch(`${this.baseUrl}${endpoint}`, options);
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Request failed');
            }
            
            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    },
    
    // =============================================
    // Code Generation
    // =============================================
    
    /**
     * Generate a new redeemable code
     */
    async generateCode(params) {
        return this.request('/generate', 'POST', params);
    },
    
    /**
     * Generate multiple codes in batch
     */
    async generateBatch(params) {
        return this.request('/generate/batch', 'POST', params);
    },
    
    /**
     * Generate validator registration codes
     */
    async generateValidatorCodes(params) {
        return this.request('/generate/validator', 'POST', params);
    },
    
    // =============================================
    // Code Redemption
    // =============================================
    
    /**
     * Redeem a code
     */
    async redeemCode(code, recipientAddress, contentType = null) {
        return this.request('/redeem', 'POST', {
            code,
            recipient_address: recipientAddress,
            content_type: contentType,
        });
    },
    
    /**
     * Redeem a validator registration code
     */
    async redeemValidator(code, nodeId, walletAddress) {
        return this.request('/redeem/validator', 'POST', {
            code,
            node_id: nodeId,
            wallet_address: walletAddress,
        });
    },
    
    // =============================================
    // Code Status & Management
    // =============================================
    
    /**
     * Get public code status
     */
    async getStatus(uid) {
        return this.request(`/status/${encodeURIComponent(uid)}`);
    },
    
    /**
     * Freeze a code
     */
    async freezeCode(uid, managerAddress) {
        return this.request('/freeze', 'POST', {
            uid,
            manager_address: managerAddress,
        });
    },
    
    /**
     * Unfreeze/activate a code
     */
    async unfreezeCode(uid, managerAddress) {
        return this.request('/unfreeze', 'POST', {
            uid,
            manager_address: managerAddress,
        });
    },
    
    /**
     * Revoke a code
     */
    async revokeCode(uid, managerAddress) {
        return this.request('/revoke', 'POST', {
            uid,
            manager_address: managerAddress,
        });
    },
    
    /**
     * Report a code as lost
     */
    async reportLost(uid, managerAddress, proofOfOwnership) {
        return this.request('/report-lost', 'POST', {
            uid,
            manager_address: managerAddress,
            proof_of_ownership: proofOfOwnership,
        });
    },
    
    // =============================================
    // Batch Operations
    // =============================================
    
    /**
     * Batch freeze multiple codes
     */
    async batchFreeze(uids, managerAddress) {
        return this.request('/batch/freeze', 'POST', {
            uids,
            manager_address: managerAddress,
        });
    },
    
    /**
     * Batch activate multiple codes
     */
    async batchActivate(uids, managerAddress) {
        return this.request('/batch/activate', 'POST', {
            uids,
            manager_address: managerAddress,
        });
    },
    
    // =============================================
    // Content Management
    // =============================================
    
    /**
     * Assign content to a code
     */
    async assignContent(uid, content, managerAddress) {
        return this.request('/content/assign', 'POST', {
            uid,
            content,
            manager_address: managerAddress,
        });
    },
    
    // =============================================
    // Queries
    // =============================================
    
    /**
     * List codes with filters
     */
    async listCodes(filters = {}) {
        const params = new URLSearchParams();
        
        if (filters.status) params.append('status', filters.status);
        if (filters.manager) params.append('manager', filters.manager);
        if (filters.limit) params.append('limit', filters.limit);
        if (filters.offset) params.append('offset', filters.offset);
        
        const query = params.toString();
        return this.request(`/list${query ? '?' + query : ''}`);
    },
    
    /**
     * Get redemption history
     */
    async getHistory(filters = {}) {
        const params = new URLSearchParams();
        
        if (filters.address) params.append('address', filters.address);
        if (filters.limit) params.append('limit', filters.limit);
        
        const query = params.toString();
        return this.request(`/history${query ? '?' + query : ''}`);
    },
    
    /**
     * Get stats overview
     */
    async getStats() {
        return this.request('/stats');
    },
    
    /**
     * Get module health/connection status
     */
    async health() {
        return this.request('/health');
    },
};

// Export for use in other modules
window.API = API;
