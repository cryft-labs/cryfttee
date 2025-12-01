// Explore Page - Browse IPFS content by CID

(function() {
    const { formatBytes, showToast, isValidCID, parseIPFSPath, truncate, getFileIcon } = window.IPFSUtils;
    
    let currentCid = null;
    let currentContent = null;
    
    function render() {
        const container = document.getElementById('page-explore');
        container.innerHTML = `
            <div class="page-header">
                <h1>Explore IPFS</h1>
            </div>
            
            <div class="card">
                <div class="card-body">
                    <div class="explore-input-group">
                        <input type="text" class="explore-input" id="explore-cid" 
                               placeholder="Enter CID, IPNS name, or /ipfs/... path">
                        <button class="btn btn-primary" id="btn-explore">
                            <span class="btn-icon">🔍</span>
                            Explore
                        </button>
                    </div>
                    <div class="explore-examples">
                        <span class="example-label">Examples:</span>
                        <button class="example-btn" data-cid="QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG">IPFS Docs</button>
                        <button class="example-btn" data-cid="bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi">Wikipedia</button>
                        <button class="example-btn" data-cid="QmT5NvUtoM5nWFfrQdVrFtvGfKFmG7AHE8P34isapyhCxX">random.txt</button>
                    </div>
                </div>
            </div>
            
            <!-- Explore Results -->
            <div class="card" id="explore-results" style="display: none;">
                <div class="card-header">
                    <h2 class="card-title">Content</h2>
                    <div class="header-actions">
                        <button class="btn btn-sm btn-secondary" id="btn-pin-explored">📌 Pin</button>
                        <button class="btn btn-sm btn-secondary" id="btn-copy-cid">📋 Copy CID</button>
                        <button class="btn btn-sm btn-secondary" id="btn-open-gateway">🌐 Open</button>
                    </div>
                </div>
                <div class="card-body">
                    <div class="explore-meta" id="explore-meta"></div>
                    <div id="explore-content"></div>
                </div>
            </div>
        `;
        
        attachEventListeners();
    }
    
    function attachEventListeners() {
        // Explore button
        document.getElementById('btn-explore').addEventListener('click', explore);
        
        // Enter key in input
        document.getElementById('explore-cid').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') explore();
        });
        
        // Example buttons
        document.querySelectorAll('.example-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.getElementById('explore-cid').value = btn.dataset.cid;
                explore();
            });
        });
        
        // Action buttons
        document.getElementById('btn-pin-explored').addEventListener('click', pinCurrent);
        document.getElementById('btn-copy-cid').addEventListener('click', () => {
            if (currentCid) IPFSUtils.copyToClipboard(currentCid);
        });
        document.getElementById('btn-open-gateway').addEventListener('click', openInGateway);
    }
    
    async function explore() {
        const input = document.getElementById('explore-cid').value.trim();
        if (!input) {
            showToast('Please enter a CID or path', 'warning');
            return;
        }
        
        const parsed = parseIPFSPath(input);
        if (!parsed && !isValidCID(input)) {
            showToast('Invalid CID or path format', 'error');
            return;
        }
        
        const cid = parsed ? (parsed.cid || parsed.name) : input;
        currentCid = cid;
        
        const resultsCard = document.getElementById('explore-results');
        const contentEl = document.getElementById('explore-content');
        const metaEl = document.getElementById('explore-meta');
        
        resultsCard.style.display = 'block';
        contentEl.innerHTML = '<div class="loading"></div> Loading...';
        metaEl.innerHTML = '';
        
        try {
            // Get block stat first
            let stat = null;
            try {
                stat = await IPFS_API.blockStat(cid);
            } catch (e) {
                // Might not be available
            }
            
            // Try to list as directory
            let isDirectory = false;
            let entries = [];
            try {
                const lsResult = await IPFS_API.ls(cid);
                if (lsResult.entries && lsResult.entries.length > 0) {
                    isDirectory = true;
                    entries = lsResult.entries;
                }
            } catch (e) {
                // Not a directory
            }
            
            // Render metadata
            if (stat) {
                metaEl.innerHTML = `
                    <div class="info-row">
                        <span class="info-label">CID</span>
                        <span class="info-value monospace">${cid}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Size</span>
                        <span class="info-value">${formatBytes(stat.size || 0)}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Type</span>
                        <span class="info-value">${isDirectory ? 'Directory' : 'File'}</span>
                    </div>
                `;
            }
            
            if (isDirectory) {
                renderDirectory(entries);
            } else {
                // Try to fetch content
                await renderFile(cid, stat);
            }
            
        } catch (error) {
            contentEl.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">❌</div>
                    <div class="empty-text">Failed to load content</div>
                    <div class="empty-subtext">${error.message}</div>
                </div>
            `;
        }
    }
    
    function renderDirectory(entries) {
        const contentEl = document.getElementById('explore-content');
        
        if (entries.length === 0) {
            contentEl.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">📁</div>
                    <div class="empty-text">Empty directory</div>
                </div>
            `;
            return;
        }
        
        contentEl.innerHTML = entries.map(entry => `
            <div class="list-item" onclick="ExplorePage.exploreEntry('${entry.cid}')">
                <div class="list-item-icon">${getFileIcon(entry.name, entry.type === 'directory')}</div>
                <div class="list-item-content">
                    <div class="list-item-title">${entry.name}</div>
                    <div class="list-item-subtitle">${truncate(entry.cid, 20)} • ${formatBytes(entry.size || 0)}</div>
                </div>
            </div>
        `).join('');
    }
    
    async function renderFile(cid, stat) {
        const contentEl = document.getElementById('explore-content');
        const size = stat?.size || 0;
        
        // Don't try to render large files
        if (size > 1024 * 1024) {
            contentEl.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">📄</div>
                    <div class="empty-text">File too large to preview</div>
                    <div class="empty-subtext">${formatBytes(size)} - Use "Open" to view in gateway</div>
                </div>
            `;
            return;
        }
        
        try {
            const result = await IPFS_API.cat(cid, { length: 10240 });
            
            if (result.content) {
                // Try to decode as text
                try {
                    const text = atob(result.content);
                    if (isPrintable(text)) {
                        contentEl.innerHTML = `<pre class="code-preview">${escapeHtml(text)}</pre>`;
                    } else {
                        contentEl.innerHTML = `
                            <div class="empty-state">
                                <div class="empty-icon">📄</div>
                                <div class="empty-text">Binary content</div>
                                <div class="empty-subtext">Use "Open" to download</div>
                            </div>
                        `;
                    }
                } catch (e) {
                    contentEl.innerHTML = `
                        <div class="empty-state">
                            <div class="empty-icon">📄</div>
                            <div class="empty-text">Unable to decode content</div>
                        </div>
                    `;
                }
            }
        } catch (error) {
            contentEl.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">📄</div>
                    <div class="empty-text">Content not available locally</div>
                    <div class="empty-subtext">Use "Open" to fetch from network</div>
                </div>
            `;
        }
    }
    
    function isPrintable(str) {
        // Check if string is mostly printable ASCII
        let printable = 0;
        for (let i = 0; i < Math.min(str.length, 1000); i++) {
            const code = str.charCodeAt(i);
            if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13) {
                printable++;
            }
        }
        return printable / Math.min(str.length, 1000) > 0.9;
    }
    
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
    
    function exploreEntry(cid) {
        document.getElementById('explore-cid').value = cid;
        explore();
    }
    
    async function pinCurrent() {
        if (!currentCid) return;
        
        try {
            await IPFS_API.addPin(currentCid);
            showToast('Content pinned', 'success');
        } catch (error) {
            showToast(`Failed to pin: ${error.message}`, 'error');
        }
    }
    
    function openInGateway() {
        if (!currentCid) return;
        
        const settings = IPFSUtils.loadSettings();
        const url = `${settings.gateway}/ipfs/${currentCid}`;
        window.open(url, '_blank');
    }
    
    // Initialize
    function init() {
        render();
    }
    
    // Expose for app.js
    window.ExplorePage = {
        init,
        render,
        exploreEntry
    };
})();
