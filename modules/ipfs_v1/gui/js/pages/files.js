// Files Page - File browser and upload

(function() {
    const { formatBytes, showToast, getFileIcon, truncate } = window.IPFSUtils;
    
    let currentPath = '/';
    let files = [];
    
    function render() {
        const container = document.getElementById('page-files');
        container.innerHTML = `
            <div class="page-header">
                <h1>Files</h1>
                <div class="header-actions">
                    <button class="btn btn-secondary" id="btn-new-folder">
                        <span class="btn-icon">📁</span>
                        New Folder
                    </button>
                    <button class="btn btn-primary" id="btn-add-files">
                        <span class="btn-icon">➕</span>
                        Add Files
                    </button>
                </div>
            </div>
            
            <!-- Breadcrumb -->
            <div class="breadcrumb" id="file-breadcrumb">
                <span class="breadcrumb-item active" data-path="/">📁 Files</span>
            </div>
            
            <!-- Drop Zone -->
            <div class="drop-zone" id="drop-zone">
                <div class="drop-zone-content">
                    <div class="drop-zone-icon">📤</div>
                    <div class="drop-zone-text">Drag & drop files here</div>
                    <div class="drop-zone-subtext">or click to browse</div>
                </div>
                <input type="file" id="file-input" multiple hidden>
            </div>
            
            <!-- File List -->
            <div class="file-list" id="file-list">
                <div class="empty-state">
                    <div class="empty-icon">📂</div>
                    <div class="empty-text">No files yet</div>
                    <div class="empty-subtext">Add files using the button above or drag & drop</div>
                </div>
            </div>
        `;
        
        attachEventListeners();
        loadFiles();
    }
    
    function attachEventListeners() {
        const dropZone = document.getElementById('drop-zone');
        const fileInput = document.getElementById('file-input');
        const addBtn = document.getElementById('btn-add-files');
        const newFolderBtn = document.getElementById('btn-new-folder');
        
        // Click to browse
        dropZone.addEventListener('click', () => fileInput.click());
        addBtn.addEventListener('click', () => fileInput.click());
        
        // File input change
        fileInput.addEventListener('change', handleFileSelect);
        
        // Drag and drop
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
        
        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });
        
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            handleFileDrop(e.dataTransfer.files);
        });
        
        // New folder
        newFolderBtn.addEventListener('click', createNewFolder);
    }
    
    async function handleFileSelect(e) {
        const files = e.target.files;
        if (files.length > 0) {
            await uploadFiles(files);
        }
    }
    
    async function handleFileDrop(fileList) {
        if (fileList.length > 0) {
            await uploadFiles(fileList);
        }
    }
    
    async function uploadFiles(fileList) {
        showToast(`Uploading ${fileList.length} file(s)...`, 'info');
        
        for (const file of fileList) {
            try {
                const reader = new FileReader();
                const content = await new Promise((resolve, reject) => {
                    reader.onload = () => resolve(reader.result);
                    reader.onerror = reject;
                    reader.readAsArrayBuffer(file);
                });
                
                // Convert to base64 for API
                const base64 = btoa(String.fromCharCode(...new Uint8Array(content)));
                
                const result = await IPFS_API.addFile(base64, {
                    filename: file.name,
                    pin: true
                });
                
                showToast(`Added: ${file.name}`, 'success');
                
            } catch (error) {
                showToast(`Failed to upload ${file.name}: ${error.message}`, 'error');
            }
        }
        
        loadFiles();
    }
    
    async function loadFiles() {
        try {
            // For MFS (Mutable File System) root
            const result = await IPFS_API.ls(currentPath === '/' ? '/ipfs' : currentPath);
            files = result.entries || [];
            renderFileList();
        } catch (error) {
            console.error('Failed to load files:', error);
            files = [];
            renderFileList();
        }
    }
    
    function renderFileList() {
        const container = document.getElementById('file-list');
        
        if (files.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">📂</div>
                    <div class="empty-text">No files yet</div>
                    <div class="empty-subtext">Add files using the button above or drag & drop</div>
                </div>
            `;
            return;
        }
        
        container.innerHTML = files.map(file => `
            <div class="list-item" data-cid="${file.cid}" data-type="${file.type}">
                <div class="list-item-icon">${getFileIcon(file.name, file.type === 'directory')}</div>
                <div class="list-item-content">
                    <div class="list-item-title">${file.name}</div>
                    <div class="list-item-subtitle">${truncate(file.cid, 24)} • ${formatBytes(file.size || 0)}</div>
                </div>
                <div class="list-item-actions">
                    <button class="btn btn-sm btn-secondary" onclick="FilesPage.copyLink('${file.cid}')">🔗</button>
                    <button class="btn btn-sm btn-secondary" onclick="FilesPage.pinFile('${file.cid}')">📌</button>
                    <button class="btn btn-sm btn-secondary" onclick="FilesPage.downloadFile('${file.cid}', '${file.name}')">⬇️</button>
                </div>
            </div>
        `).join('');
        
        // Add click handlers for navigation
        container.querySelectorAll('.list-item').forEach(item => {
            item.addEventListener('dblclick', () => {
                if (item.dataset.type === 'directory') {
                    navigateTo(item.dataset.cid);
                }
            });
        });
    }
    
    function updateBreadcrumb() {
        const container = document.getElementById('file-breadcrumb');
        const parts = currentPath.split('/').filter(Boolean);
        
        let html = '<span class="breadcrumb-item" data-path="/" onclick="FilesPage.navigateTo(\'/\')">📁 Files</span>';
        
        let path = '';
        for (const part of parts) {
            path += '/' + part;
            html += `<span class="breadcrumb-separator">/</span>`;
            html += `<span class="breadcrumb-item" data-path="${path}" onclick="FilesPage.navigateTo('${path}')">${part}</span>`;
        }
        
        container.innerHTML = html;
        container.querySelector('.breadcrumb-item:last-child').classList.add('active');
    }
    
    function navigateTo(path) {
        currentPath = path;
        updateBreadcrumb();
        loadFiles();
    }
    
    async function createNewFolder() {
        const name = prompt('Enter folder name:');
        if (!name) return;
        
        try {
            await IPFS_API.call('files_mkdir', { path: `${currentPath}/${name}` });
            showToast(`Created folder: ${name}`, 'success');
            loadFiles();
        } catch (error) {
            showToast(`Failed to create folder: ${error.message}`, 'error');
        }
    }
    
    function copyLink(cid) {
        const settings = IPFSUtils.loadSettings();
        const url = `${settings.gateway}/ipfs/${cid}`;
        IPFSUtils.copyToClipboard(url);
    }
    
    async function pinFile(cid) {
        try {
            await IPFS_API.addPin(cid);
            showToast('File pinned', 'success');
        } catch (error) {
            showToast(`Failed to pin: ${error.message}`, 'error');
        }
    }
    
    async function downloadFile(cid, filename) {
        try {
            const settings = IPFSUtils.loadSettings();
            const url = `${settings.gateway}/ipfs/${cid}?filename=${encodeURIComponent(filename)}`;
            window.open(url, '_blank');
        } catch (error) {
            showToast(`Failed to download: ${error.message}`, 'error');
        }
    }
    
    // Initialize
    function init() {
        render();
    }
    
    // Expose for app.js and inline handlers
    window.FilesPage = {
        init,
        render,
        navigateTo,
        copyLink,
        pinFile,
        downloadFile
    };
})();
