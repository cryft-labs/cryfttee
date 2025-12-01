/**
 * Add Content Tab
 */

function renderAddTab() {
    const container = document.getElementById('tab-add');
    container.innerHTML = `
        <!-- File Upload Card -->
        <div class="card">
            <div class="card-title" style="margin-bottom: 16px;">📁 Upload Files</div>
            <div class="drop-zone" id="drop-zone" onclick="document.getElementById('file-input').click()">
                <div class="drop-zone-icon">📁</div>
                <p>Drop files here or click to browse</p>
                <p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 8px;">
                    Files will be added and pinned to your local IPFS node
                </p>
                <input type="file" id="file-input" style="display: none;" multiple>
            </div>
            
            <div id="upload-progress" style="display: none; margin-top: 16px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                    <span id="upload-filename">Uploading...</span>
                    <span id="upload-percent">0%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" id="upload-progress-bar" style="width: 0%;"></div>
                </div>
            </div>
            
            <div id="upload-results" style="margin-top: 16px;"></div>
        </div>
        
        <!-- Text Content Card -->
        <div class="card">
            <div class="card-title" style="margin-bottom: 16px;">📝 Add Text Content</div>
            <div class="form-group">
                <label>Content</label>
                <textarea id="add-text-content" placeholder="Enter text content here..."></textarea>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>Filename (optional)</label>
                    <input type="text" id="add-text-filename" placeholder="readme.txt">
                </div>
                <div class="form-group">
                    <label>CID Version</label>
                    <select id="add-text-cid-version">
                        <option value="1">CIDv1 (default)</option>
                        <option value="0">CIDv0 (legacy Qm...)</option>
                    </select>
                </div>
            </div>
            <div class="form-group">
                <label class="checkbox-label">
                    <input type="checkbox" id="add-text-pin" checked>
                    Pin after adding
                </label>
            </div>
            <button class="btn btn-success" onclick="addTextContent()">➕ Add to IPFS</button>
        </div>
        
        <!-- Directory Card -->
        <div class="card">
            <div class="card-title" style="margin-bottom: 16px;">📂 Add Directory</div>
            <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem;">
                Add an entire directory structure to IPFS. Each file will be added and the directory will get a root CID.
            </p>
            <div class="drop-zone" id="dir-drop-zone" onclick="document.getElementById('dir-input').click()">
                <div class="drop-zone-icon">📂</div>
                <p>Drop folder here or click to browse</p>
                <input type="file" id="dir-input" style="display: none;" webkitdirectory directory multiple>
            </div>
        </div>
        
        <!-- Import from URL Card -->
        <div class="card">
            <div class="card-title" style="margin-bottom: 16px;">🌐 Import from URL</div>
            <p style="color: var(--text-secondary); margin-bottom: 16px; font-size: 0.9rem;">
                Fetch content from a URL and add it to IPFS.
            </p>
            <div class="form-group">
                <label>URL</label>
                <input type="text" id="import-url" placeholder="https://example.com/file.txt">
            </div>
            <div class="form-group">
                <label class="checkbox-label">
                    <input type="checkbox" id="import-pin" checked>
                    Pin after importing
                </label>
            </div>
            <button class="btn btn-primary" onclick="importFromUrl()">📥 Import</button>
        </div>
    `;
    
    setupDropZone();
}

function setupDropZone() {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const dirDropZone = document.getElementById('dir-drop-zone');
    const dirInput = document.getElementById('dir-input');
    
    // File drop zone
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
        handleFiles(e.dataTransfer.files);
    });
    
    fileInput.addEventListener('change', (e) => {
        handleFiles(e.target.files);
    });
    
    // Directory drop zone
    dirDropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dirDropZone.classList.add('dragover');
    });
    
    dirDropZone.addEventListener('dragleave', () => {
        dirDropZone.classList.remove('dragover');
    });
    
    dirDropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dirDropZone.classList.remove('dragover');
        handleDirectory(e.dataTransfer.items);
    });
    
    dirInput.addEventListener('change', (e) => {
        handleDirectoryFiles(e.target.files);
    });
}

async function handleFiles(files) {
    const progressContainer = document.getElementById('upload-progress');
    const resultsContainer = document.getElementById('upload-results');
    
    resultsContainer.innerHTML = '';
    
    for (const file of files) {
        progressContainer.style.display = 'block';
        document.getElementById('upload-filename').textContent = file.name;
        document.getElementById('upload-percent').textContent = '0%';
        document.getElementById('upload-progress-bar').style.width = '0%';
        
        try {
            const content = await readFileAsBase64(file);
            
            document.getElementById('upload-percent').textContent = '50%';
            document.getElementById('upload-progress-bar').style.width = '50%';
            
            const result = await api.addContent(content, {
                base64: true,
                filename: file.name,
                pin: true,
                cidVersion: 1
            });
            
            document.getElementById('upload-percent').textContent = '100%';
            document.getElementById('upload-progress-bar').style.width = '100%';
            
            if (result.error) {
                addUploadResult(file.name, null, result.error);
            } else {
                addUploadResult(file.name, result.cid || result.Hash);
            }
        } catch (error) {
            addUploadResult(file.name, null, error.message);
        }
    }
    
    progressContainer.style.display = 'none';
    showToast(`Added ${files.length} file(s) to IPFS`, 'success');
}

function readFileAsBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            const base64 = btoa(
                new Uint8Array(reader.result)
                    .reduce((data, byte) => data + String.fromCharCode(byte), '')
            );
            resolve(base64);
        };
        reader.onerror = () => reject(reader.error);
        reader.readAsArrayBuffer(file);
    });
}

function addUploadResult(filename, cid, error) {
    const container = document.getElementById('upload-results');
    
    if (error) {
        container.innerHTML += `
            <div class="info-banner error" style="margin-bottom: 8px;">
                <span class="icon">❌</span>
                <div>
                    <strong>${escapeHtml(filename)}</strong>
                    <div style="font-size: 0.85rem;">${escapeHtml(error)}</div>
                </div>
            </div>
        `;
    } else {
        container.innerHTML += `
            <div class="info-banner success" style="margin-bottom: 8px;">
                <span class="icon">✅</span>
                <div style="flex: 1;">
                    <strong>${escapeHtml(filename)}</strong>
                    <div style="font-size: 0.85rem; font-family: monospace;">${cid}</div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-sm btn-secondary" onclick="copyToClipboard('${cid}')">📋</button>
                    <button class="btn btn-sm btn-secondary" onclick="openGateway('${cid}')">🔗</button>
                </div>
            </div>
        `;
    }
}

async function addTextContent() {
    const content = document.getElementById('add-text-content').value;
    const filename = document.getElementById('add-text-filename').value.trim() || undefined;
    const cidVersion = parseInt(document.getElementById('add-text-cid-version').value);
    const pin = document.getElementById('add-text-pin').checked;
    
    if (!content) {
        showToast('Please enter content to add', 'error');
        return;
    }
    
    showToast('Adding content...', 'info');
    
    const result = await api.addContent(content, {
        base64: false,
        filename,
        pin,
        cidVersion
    });
    
    if (result.error) {
        showToast('Failed to add content: ' + result.error, 'error');
    } else {
        const cid = result.cid || result.Hash;
        showToast(`Added! CID: ${truncateCid(cid)}`, 'success');
        document.getElementById('add-text-content').value = '';
        
        // Show result
        document.getElementById('upload-results').innerHTML = `
            <div class="info-banner success">
                <span class="icon">✅</span>
                <div style="flex: 1;">
                    <strong>Content Added</strong>
                    <div style="font-size: 0.85rem; font-family: monospace;">${cid}</div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-sm btn-secondary" onclick="copyToClipboard('${cid}')">📋</button>
                    <button class="btn btn-sm btn-secondary" onclick="openGateway('${cid}')">🔗</button>
                </div>
            </div>
        `;
    }
}

async function handleDirectory(items) {
    showToast('Directory upload not yet implemented in this version', 'warning');
}

async function handleDirectoryFiles(files) {
    if (files.length === 0) return;
    
    showToast(`Adding ${files.length} files from directory...`, 'info');
    await handleFiles(files);
}

async function importFromUrl() {
    const url = document.getElementById('import-url').value.trim();
    const pin = document.getElementById('import-pin').checked;
    
    if (!url) {
        showToast('Please enter a URL', 'error');
        return;
    }
    
    showToast('Importing from URL...', 'info');
    
    const result = await api.callModule('ipfs_import_url', { url, pin });
    
    if (result.error) {
        showToast('Import failed: ' + result.error, 'error');
    } else {
        const cid = result.cid || result.Hash;
        showToast(`Imported! CID: ${truncateCid(cid)}`, 'success');
        document.getElementById('import-url').value = '';
        
        // Show result
        document.getElementById('upload-results').innerHTML = `
            <div class="info-banner success">
                <span class="icon">✅</span>
                <div style="flex: 1;">
                    <strong>Imported from URL</strong>
                    <div style="font-size: 0.85rem; font-family: monospace;">${cid}</div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-sm btn-secondary" onclick="copyToClipboard('${cid}')">📋</button>
                    <button class="btn btn-sm btn-secondary" onclick="openGateway('${cid}')">🔗</button>
                </div>
            </div>
        `;
    }
}

// Export
window.renderAddTab = renderAddTab;
window.addTextContent = addTextContent;
window.importFromUrl = importFromUrl;
