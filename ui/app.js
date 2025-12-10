/**
 * CryftTEE Kiosk UI Application
 * Robust module loading with error isolation
 */

const API_BASE = '';

// ============================================================================
// State
// ============================================================================

const state = {
    modules: [],
    attestation: null,
    schema: null,
    manifest: null,
    context: null,  // Runtime context including health status
    activeTab: 'dashboard',
    moduleGuiTabs: new Map(),      // Tab-type module GUIs
    llmModules: [],                 // LLM-type modules (use pill popup)
    activeLlmModule: null,          // Currently enabled LLM module ID (only one)
    popupOpen: false,
    tabOrder: [],                   // Ordered list of tab IDs
    inReorderMode: false,
    // Connection status
    connection: {
        status: 'checking',        // 'connected', 'disconnected', 'checking'
        endpoint: window.location.origin,
        lastLatency: null,
        lastCheck: null,
        consecutiveFailures: 0
    },
    // Dynamic module status panels (keyed by module ID)
    moduleStatusPanels: new Map()
};

// ============================================================================
// DOM Utilities
// ============================================================================

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function createElement(tag, attrs = {}, children = []) {
    const el = document.createElement(tag);
    for (const [key, val] of Object.entries(attrs)) {
        if (key === 'className') el.className = val;
        else if (key === 'dataset') Object.assign(el.dataset, val);
        else if (key.startsWith('on') && typeof val === 'function') {
            el.addEventListener(key.slice(2).toLowerCase(), val);
        }
        else el.setAttribute(key, val);
    }
    for (const child of children) {
        if (typeof child === 'string') el.appendChild(document.createTextNode(child));
        else if (child) el.appendChild(child);
    }
    return el;
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ============================================================================
// Toast
// ============================================================================

let toastTimeout = null;

function toast(message, type = 'ok', duration = 2500) {
    const toastEl = $('#toast');
    if (!toastEl) return;
    
    toastEl.textContent = message;
    toastEl.className = `toast show ${type}`;
    
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => {
        toastEl.classList.remove('show');
    }, duration);
}

// ============================================================================
// Tab Management (with reorder support)
// ============================================================================

const TAB_ORDER_KEY = 'cryfttee_tab_order';
const ACTIVE_TAB_KEY = 'cryfttee_active_tab';
const TAB_SCROLL_AMOUNT = 150; // pixels to scroll per click

// Base tabs that always exist
const BASE_TABS = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'modules', label: 'Modules', badge: 'modules-badge' },
    { id: 'attestation', label: 'Attestation' }
];

function initTabs() {
    const tabBar = $('#tab-bar');
    const tabsScroll = $('#tabs-scroll');
    const scrollLeft = $('#tab-scroll-left');
    const scrollRight = $('#tab-scroll-right');
    const reorderHint = $('#tab-reorder-hint');
    const reorderDone = $('#tab-reorder-done');
    
    if (!tabBar) return;
    
    // Load saved tab order
    loadTabOrder();
    
    // Render tabs
    renderTabs();
    
    // Tab scroll buttons
    if (scrollLeft && scrollRight && tabsScroll) {
        scrollLeft.addEventListener('click', () => {
            tabsScroll.scrollBy({ left: -TAB_SCROLL_AMOUNT, behavior: 'smooth' });
        });
        
        scrollRight.addEventListener('click', () => {
            tabsScroll.scrollBy({ left: TAB_SCROLL_AMOUNT, behavior: 'smooth' });
        });
        
        // Update scroll button visibility on scroll and resize
        tabsScroll.addEventListener('scroll', updateTabScrollButtons);
        window.addEventListener('resize', updateTabScrollButtons);
        
        // Initial check
        setTimeout(updateTabScrollButtons, 100);
    }
    
    // Tab click handler
    tabBar.addEventListener('click', (e) => {
        const tab = e.target.closest('.tab-btn');
        if (!tab) return;
        
        // Don't activate if in reorder mode
        if (state.inReorderMode) return;
        
        const tabId = tab.dataset.tab;
        if (tabId) switchTab(tabId);
    });
    
    // Triple-click to enter reorder mode
    let tripleClickTimer = null;
    let tripleCount = 0;
    
    tabBar.addEventListener('mousedown', (e) => {
        const tab = e.target.closest('.tab-btn');
        if (!tab) return;
        
        tripleCount++;
        clearTimeout(tripleClickTimer);
        tripleClickTimer = setTimeout(() => tripleCount = 0, 420);
        
        if (tripleCount >= 3) {
            tripleCount = 0;
            enableReorderMode();
        }
    });
    
    // Drag & drop handlers
    let dragId = null;
    let lastOverBtn = null;
    
    function clearAllDropTargets() {
        $$('.tab-btn', tabBar).forEach(x => x.classList.remove('drag-over-left', 'drag-over-right'));
        lastOverBtn = null;
    }
    
    tabBar.addEventListener('dragstart', (e) => {
        const btn = e.target.closest('.tab-btn');
        if (!btn || !state.inReorderMode) return;
        dragId = btn.dataset.tab;
        btn.classList.add('dragging');
    });
    
    tabBar.addEventListener('dragend', (e) => {
        const btn = e.target.closest('.tab-btn');
        if (btn) btn.classList.remove('dragging');
        clearAllDropTargets();
        dragId = null;
    });
    
    tabBar.addEventListener('dragover', (e) => {
        if (!dragId || !state.inReorderMode) return;
        e.preventDefault();
        
        const over = e.target.closest('.tab-btn');
        if (!over || over.dataset.tab === dragId) {
            clearAllDropTargets();
            return;
        }
        
        if (lastOverBtn !== over) clearAllDropTargets();
        
        const rect = over.getBoundingClientRect();
        const left = e.clientX < rect.left + rect.width / 2;
        over.classList.toggle('drag-over-left', left);
        over.classList.toggle('drag-over-right', !left);
        lastOverBtn = over;
    });
    
    tabBar.addEventListener('dragleave', (e) => {
        if (!dragId || !state.inReorderMode) return;
        const leaving = e.target.closest('.tab-btn');
        if (leaving) {
            leaving.classList.remove('drag-over-left', 'drag-over-right');
            if (leaving === lastOverBtn) lastOverBtn = null;
        }
    });
    
    tabBar.addEventListener('drop', (e) => {
        if (!dragId || !state.inReorderMode) return;
        e.preventDefault();
        
        const over = e.target.closest('.tab-btn');
        if (!over || over.dataset.tab === dragId) {
            clearAllDropTargets();
            return;
        }
        
        const rect = over.getBoundingClientRect();
        const left = e.clientX < rect.left + rect.width / 2;
        
        const fromIdx = state.tabOrder.indexOf(dragId);
        let toIdx = state.tabOrder.indexOf(over.dataset.tab);
        if (!left) toIdx++;
        
        // Reorder
        state.tabOrder.splice(fromIdx, 1);
        if (fromIdx < toIdx) toIdx--;
        state.tabOrder.splice(toIdx, 0, dragId);
        
        saveTabOrder();
        renderTabs();
        enableReorderMode(); // Keep in reorder mode
        clearAllDropTargets();
    });
    
    // Done button
    if (reorderDone) {
        reorderDone.addEventListener('click', disableReorderMode);
    }
    
    // Escape key to exit reorder mode
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && state.inReorderMode) {
            disableReorderMode();
        }
    });
    
    // Load and activate saved tab
    const savedActive = localStorage.getItem(ACTIVE_TAB_KEY);
    const validTab = state.tabOrder.includes(savedActive) ? savedActive : state.tabOrder[0];
    switchTab(validTab || 'dashboard');
}

function loadTabOrder() {
    try {
        const saved = localStorage.getItem(TAB_ORDER_KEY);
        const parsed = saved ? JSON.parse(saved) : null;
        if (Array.isArray(parsed) && parsed.length > 0) {
            state.tabOrder = parsed;
        } else {
            state.tabOrder = BASE_TABS.map(t => t.id);
        }
    } catch (e) {
        state.tabOrder = BASE_TABS.map(t => t.id);
    }
}

function saveTabOrder() {
    try {
        localStorage.setItem(TAB_ORDER_KEY, JSON.stringify(state.tabOrder));
    } catch (e) {
        console.warn('Failed to save tab order:', e);
    }
}

function updateTabScrollButtons() {
    const tabsScroll = $('#tabs-scroll');
    const tabBar = $('#tab-bar');
    const scrollLeft = $('#tab-scroll-left');
    const scrollRight = $('#tab-scroll-right');
    
    if (!tabsScroll || !tabBar || !scrollLeft || !scrollRight) return;
    
    const scrollWidth = tabsScroll.scrollWidth;
    const clientWidth = tabsScroll.clientWidth;
    const scrollPos = tabsScroll.scrollLeft;
    const hasOverflow = scrollWidth > clientWidth + 2; // 2px tolerance
    
    // Show/hide scroll buttons based on overflow and position
    const canScrollLeft = scrollPos > 2;
    const canScrollRight = scrollPos < scrollWidth - clientWidth - 2;
    
    scrollLeft.classList.toggle('visible', hasOverflow && canScrollLeft);
    scrollRight.classList.toggle('visible', hasOverflow && canScrollRight);
    
    // Center tabs if no overflow
    tabBar.classList.toggle('centered', !hasOverflow);
}

function renderTabs() {
    const tabBar = $('#tab-bar');
    if (!tabBar) return;
    
    tabBar.innerHTML = '';
    
    // Build full tab spec including module GUI tabs
    const allTabs = [
        ...BASE_TABS,
        ...Array.from(state.moduleGuiTabs.entries()).map(([id, data]) => ({
            id: `module-gui-${id}`,
            label: id,
            isModuleGui: true,
            moduleId: id
        }))
    ];
    
    // Ensure all tabs are in order (add new ones to end)
    for (const tab of allTabs) {
        if (!state.tabOrder.includes(tab.id)) {
            state.tabOrder.push(tab.id);
        }
    }
    
    // Remove tabs that no longer exist
    const validIds = new Set(allTabs.map(t => t.id));
    state.tabOrder = state.tabOrder.filter(id => validIds.has(id));
    
    // Render in order
    for (const tabId of state.tabOrder) {
        const spec = allTabs.find(t => t.id === tabId);
        if (!spec) continue;
        
        const btn = document.createElement('button');
        btn.className = 'tab-btn';
        btn.dataset.tab = spec.id;
        btn.setAttribute('draggable', 'true');
        
        if (state.inReorderMode) {
            btn.classList.add('draggable');
        }
        
        if (spec.id === state.activeTab) {
            btn.classList.add('active');
        }
        
        // Label
        let labelText = spec.label;
        btn.textContent = labelText;
        
        // Badge for modules tab
        if (spec.badge) {
            const badge = document.createElement('span');
            badge.className = 'pill';
            badge.id = spec.badge;
            badge.style.marginLeft = '6px';
            badge.textContent = state.modules.length.toString();
            btn.appendChild(badge);
        }
        
        // GUI pill for module tabs
        if (spec.isModuleGui) {
            const pill = document.createElement('span');
            pill.className = 'pill';
            pill.style.marginLeft = '6px';
            pill.textContent = 'GUI';
            btn.appendChild(pill);
        }
        
        tabBar.appendChild(btn);
    }
    
    saveTabOrder();
    
    // Update scroll buttons after render
    setTimeout(updateTabScrollButtons, 0);
}

function enableReorderMode() {
    state.inReorderMode = true;
    document.body.classList.add('reorder-mode');
    
    const hint = $('#tab-reorder-hint');
    if (hint) hint.hidden = false;
    
    $$('.tab-btn').forEach(btn => btn.classList.add('draggable'));
}

function disableReorderMode() {
    state.inReorderMode = false;
    document.body.classList.remove('reorder-mode');
    
    const hint = $('#tab-reorder-hint');
    if (hint) hint.hidden = true;
    
    $$('.tab-btn').forEach(btn => {
        btn.classList.remove('draggable', 'dragging', 'drag-over-left', 'drag-over-right');
    });
}

function switchTab(tabId) {
    state.activeTab = tabId;
    
    // Update tab buttons
    $$('.tab-btn').forEach(tab => {
        const isActive = tab.dataset.tab === tabId;
        tab.classList.toggle('active', isActive);
        
        // Scroll active tab into view
        if (isActive) {
            const tabsScroll = $('#tabs-scroll');
            if (tabsScroll) {
                const tabRect = tab.getBoundingClientRect();
                const scrollRect = tabsScroll.getBoundingClientRect();
                
                if (tabRect.left < scrollRect.left) {
                    tabsScroll.scrollBy({ left: tabRect.left - scrollRect.left - 16, behavior: 'smooth' });
                } else if (tabRect.right > scrollRect.right) {
                    tabsScroll.scrollBy({ left: tabRect.right - scrollRect.right + 16, behavior: 'smooth' });
                }
            }
        }
    });
    
    // Update tab content panels
    $$('.tab-content').forEach(panel => {
        const isActive = panel.id === `tab-${tabId}`;
        panel.classList.toggle('active', isActive);
    });
    
    // Save active tab
    try {
        localStorage.setItem(ACTIVE_TAB_KEY, tabId);
    } catch (e) {}
    
    // Update scroll buttons
    updateTabScrollButtons();
}

// ============================================================================
// Module GUI Tabs (with error isolation)
// ============================================================================

async function createModuleGuiTab(module) {
    const contentArea = $('#content');
    const tabId = `module-gui-${module.id}`;
    
    if (!contentArea) {
        console.warn('Content area not found');
        return;
    }
    
    // Check if tab already exists
    if (state.moduleGuiTabs.has(module.id)) {
        return;
    }
    
    try {
        
        // Create tab content panel
        const guiContent = createElement('div', {
            className: 'module-gui-content',
            id: `gui-content-${module.id}`
        }, [
            createElement('div', { className: 'gui-loading' }, ['Loading module GUI...'])
        ]);
        
        const tabContent = createElement('div', {
            className: 'tab-content',
            id: `tab-${tabId}`
        }, [
            createElement('div', { className: 'module-gui-container' }, [
                createElement('div', { className: 'module-gui-header' }, [
                    createElement('div', { className: 'module-gui-title' }, [
                        createElement('span', { className: 'pill' }, ['MODULE']),
                        ` ${module.id} `,
                        createElement('span', { className: 'pill' }, [module.version])
                    ]),
                    createElement('div', { className: 'module-gui-actions' }, [
                        createElement('button', {
                            className: 'btn btn-soft',
                            title: 'Refresh',
                            onClick: () => safeRefreshModuleGui(module.id)
                        }, ['↻']),
                        createElement('button', {
                            className: 'btn btn-soft',
                            title: 'Open in new window',
                            onClick: () => window.open(module.gui_url, '_blank')
                        }, ['↗'])
                    ])
                ]),
                guiContent
            ])
        ]);
        
        contentArea.appendChild(tabContent);
        state.moduleGuiTabs.set(module.id, { tabContent, guiContent, module });
        
        // Load GUI content safely (won't break the app if it fails)
        await safeLoadModuleGui(module);
        
    } catch (error) {
        console.error(`Failed to create tab for module ${module.id}:`, error);
        // Don't let this break the app
    }
}

function removeModuleGuiTab(moduleId) {
    const tabData = state.moduleGuiTabs.get(moduleId);
    if (!tabData) return;
    
    try {
        // Clean up module-specific resources
        $$(`script[data-module="${moduleId}"]`).forEach(s => s.remove());
        $$(`style[data-module="${moduleId}"]`).forEach(s => s.remove());
        
        if (tabData.tabContent) tabData.tabContent.remove();
    } catch (e) {
        console.warn(`Error cleaning up module ${moduleId}:`, e);
    }
    
    state.moduleGuiTabs.delete(moduleId);
    
    // Remove from tab order
    const tabId = `module-gui-${moduleId}`;
    state.tabOrder = state.tabOrder.filter(id => id !== tabId);
    saveTabOrder();
    
    if (state.activeTab === tabId) {
        switchTab('dashboard');
    }
}

async function safeRefreshModuleGui(moduleId) {
    try {
        const tabData = state.moduleGuiTabs.get(moduleId);
        if (!tabData) return;
        
        tabData.guiContent.innerHTML = '<div class="gui-loading">Reloading...</div>';
        await safeLoadModuleGui(tabData.module);
    } catch (error) {
        console.error(`Failed to refresh module GUI ${moduleId}:`, error);
    }
}

/**
 * Safely load module GUI - errors are contained and won't break the app
 */
async function safeLoadModuleGui(module) {
    const tabData = state.moduleGuiTabs.get(module.id);
    if (!tabData) return;
    
    const container = tabData.guiContent;
    
    try {
        // Fetch the module's GUI HTML
        const response = await fetch(module.gui_url);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const html = await response.text();
        
        // Parse the HTML safely
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        
        // Clear container
        container.innerHTML = '';
        
        // Extract and inject styles (scoped)
        const styles = doc.querySelectorAll('style');
        styles.forEach((style) => {
            try {
                const scopedStyle = document.createElement('style');
                scopedStyle.dataset.module = module.id;
                scopedStyle.textContent = scopeCSS(style.textContent, `#gui-content-${module.id}`);
                document.head.appendChild(scopedStyle);
            } catch (e) {
                console.warn(`Failed to scope style for ${module.id}:`, e);
            }
        });
        
        // Clone body content (excluding scripts)
        Array.from(doc.body.children).forEach(child => {
            if (child.tagName !== 'SCRIPT') {
                container.appendChild(child.cloneNode(true));
            }
        });
        
        // Execute scripts safely
        const scripts = doc.querySelectorAll('script');
        for (const script of scripts) {
            try {
                await executeModuleScript(module, script);
            } catch (e) {
                console.warn(`Script execution error in ${module.id}:`, e);
            }
        }
        
    } catch (error) {
        console.error(`Failed to load GUI for ${module.id}:`, error);
        
        // Show error in container but don't break the app
        container.innerHTML = `
            <div class="gui-error">
                <div class="gui-error-icon">⚠</div>
                <div class="gui-error-title">Failed to Load Module GUI</div>
                <div class="gui-error-message">${escapeHtml(error.message)}</div>
                <button class="btn btn-soft" onclick="window.kiosk.refreshModuleGui('${escapeHtml(module.id)}')">
                    Retry
                </button>
            </div>
        `;
    }
}

/**
 * Scope CSS selectors to a container ID
 */
function scopeCSS(css, scopeSelector) {
    if (!css) return '';
    
    try {
        // Replace :root with scope selector
        css = css.replace(/:root/g, scopeSelector);
        
        // Simple scoping - add scope to each selector
        return css.replace(
            /([^{}@]+)(\{[^{}]*\})/g,
            (match, selector, block) => {
                // Skip @-rules
                if (selector.trim().startsWith('@')) {
                    return match;
                }
                
                const scopedSelectors = selector
                    .split(',')
                    .map(s => {
                        s = s.trim();
                        if (!s) return s;
                        if (s.includes(scopeSelector)) return s;
                        if (s === 'body' || s === 'html') return scopeSelector;
                        if (s.startsWith('body ')) return `${scopeSelector} ${s.slice(5)}`;
                        if (s.startsWith('html ')) return `${scopeSelector} ${s.slice(5)}`;
                        return `${scopeSelector} ${s}`;
                    })
                    .join(', ');
                
                return scopedSelectors + block;
            }
        );
    } catch (e) {
        console.warn('CSS scoping failed:', e);
        return css;
    }
}

/**
 * Execute module script in isolated context
 */
function executeModuleScript(module, scriptEl) {
    return new Promise((resolve) => {
        try {
            const newScript = document.createElement('script');
            newScript.dataset.module = module.id;
            
            if (scriptEl.src) {
                const src = new URL(scriptEl.getAttribute('src'), module.gui_url).href;
                newScript.src = src;
                newScript.onload = resolve;
                newScript.onerror = () => {
                    console.warn(`Failed to load script: ${src}`);
                    resolve();
                };
            } else {
                // Wrap inline script to scope document queries
                const code = scriptEl.textContent;
                newScript.textContent = `
                    (function() {
                        try {
                            const moduleContainer = document.getElementById('gui-content-${module.id}');
                            if (!moduleContainer) return;
                            
                            // Scoped element lookup
                            const getEl = (id) => moduleContainer.querySelector('#' + id) || document.getElementById(id);
                            
                            ${code}
                        } catch (e) {
                            console.error('Module script error (${module.id}):', e);
                        }
                    })();
                `;
                setTimeout(resolve, 0);
            }
            
            document.body.appendChild(newScript);
        } catch (e) {
            console.warn('Script execution setup failed:', e);
            resolve();
        }
    });
}

async function updateModuleGuiTabs(modules) {
    try {
        // Filter out LLM modules - they use the popup pill instead of tabs
        const guiModules = modules.filter(m => m.loaded && m.has_gui && m.gui_url && m.module_type !== 'llm');
        const currentIds = new Set(guiModules.map(m => m.id));
        
        // Remove stale tabs
        for (const moduleId of state.moduleGuiTabs.keys()) {
            if (!currentIds.has(moduleId)) {
                removeModuleGuiTab(moduleId);
            }
        }
        
        // Add new tabs
        for (const module of guiModules) {
            if (!state.moduleGuiTabs.has(module.id)) {
                await createModuleGuiTab(module);
            }
        }
        
        // Re-render tabs to include new module GUI tabs
        renderTabs();
    } catch (error) {
        console.error('Failed to update module GUI tabs:', error);
        // Don't break the app
    }
}

// ============================================================================
// Status Dropdown
// ============================================================================

function initStatusDropdown() {
    const dropdown = $('#status-dropdown');
    const trigger = $('#status-trigger');
    
    if (!trigger || !dropdown) return;
    
    trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        
        // Position dropdown below header
        const rect = trigger.getBoundingClientRect();
        dropdown.style.top = (rect.bottom + 8) + 'px';
        
        dropdown.classList.toggle('open');
    });
    
    document.addEventListener('click', () => {
        dropdown.classList.remove('open');
    });
}

function updateStatus() {
    const loaded = state.modules.filter(m => m.loaded).length;
    const total = state.modules.length;
    
    const indicator = $('#status-indicator');
    const moduleCount = $('#module-count');
    const modulesLoaded = $('#modules-loaded');
    const statusText = $('#status-text');
    
    // Status indicator reflects connection status
    if (indicator) {
        if (state.connection.status === 'connected') {
            indicator.className = 'status-dot ok';
        } else if (state.connection.status === 'disconnected') {
            indicator.className = 'status-dot bad';
        } else {
            indicator.className = 'status-dot pending';
        }
    }
    
    if (moduleCount) {
        moduleCount.textContent = `${loaded} module${loaded !== 1 ? 's' : ''}`;
    }
    
    if (modulesLoaded) {
        modulesLoaded.textContent = `${loaded}/${total}`;
    }
    
    if (statusText) {
        if (state.connection.status === 'connected') {
            statusText.textContent = 'Healthy';
        } else if (state.connection.status === 'disconnected') {
            statusText.textContent = 'Disconnected';
        } else {
            statusText.textContent = 'Checking...';
        }
    }
    
    // Update connection info in popup
    updateConnectionDisplay();
    
    // Update module chips in popup
    renderPopupModulesChips();
    
    // Fetch and display dynamic module status panels
    fetchModuleStatusPanels().catch(e => console.warn('Failed to fetch module status panels:', e));
}

function updateConnectionDisplay() {
    const statusEl = $('#connection-status');
    const endpointEl = $('#connection-endpoint');
    const latencyEl = $('#connection-latency');
    const lastCheckEl = $('#connection-last-check');
    
    if (statusEl) {
        if (state.connection.status === 'connected') {
            statusEl.innerHTML = '<span class="dot ok" style="margin-right:6px"></span>Connected';
        } else if (state.connection.status === 'disconnected') {
            statusEl.innerHTML = '<span class="dot bad" style="margin-right:6px"></span>Disconnected';
        } else {
            statusEl.innerHTML = '<span class="dot pending" style="margin-right:6px"></span>Checking...';
        }
    }
    
    if (endpointEl) {
        endpointEl.textContent = state.connection.endpoint || window.location.origin;
    }
    
    if (latencyEl) {
        if (state.connection.lastLatency !== null) {
            latencyEl.textContent = `${state.connection.lastLatency}ms`;
        } else {
            latencyEl.textContent = '—';
        }
    }
    
    if (lastCheckEl) {
        if (state.connection.lastCheck) {
            lastCheckEl.textContent = new Date(state.connection.lastCheck).toLocaleTimeString();
        } else {
            lastCheckEl.textContent = '—';
        }
    }
}

async function checkConnection() {
    const startTime = performance.now();
    
    try {
        const response = await fetch(`${API_BASE}/api/modules`, {
            method: 'GET',
            cache: 'no-store'
        });
        
        const latency = Math.round(performance.now() - startTime);
        
        if (response.ok) {
            state.connection.status = 'connected';
            state.connection.lastLatency = latency;
            state.connection.consecutiveFailures = 0;
        } else {
            state.connection.consecutiveFailures++;
            if (state.connection.consecutiveFailures >= 2) {
                state.connection.status = 'disconnected';
            }
        }
    } catch (error) {
        state.connection.consecutiveFailures++;
        if (state.connection.consecutiveFailures >= 2) {
            state.connection.status = 'disconnected';
            state.connection.lastLatency = null;
        }
    }
    
    state.connection.lastCheck = Date.now();
    updateStatus();
}

function renderPopupModulesChips() {
    const container = $('#popup-modules-chips');
    if (!container) return;
    
    if (state.modules.length === 0) {
        container.innerHTML = '<span class="chip"><span class="dot pending"></span>No modules</span>';
        return;
    }
    
    container.innerHTML = state.modules.map(m => {
        const isActive = m.loaded && m.enabled !== false;
        const dotClass = isActive ? 'ok' : 'bad';
        const chipClass = isActive ? 'chip-ok' : '';
        const statusText = isActive ? 'Active' : 'Inactive';
        return `<span class="chip ${chipClass}"><span class="dot ${dotClass}"></span>${escapeHtml(m.id)} <span style="opacity:0.7">${statusText}</span></span>`;
    }).join('');
}

/**
 * Fetch status panels from all active modules and render them dynamically
 */
async function fetchModuleStatusPanels() {
    const container = $('#dynamic-module-panels');
    if (!container) return;
    
    // Refresh context to get latest Web3Signer status
    await loadContext();
    
    // Find all active modules that might have status panels
    const activeModules = state.modules.filter(m => 
        m.loaded && m.enabled !== false
    );
    
    if (activeModules.length === 0) {
        container.innerHTML = '';
        state.moduleStatusPanels.clear();
        return;
    }
    
    // Fetch status panels for each active module
    const panelPromises = activeModules.map(async (module) => {
        try {
            const response = await fetch(`${API_BASE}/api/modules/${encodeURIComponent(module.id)}/status-panel`);
            
            if (!response.ok) {
                // Module doesn't have status panel - check if it has capabilities worth showing
                if (module.capabilities && 
                    (module.capabilities.includes('bls_sign') || 
                     module.capabilities.includes('tls_sign') ||
                     module.capabilities.includes('key_gen'))) {
                    // Return a basic panel for signer modules
                    return {
                        moduleId: module.id,
                        module: module,
                        panel: createBasicSignerPanel(module),
                        isBasic: true
                    };
                }
                return null;
            }
            
            const panel = await response.json();
            return {
                moduleId: module.id,
                module: module,
                panel: panel,
                isBasic: false
            };
        } catch (error) {
            console.warn(`Failed to fetch status panel for ${module.id}:`, error);
            // For signer modules, show basic info on error
            if (module.capabilities && 
                (module.capabilities.includes('bls_sign') || module.capabilities.includes('tls_sign'))) {
                return {
                    moduleId: module.id,
                    module: module,
                    panel: createBasicSignerPanel(module),
                    isBasic: true
                };
            }
            return null;
        }
    });
    
    const results = await Promise.all(panelPromises);
    const validPanels = results.filter(r => r !== null);
    
    // Update state
    state.moduleStatusPanels.clear();
    for (const result of validPanels) {
        state.moduleStatusPanels.set(result.moduleId, result);
    }
    
    // Render all panels
    renderModuleStatusPanels(validPanels);
}

/**
 * Create a basic status panel for signer modules that don't implement the full API
 */
function createBasicSignerPanel(module) {
    const hasBls = module.capabilities?.includes('bls_sign');
    const hasTls = module.capabilities?.includes('tls_sign');
    const hasKeyGen = module.capabilities?.includes('key_gen');
    
    // Get Web3Signer status from context
    const web3signerConnected = state.context?.health?.web3signer ?? null;
    
    const sections = [
        {
            heading: 'Capabilities',
            items: [
                { type: 'status_indicator', status: hasBls ? 'ok' : 'pending', message: `BLS Signing: ${hasBls ? 'Available' : 'Not available'}` },
                { type: 'status_indicator', status: hasTls ? 'ok' : 'pending', message: `TLS Signing: ${hasTls ? 'Available' : 'Not available'}` }
            ].filter(item => item.status === 'ok' || module.capabilities?.length <= 3)
        },
        {
            heading: 'Status',
            items: [
                { type: 'key_value', key: 'Module Version', value: module.version },
                { 
                    type: 'status_indicator', 
                    status: web3signerConnected === true ? 'ok' : web3signerConnected === false ? 'error' : 'pending', 
                    message: `Web3Signer: ${web3signerConnected === true ? 'Connected' : web3signerConnected === false ? 'Disconnected' : 'Unknown'}`
                }
            ]
        }
    ];
    
    return {
        module_id: module.id,
        module_version: module.version,
        title: module.id.replace(/_/g, ' ').replace(/v\d+$/, '').trim(),
        sections: sections
    };
}

/**
 * Render all module status panels into the dynamic container
 */
function renderModuleStatusPanels(panels) {
    const container = $('#dynamic-module-panels');
    if (!container) return;
    
    if (panels.length === 0) {
        container.innerHTML = '';
        return;
    }
    
    container.innerHTML = panels.map(({ moduleId, module, panel, isBasic }) => {
        const title = panel.title || moduleId;
        const sections = panel.sections || [];
        
        return `
            <div class="status-section module-status-panel" data-module-id="${escapeHtml(moduleId)}">
                <div class="status-section-title">
                    ${escapeHtml(title)}
                    <span class="pill" style="margin-left: 8px; font-size: 0.65rem;">${escapeHtml(module.version)}</span>
                    ${isBasic ? '<span class="pill" style="margin-left: 4px; font-size: 0.65rem; opacity: 0.7;">Basic</span>' : ''}
                </div>
                <div class="panel status-module-panel">
                    ${sections.map(section => renderStatusSection(section)).join('')}
                </div>
            </div>
        `;
    }).join('');
}

/**
 * Render a single section of a module status panel
 */
function renderStatusSection(section) {
    if (!section || !section.items || section.items.length === 0) return '';
    
    return `
        <div class="module-panel-section">
            <div class="module-panel-heading">${escapeHtml(section.heading || '')}</div>
            <div class="attestation-grid">
                ${section.items.map(item => renderStatusItem(item)).join('')}
            </div>
        </div>
    `;
}

/**
 * Render a single status item based on its type
 */
function renderStatusItem(item) {
    if (!item) return '';
    
    switch (item.type) {
        case 'key_value':
            return `
                <div class="attestation-row">
                    <span class="attestation-label">${escapeHtml(item.key || '')}</span>
                    <span class="attestation-value">${escapeHtml(item.value || '—')}</span>
                </div>
            `;
        
        case 'public_key':
            const truncatedKey = truncatePublicKey(item.public_key);
            const keyTypeClass = item.key_type === 'BLS' ? 'key-bls' : 'key-tls';
            return `
                <div class="attestation-row">
                    <span class="attestation-label">
                        <span class="key-type-badge ${keyTypeClass}">${escapeHtml(item.key_type || 'KEY')}</span>
                        ${item.label ? escapeHtml(item.label) : 'Public Key'}
                    </span>
                    <span class="attestation-value key-value" title="${escapeHtml(item.public_key || '')}">
                        <span class="dot ok" style="margin-right:6px"></span>
                        <code>${escapeHtml(truncatedKey)}</code>
                    </span>
                </div>
            `;
        
        case 'status_indicator':
            const statusDot = item.status === 'ok' ? 'ok' : item.status === 'warning' ? 'pending' : item.status === 'error' ? 'bad' : 'pending';
            return `
                <div class="attestation-row">
                    <span class="attestation-label">${escapeHtml(item.message || 'Status')}</span>
                    <span class="attestation-value">
                        <span class="dot ${statusDot}" style="margin-right:6px"></span>
                        ${item.status === 'ok' ? 'OK' : item.status === 'warning' ? 'Warning' : item.status === 'error' ? 'Error' : 'Pending'}
                    </span>
                </div>
            `;
        
        default:
            // Unknown type - try to render as key/value
            if (item.key && item.value) {
                return `
                    <div class="attestation-row">
                        <span class="attestation-label">${escapeHtml(item.key)}</span>
                        <span class="attestation-value">${escapeHtml(item.value)}</span>
                    </div>
                `;
            }
            return '';
    }
}

/**
 * Truncate a public key for display
 */
function truncatePublicKey(key) {
    if (!key) return 'Not registered';
    if (key.length <= 20) return key;
    return key.slice(0, 10) + '...' + key.slice(-6);
}

function updatePopupAttestation() {
    if (!state.attestation) return;
    
    const data = state.attestation;
    
    const setPopup = (id, val) => {
        const el = $(`#${id}`);
        if (el) el.textContent = val || 'N/A';
    };
    
    // Use same format as attestation tab (full values)
    setPopup('popup-core-hash', data.core_binary_hash || data.coreBinaryHash);
    setPopup('popup-manifest-hash', data.manifest_hash || data.manifestHash);
    setPopup('popup-runtime-version', data.cryfttee_version || data.cryftteeVersion);
    setPopup('popup-attestation-time', data.timestamp ? new Date(data.timestamp).toLocaleString() : null);
}

// ============================================================================
// Popup Module System (replaces hardcoded chat)
// ============================================================================

function initPopupModules() {
    const pill = $('#popup-pill');
    const overlay = $('#popup-overlay');
    const backdrop = $('#popup-backdrop');
    const closeBtn = $('#popup-close');
    const content = $('#popup-content');
    const title = $('#popup-title');
    
    if (!pill || !overlay) return;
    
    // Update pill button based on active LLM module
    updatePopupPill();
    
    pill.addEventListener('click', () => {
        // Only open if there's an active LLM module
        if (!state.activeLlmModule) {
            toast('No LLM module enabled. Enable an LLM module in the Modules tab.', 'warn');
            return;
        }
        
        openLlmPopup();
    });
    
    if (closeBtn) closeBtn.addEventListener('click', closePopup);
    if (backdrop) backdrop.addEventListener('click', closePopup);
    
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && state.popupOpen) closePopup();
    });
}

function updatePopupPill() {
    const pill = $('#popup-pill');
    if (!pill) return;
    
    // Get all LLM modules
    state.llmModules = state.modules.filter(m => 
        m.module_type === 'llm' && m.has_gui && m.gui_url
    );
    
    // Find active (enabled) LLM module - only one can be active
    const activeLlm = state.llmModules.find(m => m.enabled);
    state.activeLlmModule = activeLlm ? activeLlm.id : null;
    
    if (!state.activeLlmModule) {
        pill.textContent = 'No LLM';
        pill.classList.add('disabled');
    } else {
        // Show the active LLM module name
        const displayName = state.activeLlmModule
            .replace(/_/g, ' ')
            .replace(/v\d+$/, '')
            .trim();
        pill.textContent = displayName || 'LLM Chat';
        pill.classList.remove('disabled');
    }
}

async function openLlmPopup() {
    if (!state.activeLlmModule) {
        toast('No LLM module enabled', 'warn');
        return;
    }
    
    const module = state.modules.find(m => m.id === state.activeLlmModule);
    if (!module || !module.gui_url) {
        toast('LLM module not found or has no GUI', 'bad');
        return;
    }
    
    const overlay = $('#popup-overlay');
    const backdrop = $('#popup-backdrop');
    const content = $('#popup-content');
    const title = $('#popup-title');
    
    if (!overlay || !content) return;
    
    // Update title
    title.textContent = module.id.replace(/_/g, ' ').replace(/v\d+$/, '').trim();
    
    // Show loading
    content.innerHTML = '<div class="popup-loading">Loading module...</div>';
    
    state.popupOpen = true;
    state.activePopupModule = module.id;
    document.body.classList.add('popup-open');
    overlay.classList.add('open');
    backdrop.classList.add('open');
    
    // Load the module GUI
    try {
        const response = await fetch(module.gui_url);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const html = await response.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        
        // Clear content
        content.innerHTML = '';
        
        // Extract and inject styles (scoped to popup)
        const styles = doc.querySelectorAll('style');
        styles.forEach(style => {
            const scopedStyle = document.createElement('style');
            scopedStyle.setAttribute('data-module', module.id);
            scopedStyle.textContent = style.textContent;
            content.appendChild(scopedStyle);
        });
        
        // Extract body content
        const bodyContent = doc.body.innerHTML;
        const wrapper = document.createElement('div');
        wrapper.className = 'popup-module-content';
        wrapper.innerHTML = bodyContent;
        content.appendChild(wrapper);
        
        // Extract and inject scripts
        const scripts = doc.querySelectorAll('script');
        for (const script of scripts) {
            const newScript = document.createElement('script');
            newScript.setAttribute('data-module', module.id);
            if (script.src) {
                newScript.src = script.src;
            } else {
                newScript.textContent = script.textContent;
            }
            content.appendChild(newScript);
        }
    } catch (error) {
        console.error(`Failed to load LLM module GUI:`, error);
        content.innerHTML = `<div class="popup-error">Failed to load module: ${error.message}</div>`;
    }
}

function showPopupSelector() {
    const overlay = $('#popup-overlay');
    const backdrop = $('#popup-backdrop');
    const content = $('#popup-content');
    const title = $('#popup-title');
    
    if (!overlay || !content) return;
    
    title.textContent = 'Select Module';
    content.innerHTML = `
        <div class="popup-selector">
            ${state.popupModules.map(m => `
                <button class="popup-module-btn" onclick="window.kiosk.openPopupModule('${escapeHtml(m.id)}')">
                    <div class="popup-module-name">${escapeHtml(m.id)}</div>
                    <div class="popup-module-desc">${escapeHtml(m.description || '')}</div>
                </button>
            `).join('')}
        </div>
    `;
    
    state.popupOpen = true;
    state.activePopupModule = null;
    document.body.classList.add('popup-open');
    overlay.classList.add('open');
    backdrop.classList.add('open');
}

async function openPopupModule(moduleId) {
    const module = state.popupModules.find(m => m.id === moduleId);
    if (!module) {
        toast('Module not found', 'bad');
        return;
    }
    
    const overlay = $('#popup-overlay');
    const backdrop = $('#popup-backdrop');
    const content = $('#popup-content');
    const title = $('#popup-title');
    
    if (!overlay || !content) return;
    
    // Update title
    title.textContent = module.id.replace(/_/g, ' ').replace(/v\d+$/, '').trim();
    
    // Show loading
    content.innerHTML = '<div class="popup-loading">Loading module...</div>';
    
    state.popupOpen = true;
    state.activePopupModule = moduleId;
    document.body.classList.add('popup-open');
    overlay.classList.add('open');
    backdrop.classList.add('open');
    
    // Load the module GUI
    try {
        const response = await fetch(module.gui_url);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const html = await response.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        
        // Clear content
        content.innerHTML = '';
        
        // Extract and inject styles (scoped to popup)
        const styles = doc.querySelectorAll('style');
        styles.forEach(style => {
            const scopedStyle = document.createElement('style');
            scopedStyle.dataset.popupModule = moduleId;
            scopedStyle.textContent = scopeCSS(style.textContent, '#popup-content');
            document.head.appendChild(scopedStyle);
        });
        
        // Clone body content
        Array.from(doc.body.children).forEach(child => {
            if (child.tagName !== 'SCRIPT') {
                content.appendChild(child.cloneNode(true));
            }
        });
        
        // Execute scripts
        const scripts = doc.querySelectorAll('script');
        for (const script of scripts) {
            await executePopupScript(moduleId, script, module.gui_url);
        }
        
    } catch (error) {
        console.error(`Failed to load popup module ${moduleId}:`, error);
        content.innerHTML = `
            <div class="popup-error">
                <div class="popup-error-icon">⚠</div>
                <div class="popup-error-title">Failed to Load Module</div>
                <div class="popup-error-message">${escapeHtml(error.message)}</div>
                <button class="btn btn-soft" onclick="window.kiosk.openPopupModule('${escapeHtml(moduleId)}')">Retry</button>
            </div>
        `;
    }
}

function executeLlmScript(moduleId, scriptEl, baseUrl) {
    return new Promise((resolve) => {
        try {
            const newScript = document.createElement('script');
            newScript.dataset.llmModule = moduleId;
            
            if (scriptEl.src) {
                const src = new URL(scriptEl.getAttribute('src'), baseUrl).href;
                newScript.src = src;
                newScript.onload = resolve;
                newScript.onerror = () => resolve();
            } else {
                newScript.textContent = scriptEl.textContent;
                setTimeout(resolve, 0);
            }
            
            document.body.appendChild(newScript);
        } catch (e) {
            console.warn('LLM script error:', e);
            resolve();
        }
    });
}

function closePopup() {
    const overlay = $('#popup-overlay');
    const backdrop = $('#popup-backdrop');
    const content = $('#popup-content');
    
    state.popupOpen = false;
    document.body.classList.remove('popup-open');
    
    if (overlay) overlay.classList.remove('open');
    if (backdrop) backdrop.classList.remove('open');
    
    // Clean up LLM module styles/scripts
    if (state.activeLlmModule) {
        $$(`style[data-llm-module="${state.activeLlmModule}"]`).forEach(s => s.remove());
        $$(`script[data-llm-module="${state.activeLlmModule}"]`).forEach(s => s.remove());
    }
    
    if (content) content.innerHTML = '';
}

// ============================================================================
// API
// ============================================================================

async function fetchJson(url) {
    const response = await fetch(`${API_BASE}${url}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
}

async function loadModules() {
    try {
        const data = await fetchJson('/api/modules');
        
        state.modules = data.modules || [];
        
        const versionEl = $('#version');
        if (versionEl) versionEl.textContent = `v${data.cryftteeVersion || data.cryfttee_version || '0.4.0'}`;
        
        const badgeEl = $('#modules-badge');
        if (badgeEl) badgeEl.textContent = state.modules.length;
        
        renderDashboardModules(data);
        renderModulesGrid(data);
        updateStatus();
        
        // Update popup pill with available popup modules
        updatePopupPill();
        
        // Update GUI tabs safely - don't await, let it run async
        updateModuleGuiTabs(state.modules).catch(e => {
            console.warn('Module GUI tabs update failed:', e);
        });
        
    } catch (error) {
        console.error('Failed to load modules:', error);
        toast('Failed to load modules', 'bad');
    }
}

async function loadAttestation() {
    try {
        const data = await fetchJson('/api/attestation');
        if (!data.error) {
            state.attestation = data;
            renderAttestation(data);
            updatePopupAttestation();
        }
    } catch (error) {
        console.error('Failed to load attestation:', error);
    }
}

async function loadSchema() {
    try {
        state.schema = await fetchJson('/api/schema');
        const el = $('#schema-content');
        if (el) el.textContent = JSON.stringify(state.schema, null, 2);
    } catch (error) {
        console.error('Failed to load schema:', error);
        const el = $('#schema-content');
        if (el) el.textContent = 'Failed to load schema';
    }
}

async function loadManifest() {
    try {
        state.manifest = await fetchJson('/api/manifest');
        const el = $('#manifest-content');
        if (el) el.textContent = JSON.stringify(state.manifest, null, 2);
    } catch (error) {
        console.error('Failed to load manifest:', error);
        const el = $('#manifest-content');
        if (el) el.textContent = 'Failed to load manifest';
    }
}

async function loadContext() {
    try {
        state.context = await fetchJson('/api/context');
    } catch (error) {
        console.error('Failed to load context:', error);
        state.context = null;
    }
}

async function reloadModules() {
    const btn = $('#reload-btn');
    if (btn) {
        btn.disabled = true;
        btn.textContent = '↻ Loading...';
    }
    
    try {
        const response = await fetch(`${API_BASE}/api/reload`, { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            state.modules = data.modules || [];
            renderDashboardModules(data);
            renderModulesGrid(data);
            updateStatus();
            await updateModuleGuiTabs(state.modules);
            await loadAttestation();
            updatePopupAttestation();
            toast('Modules reloaded', 'ok');
        } else {
            toast(data.error || 'Reload failed', 'bad');
        }
    } catch (error) {
        console.error('Failed to reload modules:', error);
        toast('Failed to reload modules', 'bad');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.textContent = '↻ Reload';
        }
    }
}

// ============================================================================
// Rendering
// ============================================================================

function renderDashboardModules(data) {
    const container = $('#dashboard-modules');
    const emptyState = $('#dashboard-empty');
    
    if (!container) return;
    
    const activeModules = state.modules.filter(m => m.loaded);
    
    if (activeModules.length === 0) {
        container.innerHTML = '';
        if (emptyState) emptyState.classList.remove('hidden');
        return;
    }
    
    if (emptyState) emptyState.classList.add('hidden');
    container.innerHTML = activeModules.map(m => renderModuleCard(m, data.defaults, false)).join('');
}

function renderModulesGrid(data) {
    const container = $('#modules-grid');
    if (!container) return;
    
    if (state.modules.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">⬡</div>
                <div class="empty-title">No Modules Found</div>
                <div class="empty-description">No modules defined in the manifest.</div>
            </div>
        `;
        return;
    }
    
    container.innerHTML = state.modules.map(m => renderModuleCard(m, data.defaults, true)).join('');
}

function renderModuleCard(module, defaults, showToggle = false) {
    const isDefaultBls = defaults?.bls === module.id;
    const isDefaultTls = defaults?.tls === module.id;
    const isLoaded = module.loaded;
    const isTrusted = module.trusted;
    const isCompatible = module.compatible;
    const isEnabled = module.enabled !== false; // Default to enabled if not specified
    const hasGui = module.has_gui && module.gui_url;
    const isLlmModule = module.module_type === 'llm';
    
    let cardClass = 'module-card';
    if (!isEnabled) cardClass += ' disabled';
    else if (isLoaded) cardClass += ' active';
    else if (!isCompatible) cardClass += ' incompatible';
    else cardClass += ' inactive';
    
    // Can toggle if compatible (even if currently has load error)
    const canToggle = showToggle && (isCompatible || isLoaded || module.reason);
    
    // Determine the single module status chip
    let statusChip = '';
    if (!isEnabled) {
        statusChip = '<span class="chip chip-bad"><span class="dot bad"></span>Disabled</span>';
    } else if (!isCompatible) {
        statusChip = '<span class="chip chip-bad"><span class="dot bad"></span>Incompatible</span>';
    } else if (isLoaded) {
        statusChip = '<span class="chip chip-ok"><span class="dot ok"></span>Loaded</span>';
    } else {
        statusChip = '<span class="chip"><span class="dot pending"></span>Available</span>';
    }
    
    return `
        <div class="${cardClass}" data-module-id="${escapeHtml(module.id)}">
            <div class="module-header">
                <div class="module-header-left">
                    <span class="module-name">${escapeHtml(module.id)}</span>
                    <span class="module-version">${escapeHtml(module.version)}</span>
                </div>
                ${canToggle ? `
                <label class="toggle" title="${isEnabled ? 'Disable' : 'Enable'} module">
                    <input type="checkbox" 
                           ${isEnabled ? 'checked' : ''} 
                           onchange="window.kiosk.toggleModule('${escapeHtml(module.id)}', this.checked)"
                           ${module._toggling ? 'disabled' : ''}>
                    <span class="toggle-slider"></span>
                </label>
                ` : ''}
            </div>
            
            <div class="chips chips-inside">
                ${statusChip}
                ${isDefaultBls ? '<span class="chip chip-ok"><span class="dot ok"></span>Default BLS</span>' : ''}
                ${isDefaultTls ? '<span class="chip chip-ok"><span class="dot ok"></span>Default TLS</span>' : ''}
                ${isTrusted ? '<span class="chip chip-ok"><span class="dot ok"></span>Trusted</span>' : '<span class="chip chip-bad"><span class="dot bad"></span>Untrusted</span>'}
                ${isLlmModule ? '<span class="chip chip-accent"><span class="dot accent"></span>LLM Module</span>' : hasGui ? '<span class="chip chip-pending"><span class="dot pending"></span>Has GUI</span>' : ''}
            </div>

            <p class="module-description">${escapeHtml(module.description || 'No description')}</p>

            <div class="module-meta">
                <div class="meta-item">
                    <span class="meta-label">Min Version</span>
                    <span class="meta-value">${escapeHtml(module.min_cryfttee_version || module.minCryftteeVersion || 'N/A')}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Publisher</span>
                    <span class="meta-value">${escapeHtml(module.publisher_id || module.publisherId || 'Unknown')}</span>
                </div>
            </div>

            <div class="capabilities">
                ${(module.capabilities || []).map(cap => `<span class="capability">${escapeHtml(cap)}</span>`).join('')}
            </div>

            ${module.reason ? `<div class="module-reason">⚠ ${escapeHtml(module.reason)}</div>` : ''}
            
            ${hasGui && isLoaded && isEnabled ? `
                <div class="module-actions">
                    ${module.module_type === 'llm' ? `
                        <button class="btn btn-soft" onclick="window.kiosk.openLlmPopup()">
                            Open Chat
                        </button>
                    ` : `
                        <button class="btn btn-soft" onclick="window.kiosk.openModuleGui('${escapeHtml(module.id)}')">
                            Open GUI
                        </button>
                    `}
                </div>
            ` : ''}
        </div>
    `;
}

function renderAttestation(data) {
    const set = (id, val) => {
        const el = $(`#${id}`);
        if (el) el.textContent = val || 'N/A';
    };
    
    set('core-hash', data.core_binary_hash || data.coreBinaryHash);
    set('manifest-hash', data.manifest_hash || data.manifestHash);
    set('attestation-time', data.timestamp ? new Date(data.timestamp).toLocaleString() : null);
    set('runtime-version', data.cryfttee_version || data.cryftteeVersion);
}

// ============================================================================
// Public API
// ============================================================================

class CryftteeKiosk {
    constructor() {
        this.init();
    }
    
    async init() {
        try {
            initTabs();
            initStatusDropdown();
            initPopupModules();
            
            const reloadBtn = $('#reload-btn');
            if (reloadBtn) {
                reloadBtn.addEventListener('click', () => reloadModules());
            }
            
            // Initial connection check
            await checkConnection();
            
            // Load data - don't let failures break the app
            await Promise.allSettled([
                loadContext(),
                loadModules(),
                loadAttestation(),
                loadSchema(),
                loadManifest()
            ]);
            
            // Periodic refresh (modules + connection check + context)
            setInterval(() => {
                loadContext().catch(console.error);
                loadModules().catch(console.error);
                checkConnection().catch(console.error);
            }, 30000);
            
            // More frequent connection check
            setInterval(() => {
                checkConnection().catch(console.error);
            }, 10000);
            
        } catch (error) {
            console.error('App initialization error:', error);
        }
    }
    
    openModuleGui(moduleId) {
        const tabId = `module-gui-${moduleId}`;
        if (state.moduleGuiTabs.has(moduleId)) {
            switchTab(tabId);
        }
    }
    
    refreshModuleGui(moduleId) {
        safeRefreshModuleGui(moduleId);
    }
    
    async toggleModule(moduleId, enabled) {
        try {
            // Find and mark the module as toggling
            const module = state.modules.find(m => m.id === moduleId);
            if (module) {
                module._toggling = true;
            }
            
            // If enabling an LLM module, disable any other active LLM module first
            if (enabled && module && module.module_type === 'llm') {
                const otherLlm = state.modules.find(m => 
                    m.module_type === 'llm' && m.enabled && m.id !== moduleId
                );
                if (otherLlm) {
                    // Disable the other LLM module first
                    await fetch(`${API_BASE}/api/modules/${encodeURIComponent(otherLlm.id)}/disable`, {
                        method: 'POST'
                    });
                }
            }
            
            const response = await fetch(`${API_BASE}/api/modules/${encodeURIComponent(moduleId)}/${enabled ? 'enable' : 'disable'}`, {
                method: 'POST'
            });
            
            const data = await response.json();
            
            if (data.success) {
                toast(`Module ${moduleId} ${enabled ? 'enabled' : 'disabled'}`, 'ok');
                
                // Update state and re-render
                state.modules = data.modules || state.modules;
                renderDashboardModules({ modules: state.modules, defaults: data.defaults });
                renderModulesGrid({ modules: state.modules, defaults: data.defaults });
                updateStatus();
                updatePopupPill();
                
                // Update GUI tabs
                await updateModuleGuiTabs(state.modules);
            } else {
                toast(data.error || `Failed to ${enabled ? 'enable' : 'disable'} module`, 'bad');
                // Reload to get correct state
                await loadModules();
            }
        } catch (error) {
            console.error('Failed to toggle module:', error);
            toast(`Failed to ${enabled ? 'enable' : 'disable'} module`, 'bad');
            // Reload to get correct state
            await loadModules();
        } finally {
            const module = state.modules.find(m => m.id === moduleId);
            if (module) {
                module._toggling = false;
            }
        }
    }
    
    getState() {
        return { ...state };
    }
    
    openLlmPopup() {
        openLlmPopup();
    }
    
    closePopup() {
        closePopup();
    }
    
    toast(message, type, duration) {
        toast(message, type, duration);
    }
}

// ============================================================================
// Init
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    window.kiosk = new CryftteeKiosk();
});
