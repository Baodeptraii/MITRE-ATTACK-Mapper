// ============================================================
// SCENARIOS MODULE (Kịch Bản) — scenarios.js
// ============================================================
const ScenariosManager = (() => {
    const ART_API = 'https://api.github.com/repos/Baodeptraii/AttackTrafficGenerator/contents/ART_YAML_Scenarios';
    const CALDERA_API = 'https://api.github.com/repos/Baodeptraii/AttackTrafficGenerator/contents/CALDERA_YAML_Scenarios';
    const CACHE_KEY = 'scenario_list_cache';
    const CACHE_TTL = 600000; // 10 minutes
    const TCODE_RE = /T\d{4}(?:\.\d{3})?/g;

    let scenarioList = [];
    let customScenarios = [];
    let currentFilter = 'all';
    let isVisible = false;

    // ── Cache Manager ──────────────────────────────────────
    const cache = {
        get() {
            try {
                const raw = localStorage.getItem(CACHE_KEY);
                if (!raw) return null;
                const c = JSON.parse(raw);
                if (Date.now() - c.timestamp < (c.ttl_ms || CACHE_TTL)) return c.data;
            } catch (_) {}
            return null;
        },
        set(data) {
            try {
                localStorage.setItem(CACHE_KEY, JSON.stringify({
                    timestamp: Date.now(), ttl_ms: CACHE_TTL, data
                }));
            } catch (_) {}
        },
        bust() { localStorage.removeItem(CACHE_KEY); }
    };

    // ── Toast ──────────────────────────────────────────────
    function toast(msg, type = 'success') {
        let container = document.getElementById('toastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toastContainer';
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        const icons = { success: 'fa-circle-check', error: 'fa-circle-xmark', warning: 'fa-triangle-exclamation' };
        const colors = { success: 'var(--green)', error: 'var(--red)', warning: 'var(--amber)' };
        const el = document.createElement('div');
        el.className = `toast ${type}`;
        el.innerHTML = `<i class="fa-solid ${icons[type]||icons.success}" style="color:${colors[type]}"></i><span class="toast-msg">${msg}</span>`;
        container.appendChild(el);
        setTimeout(() => { el.classList.add('hiding'); setTimeout(() => el.remove(), 300); }, 4000);
    }

    // ── Escaping ───────────────────────────────────────────
    function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

    // ── GitHub Fetch ───────────────────────────────────────
    async function fetchFileList(apiUrl, source) {
        const resp = await fetch(apiUrl, { headers: { 'Accept': 'application/vnd.github.v3+json' } });
        if (resp.status === 403) {
            const reset = resp.headers.get('X-RateLimit-Reset');
            const mins = reset ? Math.ceil((parseInt(reset)*1000 - Date.now()) / 60000) : '?';
            throw new Error(`GitHub API rate limit, thử lại sau ${mins} phút`);
        }
        if (!resp.ok) throw new Error(`GitHub API error: ${resp.status}`);
        const files = await resp.json();
        return files.filter(f =>
            f.type === 'file' &&
            /\.(ya?ml)$/i.test(f.name) &&
            f.size >= 50
        ).map(f => ({
            name: f.name.replace(/\.(ya?ml)$/i, ''),
            filename: f.name,
            source,
            raw_url: f.download_url,
            size: f.size,
            validated: false,
            metadata: null
        }));
    }

    // ── YAML Validation ────────────────────────────────────
    function validateYAML(text, source) {
        if (!text || text.length < 50) return null;
        let parsed;
        try { parsed = jsyaml.load(text); } catch (e) { console.warn('[Scenarios] YAML parse error:', e.message); return null; }
        if (!parsed || typeof parsed !== 'object') return null;
        const isART = parsed.attack_technique && parsed.atomic_tests;
        const isCALDERA = (parsed.id && parsed.name && parsed.steps) || (parsed.name && parsed.technique && parsed.tactic);
        if (!isART && !isCALDERA) return null;
        return parsed;
    }

    // ── Metadata Extraction ────────────────────────────────
    function extractMetadata(parsed, source, filename) {
        const tcodes = new Set();
        let name = filename;
        let description = '';
        let platform = '';
        let tactics = [];
        let behaviors = [];

        if (parsed.attack_technique) {
            const at = String(parsed.attack_technique);
            const m = at.match(TCODE_RE);
            if (m) m.forEach(t => tcodes.add(t));
        }
        if (parsed.display_name) name = parsed.display_name;
        else if (parsed.name) name = parsed.name;

        if (parsed.atomic_tests && Array.isArray(parsed.atomic_tests)) {
            parsed.atomic_tests.forEach(t => {
                if (t.name) {
                    const m2 = t.name.match(TCODE_RE);
                    if (m2) m2.forEach(tc => tcodes.add(tc));
                    behaviors.push(t.name);
                }
                if (t.description && !description) description = String(t.description).substring(0, 200);
                if (t.supported_platforms) platform = t.supported_platforms.join(', ');
            });
        }

        if (parsed.technique) {
            const m3 = String(parsed.technique).match(TCODE_RE);
            if (m3) m3.forEach(t => tcodes.add(t));
        }
        if (parsed.tactic) tactics = Array.isArray(parsed.tactic) ? parsed.tactic : [parsed.tactic];
        if (parsed.steps && Array.isArray(parsed.steps)) {
            parsed.steps.forEach(s => {
                if (s.technique) { const m4 = String(s.technique).match(TCODE_RE); if (m4) m4.forEach(t => tcodes.add(t)); }
                if (s.name) behaviors.push(s.name);
            });
        }
        if (parsed.description && !description) description = String(parsed.description).substring(0, 200);

        return {
            name, description: description.trim(),
            tcodes: [...tcodes], tactics, platform,
            behaviors, stepCount: behaviors.length
        };
    }

    // ── Fetch + Validate Individual YAML ───────────────────
    async function fetchAndValidate(scenario) {
        try {
            const resp = await fetch(scenario.raw_url);
            if (!resp.ok) return null;
            const text = await resp.text();
            const parsed = validateYAML(text, scenario.source);
            if (!parsed) return null;
            const meta = extractMetadata(parsed, scenario.source, scenario.name);
            return { ...scenario, validated: true, metadata: meta, yamlText: text, parsed };
        } catch (e) { console.warn('[Scenarios] fetch error:', scenario.filename, e); return null; }
    }

    // ── Fetch All Scenarios ────────────────────────────────
    async function fetchAllScenarios(bustCache = false) {
        if (bustCache) cache.bust();
        const cached = cache.get();
        if (cached) { scenarioList = cached; return cached; }

        const [artFiles, calderaFiles] = await Promise.all([
            fetchFileList(ART_API, 'ART').catch(e => { console.warn('[Scenarios] ART fetch error:', e); throw e; }),
            fetchFileList(CALDERA_API, 'CALDERA').catch(e => { console.warn('[Scenarios] CALDERA fetch error:', e); return []; })
        ]);

        const allFiles = [...artFiles, ...calderaFiles];
        // Fetch and validate each file to get metadata for cards
        const results = await Promise.all(allFiles.map(f => fetchAndValidate(f)));
        scenarioList = results.filter(Boolean).map(s => ({
            name: s.metadata.name,
            source: s.source,
            filename: s.filename,
            raw_url: s.raw_url,
            validated: true,
            metadata: s.metadata
        }));
        cache.set(scenarioList);
        return scenarioList;
    }

    // ── YAML Syntax Highlight ──────────────────────────────
    function highlightYAML(text) {
        return esc(text)
            .replace(/^(\s*#.*)$/gm, '<span class="yaml-comment">$1</span>')
            .replace(/(T\d{4}(?:\.\d{3})?)/g, '<span class="yaml-tcode">$1</span>')
            .replace(/^(\s*[\w_.-]+)(\s*:)/gm, '<span class="yaml-key">$1</span>$2')
            .replace(/:\s+(true|false|yes|no|null)\s*$/gim, ': <span class="yaml-bool">$1</span>')
            .replace(/:\s+(\d+(?:\.\d+)?)\s*$/gm, ': <span class="yaml-number">$1</span>');
    }

    // ── Render Cards ───────────────────────────────────────
    function renderCards(list) {
        const grid = document.getElementById('scenarioGrid');
        const empty = document.getElementById('scenarioEmpty');
        const loading = document.getElementById('scenarioLoading');
        if (loading) loading.style.display = 'none';

        const filtered = list.filter(s => {
            if (currentFilter === 'all') return true;
            return s.source.toLowerCase() === currentFilter.toLowerCase();
        });

        if (filtered.length === 0) {
            grid.innerHTML = '';
            if (empty) { empty.style.display = ''; empty.querySelector('h3').textContent = currentFilter === 'all' ? 'Không có kịch bản nào' : `Không có kịch bản ${currentFilter}`; }
            return;
        }
        if (empty) empty.style.display = 'none';

        const frag = document.createDocumentFragment();
        filtered.forEach((s, i) => {
            const card = document.createElement('div');
            card.className = 'scenario-card';
            card.style.animationDelay = `${i * 0.05}s`;
            card.style.animation = 'fadeInUp 0.3s ease-out both';

            const badgeCls = s.source === 'ART' ? 'art' : s.source === 'CALDERA' ? 'caldera' : 'custom';
            const tcodes = s.metadata?.tcodes || [];
            const showTcodes = tcodes.slice(0, 5);
            const moreTcodes = tcodes.length > 5 ? tcodes.length - 5 : 0;
            const desc = s.metadata?.description || 'Kịch bản diễn tập tấn công';
            const steps = s.metadata?.stepCount || 0;

            card.innerHTML = `
                <div class="scenario-card-header">
                    <div class="scenario-card-name">${esc(s.metadata?.name || s.name)}</div>
                    <span class="source-badge ${badgeCls}">${esc(s.source)}</span>
                </div>
                <div class="scenario-card-desc">${esc(desc)}</div>
                <div class="scenario-tech-pills">
                    ${showTcodes.map(t => `<span class="scenario-tech-pill">${esc(t)}</span>`).join('')}
                    ${moreTcodes > 0 ? `<span class="scenario-tech-pill more">+${moreTcodes}</span>` : ''}
                </div>
                <div class="scenario-card-meta">
                    <span class="scenario-meta-item"><i class="fa-solid fa-crosshairs"></i><span class="meta-value">${tcodes.length}</span> T-Code${tcodes.length !== 1 ? 's' : ''}</span>
                    <span class="scenario-meta-item"><i class="fa-solid fa-list-ol"></i><span class="meta-value">${steps}</span> bước</span>
                    ${s.metadata?.platform ? `<span class="scenario-meta-item"><i class="fa-solid fa-desktop"></i>${esc(s.metadata.platform)}</span>` : ''}
                </div>
                <div class="scenario-card-actions">
                    <button class="btn btn-ghost" data-action="detail" data-idx="${i}"><i class="fa-solid fa-eye"></i> Xem Chi Tiết</button>
                    <button class="btn btn-use-scenario" data-action="use" data-idx="${i}"><i class="fa-solid fa-play"></i> Dùng Kịch Bản</button>
                </div>`;
            frag.appendChild(card);
        });
        grid.innerHTML = '';
        grid.appendChild(frag);

        // Event delegation
        grid.onclick = (e) => {
            const btn = e.target.closest('[data-action]');
            if (!btn) return;
            const idx = parseInt(btn.dataset.idx);
            const scenario = filtered[idx];
            if (!scenario) return;
            if (btn.dataset.action === 'detail') openDetailModal(scenario);
            else if (btn.dataset.action === 'use') useScenario(scenario);
        };

        // Update count
        const badge = document.getElementById('scenarioCountBadge');
        if (badge) badge.textContent = `${list.length} kịch bản`;
    }

    // ── Detail Modal ───────────────────────────────────────
    async function openDetailModal(scenario) {
        const modal = document.getElementById('scenarioDetailModal');
        const title = document.getElementById('scenarioModalTitle');
        const body = document.getElementById('scenarioModalBody');
        if (!modal) return;

        title.innerHTML = `<span class="source-badge ${scenario.source.toLowerCase()}">${esc(scenario.source)}</span> ${esc(scenario.metadata?.name || scenario.name)}`;
        body.innerHTML = '<div style="text-align:center;padding:40px;"><i class="fa-solid fa-circle-notch fa-spin" style="font-size:28px;color:var(--blue);"></i><p style="margin-top:12px;color:var(--text-secondary);font-size:13px;">Đang tải YAML...</p></div>';
        modal.style.display = 'flex';

        let yamlText, parsed;
        try {
            const resp = await fetch(scenario.raw_url);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            yamlText = await resp.text();
            parsed = jsyaml.load(yamlText);
        } catch (e) {
            body.innerHTML = `<div class="scenario-error-state"><i class="fa-solid fa-circle-exclamation"></i><h3>Lỗi tải kịch bản</h3><p>${esc(e.message)}</p></div>`;
            return;
        }

        const meta = scenario.metadata || extractMetadata(parsed, scenario.source, scenario.filename);

        body.innerHTML = `
            <div class="scenario-detail-tabs">
                <button class="scenario-detail-tab active" data-tab="meta">Metadata</button>
                <button class="scenario-detail-tab" data-tab="yaml">YAML</button>
            </div>
            <div class="scenario-detail-panel active" data-panel="meta">
                <table class="scenario-meta-table">
                    <tr><th><i class="fa-solid fa-tag"></i> Tên</th><td>${esc(meta.name)}</td></tr>
                    <tr><th><i class="fa-solid fa-crosshairs"></i> T-Codes</th><td>${meta.tcodes.map(t => `<span class="t-code">${esc(t)}</span>`).join(' ') || '<em style="color:var(--text-muted)">Không có</em>'}</td></tr>
                    ${meta.tactics.length ? `<tr><th><i class="fa-solid fa-layer-group"></i> Tactics</th><td>${meta.tactics.map(t => esc(t)).join(', ')}</td></tr>` : ''}
                    ${meta.platform ? `<tr><th><i class="fa-solid fa-desktop"></i> Platform</th><td>${esc(meta.platform)}</td></tr>` : ''}
                    <tr><th><i class="fa-solid fa-align-left"></i> Mô tả</th><td>${esc(meta.description) || '<em style="color:var(--text-muted)">Không có mô tả</em>'}</td></tr>
                    <tr><th><i class="fa-solid fa-list-ol"></i> Số bước</th><td>${meta.stepCount}</td></tr>
                </table>
            </div>
            <div class="scenario-detail-panel" data-panel="yaml">
                <div class="yaml-code-wrapper">
                    <div class="yaml-code-toolbar">
                        <span>${esc(scenario.filename)} (${(yamlText.length / 1024).toFixed(1)} KB)</span>
                        <button class="yaml-copy-btn" id="yamlCopyBtn"><i class="fa-regular fa-copy"></i> Copy</button>
                    </div>
                    <pre class="yaml-code-block">${highlightYAML(yamlText)}</pre>
                </div>
            </div>`;

        // Tab switching
        body.querySelectorAll('.scenario-detail-tab').forEach(tab => {
            tab.onclick = () => {
                body.querySelectorAll('.scenario-detail-tab').forEach(t => t.classList.remove('active'));
                body.querySelectorAll('.scenario-detail-panel').forEach(p => p.classList.remove('active'));
                tab.classList.add('active');
                body.querySelector(`[data-panel="${tab.dataset.tab}"]`).classList.add('active');
            };
        });

        // Copy button
        const copyBtn = document.getElementById('yamlCopyBtn');
        if (copyBtn) {
            copyBtn.onclick = async () => {
                try { await navigator.clipboard.writeText(yamlText); copyBtn.innerHTML = '<i class="fa-solid fa-check"></i> Đã copy'; copyBtn.classList.add('copied'); setTimeout(() => { copyBtn.innerHTML = '<i class="fa-regular fa-copy"></i> Copy'; copyBtn.classList.remove('copied'); }, 2000); }
                catch (_) { toast('Không thể copy', 'error'); }
            };
        }

        // Update modal footer use button
        const useBtn = document.getElementById('scenarioModalUseBtn');
        if (useBtn) {
            useBtn.onclick = () => { modal.style.display = 'none'; useScenario(scenario); };
        }
    }

    // ── Use Scenario ───────────────────────────────────────
    async function useScenario(scenario) {
        const aptInput = document.getElementById('aptInput');
        const mapBtn = document.getElementById('mapBtn');
        if (!aptInput || !mapBtn) return;

        let behaviors = scenario.metadata?.behaviors || [];
        if (behaviors.length === 0) {
            try {
                const resp = await fetch(scenario.raw_url);
                const text = await resp.text();
                const parsed = jsyaml.load(text);
                const meta = extractMetadata(parsed, scenario.source, scenario.filename);
                behaviors = meta.behaviors;
            } catch (e) { toast('Lỗi tải kịch bản: ' + e.message, 'error'); return; }
        }

        if (behaviors.length === 0) { toast('Kịch bản không có bước nào để mapping', 'warning'); return; }

        // Hide scenario section
        const section = document.getElementById('scenarioSection');
        if (section) section.style.display = 'none';
        isVisible = false;

        // Close detail modal if open
        const modal = document.getElementById('scenarioDetailModal');
        if (modal) modal.style.display = 'none';

        aptInput.value = behaviors.join('\n');
        aptInput.disabled = false;
        toast(`Đã tải kịch bản: ${scenario.metadata?.name || scenario.name}`);
        
        setTimeout(() => {
            mapBtn.click();
            setTimeout(() => {
                const results = document.getElementById('resultsSection');
                if (results) results.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, 500);
        }, 100);
    }

    // ── Show / Hide Section ────────────────────────────────
    async function show() {
        const section = document.getElementById('scenarioSection');
        if (!section) return;

        if (isVisible) { section.style.display = 'none'; isVisible = false; return; }

        section.style.display = '';
        isVisible = true;
        section.scrollIntoView({ behavior: 'smooth', block: 'start' });

        const grid = document.getElementById('scenarioGrid');
        const loading = document.getElementById('scenarioLoading');
        const empty = document.getElementById('scenarioEmpty');

        if (scenarioList.length > 0) {
            renderCards([...scenarioList, ...customScenarios]);
            return;
        }

        if (loading) loading.style.display = '';
        if (grid) grid.innerHTML = '';
        if (empty) empty.style.display = 'none';

        try {
            await fetchAllScenarios();
            renderCards([...scenarioList, ...customScenarios]);
        } catch (e) {
            if (loading) loading.style.display = 'none';
            if (grid) grid.innerHTML = `<div class="scenario-error-state"><i class="fa-solid fa-circle-exclamation"></i><h3>Lỗi tải danh sách</h3><p>${esc(e.message)}</p><button class="btn btn-ghost" onclick="ScenariosManager.refresh()"><i class="fa-solid fa-rotate-right"></i> Thử lại</button></div>`;
        }
    }

    async function refresh() {
        scenarioList = [];
        const grid = document.getElementById('scenarioGrid');
        const loading = document.getElementById('scenarioLoading');
        if (grid) grid.innerHTML = '';
        if (loading) loading.style.display = '';
        try {
            await fetchAllScenarios(true);
            renderCards([...scenarioList, ...customScenarios]);
            toast('Đã làm mới danh sách kịch bản');
        } catch (e) {
            if (loading) loading.style.display = 'none';
            if (grid) grid.innerHTML = `<div class="scenario-error-state"><i class="fa-solid fa-circle-exclamation"></i><h3>Lỗi</h3><p>${esc(e.message)}</p></div>`;
            toast(e.message, 'error');
        }
    }

    function hide() {
        const section = document.getElementById('scenarioSection');
        if (section) section.style.display = 'none';
        isVisible = false;
    }

    // ── Filter ─────────────────────────────────────────────
    function setFilter(filter) {
        currentFilter = filter;
        document.querySelectorAll('.scenario-filter-btn').forEach(b => {
            b.classList.toggle('active', b.dataset.filter === filter);
        });
        renderCards([...scenarioList, ...customScenarios]);
    }

    // ── Upload ─────────────────────────────────────────────
    function showUpload() {
        show();
        setTimeout(() => {
            const zone = document.getElementById('scenarioUploadZone');
            if (zone) zone.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, 300);
    }

    function handleUpload(file) {
        const errEl = document.getElementById('uploadError');
        const succEl = document.getElementById('uploadSuccess');
        if (errEl) { errEl.classList.remove('visible'); errEl.textContent = ''; }
        if (succEl) { succEl.classList.remove('visible'); }

        if (!file) return;
        if (!/\.(ya?ml)$/i.test(file.name)) {
            if (errEl) { errEl.textContent = 'Chỉ chấp nhận file .yml hoặc .yaml'; errEl.classList.add('visible'); }
            return;
        }
        const reader = new FileReader();
        reader.onload = (e) => {
            const text = e.target.result;
            if (text.length < 50) { if (errEl) { errEl.textContent = 'File quá nhỏ (< 50 bytes)'; errEl.classList.add('visible'); } return; }
            const parsed = validateYAML(text, 'Custom');
            if (!parsed) { if (errEl) { errEl.textContent = 'YAML không hợp lệ: thiếu trường bắt buộc (attack_technique, atomic_tests, name, steps...)'; errEl.classList.add('visible'); } return; }
            const meta = extractMetadata(parsed, 'Custom', file.name);
            const custom = { name: meta.name, source: 'Custom', filename: file.name, raw_url: null, validated: true, metadata: meta, yamlText: text, parsed };
            customScenarios.push(custom);
            renderCards([...scenarioList, ...customScenarios]);
            if (succEl) { succEl.textContent = `Đã thêm kịch bản: ${meta.name}`; succEl.classList.add('visible'); }
            toast(`Đã thêm kịch bản custom: ${meta.name}`);
        };
        reader.readAsText(file);
    }

    // ── Init Event Listeners ───────────────────────────────
    document.addEventListener('DOMContentLoaded', () => {
        // Filter buttons
        document.querySelectorAll('.scenario-filter-btn').forEach(btn => {
            btn.addEventListener('click', () => setFilter(btn.dataset.filter));
        });
        // Upload zone
        const uploadInput = document.getElementById('scenarioUploadInput');
        if (uploadInput) uploadInput.addEventListener('change', (e) => { if (e.target.files[0]) handleUpload(e.target.files[0]); e.target.value = ''; });
        const uploadZone = document.getElementById('scenarioUploadZone');
        if (uploadZone) {
            uploadZone.addEventListener('dragover', (e) => { e.preventDefault(); uploadZone.classList.add('dragover'); });
            uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('dragover'));
            uploadZone.addEventListener('drop', (e) => { e.preventDefault(); uploadZone.classList.remove('dragover'); if (e.dataTransfer.files[0]) handleUpload(e.dataTransfer.files[0]); });
        }
        // Detail modal close
        const modal = document.getElementById('scenarioDetailModal');
        const closeBtn = document.getElementById('closeScenarioModalBtn');
        if (closeBtn) closeBtn.addEventListener('click', () => { if (modal) modal.style.display = 'none'; });
        if (modal) modal.addEventListener('click', (e) => { if (e.target === modal) modal.style.display = 'none'; });
    });

    return { show, hide, refresh, showUpload, setFilter, toast };
})();
