// ============================================================
// ATT&CK MAPPER — app.js
// Dynamic Rule Mapping & Coverage Explorer
// ============================================================

const STIX_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v14.1/enterprise-attack/enterprise-attack.json';
const RULES_DB_URL = 'data/rules_db.json';
const LOG_SOURCE_MAP_URL = 'data/log_source_map.json';
const DETECTION_RULES_DB_URL = 'data/detection_rules_db.json';
const KEYWORD_ALIASES_URL = 'data/keyword_aliases.json';

// ---- State ----
let techniques = [];
let rulesDb = {};
let logSourceCategories = []; // Loaded from log_source_map.json
let detectionRulesDb = {}; // Loaded from detection_rules_db.json
let keywordAliases = {};  // Loaded from keyword_aliases.json
let tacticSet = new Set(); // All tactics found in loaded techniques
let currentRows = []; // Keep track of current mapping results for Matrix

// ─── DB Load Status ───────────────────────────────────────────────────────────
const dataLoadStatus = {
    stix:             { loaded: false, critical: true  },
    rulesDb:          { loaded: false, critical: false },
    logSourceMap:     { loaded: false, critical: true  }, // critical vì tool mapping dựa vào đây
    detectionRulesDb: { loaded: false, critical: false },
    keywordAliases:   { loaded: false, critical: false }
};
// ─────────────────────────────────────────────────────────────────────────────

// ─── Translation Cache (3-tier) ──────────────────────────────────────────────
const translationCache = {
    memory: new Map(),
    TTL: 24 * 60 * 60 * 1000, // 24 giờ

    _normalize(text) {
        // Chuẩn hóa key: lowercase, trim, collapse spaces
        return text.toLowerCase().trim().replace(/\s+/g, ' ');
    },

    async get(text) {
        const key = this._normalize(text);

        // Tier 1 — memory (instant)
        const mem = this.memory.get(key);
        if (mem && Date.now() - mem.ts < this.TTL) return mem.val;

        // Tier 2 — localStorage (persist qua session)
        try {
            const storageKey = 'tc_' + btoa(encodeURIComponent(key)).slice(0, 40);
            const raw = localStorage.getItem(storageKey);
            if (raw) {
                const { val, ts } = JSON.parse(raw);
                if (Date.now() - ts < this.TTL) {
                    this.memory.set(key, { val, ts }); // warm memory tier
                    return val;
                }
            }
        } catch (_) {}

        // Tier 3 — pure English → skip API hoàn toàn
        if (!/[^\x00-\x7F]/.test(text)) return text.toLowerCase();

        return null; // cache miss → cần gọi API
    },

    set(text, val) {
        const key = this._normalize(text);
        const entry = { val, ts: Date.now() };
        this.memory.set(key, entry);
        try {
            const storageKey = 'tc_' + btoa(encodeURIComponent(key)).slice(0, 40);
            if (this.memory.size <= 500) { // giới hạn tránh đầy localStorage
                localStorage.setItem(storageKey, JSON.stringify(entry));
            }
        } catch (_) {}
    }
};

async function translateCached(line) {
    const cached = await translationCache.get(line);
    if (cached !== null) return cached;

    try {
        const result = await translate(line); // gọi API chỉ khi thật sự cần
        translationCache.set(line, result);
        return result;
    } catch (e) {
        console.warn('[translateCached] API failed, using original:', e);
        return line.toLowerCase(); // graceful fallback
    }
}
// ─────────────────────────────────────────────────────────────────────────────

// ─── Alias Index (inverted index, build một lần) ──────────────────────────────
let aliasIndex = null; // null = chưa build

function buildAliasIndex(aliases) {
    // aliasIndex: Map<firstWord, Map<fullPhrase, { techIds, wordCount }>>
    const idx = new Map();

    for (const [phrase, techIds] of Object.entries(aliases)) {
        if (phrase.startsWith('_')) continue; // bỏ qua _meta

        const words = phrase.toLowerCase().split(/[\s\-_]+/).filter(w => w.length > 1);
        if (words.length === 0) continue;

        const firstWord = words[0];
        if (!idx.has(firstWord)) idx.set(firstWord, new Map());
        idx.get(firstWord).set(phrase, {
            techIds: Array.isArray(techIds) ? techIds : [techIds],
            wordCount: words.length
        });
    }

    console.log(`[buildAliasIndex] Built index: ${idx.size} first-word buckets`);
    return idx;
}
// ─────────────────────────────────────────────────────────────────────────────

// Detection tools for matrix display
const DETECTION_TOOLS = [
    { id: 'Sysmon',            label: 'Sysmon',            clsList: ['ds-sysmon', 'ds-wazuh'] },
    { id: 'Wazuh',             label: 'Wazuh',             clsList: ['ds-wazuh'] },
    { id: 'Suricata',          label: 'Suricata',          clsList: ['ds-suricata'] },
    { id: 'Windows Event Log', label: 'Windows Event Log', clsList: ['ds-auth'] },
    { id: 'Sigma',             label: 'Sigma',             clsList: [] }
];

// ---- DOM refs ----
const aptInput     = document.getElementById('aptInput');
const mapBtn       = document.getElementById('mapBtn');
const clearBtn     = document.getElementById('clearBtn');
const matrixBtn    = document.getElementById('matrixBtn');
const dbStatus     = document.getElementById('dbStatus');
const dbStatusDot  = dbStatus.querySelector('.status-dot');
const dbStatusText = document.getElementById('dbStatusText');

const filterSection  = document.getElementById('filterSection');
const tacticFilter   = document.getElementById('tacticFilter');
const resultsSummary = document.getElementById('resultsSummary');
const resultsSection = document.getElementById('resultsSection');
const tableBody      = document.getElementById('mappingTableBody');
const emptyState     = document.getElementById('emptyState');
const loadingState   = document.getElementById('loadingState');

// Modal refs (Rule Info)
const infoModal     = document.getElementById('infoModal');
const closeModalBtn = document.getElementById('closeModalBtn');
const modalTitle    = document.getElementById('modalTitle');
const modalContent  = document.getElementById('modalContent');

// Modal refs (Matrix)
const matrixModal      = document.getElementById('matrixModal');
const closeMatrixBtn   = document.getElementById('closeMatrixBtn');
const matrixContent    = document.getElementById('matrixContent');

// Drawer refs
const sideDrawer       = document.getElementById('sideDrawer');
const drawerOverlay    = document.getElementById('drawerOverlay');
const drawerToggleBtn  = document.getElementById('drawerToggleBtn');
const closeDrawerBtn   = document.getElementById('closeDrawerBtn');

// ---- Event Listeners ----
document.querySelectorAll('.qe-chip').forEach(chip => {
    chip.addEventListener('click', () => {
        aptInput.value = chip.dataset.example;
        aptInput.focus();
    });
});

clearBtn.addEventListener('click', () => {
    aptInput.value = '';
    showEmpty();
    aptInput.focus();
});

mapBtn.addEventListener('click', runMapping);
aptInput.addEventListener('keydown', e => {
    if (e.ctrlKey && e.key === 'Enter') runMapping();
});

matrixBtn.addEventListener('click', showMatrix);

// Modal Close logic
closeModalBtn.addEventListener('click', () => infoModal.style.display = 'none');
infoModal.addEventListener('click', (e) => {
    if (e.target === infoModal) infoModal.style.display = 'none';
});

closeMatrixBtn.addEventListener('click', () => matrixModal.style.display = 'none');
matrixModal.addEventListener('click', (e) => {
    if (e.target === matrixModal) matrixModal.style.display = 'none';
});

// Drawer logic
function openDrawer() {
    sideDrawer.classList.add('open');
    drawerOverlay.style.display = 'block';
    // a slight delay to allow display:block to apply before opacity transition
    setTimeout(() => drawerOverlay.classList.add('open'), 10);
}
function closeDrawer() {
    sideDrawer.classList.remove('open');
    drawerOverlay.classList.remove('open');
    setTimeout(() => drawerOverlay.style.display = 'none', 300);
}
drawerToggleBtn.addEventListener('click', openDrawer);
closeDrawerBtn.addEventListener('click', closeDrawer);
drawerOverlay.addEventListener('click', closeDrawer);


// ============================================================
// INIT: Fetch STIX Data & Rules DB
// ============================================================
function updateDbStatusUI() {
    const failed = Object.entries(dataLoadStatus)
        .filter(([, v]) => !v.loaded)
        .map(([k]) => k);

    const criticalFailed = Object.entries(dataLoadStatus)
        .filter(([, v]) => !v.loaded && v.critical)
        .length > 0;

    if (criticalFailed) {
        dbStatusDot.className = 'status-dot error';
        dbStatusText.innerHTML = `Lỗi tải database: <strong>${failed.join(', ')}</strong>`;
    } else if (failed.length > 0) {
        dbStatusDot.className = 'status-dot warning';
        dbStatusText.innerHTML =
            `${techniques.length} kỹ thuật &nbsp;` +
            `<span class="db-warn">Thiếu: ${failed.join(', ')}</span>`;
    } else {
        dbStatusDot.className = 'status-dot ready';
        dbStatusText.textContent = `${techniques.length} kỹ thuật `;
    }

    // Thêm retry button nếu có lỗi
    const existingRetry = document.getElementById('retryDbBtn');
    if (failed.length > 0 && !existingRetry) {
        const retryBtn = document.createElement('button');
        retryBtn.id = 'retryDbBtn';
        retryBtn.className = 'btn btn-ghost';
        retryBtn.innerHTML = '<i class="fa-solid fa-rotate-right"></i> Retry';
        retryBtn.style.marginLeft = '10px';
        retryBtn.style.fontSize = '12px';
        retryBtn.onclick = () => {
            document.getElementById('retryDbBtn')?.remove();
            init();
        };
        dbStatus.appendChild(retryBtn);
    }
}

async function init() {
    try {
        dbStatusText.textContent = 'Đang tải database...';
        dbStatusDot.className = 'status-dot loading';
        
        const [stixResp, rulesResp, logMapResp, detRulesResp, kwResp] = await Promise.all([
            fetch(STIX_URL).catch(() => ({ok: false})),
            fetch(RULES_DB_URL).catch(() => ({ok: false})),
            fetch(LOG_SOURCE_MAP_URL).catch(() => ({ok: false})),
            fetch(DETECTION_RULES_DB_URL).catch(() => ({ok: false})),
            fetch(KEYWORD_ALIASES_URL).catch(() => ({ok: false}))
        ]);

        if (stixResp.ok) {
            const stixData = await stixResp.json();
            parseSTIX(stixData.objects);
            dataLoadStatus.stix.loaded = true;
        }

        if (rulesResp.ok) {
            rulesDb = await rulesResp.json();
            dataLoadStatus.rulesDb.loaded = true;
        } else {
            console.warn('Không thể load rules_db.json, sẽ sử dụng database trống.');
            rulesDb = {};
        }

        if (logMapResp.ok) {
            const logMapData = await logMapResp.json();
            logSourceCategories = logMapData.categories || [];
            dataLoadStatus.logSourceMap.loaded = true;
        } else {
            console.warn('Không thể load log_source_map.json');
        }

        if (detRulesResp.ok) {
            detectionRulesDb = await detRulesResp.json();
            delete detectionRulesDb._meta;
            dataLoadStatus.detectionRulesDb.loaded = true;
        } else {
            console.warn('Không thể load detection_rules_db.json');
            detectionRulesDb = {};
        }

        if (kwResp.ok) {
            keywordAliases = await kwResp.json();
            delete keywordAliases._meta;
            console.log(`Loaded ${Object.keys(keywordAliases).length} keyword aliases`);
            aliasIndex = buildAliasIndex(keywordAliases); // BUILD INDEX
            dataLoadStatus.keywordAliases.loaded = true;
        } else {
            console.warn('Không thể load keyword_aliases.json');
            keywordAliases = {};
        }

        const criticalFailed = Object.entries(dataLoadStatus)
            .filter(([, v]) => !v.loaded && v.critical).length > 0;
            
        if (!criticalFailed) {
            aptInput.disabled = false;
            mapBtn.disabled = false;
            clearBtn.disabled = false;
            matrixBtn.disabled = false;
            aptInput.focus();
        }

        updateDbStatusUI();
    } catch (err) {
        console.error(err);
        updateDbStatusUI();
    }
}

function parseSTIX(objects) {
    // ---- Step 1: Build data source lookup (stix_id -> source name) ----
    const dataSourceMap = {};
    objects.filter(o => o.type === 'x-mitre-data-source').forEach(ds => {
        dataSourceMap[ds.id] = ds.name || '';
    });

    // ---- Step 2: Build data component lookup (stix_id -> { componentName, sourceName }) ----
    const dataComponentMap = {};
    objects.filter(o => o.type === 'x-mitre-data-component').forEach(dc => {
        dataComponentMap[dc.id] = {
            componentName: (dc.name || '').toLowerCase(),
            sourceName: (dataSourceMap[dc.x_mitre_data_source_ref] || '').toLowerCase()
        };
    });

    // ---- Step 3: Build relationship map: technique_stix_id -> Array of { componentName, sourceName } ----
    // ATT&CK v10+: 'detects' relationships link data-components to attack-patterns
    const techDataSourceMap = {};
    objects.filter(o => o.type === 'relationship' && o.relationship_type === 'detects').forEach(rel => {
        const comp = dataComponentMap[rel.source_ref];
        const techId   = rel.target_ref; // stix id of the attack-pattern
        if (!comp || !techId) return;
        if (!techDataSourceMap[techId]) techDataSourceMap[techId] = [];
        if (!techDataSourceMap[techId].some(c => c.componentName === comp.componentName && c.sourceName === comp.sourceName)) {
            techDataSourceMap[techId].push(comp);
        }
    });

    // ---- Step 4: Parse attack-patterns ----
    techniques = objects
        .filter(o => o.type === 'attack-pattern' && !o.revoked && !o.x_mitre_deprecated)
        .map(o => {
            const ext = (o.external_references || []).find(r => r.source_name === 'mitre-attack');
            const tid  = ext ? ext.external_id : '';
            const url  = ext ? ext.url : '#';
            const tactics = (o.kill_chain_phases || [])
                .filter(p => p.kill_chain_name === 'mitre-attack')
                .map(p => p.phase_name);

            tactics.forEach(t => tacticSet.add(t));

            // Get data sources from relationship model (v10+) OR fallback to legacy field
            const relDataSources = techDataSourceMap[o.id] ? [...techDataSourceMap[o.id]] : [];
            const legacyDataSources = (o.x_mitre_data_sources || []).map(s => ({ sourceName: s.toLowerCase(), componentName: '' }));
            const dataSources = relDataSources.length > 0 ? relDataSources : legacyDataSources;

            const fullDesc = (o.description || '').replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1');

            return {
                id: tid,
                name: o.name || '',
                description: fullDesc.substring(0, 300),
                tactics,
                dataSources,
                url,
                search: (tid + ' ' + o.name + ' ' + fullDesc + ' ' + tactics.join(' ')).toLowerCase()
            };
        });
}

// ============================================================
// TRANSLATE via Google (free endpoint)
// ============================================================
async function translate(text) {
    const nonAscii = (text.match(/[^\x00-\x7F]/g) || []).length;
    if (nonAscii < 3) return text.toLowerCase();
    try {
        const url = `https://translate.googleapis.com/translate_a/single?client=gtx&sl=vi&tl=en&dt=t&q=${encodeURIComponent(text)}`;
        const res = await fetch(url);
        const data = await res.json();
        let out = '';
        (data[0] || []).forEach(chunk => { if (chunk[0]) out += chunk[0]; });
        return out.toLowerCase();
    } catch {
        return text.toLowerCase();
    }
}

// ============================================================
// SMART SEARCH (with keyword alias support)
// ============================================================

/**
 * Look up keyword aliases for a query string.
 * Tries longest phrase match first, then individual words.
 * Returns a Set of technique IDs matched via aliases.
 */
function getAliasMatches(queryStr) {
    if (!aliasIndex) return new Map();

    const q        = queryStr.toLowerCase().trim();
    const words    = q.split(/[\s\-_,;]+/).filter(w => w.length > 1);
    const scores   = new Map(); // techId → điểm cao nhất

    const addScore = (techIds, pts) => {
        techIds.forEach((tid, i) => {
            const s = pts - i * 3; // rank penalty nhỏ trong alias array
            if (!scores.has(tid) || scores.get(tid) < s) scores.set(tid, s);
        });
    };

    // Pass 1 — exact full-phrase match (ưu tiên cao nhất: 200 pts)
    if (aliasIndex.has(words[0])) {
        const candidates = aliasIndex.get(words[0]);
        const entry = candidates.get(q);
        if (entry) addScore(entry.techIds, 200);
    }

    // Pass 2 — sub-phrase match: quét từng vị trí i trong query
    // Chỉ check các phrase có first-word match → O(k) thay vì O(n²)
    const covered = new Set();

    for (let i = 0; i < words.length; i++) {
        const w = words[i];
        if (!aliasIndex.has(w)) continue;

        const candidates = aliasIndex.get(w);
        for (const [phrase, { techIds, wordCount }] of candidates) {
            const covKey = phrase + ':' + i;
            if (covered.has(covKey)) continue;

            // Kiểm tra phrase có khớp đúng từ vị trí i không
            const phraseWords = phrase.split(/[\s\-_]+/);
            const querySlice  = words.slice(i, i + phraseWords.length).join(' ');

            if (querySlice === phrase) {
                covered.add(covKey);
                // Score theo độ dài phrase: càng dài càng cụ thể
                const pts = wordCount >= 3 ? 160 : wordCount === 2 ? 130 : 80;
                addScore(techIds, pts);
            }
        }
    }

    return scores;
}

function searchTechniques(translatedQuery, originalQuery = '', maxResults = 5) {
    const q = translatedQuery.toLowerCase();

    // Stopwords — không đóng góp vào score (tránh "the", "from" làm nhiễu)
    const STOP = new Set([
        'the','a','an','to','from','with','using','via','by',
        'and','or','on','in','at','for','of','is','are','was',
        'that','this','it','its','their','they','be','been',
        'has','have','had','do','does','did','will','would','can','could'
    ]);

    const rawWords = q.split(/\W+/).filter(w => w.length > 2);
    const words    = rawWords.filter(w => !STOP.has(w)); // chỉ giữ meaningful words
    const phrase   = words.join(' ');

    if (words.length === 0) return [];

    // Lấy alias scores từ cả query dịch lẫn query gốc (tiếng Việt)
    const aliasScores     = getAliasMatches(q);
    const aliasScoresOrig = originalQuery
        ? getAliasMatches(originalQuery.toLowerCase())
        : new Map();

    const results = [];

    for (const t of techniques) {
        const tid  = t.id.toLowerCase();
        const name = (t.name || '').toLowerCase();
        const desc = (t.description || '').toLowerCase();
        const srch = (t.search || '').toLowerCase();

        let score = 0;

        // ── Alias score (tín hiệu mạnh nhất) ────────────────────────────────
        const aScore = Math.max(
            aliasScores.get(t.id)     || 0,
            aliasScoresOrig.get(t.id) || 0
        );
        score += aScore;

        // ── STIX text score ──────────────────────────────────────────────────

        // Phrase match (bonus lớn — chỉ có ý nghĩa khi 2+ words)
        if (words.length >= 2) {
            if (name.includes(phrase)) score += 90;
            if (desc.includes(phrase)) score += 50;
            if (srch.includes(phrase)) score += 25;
        }

        // Word-level scoring
        let nameHits = 0, descHits = 0;
        for (const w of words) {
            if (name.includes(w)) { score += 50; nameHits++; }
            if (desc.includes(w)) { score += 20; descHits++; }
            if (srch.includes(w))   score += 10;
            if (tid === w)          score += 60; // exact ID như "t1059"
            if (tid.includes(w) && w.length > 2) score += 15;
            t.tactics?.forEach(tac => {
                if (tac.includes(w)) score += 20;
            });
        }

        // Bonus: nhiều words hit cùng field → kỹ thuật liên quan chặt
        if (nameHits >= 2) score += 30;
        if (descHits >= 3) score += 20;

        // Skip sớm: không có alias match VÀ score quá thấp → likely noise
        if (aScore === 0 && score < 30) continue;

        if (score > 0) results.push({ ...t, score });
    }

    return results
        .sort((a, b) => b.score - a.score)
        .slice(0, maxResults);
}

// ============================================================
// RENDER HELPERS
// ============================================================
function renderTacticBadge(tactic) {
    const cls = 'tactic-' + tactic.replace(/\s+/g, '-');
    const label = tactic.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    return `<span class="tactic-badge ${cls}">${label}</span>`;
}

function renderTechniqueCard(t) {
    return `
    <div class="technique-card">
        <span class="t-code">${t.id}</span>
        <div class="t-name">${t.name}</div>
        <div class="t-desc">${t.description}</div>
        <a class="t-link" href="${t.url}" target="_blank" rel="noopener">
            Xem trên MITRE <i class="fa-solid fa-arrow-up-right-from-square"></i>
        </a>
    </div>`;
}

/**
 * Trả về Map: toolId → [data components mà tool đó cover]
 * Dùng để render badge và tooltip
 */
function getToolCoverage(tech) {
    if (!tech.dataSources || tech.dataSources.length === 0) return new Map();

    // coverage: Map<toolId, Set<componentName>>
    const coverage = new Map();

    tech.dataSources.forEach(ds => {
        const componentName = (ds.componentName || '').toLowerCase().trim();
        const sourceName    = (ds.sourceName    || '').toLowerCase().trim();
        const textsToTry    = [componentName, sourceName].filter(Boolean);

        for (const text of textsToTry) {
            let bestLen   = 0;
            let bestToolId = null;
            let bestComponent = text;

            // Longest-match-first: tìm keyword dài nhất khớp
            for (const cat of logSourceCategories) {
                for (const kw of cat.keywords) {
                    if (text.includes(kw) && kw.length > bestLen) {
                        bestLen      = kw.length;
                        bestToolId   = cat.cls; // dùng để map sang tool
                        bestComponent = componentName || sourceName;
                    }
                }
            }

            if (bestToolId) {
                // Map cls → toolIds
                const matchedTools = DETECTION_TOOLS.filter(t =>
                    Array.isArray(t.clsList)
                        ? t.clsList.includes(bestToolId)
                        : t.cls === bestToolId
                );
                
                matchedTools.forEach(matchedTool => {
                    if (!coverage.has(matchedTool.id)) coverage.set(matchedTool.id, new Set());
                    coverage.get(matchedTool.id).add(
                        bestComponent.replace(/\b\w/g, c => c.toUpperCase())
                    );
                });
                break; // component đã match → không thử text tiếp theo
            }
        }
    });

    return coverage;
}

/**
 * Tìm các rules trong DB match với một category.
 * Match dựa trên cls hoặc keyword của category vs source field của rule.
 */
function getRulesForCategory(tcode, cat) {
    const allRules = rulesDb[tcode] || [];
    return allRules.filter(r => {
        const s = r.source.toLowerCase();
        return cat.keywords.some(kw => s.includes(kw)) || s.includes(cat.id);
    });
}

function renderDetectedBy(matchedTechniques) {
    let html = '';
    matchedTechniques.forEach(tech => {
        html += `<div class="cov-matrix-block" data-tcode="${tech.id}">`;
        html += `<div class="cov-matrix-header">`;
        html += `<span class="cov-tcode">${tech.id}</span>`;
        html += `<span class="cov-tname">${tech.name}</span>`;
        html += `</div>`;
        html += `<div class="cov-matrix-body">`;
        
        if (tech.dataSources && tech.dataSources.length > 0) {
            // Group components by source
            const grouped = {};
            tech.dataSources.forEach(ds => {
                const src = ds.sourceName ? ds.sourceName.replace(/\b\w/g, c => c.toUpperCase()) : 'Unknown';
                const comp = ds.componentName ? ds.componentName.replace(/\b\w/g, c => c.toUpperCase()) : '';
                if (!grouped[src]) grouped[src] = new Set();
                if (comp) grouped[src].add(comp);
            });

            html += `<div class="stix-ds-compact">`;
            Object.entries(grouped).forEach(([src, comps]) => {
                html += `<div class="stix-ds-item">`;
                html += `<span class="stix-ds-name"><i class="fa-solid fa-database"></i> ${src}:</span> `;
                if (comps.size > 0) {
                    [...comps].forEach(c => {
                        html += `<span class="stix-dc-tag">${c}</span>`;
                    });
                }
                html += `</div>`;
            });
            html += `</div>`;
        } else {
             html += `<div class="cov-empty-note">Không có dữ liệu STIX Data Source</div>`;
        }

        html += `</div></div>`;
    });
    return html;
}

function renderToolMapping(matchedTechniques) {
    let html = '';

    matchedTechniques.forEach(tech => {
        const detEntry  = detectionRulesDb[tech.id] || {};
        const toolCoverage = getToolCoverage(tech); // Map<toolId, Set<components>>

        html += `<div class="cov-matrix-block" data-tcode="${tech.id}">`;
        html += `<div class="cov-matrix-header">`;
        html += `  <span class="cov-tcode">${tech.id}</span>`;
        html += `  <span class="cov-tname">Tools & Rules</span>`;
        html += `</div>`;
        html += `<div class="cov-matrix-body"><div class="tools-badge-group">`;

        // Thêm Sigma nếu có rule (Sigma không dựa vào log coverage)
        const sigmaRules = detEntry?.rules?.Sigma || detEntry?.rules?.sigma || [];
        if (sigmaRules.length > 0) {
            toolCoverage.set('Sigma', new Set(['Generic Rule']));
        }

        if (toolCoverage.size === 0) {
            html += `<div class="cov-empty-note">
                <i class="fa-solid fa-circle-question"></i>
                Chưa có mapping log source cho technique này
            </div>`;
        } else {
            // Sort: có rule trước, chỉ coverage sau
            const sorted = [...toolCoverage.entries()].sort(([aId], [bId]) => {
                const aHasRule = (detEntry?.rules?.[aId] || []).length > 0;
                const bHasRule = (detEntry?.rules?.[bId] || []).length > 0;
                return (bHasRule ? 1 : 0) - (aHasRule ? 1 : 0);
            });

            sorted.forEach(([toolId, components]) => {
                const toolDef  = DETECTION_TOOLS.find(t => t.id === toolId);
                const toolLabel = toolDef?.label || toolId;
                const rules    = detEntry?.rules?.[toolId] || [];
                const hasRule  = rules.length > 0;

                // Tooltip: luôn hiện log components, thêm rule nếu có
                const compList = [...components].join(', ');
                let tooltipText = `📋 Log: ${compList}`;
                if (hasRule) {
                    tooltipText += ` | ✅ ${rules.length} rule(s) có sẵn`;
                    if (rules[0]?.name) tooltipText += `: ${rules[0].name}`;
                } else {
                    tooltipText += ` | ℹ️ Chưa có rule — nhưng ${toolLabel} có thể thu log này`;
                }

                const badgeClass = hasRule ? 'has-rule' : 'log-coverage';
                const statusIcon = hasRule
                    ? `<i class="fa-solid fa-circle-check"></i>`
                    : `<i class="fa-regular fa-circle"></i>`;

                // onClick: hiện detail panel
                const onClickData = JSON.stringify({
                    toolId, techId: tech.id,
                    components: [...components],
                    hasRule,
                    ruleCount: rules.length,
                    firstRule: rules[0]?.name || null
                }).replace(/"/g, '&quot;');

                html += `
                    <span class="cov-tool-badge ${badgeClass}"
                          title="${tooltipText}"
                          onclick='showToolDetail(${onClickData})'>
                        ${statusIcon}
                        ${toolLabel}
                        ${hasRule ? `<span class="rule-count">${rules.length}</span>` : ''}
                    </span>`;
            });
        }

        html += `</div></div></div>`;
    });

    return html;
}

function showToolDetail(data) {
    // data: { toolId, techId, components, hasRule, ruleCount, firstRule }
    const modal = document.getElementById('toolDetailModal') || createToolDetailModal();

    const compHtml = data.components
        .map(c => `<span class="component-tag">${c}</span>`)
        .join('');

    const ruleHtml = data.hasRule
        ? `<div class="modal-rule-info">
               <i class="fa-solid fa-circle-check" style="color:var(--green)"></i>
               <strong>${data.ruleCount} detection rule(s) có sẵn</strong>
               ${data.firstRule ? `<div class="rule-name">→ ${data.firstRule}</div>` : ''}
           </div>`
        : `<div class="modal-rule-info no-rule">
               <i class="fa-regular fa-circle" style="color:var(--blue-lt)"></i>
               <strong>Chưa có rule trong database</strong>
               <div class="rule-hint">
                   Tuy nhiên, <strong>${data.toolId}</strong> có thể detect technique
                   <strong>${data.techId}</strong> thông qua các log sau:
               </div>
           </div>`;

    modal.querySelector('.modal-tool-name').textContent = data.toolId;
    modal.querySelector('.modal-tech-id').textContent   = data.techId;
    modal.querySelector('.modal-components').innerHTML  = compHtml;
    modal.querySelector('.modal-rule-section').innerHTML = ruleHtml;
    modal.style.display = 'flex';
}

function createToolDetailModal() {
    const modal = document.createElement('div');
    modal.id = 'toolDetailModal';
    modal.className = 'tool-detail-modal';
    modal.innerHTML = `
        <div class="modal-backdrop" onclick="this.parentElement.style.display='none'"></div>
        <div class="modal-box">
            <div class="modal-header">
                <span class="modal-tool-name"></span>
                <span class="modal-sep">→</span>
                <span class="modal-tech-id"></span>
                <button class="modal-close" onclick="document.getElementById('toolDetailModal').style.display='none'">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>
            <div class="modal-body">
                <div class="modal-section-label">Log được thu thập:</div>
                <div class="modal-components"></div>
                <div class="modal-rule-section"></div>
            </div>
        </div>`;
    document.body.appendChild(modal);
    return modal;
}


// ============================================================
// RUN MAPPING
// ============================================================
async function runMapping() {
    const raw = aptInput.value.trim();
    if (!raw) return;

    const lines = raw.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    if (!lines.length) return;

    showLoading();

    const rows = [];
    const usedTactics = new Set();

    for (const line of lines) {
        const translated = await translateCached(line);
        // Pass both translated AND original text for alias matching
        const matched = searchTechniques(translated, line);
        const allTactics = [...new Set(matched.flatMap(t => t.tactics))];
        allTactics.forEach(t => usedTactics.add(t));
        rows.push({ original: line, translated, matched, tactics: allTactics });
    }

    currentRows = rows;
    updateMatchedTechIds(rows);
    renderTable(rows);
    buildTacticFilter(usedTactics);
    showResults();
}

function renderTable(rows) {
    tableBody.innerHTML = '';
    rows.forEach((row, i) => {
        const tr = document.createElement('tr');
        tr.className = 'mapping-row';
        tr.dataset.tactics = row.tactics.join(',');
        tr.style.animationDelay = `${i * 0.05}s`;

        // Col 1 — input
        const isTranslated = row.translated !== row.original.toLowerCase();
        const translatedHtml = isTranslated
            ? `<div class="apt-translated"><i class="fa-solid fa-language"></i> ${row.translated}</div>`
            : '';

        // Col 2 — mapping
        let mappingHtml = '';
        if (row.matched.length === 0) {
            mappingHtml = `<div class="no-match-cell"><i class="fa-solid fa-triangle-exclamation"></i>Không tìm thấy kỹ thuật phù hợp</div>`;
        } else {
            const tacticBadges = [...new Set(row.matched.flatMap(t => t.tactics))]
                .map(renderTacticBadge).join(' ');
            const cards = row.matched.map(renderTechniqueCard).join('');
            mappingHtml = `${tacticBadges}<div class="techniques-list">${cards}</div>`;
        }

        // Col 3 — detected by (Data Components & Sources)
        const detectedByHtml = row.matched.length > 0
            ? `<div class="scenario-block">${renderDetectedBy(row.matched)}</div>`
            : `<div class="no-match-cell">-</div>`;

        // Col 4 — SIEM Mapping (Rules & Tools)
        const toolMappingHtml = row.matched.length > 0
            ? `<div class="scenario-block">${renderToolMapping(row.matched)}</div>`
            : `<div class="no-match-cell">-</div>`;

        tr.innerHTML = `
            <td><div class="apt-action-text">${escHtml(row.original)}</div>${translatedHtml}</td>
            <td>${mappingHtml}</td>
            <td>${detectedByHtml}</td>
            <td>${toolMappingHtml}</td>
        `;
        tableBody.appendChild(tr);
    });
}

function escHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ============================================================
// EVENT DELEGATION FOR MODALS
// ============================================================
tableBody.addEventListener('click', (e) => {
    // Handle coverage matrix tool badge clicks
    const toolBadge = e.target.closest('.cov-tool-badge');
    if (toolBadge) {
        const tcode = toolBadge.dataset.tcode;
        const toolId = toolBadge.dataset.toolid;
        const tool = DETECTION_TOOLS.find(t => t.id === toolId);
        const detEntry = detectionRulesDb[tcode];
        const rules = detEntry && detEntry.rules && detEntry.rules[toolId] ? detEntry.rules[toolId] : [];
        const techName = detEntry ? detEntry.name : tcode;

        if (rules.length > 0) {
            let contentHtml = '';
            rules.forEach((rule, idx) => {
                const refHtml = rule.reference
                    ? `<p><a href="${rule.reference}" target="_blank" style="color:var(--blue-lt);">Xem Reference <i class="fa-solid fa-arrow-up-right-from-square" style="font-size:10px;"></i></a></p>` : '';
                const confCls = rule.confidence === 'High' ? 'conf-high' : rule.confidence === 'Medium' ? 'conf-med' : 'conf-low';
                const confHtml = rule.confidence
                    ? `<li><strong>Confidence:</strong> <span class="${confCls}">${rule.confidence}</span></li>` : '';

                contentHtml += `
                    <div class="rule-box">
                        <h4><i class="fa-solid ${tool.icon}" style="margin-right:6px;"></i>${rule.name}</h4>
                        <code>${escHtml(rule.query)}</code>
                    </div>
                    <ul>
                        <li><strong>Ánh xạ ATT&CK:</strong> ${tcode} — ${techName}</li>
                        ${confHtml}
                    </ul>
                    ${refHtml}
                    ${idx < rules.length - 1 ? '<hr style="border:0;border-top:1px solid rgba(255,255,255,0.1);margin:16px 0;">' : ''}
                `;
            });
            openModal(`Detection Rules — ${tool.label} — ${tcode}`, contentHtml);
        } else {
            openModal(`${tool.label} — ${tcode}`, `
                <div style="padding:30px 0;font-size:14px;text-align:center;">
                    <i class="fa-solid fa-database" style="font-size:40px;display:block;margin-bottom:16px;color:var(--text-muted);opacity:0.5;"></i>
                    <p style="font-size:16px;font-weight:600;color:var(--text-primary);margin-bottom:8px;">Không có dữ liệu</p>
                    <p style="color:var(--text-secondary);font-size:13px;">Chưa có detection rule <strong>${tool.label}</strong> cho kỹ thuật <strong>${tcode}</strong> (${techName}) trong database.</p>
                    <p style="margin-top:12px;color:var(--text-muted);font-size:12px;">Thêm rule vào <code>detection_rules_db.json</code> để hiển thị tại đây.</p>
                </div>
            `);
        }
        return;
    }

    // Legacy: handle old detection-source badge clicks
    const sourceBadge = e.target.closest('.detection-source');
    if (!sourceBadge) return;
    const tcode = sourceBadge.dataset.tcode;
    const catId = sourceBadge.dataset.rulecatid;
    const cat = logSourceCategories.find(c => c.id === catId);
    const catLabel = cat ? cat.label : catId;
    openModal(`${catLabel} — ${tcode}`, '<p>Xem detection_rules_db.json để biết thêm chi tiết.</p>');
});

function openModal(title, content) {
    modalTitle.textContent = title;
    modalContent.innerHTML = content;
    infoModal.style.display = 'flex';
}

// ============================================================
// TACTIC FILTER
// ============================================================
function buildTacticFilter(usedTactics) {
    tacticFilter.innerHTML = '<button class="pill active" data-tactic="all">Tất cả</button>';
    usedTactics.forEach(tac => {
        const label = tac.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        const btn = document.createElement('button');
        btn.className = 'pill';
        btn.dataset.tactic = tac;
        btn.textContent = label;
        tacticFilter.appendChild(btn);
    });

    tacticFilter.querySelectorAll('.pill').forEach(btn => {
        btn.addEventListener('click', () => {
            tacticFilter.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            filterRows(btn.dataset.tactic);
        });
    });
}

function filterRows(tactic) {
    const rows = tableBody.querySelectorAll('.mapping-row');
    let visible = 0;
    rows.forEach(row => {
        const rowTactics = (row.dataset.tactics || '').split(',');
        const show = tactic === 'all' || rowTactics.includes(tactic);
        row.classList.toggle('filtered-out', !show);
        if (show) visible++;
    });
    resultsSummary.textContent = tactic === 'all'
        ? `${rows.length} hành động`
        : `${visible}/${rows.length} hành động`;
}

// ============================================================
// RESULTS STATISTICS
// ============================================================
function updateResultsStats(rows) {
    // Tính toán các số liệu
    const totalActions = rows.length;
    const uniqueTechniques = new Set(rows.flatMap(r => r.matched.map(t => t.id))).size;
    const uniqueTactics = new Set(rows.flatMap(r => r.tactics)).size;
    
    // Đếm detection rules
    let totalRules = 0;
    rows.forEach(row => {
        row.matched.forEach(tech => {
            const detEntry = detectionRulesDb[tech.id] || {};
            for (const tool in (detEntry.rules || {})) {
                const rules = detEntry.rules[tool] || [];
                totalRules += rules.length;
            }
        });
    });
    
    // Tạo HTML cho stats
    const statsHtml = `
        <div class="results-stats-container">
            <div class="stat-item">
                <i class="fa-solid fa-list-check"></i>
                <span class="stat-value">${totalActions}</span>
                <span class="stat-label">Actions</span>
            </div>
            <div class="stat-item">
                <i class="fa-solid fa-bullseye"></i>
                <span class="stat-value">${uniqueTechniques}</span>
                <span class="stat-label">Techniques</span>
            </div>
            <div class="stat-item">
                <i class="fa-solid fa-layer-group"></i>
                <span class="stat-value">${uniqueTactics}</span>
                <span class="stat-label">Tactics</span>
            </div>
            <div class="stat-item">
                <i class="fa-solid fa-shield"></i>
                <span class="stat-value">${totalRules}</span>
                <span class="stat-label">Rules</span>
            </div>
        </div>
    `;
    
    resultsSummary.innerHTML = statsHtml;
}

// ============================================================
// DETECTION MATRIX (COVERAGE EXPLORER)
// ============================================================
const TACTICS_ORDER = [
    'initial-access', 'execution', 'persistence', 'privilege-escalation',
    'defense-evasion', 'credential-access', 'discovery', 'lateral-movement',
    'collection', 'command-and-control', 'exfiltration', 'impact'
];

// Biến global để lưu danh sách technique IDs đã match
let currentMatchedTechIds = new Set();

function updateMatchedTechIds(rows) {
    currentMatchedTechIds = new Set(
        rows.flatMap(r => (r.matched || []).map(t => t.id))
    );
}

function showMatrix(showAll = false) {
    const matrixEl = document.getElementById('matrixContent');
    if (!matrixEl) return;

    // Nếu không showAll và có kết quả đang active → chỉ render matched
    const techsToRender = (!showAll && currentMatchedTechIds.size > 0)
        ? techniques.filter(t => currentMatchedTechIds.has(t.id))
        : techniques;

    // Group theo tactic
    const byTactic = {};
    techsToRender.forEach(t => {
        (t.tactics || ['unknown']).forEach(tac => {
            if (!byTactic[tac]) byTactic[tac] = [];
            byTactic[tac].push(t);
        });
    });

    // Dùng DocumentFragment để tránh reflow liên tục
    const fragment = document.createDocumentFragment();

    Object.entries(byTactic).forEach(([tactic, techs]) => {
        const section = document.createElement('div');
        section.className = 'matrix-tactic-section';

        // Header tactic — clickable để collapse
        section.innerHTML = `
            <div class="matrix-tactic-header" onclick="this.parentElement.classList.toggle('collapsed')">
                <span class="tactic-name">${tactic}</span>
                <span class="tactic-count">${techs.length} techniques</span>
                <i class="fa-solid fa-chevron-down toggle-icon"></i>
            </div>
            <div class="matrix-tactic-body">
                ${techs.map(t => `
                    <div class="matrix-cell ${currentMatchedTechIds.has(t.id) ? 'matched' : ''}"
                         title="${t.id}: ${t.name}">
                        <span class="matrix-cell-id">${t.id}</span>
                        <span class="matrix-cell-name">${t.name}</span>
                    </div>
                `).join('')}
            </div>`;

        fragment.appendChild(section);
    });

    matrixEl.innerHTML = ''; // clear một lần duy nhất
    matrixEl.appendChild(fragment); // insert tất cả một lần

    // Hiện nút toggle
    updateMatrixToggleButton(showAll, techsToRender.length);
    matrixModal.style.display = 'flex';
}

function updateMatrixToggleButton(showAll, count) {
    let btn = document.getElementById('matrixToggleBtn');
    if (!btn) {
        btn = document.createElement('button');
        btn.id = 'matrixToggleBtn';
        btn.className = 'btn-secondary';
        btn.style.marginBottom = '15px';
        document.getElementById('matrixContent')?.before(btn);
    }

    if (showAll) {
        btn.innerHTML = `<i class="fa-solid fa-compress"></i> Chỉ hiện matched (${currentMatchedTechIds.size})`;
        btn.onclick = () => showMatrix(false);
    } else {
        btn.innerHTML = `<i class="fa-solid fa-expand"></i> Xem full matrix (${techniques.length})`;
        btn.onclick = () => showMatrix(true);
    }
}


// ============================================================
// UI STATE HELPERS
// ============================================================
function showEmpty() {
    emptyState.style.display = '';
    loadingState.style.display = 'none';
    resultsSection.style.display = 'none';
    filterSection.style.display = 'none';
    const legend = document.getElementById('toolLegend');
    if (legend) legend.style.display = 'none';
}

function showLoading() {
    emptyState.style.display = 'none';
    loadingState.style.display = '';
    resultsSection.style.display = 'none';
    filterSection.style.display = 'none';
    const legend = document.getElementById('toolLegend');
    if (legend) legend.style.display = 'none';
}

function showResults() {
    emptyState.style.display = 'none';
    loadingState.style.display = 'none';
    resultsSection.style.display = '';
    filterSection.style.display = '';
    updateResultsStats(currentRows);
    const legend = document.getElementById('toolLegend');
    if (legend) legend.style.display = 'flex';
}

// ============================================================
// START
// ============================================================
init();

// ── Handle ?from=scenario ─────────────────────────────────────
(function checkScenarioImport() {
    const params = new URLSearchParams(window.location.search);
    if (params.get('from') !== 'scenario') return;

    // Clean URL ngay
    window.history.replaceState({}, '', 'index.html');

    // Hiển thị banner ngay lập tức để user biết đang xử lý
    function showImportBanner(msg, color) {
        let banner = document.getElementById('importBanner');
        if (!banner) {
            banner = document.createElement('div');
            banner.id = 'importBanner';
            banner.style.cssText = `position:fixed;top:0;left:0;right:0;z-index:9999;padding:12px 20px;
                display:flex;align-items:center;gap:10px;font-size:13px;font-weight:600;
                background:#0e1628;border-bottom:2px solid ${color};color:#e8edf6;
                box-shadow:0 4px 20px rgba(0,0,0,0.4);`;
            document.body.appendChild(banner);
        }
        banner.style.borderBottomColor = color;
        banner.innerHTML = msg;
    }
    showImportBanner(
        `<i class="fa-solid fa-circle-notch fa-spin" style="color:#60a5fa"></i> Đang tải kịch bản và chuẩn bị mapping...`,
        '#3b82f6'
    );

    const raw = localStorage.getItem('sc_import');
    if (!raw) return;

    let data;
    try { data = JSON.parse(raw); } catch(e) { return; }

    // Kiểm tra TTL 60 giây
    if (!data || Date.now() - (data.ts||0) > 60000) {
        localStorage.removeItem('sc_import');
        return;
    }
    localStorage.removeItem('sc_import');

    const behaviors = data.behaviors || '';
    if (!behaviors.trim()) return;

    // Đợi DB load xong rồi populate + trigger
    const MAX_WAIT = 15000;
    const started = Date.now();
    const waitAndPopulate = setInterval(() => {
        if (Date.now() - started > MAX_WAIT) {
            clearInterval(waitAndPopulate);
            showImportBanner(`<i class="fa-solid fa-circle-exclamation" style="color:#f87171"></i> Không thể tải kịch bản — database load timeout`, '#ef4444');
            setTimeout(() => { const b = document.getElementById('importBanner'); if(b) b.remove(); }, 4000);
            return;
        }
        if (techniques.length === 0) return; // chưa load xong

        clearInterval(waitAndPopulate);

        // Cập nhật banner
        showImportBanner(
            `<i class="fa-solid fa-circle-check" style="color:#10b981"></i> Đã tải kịch bản: <strong style="color:#c084fc;margin-left:4px">${data.name||''}</strong> — đang mapping...`,
            '#10b981'
        );

        // Điền vào textarea
        aptInput.value = behaviors;
        aptInput.disabled = false;
        mapBtn.disabled = false;
        clearBtn.disabled = false;
        matrixBtn.disabled = false;

        // Trigger mapping sau 300ms, dismiss banner sau 4s
        setTimeout(() => {
            mapBtn.click();
            setTimeout(() => { const b = document.getElementById('importBanner'); if(b) { b.style.transition='opacity 0.4s'; b.style.opacity='0'; setTimeout(()=>b.remove(),400); } }, 4000);
        }, 300);
    }, 200);
})();

