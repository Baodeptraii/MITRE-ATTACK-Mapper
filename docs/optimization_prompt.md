# 🎯 ATT&CK Mapper - Optimization Prompt v1.0

## 📋 PROJECT CONTEXT

**Project**: ATT&CK Mapper - Dynamic Rule Mapping & Scenario Explorer  
**Tech Stack**: HTML5 + Vanilla JS + CSS3 (no framework)  
**Scope**: Refactor 5 major issues + split scenarios into dedicated page  
**Files to Modify**:
- `src/js/app.js` (main mapping logic)
- `src/js/scenarios.js` (scenario management)
- `src/css/style.css` + `src/css/scenarios.css` (styling)
- `index.html` (structure)
- `scenarios.html` (NEW - dedicated page)

---

## 🔴 ISSUES TO FIX (Priority Order)

### Issue #1: Hiệu Suất Scenario Loading Kém
**Current Problem**:
- `fetchAllScenarios()` fetches + validates ALL YAML files before rendering ANY card
- With 50+ scenarios: 5-10 seconds wait
- No pagination, lazy loading, or progressive rendering

**Requirements**:
- ✅ Implement **Lazy Loading with Intersection Observer**
  - Load first 20 scenarios immediately
  - Fetch next batch when user scrolls near bottom
  - Show loading skeleton for upcoming batch
  
- ✅ **Progressive Rendering** (card-by-card, not batch)
  - Render cards as they validate, don't wait for all validation
  - Use `requestAnimationFrame` for smooth rendering
  
- ✅ **Advanced Caching Strategy**
  - Cache validated scenarios in IndexedDB (persist across sessions)
  - Fallback to localStorage for small dataset
  - Cache TTL: 7 days (configurable)
  - Provide manual "Clear Cache" button in settings
  
- ✅ **Metadata-Only First Load**
  - First fetch only filename + source
  - Load full YAML only when user clicks "View Details"
  - Lazy-fetch YAML inside detail modal

**Acceptance Criteria**:
- Scenarios section loads & shows first 20 cards in < 2 seconds
- Detail modal lazy-loads YAML on demand (not preloaded)
- Scrolling triggers next batch fetch without blocking UI
- Cache persists across page reloads

---

### Issue #2: Mapping Results Không Liên Kết Đến Scenarios
**Current Problem**:
- Result table shows: APT Input → T-Code → Data Sources → Tools
- Does NOT show scenarios containing the technique
- User can't discover related scenarios after mapping

**Requirements**:
- ✅ **Add 5th Column: "Related Scenarios"**
  - For each T-Code in mapping results, find all scenarios containing it
  - Show as pill/badge: `[ART] [CALDERA] [Custom]` with count
  - Badge click → filter scenarios panel by this T-Code
  
- ✅ **Smart Scenario Filtering UI** (in dedicated scenarios page)
  - Filter by: Tactic, Platform, T-Code, Name/Description
  - Multi-select filters (e.g., show scenarios for "T1059 OR T1086")
  - "Show scenarios for this result" quick-link from mapping table
  
- ✅ **Highlight Matching Scenarios**
  - In scenarios grid, highlight cards that match current mapping
  - Add visual indicator (e.g., green border, star icon, "Matches Active Result")
  - Auto-scroll scenarios page to matched cards

**Acceptance Criteria**:
- Result table has "Related Scenarios" column
- Clicking scenario badge auto-filters scenarios page
- Matched scenarios highlight visually when result is active
- Performance: filter/highlight completes in < 100ms

---

### Issue #3: Modal Management Phức Tạp & Lặp Lại Code
**Current Problem**:
- 4 separate modals: `infoModal`, `matrixModal`, `scenarioDetailModal`, `toolDetailModal`
- Close logic duplicated in each modal
- Backdrop click handler repeated
- No reusable modal component
- Header/footer/animation code scattered

**Requirements**:
- ✅ **Create Universal Modal Factory** (`class ModalManager`)
  ```javascript
  ModalManager.open({
    title: "Detection Rules — T1059.001",
    tabs: [
      { label: "Rules", content: "...", icon: "fa-list" },
      { label: "Coverage", content: "...", icon: "fa-chart" }
    ],
    size: "large", // small | normal | large
    closable: true,
    onClose: () => {}
  })
  ```
  
- ✅ **Reusable Modal HTML** (1 template, multiple instances)
  - Replace 4 modals with 1 `<div id="universalModal">`
  - Dynamically render tabs, content, footer
  - Shared CSS for animation, backdrop, sizing
  
- ✅ **Tab System in Modal**
  - Each modal can have 0+ tabs (Metadata, YAML, Code, etc)
  - Tab switching without re-rendering modal
  - Lazy-load tab content on click
  
- ✅ **Improved Animations**
  - Entrance: fade-in + slide-up (200ms)
  - Exit: fade-out + slide-down (200ms)
  - No jank, use CSS transitions

**Acceptance Criteria**:
- All 4 modals use `ModalManager.open()`
- Only 1 modal DOM node in HTML
- Modal code reduced by 60%+ lines
- Opening different modal types works without reload
- Animations smooth (60fps)

---

### Issue #4: YAML Validation Quá Đơn Giản
**Current Problem**:
```javascript
function validateYAML(text, source) {
    if (!text || text.length < 50) return null;
    try { parsed = jsyaml.load(text); } catch (e) { return null; }
    // ❌ No T-Code format validation
    // ❌ No required field checking per source type
    // ❌ No helpful error messages
}
```

**Requirements**:
- ✅ **Comprehensive Validation Schema**
  ```javascript
  ART_SCHEMA = {
    required: ['attack_technique', 'atomic_tests'],
    fields: {
      attack_technique: { type: 'string', format: 'tcode_regex' },
      atomic_tests: { type: 'array', minLength: 1 }
    }
  }
  
  CALDERA_SCHEMA = {
    required: ['id', 'name', 'steps'] OR ['name', 'technique', 'tactic'],
    fields: {
      steps: { type: 'array', minLength: 1 }
    }
  }
  ```
  
- ✅ **T-Code Format Validation**
  - Regex: `T\d{4}(\.\d{3})?` (e.g., T1059, T1059.001)
  - Validate ALL T-codes found in YAML against STIX database
  - Warn if T-code doesn't exist in current ATT&CK version
  
- ✅ **Detailed Error Messages**
  - "Missing required field: `attack_technique`"
  - "Invalid T-Code format in atomic_tests[0]: `T99`"
  - "Unknown T-Code: `T9999` (not in ATT&CK v14.1)"
  - "File size too small (< 50 bytes)"
  
- ✅ **Upload Error UI**
  - Clear, red error box with specific issue
  - Highlight problematic lines in preview (if YAML parses)
  - "Fix & Try Again" button with suggestions

**Acceptance Criteria**:
- Validation catches 100% of ART/CALDERA structure issues
- Error messages are actionable (not generic)
- T-Codes validated against STIX data
- Upload error display is clear & helpful
- Invalid YAML rejected before adding to scenarios

---

### Issue #5: Tách Scenarios Thành Trang Riêng
**Current Problem**:
- Scenarios panel embedded in `index.html` main page
- Competes with mapping results for space
- Difficult to manage scenarios without seeing mapping
- No dedicated URL for scenario management

**Requirements**:
- ✅ **Create `scenarios.html`** (New dedicated page)
  - URL: `/scenarios.html`
  - Same header/footer as index.html
  - Full-width scenarios grid (4-5 columns, not cramped)
  
- ✅ **Features in Scenarios Page**:
  - Filter by: Tactic, Platform, Source (ART/CALDERA/Custom)
  - Search: name, description, T-Code
  - Sort: name, date added, T-Code count
  - Upload custom scenarios (drag-drop + file input)
  - Bulk delete/export
  - View scenario detail (tabs: Metadata, YAML, Preview)
  - "Use in Mapping" button → switch to index.html with scenario loaded
  
- ✅ **Navigation**:
  - Header menu: "Mapping" (index.html) | "Scenarios" (scenarios.html)
  - From index.html: "Browse More Scenarios" button → scenarios.html
  - From scenarios.html: "Map Using This" → load scenario into index.html
  
- ✅ **Shared State Management**
  - sessionStorage to pass scenario selection between pages
  - Or use URL params: `index.html?scenario=T1059.001`
  - Sync custom scenarios list across both pages
  
- ✅ **Responsive Design**
  - Desktop: 4-5 columns grid
  - Tablet: 2-3 columns
  - Mobile: 1 column (or hide scenarios page, show msg)

**Acceptance Criteria**:
- New `scenarios.html` page loads and displays 20+ scenarios
- Advanced filtering/search works smoothly
- Upload → custom scenario appears immediately
- Switch to mapping page → scenario auto-loads if selected
- Sync works (upload on scenarios page → visible on index.html)

---

## ✅ IMPLEMENTATION ORDER

### Phase 1: Foundation (Issues #3 + #4)
**Why first?** Modal refactor + validation improve DX for testing other features

1. **ModalManager class** (new file: `src/js/modal.js`)
   - Centralized modal logic
   - Replace all 4 modal .addEventListener code

2. **Enhanced YAML validation** (in `scenarios.js`)
   - Add validation schemas
   - Add detailed error messages
   - Update upload error display

3. **Update all modal usage** (in `app.js` + `scenarios.js`)
   - Replace old modal.open() calls with ModalManager.open()
   - Test all modal types work

### Phase 2: Performance + UX (Issues #1 + #2)
**Why after foundation?** Easier to implement on refactored codebase

4. **Lazy loading** (in `scenarios.js`)
   - Implement Intersection Observer
   - Load-on-scroll logic
   - IndexedDB caching

5. **Result ↔ Scenario linking** (in `app.js` + `scenarios.js`)
   - Add "Related Scenarios" column to result table
   - Filter scenarios by T-Code
   - Highlight matched scenarios

### Phase 3: New Page (Issue #5)
**Why last?** Depends on all previous refactoring

6. **Create `scenarios.html`**
   - Copy header/footer from index.html
   - Import shared CSS + scenarios.js
   - Full-featured scenario manager

7. **Navigation + State Sync**
   - Add menu links (index ↔ scenarios)
   - Implement sessionStorage sync
   - Test data persistence

---

## 📊 TESTING CHECKLIST

### Performance Tests
- [ ] Scenarios page loads first 20 cards in < 2 sec (cold cache)
- [ ] First 20 cards render in < 500ms (warm cache)
- [ ] Scroll triggers next batch fetch without UI stall
- [ ] Cache persists across browser reload

### Functionality Tests
- [ ] Upload invalid YAML → clear error message shown
- [ ] Upload valid ART YAML → parsed correctly, T-Codes extracted
- [ ] Upload valid CALDERA YAML → scenario added to list
- [ ] Filter scenarios by tactic → displays only matching scenarios
- [ ] Click "Related Scenarios" in result table → filters to matching scenarios
- [ ] Switch to mapping page → selected scenario auto-loads

### UX Tests
- [ ] Modal opens/closes smoothly (no jank)
- [ ] Tab switching in modal works instantly
- [ ] Detail modal lazy-loads YAML on first tab click
- [ ] Error messages are actionable (not confusing)
- [ ] scenarios.html renders correctly on desktop/tablet/mobile

### Integration Tests
- [ ] Upload custom scenario on scenarios.html
- [ ] Switch to index.html → custom scenario visible in "Related Scenarios"
- [ ] Mapping result shows correct scenario count in "Related Scenarios"
- [ ] All 4 modal types (rule info, matrix, scenario detail, tool detail) work with ModalManager

---

## 📝 CODE STRUCTURE (After Optimization)

```
src/
  js/
    app.js                    (mapping logic - use ModalManager)
    scenarios.js              (scenario management - refactored)
    modal.js          [NEW]   (ModalManager class)
    validators.js     [NEW]   (YAML validation schemas)
  css/
    style.css                 (main styles)
    scenarios.css             (updated for new page layout)
    modal.css         [NEW]   (universal modal styles)
index.html                    (mapping page - no scenarios panel)
scenarios.html        [NEW]   (dedicated scenarios management page)
```

---

## 🎬 SUCCESS CRITERIA (Overall)

✅ All 5 issues resolved  
✅ Performance: scenarios page < 2sec initial load  
✅ UX: Mapping results link to scenarios seamlessly  
✅ Code: 40%+ reduction in duplicate modal/validation code  
✅ Testing: 100% of checklist items pass  
✅ User can: Upload, manage, filter, and use scenarios on dedicated page  
