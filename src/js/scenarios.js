// scenarios.js — Standalone Scenarios Page Logic
(function(){
const ART_API='https://api.github.com/repos/Baodeptraii/AttackTrafficGenerator/contents/ART_YAML_Scenarios';
const CAL_API='https://api.github.com/repos/Baodeptraii/AttackTrafficGenerator/contents/CALDERA_YAML_Scenarios';
const RULES_URL='data/rules_db.json';
const CACHE_KEY='scenario_v3';const CACHE_TTL=600000;
const TRE=/T\d{4}(?:\.\d{3})?/g;
let list=[],customs=[],rulesDb={};
let tFilter='all',pFilter='all',query='';
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

function toast(m,t='success'){
  let c=$('toastContainer');
  if(!c){c=document.createElement('div');c.id='toastContainer';c.className='toast-container';document.body.appendChild(c);}
  const ic={success:'fa-circle-check',error:'fa-circle-xmark',warning:'fa-triangle-exclamation'};
  const cl={success:'var(--green)',error:'var(--red)',warning:'var(--amber)'};
  const e=document.createElement('div');e.className='toast '+t;
  e.innerHTML=`<i class="fa-solid ${ic[t]||ic.success}" style="color:${cl[t]}"></i><span class="toast-msg">${m}</span>`;
  c.appendChild(e);setTimeout(()=>{e.classList.add('hiding');setTimeout(()=>e.remove(),300);},4000);
}
function debounce(fn,ms){let t;return(...a)=>{clearTimeout(t);t=setTimeout(()=>fn(...a),ms);};}

// Cache
const cache={
  get(){try{const r=localStorage.getItem(CACHE_KEY);if(!r)return null;const c=JSON.parse(r);if(Date.now()-c.ts<CACHE_TTL)return c.data;}catch(e){}return null;},
  set(d){try{localStorage.setItem(CACHE_KEY,JSON.stringify({ts:Date.now(),data:d}));}catch(e){}},
  bust(){localStorage.removeItem(CACHE_KEY);}
};

// Detect type
function detectType(y){
  if(y.abilities&&y.atomic_ordering)return'CALDERA';
  if(y.atomic_tests&&y.attack_technique)return'ART';
  if(y.id&&y.name&&y.steps)return'CALDERA';
  if(y.name&&y.technique&&y.tactic)return'CALDERA';
  return null;
}

// Extract T-codes
function extractTCodes(y,type){
  const codes=new Set();
  if(type==='ART'){
    if(y.attack_technique){const m=String(y.attack_technique).match(TRE);if(m)m.forEach(t=>codes.add(t));}
    if(y.atomic_tests)y.atomic_tests.forEach(t=>{if(t.name){const m=t.name.match(TRE);if(m)m.forEach(c=>codes.add(c));}});
  }else{
    if(y.abilities)Object.values(y.abilities).forEach(a=>{if(a.technique_id)codes.add(a.technique_id);});
    if(y.technique){const m=String(y.technique).match(TRE);if(m)m.forEach(t=>codes.add(t));}
    if(y.steps)y.steps.forEach(s=>{if(s.technique){const m=String(s.technique).match(TRE);if(m)m.forEach(t=>codes.add(t));}});
  }
  return[...codes];
}

// Extract platforms
function extractPlatforms(y,type){
  const p=new Set();
  if(type==='ART'){
    if(y.atomic_tests)y.atomic_tests.forEach(t=>{if(t.supported_platforms)t.supported_platforms.forEach(x=>p.add(x));});
  }else{
    if(y.abilities)Object.values(y.abilities).forEach(a=>{
      if(a.executors){
        (Array.isArray(a.executors)?a.executors:Object.values(a.executors)).forEach(e=>{
          if(e&&e.platform)p.add(e.platform);
          if(typeof e==='object')Object.values(e).forEach(v=>{if(v&&v.platform)p.add(v.platform);});
        });
      }
    });
    if(y.steps)y.steps.forEach(s=>{if(s.platform)p.add(s.platform);});
  }
  return[...p];
}

// Extract kill chain
function extractKillChain(y,type){
  if(type==='CALDERA'&&y.atomic_ordering&&y.abilities){
    return y.atomic_ordering.map((id,i)=>{
      const a=y.abilities[id]||{};
      let plat='';
      if(a.executors){const ex=Array.isArray(a.executors)?a.executors[0]:Object.values(a.executors)[0];
        if(ex)plat=ex.platform||(typeof ex==='object'?Object.values(ex)[0]?.platform:'');}
      return{id,name:a.name||`Step ${i+1}`,tactic:a.tactic||'',technique_id:a.technique_id||'',technique_name:a.technique_name||'',platform:plat||'',command:a.executors?JSON.stringify(a.executors):'',step:i+1};
    });
  }
  if(type==='ART'&&y.atomic_tests){
    return y.atomic_tests.map((t,i)=>({
      id:t.auto_generated_guid||`step-${i}`,name:t.name||`Step ${i+1}`,tactic:'',
      technique_id:(t.name?.match(TRE)||[y.attack_technique])[0]||'',technique_name:t.name||'',
      platform:(t.supported_platforms||[])[0]||'',command:t.executor?.command||'',step:i+1
    }));
  }
  if(y.steps)return y.steps.map((s,i)=>({id:`step-${i}`,name:s.name||`Step ${i+1}`,tactic:s.tactic||'',
    technique_id:s.technique||'',technique_name:s.name||'',platform:s.platform||'',command:s.command||'',step:i+1}));
  return[];
}

// Build scenario metadata
function buildMeta(parsed,source,filename,rawUrl,yamlText){
  const type=detectType(parsed);
  if(!type)return null;
  const tcodes=extractTCodes(parsed,type);
  const platforms=extractPlatforms(parsed,type);
  const kc=extractKillChain(parsed,type);
  const name=parsed.display_name||parsed.name||filename.replace(/\.(ya?ml)$/i,'');
  const desc=String(parsed.description||parsed.atomic_tests?.[0]?.description||'').substring(0,200);
  return{name,type,filename,raw_url:rawUrl,tcodes,platforms,killChain:kc,
    description:desc.trim(),stepCount:kc.length,source,yamlText,parsed};
}

// Fetch file list from GitHub
async function fetchFiles(api,source){
  const r=await fetch(api,{headers:{'Accept':'application/vnd.github.v3+json'}});
  if(r.status===403)throw new Error('GitHub API rate limit — thử lại sau vài phút');
  if(!r.ok)throw new Error('GitHub API error: '+r.status);
  const files=await r.json();
  return files.filter(f=>f.type==='file'&&/\.(ya?ml)$/i.test(f.name)&&f.size>=50)
    .map(f=>({filename:f.name,source,raw_url:f.download_url,size:f.size}));
}

// Fetch and validate single YAML
async function fetchOne(item){
  try{
    const r=await fetch(item.raw_url);if(!r.ok)return null;
    const text=await r.text();
    let parsed;try{parsed=jsyaml.load(text);}catch(e){return null;}
    if(!parsed||typeof parsed!=='object')return null;
    return buildMeta(parsed,item.source,item.filename,item.raw_url,text);
  }catch(e){console.warn('[Scenarios]',item.filename,e);return null;}
}

// Load all scenarios
async function loadAll(bust=false){
  if(bust)cache.bust();
  const cached=cache.get();
  if(cached){list=cached;return;}
  const[artF,calF]=await Promise.all([
    fetchFiles(ART_API,'ART').catch(e=>{toast(e.message,'error');return[];}),
    fetchFiles(CAL_API,'CALDERA').catch(()=>[])
  ]);
  const results=await Promise.all([...artF,...calF].map(fetchOne));
  list=results.filter(Boolean);
  cache.set(list);
}

// Load rules DB
async function loadRules(){
  try{const r=await fetch(RULES_URL);if(r.ok)rulesDb=await r.json();}catch(e){}
}

// Check if technique has rule
function hasRule(tid){return rulesDb[tid]&&rulesDb[tid].length>0;}

// Filter + search
function getFiltered(){
  let res=[...list,...customs];
  if(tFilter!=='all')res=res.filter(s=>s.type.toLowerCase()===tFilter.toLowerCase());
  if(pFilter!=='all')res=res.filter(s=>s.platforms.some(p=>p.toLowerCase()===pFilter));
  if(query){
    const q=query.toLowerCase();
    res=res.filter(s=>{
      if((s.name||'').toLowerCase().includes(q))return true;
      if(s.tcodes.some(t=>t.toLowerCase().includes(q)))return true;
      if(s.killChain.some(k=>(k.tactic||'').toLowerCase().includes(q)))return true;
      return false;
    });
  }
  return res;
}

// Render cards
function renderCards(){
  const grid=$('scenarioGrid'),empty=$('scenarioEmpty'),load=$('scenarioLoading');
  if(load)load.style.display='none';
  const filtered=getFiltered();
  if(!filtered.length){grid.innerHTML='';if(empty)empty.style.display='';return;}
  if(empty)empty.style.display='none';
  const frag=document.createDocumentFragment();
  filtered.forEach((s,i)=>{
    const card=document.createElement('div');card.className='scenario-card';
    card.style.animation=`fadeInUp 0.3s ease-out ${i*0.04}s both`;
    const tc=s.tcodes||[],showTc=tc.slice(0,5),more=tc.length>5?tc.length-5:0;
    const platHtml=s.platforms.map(p=>`<span class="platform-badge ${esc(p.toLowerCase())}">${esc(p)}</span>`).join('');
    card.innerHTML=`
      <div class="scenario-card-header">
        <div class="scenario-card-name">${esc(s.name)}</div>
        <span class="source-badge ${s.type.toLowerCase()}">${esc(s.type)}</span>
      </div>
      <div class="scenario-card-desc">${esc(s.description||'Kịch bản diễn tập tấn công')}</div>
      <div class="scenario-tech-pills">
        ${showTc.map(t=>`<span class="scenario-tech-pill">${esc(t)}</span>`).join('')}
        ${more?`<span class="scenario-tech-pill more">+${more}</span>`:''}
      </div>
      <div class="scenario-card-meta">
        <span class="scenario-meta-item"><i class="fa-solid fa-crosshairs"></i><span class="meta-value">${tc.length}</span> T-Code${tc.length!==1?'s':''}</span>
        <span class="scenario-meta-item"><i class="fa-solid fa-list-ol"></i><span class="meta-value">${s.stepCount}</span> bước</span>
        ${platHtml}
      </div>
      <div class="scenario-card-actions">
        <button class="btn btn-ghost" data-action="detail" data-idx="${i}"><i class="fa-solid fa-eye"></i> Xem chi tiết</button>
        <button class="btn btn-use-scenario" data-action="use" data-idx="${i}"><i class="fa-solid fa-crosshairs"></i> Kiểm tra mapping</button>
      </div>`;
    frag.appendChild(card);
  });
  grid.innerHTML='';grid.appendChild(frag);
  grid.onclick=e=>{
    const btn=e.target.closest('[data-action]');if(!btn)return;
    const s=filtered[parseInt(btn.dataset.idx)];if(!s)return;
    if(btn.dataset.action==='detail')openDetail(s);
    else if(btn.dataset.action==='use')useScenario(s);
  };
}

// YAML highlight
function hlYAML(t){
  return esc(t).replace(/^(\s*#.*)$/gm,'<span class="yaml-comment">$1</span>')
    .replace(/(T\d{4}(?:\.\d{3})?)/g,'<span class="yaml-tcode">$1</span>')
    .replace(/^(\s*[\w_.-]+)(\s*:)/gm,'<span class="yaml-key">$1</span>$2')
    .replace(/:\s+(true|false|yes|no|null)\s*$/gim,': <span class="yaml-bool">$1</span>')
    .replace(/:\s+(\d+(?:\.\d+)?)\s*$/gm,': <span class="yaml-number">$1</span>');
}

// Open detail modal
async function openDetail(s){
  const modal=$('scenarioDetailModal'),title=$('scenarioModalTitle'),body=$('scenarioModalBody');
  if(!modal)return;
  title.innerHTML=`<span class="source-badge ${s.type.toLowerCase()}">${esc(s.type)}</span> ${esc(s.name)}`;
  body.innerHTML='<div style="text-align:center;padding:40px"><i class="fa-solid fa-circle-notch fa-spin" style="font-size:28px;color:var(--blue)"></i></div>';
  modal.style.display='flex';
  let yamlText=s.yamlText,parsed=s.parsed;
  if(!yamlText&&s.raw_url){
    try{const r=await fetch(s.raw_url);yamlText=await r.text();parsed=jsyaml.load(yamlText);}
    catch(e){body.innerHTML=`<div class="scenario-error-state"><i class="fa-solid fa-circle-exclamation"></i><h3>Lỗi tải</h3><p>${esc(e.message)}</p></div>`;return;}
  }
  const kc=s.killChain||extractKillChain(parsed,s.type);
  const tc=s.tcodes||[];
  // Tabs
  body.innerHTML=`
    <div class="scenario-detail-tabs">
      <button class="scenario-detail-tab active" data-tab="killchain"><i class="fa-solid fa-route"></i> Kill Chain</button>
      <button class="scenario-detail-tab" data-tab="yaml"><i class="fa-solid fa-code"></i> Raw YAML</button>
    </div>
    <div class="scenario-detail-panel active" data-panel="killchain">${renderKC(kc)}</div>
    <div class="scenario-detail-panel" data-panel="yaml">
      <div class="yaml-code-wrapper">
        <div class="yaml-code-toolbar">
          <span>${esc(s.filename)} (${((yamlText||'').length/1024).toFixed(1)} KB)</span>
          <button class="yaml-copy-btn" id="yamlCopyBtn"><i class="fa-regular fa-copy"></i> Copy</button>
        </div>
        <pre class="yaml-code-block">${hlYAML(yamlText||'')}</pre>
      </div>
    </div>`;
  // Tab switch
  body.querySelectorAll('.scenario-detail-tab').forEach(tab=>{
    tab.onclick=()=>{
      body.querySelectorAll('.scenario-detail-tab').forEach(t=>t.classList.remove('active'));
      body.querySelectorAll('.scenario-detail-panel').forEach(p=>p.classList.remove('active'));
      tab.classList.add('active');
      body.querySelector(`[data-panel="${tab.dataset.tab}"]`).classList.add('active');
    };
  });
  // Copy
  const cb=$('yamlCopyBtn');
  if(cb)cb.onclick=async()=>{
    try{await navigator.clipboard.writeText(yamlText);cb.innerHTML='<i class="fa-solid fa-check"></i> Đã copy';cb.classList.add('copied');
      setTimeout(()=>{cb.innerHTML='<i class="fa-regular fa-copy"></i> Copy';cb.classList.remove('copied');},2000);}
    catch(e){toast('Không thể copy','error');}
  };
  // Command expand
  body.querySelectorAll('.kc-step-expand').forEach(btn=>{
    btn.onclick=()=>{const cmd=btn.parentElement.querySelector('.kc-step-command');
      if(cmd){cmd.classList.toggle('open');btn.textContent=cmd.classList.contains('open')?'▲ Ẩn command':'▼ Xem command';}};
  });
  // Footer buttons
  const useBtn=$('scenarioModalUseBtn');
  if(useBtn)useBtn.onclick=()=>{modal.style.display='none';useScenario(s);};
  const expBtn=$('exportReportBtn');
  if(expBtn)expBtn.onclick=()=>exportYAML(s);
}

// Render Kill Chain tab
function renderKC(kc){
  if(!kc.length)return'<div class="scenario-empty-state"><p>Không có dữ liệu kill chain</p></div>';
  let html='<div class="killchain-timeline">';
  kc.forEach((step,i)=>{
    if(i>0)html+='<div class="kc-step-connector"><i class="fa-solid fa-arrow-right"></i></div>';
    const tacCls=step.tactic?'tactic-'+step.tactic.replace(/\s+/g,'-'):'tactic-default';
    html+=`<div class="kc-step">
      <div class="kc-step-num">${step.step||i+1}</div>
      ${step.tactic?`<span class="kc-step-tactic tactic-badge ${tacCls}">${esc(step.tactic)}</span>`:''}
      <div class="kc-step-tcode">${esc(step.technique_id||'N/A')}</div>
      <div class="kc-step-name" title="${esc(step.name)}">${esc(step.name)}</div>
      ${step.platform?`<span class="platform-badge ${step.platform.toLowerCase()} kc-step-platform">${esc(step.platform)}</span>`:''}
      ${step.command?`<button class="kc-step-expand">▼ Xem command</button><div class="kc-step-command"><pre>${esc(String(step.command))}</pre></div>`:''}
    </div>`;
  });
  return html+'</div>';
}


// Use scenario — gửi sang index.html để mapping
function useScenario(s){
  // Dùng behaviors từ kill chain, fallback sang tên kịch bản
  let behaviors=(s.killChain||[]).map(k=>{
    const parts=[];
    if(k.technique_id)parts.push(k.technique_id);
    if(k.name)parts.push(k.name);
    return parts.join(' - ');
  }).filter(Boolean);

  // Nếu không có kill chain, dùng tên kịch bản + tcodes
  if(!behaviors.length && s.tcodes&&s.tcodes.length){
    behaviors=s.tcodes.map(t=>`${t} - ${s.name}`);
  }
  if(!behaviors.length){toast('Kịch bản không có dữ liệu để mapping','warning');return;}

  // Lưu vào localStorage với TTL 60 giây (đủ để chuyển trang)
  const payload={name:s.name,behaviors:behaviors.join('\n'),tcodes:s.tcodes||[],ts:Date.now()};
  localStorage.setItem('sc_import',JSON.stringify(payload));
  toast(`Đang chuyển sang Mapper: ${s.name}`);
  window.location.href='index.html?from=scenario';
}

// Export YAML
function exportYAML(s){
  const yamlText=s.yamlText;
  if(!yamlText){toast('Không có dữ liệu YAML để export','warning');return;}
  const blob=new Blob([yamlText],{type:'text/yaml'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download=s.filename||`${(s.name||'scenario').replace(/\s+/g,'_')}.yml`;a.click();
  toast('Đã export YAML');
}

// Upload
function handleUpload(file){
  const err=$('uploadError'),suc=$('uploadSuccess');
  if(err){err.classList.remove('visible');err.textContent='';}
  if(suc)suc.classList.remove('visible');
  if(!file)return;
  if(!/\.(ya?ml)$/i.test(file.name)){if(err){err.textContent='Chỉ chấp nhận file .yml hoặc .yaml';err.classList.add('visible');}return;}
  const reader=new FileReader();
  reader.onload=e=>{
    const text=e.target.result;
    if(text.length<50){if(err){err.textContent='File quá nhỏ hoặc rỗng';err.classList.add('visible');}return;}
    let parsed;try{parsed=jsyaml.load(text);}catch(ex){if(err){err.textContent='YAML parse error: '+ex.message;err.classList.add('visible');}return;}
    const meta=buildMeta(parsed,'Custom',file.name,null,text);
    if(!meta){if(err){err.textContent='Không nhận dạng được format — file phải là ART hoặc CALDERA YAML';err.classList.add('visible');}return;}
    meta.source='Custom';customs.push(meta);renderCards();
    if(suc){suc.textContent=`Đã thêm: ${meta.name}`;suc.classList.add('visible');}
    toast(`Đã thêm kịch bản: ${meta.name}`);
  };
  reader.readAsText(file);
}

// Init
async function init(){
  const load=$('scenarioLoading');if(load)load.style.display='';
  await loadRules();
  try{await loadAll();renderCards();}
  catch(e){if(load)load.style.display='none';
    const grid=$('scenarioGrid');
    if(grid)grid.innerHTML=`<div class="scenario-error-state"><i class="fa-solid fa-circle-exclamation"></i><h3>Lỗi</h3><p>${esc(e.message)}</p><button class="btn btn-ghost" onclick="location.reload()"><i class="fa-solid fa-rotate-right"></i> Thử lại</button></div>`;
  }
}

// Events
document.addEventListener('DOMContentLoaded',()=>{
  init();
  // Search
  const si=$('searchInput');
  if(si)si.addEventListener('input',debounce(()=>{query=si.value.trim();renderCards();},300));
  // Type filter
  document.querySelectorAll('#typeFilters .scenario-filter-btn').forEach(b=>{
    b.addEventListener('click',()=>{
      document.querySelectorAll('#typeFilters .scenario-filter-btn').forEach(x=>x.classList.remove('active'));
      b.classList.add('active');tFilter=b.dataset.filter;renderCards();
    });
  });
  // Platform filter
  document.querySelectorAll('#platformFilters .scenario-filter-btn').forEach(b=>{
    b.addEventListener('click',()=>{
      document.querySelectorAll('#platformFilters .scenario-filter-btn').forEach(x=>x.classList.remove('active'));
      b.classList.add('active');pFilter=b.dataset.platform;renderCards();
    });
  });
  // Refresh
  const rb=$('refreshBtn');
  if(rb)rb.addEventListener('click',async()=>{list=[];const l=$('scenarioLoading');if(l)l.style.display='';
    $('scenarioGrid').innerHTML='';try{await loadAll(true);renderCards();toast('Đã làm mới');}catch(e){toast(e.message,'error');}});
  // Upload
  const ui=$('uploadInput');if(ui)ui.addEventListener('change',e=>{if(e.target.files[0])handleUpload(e.target.files[0]);e.target.value='';});
  const sui=$('scenarioUploadInput');if(sui)sui.addEventListener('change',e=>{if(e.target.files[0])handleUpload(e.target.files[0]);e.target.value='';});
  const uz=$('scenarioUploadZone');
  if(uz){
    uz.addEventListener('dragover',e=>{e.preventDefault();uz.classList.add('dragover');});
    uz.addEventListener('dragleave',()=>uz.classList.remove('dragover'));
    uz.addEventListener('drop',e=>{e.preventDefault();uz.classList.remove('dragover');if(e.dataTransfer.files[0])handleUpload(e.dataTransfer.files[0]);});
  }
  // Modal close
  const modal=$('scenarioDetailModal'),closeBtn=$('closeScenarioModalBtn');
  if(closeBtn)closeBtn.addEventListener('click',()=>{if(modal)modal.style.display='none';});
  if(modal)modal.addEventListener('click',e=>{if(e.target===modal)modal.style.display='none';});

  // Handle ?action=upload — khi click từ drawer menu
  const urlParams=new URLSearchParams(window.location.search);
  if(urlParams.get('action')==='upload'){
    window.history.replaceState({},'','scenarios.html');
    // Đợi page load xong rồi scroll + highlight upload zone
    setTimeout(()=>{
      const uz=$('scenarioUploadZone');
      if(uz){
        uz.scrollIntoView({behavior:'smooth',block:'center'});
        uz.style.borderColor='rgba(124,58,237,0.7)';
        uz.style.background='rgba(124,58,237,0.08)';
        setTimeout(()=>{uz.style.borderColor='';uz.style.background='';},3000);
      }
    },800);
  }
});
})();
