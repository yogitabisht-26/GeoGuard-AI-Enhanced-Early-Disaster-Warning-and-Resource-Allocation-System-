const API='http://localhost:8000';
const GG={token:()=>localStorage.getItem('gg_token')||'',user:()=>{try{return JSON.parse(localStorage.getItem('gg_user'))}catch{return null}},set:(k,v)=>localStorage.setItem(k,JSON.stringify(v)),get:k=>{try{return JSON.parse(localStorage.getItem(k))}catch{return null}},del:k=>localStorage.removeItem(k)};

async function api(endpoint,body=null,method=null){
  const opts={method:method||(body?'POST':'GET'),headers:{'Content-Type':'application/json'}};
  const token=GG.token();
  if(token)opts.headers['Authorization']=`Bearer ${token}`;
  if(body)opts.body=JSON.stringify(body);
  const res=await fetch(API+endpoint,opts);
  const data=await res.json();
  if(!res.ok)throw new Error(data.detail||'Something went wrong');
  return data;
}

function requireAuth(){
  if(!GG.token()||!GG.user()){window.location.href='index.html';return false}
  return true;
}

function logout(){
  GG.del('gg_token');GG.del('gg_user');GG.del('gg_nearby');
  window.location.href='index.html';
}

function initSidebar(activeId){
  const user=GG.user();if(!user)return;
  const n=document.getElementById('sb-name'),em=document.getElementById('sb-email'),ini=document.getElementById('sb-initials');
  if(n)n.textContent=user.name||'User';
  if(em)em.textContent=user.email||'';
  if(ini)ini.textContent=(user.name||'U')[0].toUpperCase();
  if(activeId){
    document.querySelectorAll('.sb-item').forEach(e=>e.classList.remove('active'));
    const e=document.getElementById(activeId);
    if(e)e.classList.add('active');
  }
  setInterval(()=>{
    const e=document.getElementById('tb-clock');
    if(e)e.textContent=new Date().toLocaleString('en-IN',{dateStyle:'medium',timeStyle:'short'});
  },1000);
}

function toggleSidebar(){
  const sb=document.getElementById('sidebar');
  if(sb){sb.classList.toggle('closed');sb.classList.toggle('open');}
}

function pageInit(id){
  if(!requireAuth())return false;
  initSidebar(id);
  if('Notification' in window&&Notification.permission==='default')Notification.requestPermission();
  return true;
}

const el=id=>document.getElementById(id);
const show=id=>{const e=el(id);if(e)e.style.display='block'};
const hide=id=>{const e=el(id);if(e)e.style.display='none'};
const txt=(id,v)=>{const e=el(id);if(e)e.textContent=v};
const html=(id,v)=>{const e=el(id);if(e)e.innerHTML=v};
const val=id=>el(id)?.value?.trim()||'';
const dis=id=>{const e=el(id);if(e)e.disabled=true};
const ena=id=>{const e=el(id);if(e)e.disabled=false};

function showMsg(id,text,type='info'){
  const e=el(id);if(!e)return;
  e.className=type==='success'?'msg-ok':type==='error'?'msg-err':'msg-info';
  e.textContent=text;
  e.style.display='block';
}

const RISK_COLOR={HIGH:'#f87171',MEDIUM:'#fb923c',LOW:'#fbbf24',MINIMAL:'#4ade80'};
const RISK_BG={HIGH:'rgba(248,113,113,.1)',MEDIUM:'rgba(251,146,60,.1)',LOW:'rgba(251,191,36,.08)',MINIMAL:'rgba(74,222,128,.08)'};
const RISK_BD={HIGH:'rgba(248,113,113,.3)',MEDIUM:'rgba(251,146,60,.3)',LOW:'rgba(251,191,36,.25)',MINIMAL:'rgba(74,222,128,.25)'};

const DISASTER_META={
  landslide:{name:'Landslide',emoji:'⛰',color:'#fb923c',bg:'rgba(251,146,60,.1)'},
  flood:{name:'Flood',emoji:'🌊',color:'#60a5fa',bg:'rgba(96,165,250,.1)'},
  cyclone:{name:'Cyclone',emoji:'🌀',color:'#a78bfa',bg:'rgba(167,139,250,.1)'},
  drought:{name:'Drought',emoji:'☀️',color:'#fbbf24',bg:'rgba(251,191,36,.1)'},
  earthquake:{name:'Earthquake',emoji:'🏚',color:'#f87171',bg:'rgba(248,113,113,.1)'}
};

function renderDisasterCards(disasters,containerId){
  const container=el(containerId);
  if(!container||!disasters)return;
  container.innerHTML=Object.entries(disasters).map(([key,v])=>{
    const info=DISASTER_META[key]||{name:key,emoji:'⚠',color:'#4ade80',bg:'rgba(74,222,128,.1)'};
    const risk=v.risk;
    const conf=v.confidence;
    const good=v.is_good_month;
    return `<div class="d-card" onclick="toggleCardDetail('dc-${key}')" style="cursor:pointer">
      <div class="d-head">
        <div class="d-icon" style="background:${info.bg}"><span>${info.emoji}</span></div>
        <div class="d-name font-sg">${info.name}</div>
        <span class="badge badge-${risk}">${risk}</span>
        ${good!==undefined?`<span style="font-size:10px;padding:2px 8px;border-radius:100px;background:${good?'rgba(74,222,128,.1)':'rgba(248,113,113,.1)'};color:${good?'var(--green)':'var(--red)'};margin-left:4px">${good?'✓ Good month':'⚠ Bad month'}</span>`:''}
      </div>
      <div class="bar-wrap" style="margin:10px 0 6px">
        <div class="bar bar-${risk}" style="width:0%" data-w="${conf}"></div>
      </div>
      <div style="font-size:12px;color:var(--muted);margin-bottom:8px">${conf}% confidence</div>
      <div id="dc-${key}" style="display:none;border-top:1px solid var(--border);padding-top:10px;margin-top:4px">
        <div style="font-size:12px;line-height:1.6;margin-bottom:8px">
          <div style="color:var(--green);font-weight:600;font-size:11px;margin-bottom:4px">ENGLISH</div>
          <div style="color:var(--muted)">${v.advice_en||''}</div>
        </div>
        <div style="font-size:12px;line-height:1.6;margin-bottom:8px">
          <div style="color:var(--green);font-weight:600;font-size:11px;margin-bottom:4px">हिंदी</div>
          <div style="color:var(--muted)">${v.advice_hi||''}</div>
        </div>
        ${v.travel_tip_en?`<div style="font-size:11px;color:var(--muted2);border-top:1px solid var(--border);padding-top:8px">Travel tip: ${v.travel_tip_en}</div>`:''}
      </div>
      <div style="font-size:11px;color:var(--muted2);text-align:right;margin-top:4px">Click to expand ↓</div>
    </div>`;
  }).join('');
  setTimeout(()=>{
    container.querySelectorAll('.bar[data-w]').forEach(b=>b.style.width=b.dataset.w+'%');
  },80);
}

function toggleCardDetail(id){
  const e=el(id);if(!e)return;
  e.style.display=e.style.display==='none'?'block':'none';
}

function renderWeather(weather,containerId){
  const container=el(containerId);
  if(!container||!weather)return;
  container.innerHTML=[
    {v:(weather.rain_today??'—')+' mm',k:'Rain Today'},
    {v:(weather.rain_3day??'—')+' mm',k:'3-Day Rain'},
    {v:(weather.rain_7day??'—')+' mm',k:'7-Day Rain'},
    {v:(weather.temp??'—')+'°C',k:'Temperature'},
    {v:(weather.humidity??'—')+'%',k:'Humidity'},
    {v:weather.soil?(weather.soil*100).toFixed(0)+'%':'—',k:'Soil Moist.'},
    {v:(weather.wind??'—')+' m/s',k:'Wind Speed'}
  ].map(x=>`<div class="wx-card"><div class="wx-val">${x.v}</div><div class="wx-key">${x.k}</div></div>`).join('');
}

const CHART_OPT={
  responsive:true,
  maintainAspectRatio:false,
  plugins:{
    legend:{labels:{color:'#5a8068',font:{family:'Inter',size:11}}},
    tooltip:{backgroundColor:'#0a1410',borderColor:'#162b1e',borderWidth:1,titleColor:'#e8f5ee',bodyColor:'#5a8068'}
  },
  scales:{
    x:{ticks:{color:'#5a8068',font:{family:'Inter',size:11}},grid:{color:'rgba(255,255,255,.04)'}},
    y:{ticks:{color:'#5a8068',font:{family:'Inter',size:11}},grid:{color:'rgba(255,255,255,.04)'}}
  }
};

const CHARTS={};
function mkChart(id,config){
  if(CHARTS[id]){CHARTS[id].destroy();delete CHARTS[id];}
  const ctx=el(id)?.getContext('2d');
  if(!ctx)return;
  CHARTS[id]=new Chart(ctx,config);
  return CHARTS[id];
}

function getGPS(){
  return new Promise((res,rej)=>{
    if(!navigator.geolocation)return rej(new Error('GPS not supported'));
    navigator.geolocation.getCurrentPosition(
      p=>res({lat:p.coords.latitude,lon:p.coords.longitude}),
      ()=>rej(new Error('GPS denied'))
    );
  });
}

async function reverseGeocode(lat,lon){
  try{
    const r=await fetch(`https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lon}&format=json`,{headers:{'User-Agent':'GeoGuard/1.0'}});
    const d=await r.json();
    return d.address?.city||d.address?.town||d.address?.village||`${lat.toFixed(3)},${lon.toFixed(3)}`;
  }catch{
    return `${lat.toFixed(3)},${lon.toFixed(3)}`;
  }
}

async function checkNearby(silent=false){
  try{
    const pos=await getGPS();
    const data=await api('/predict/nearby',{lat:pos.lat,lon:pos.lon,radius_km:150});
    GG.set('gg_nearby',data);
    const high=data.alerts?.filter(a=>a.risk_level==='HIGH')||[];
    const badge=el('notif-badge');
    if(badge)badge.style.display=high.length>0?'block':'none';
    if(high.length>0&&!silent){
      if(Notification.permission==='granted')new Notification('GeoGuard Alert!',{body:high[0].msg_en});
      showNearbyToast(high[0],high.length);
    }
    return data;
  }catch(e){
    console.log('[Nearby]',e.message);
    return null;
  }
}

function showNearbyToast(alert,total){
  const old=el('gg-toast');if(old)old.remove();
  const div=document.createElement('div');
  div.id='gg-toast';
  div.style.cssText='position:fixed;bottom:24px;right:24px;z-index:9999;background:#0a1410;border:1px solid rgba(248,113,113,.4);border-radius:14px;padding:16px 18px;max-width:320px;box-shadow:0 8px 32px rgba(0,0,0,.5);font-family:Inter,sans-serif;animation:toastIn .3s ease';
  document.head.insertAdjacentHTML('beforeend','<style>@keyframes toastIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:none}}</style>');
  div.innerHTML=`<div style="display:flex;gap:10px;align-items:flex-start">
    <span style="font-size:20px;flex-shrink:0">🚨</span>
    <div style="flex:1">
      <div style="font-size:13px;font-weight:600;color:#fca5a5;margin-bottom:4px">Nearby Danger!</div>
      <div style="font-size:12px;color:#5a8068;line-height:1.5">${alert.msg_en}</div>
      <div style="font-size:12px;color:#5a8068;margin-top:3px">${alert.msg_hi}</div>
      ${total>1?`<div style="font-size:11px;color:#3d5c4a;margin-top:4px">+${total-1} more zones nearby</div>`:''}
    </div>
    <button onclick="document.getElementById('gg-toast').remove()" style="background:none;border:none;color:#5a8068;cursor:pointer;font-size:18px;padding:0;flex-shrink:0">×</button>
  </div>`;
  document.body.appendChild(div);
  setTimeout(()=>div?.remove(),10000);
}

function startNearbyMonitor(){
  setTimeout(()=>checkNearby(true),3000);
  setInterval(()=>checkNearby(false),30*60*1000);
}

function togglePass(inputId, btnId){
  const inp=document.getElementById(inputId);
  const btn=document.getElementById(btnId);
  if(!inp||!btn)return;
  if(inp.type==='password'){
    inp.type='text';
    btn.textContent='🙈';
  }else{
    inp.type='password';
    btn.textContent='👁';
  }
}

window.addEventListener('DOMContentLoaded',()=>{
  const s=document.createElement('style');
  s.textContent='.d-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:16px;transition:border-color .2s;margin-bottom:10px}.d-card:hover{border-color:var(--border2)}.d-head{display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap}.d-icon{width:34px;height:34px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0}.d-name{font-size:14px;font-weight:600;flex:1}.disaster-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;margin-bottom:18px}';
  document.head.appendChild(s);
});