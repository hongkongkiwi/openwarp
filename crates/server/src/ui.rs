pub const INDEX: &str = r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenWarp Console</title><link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>◆</text></svg>">
<style>
:root{--bg:#08080c;--bg2:#0e0e14;--panel:#12121b;--panel2:#171724;--line:#23233a;--line2:#2e2e4a;--text:#eceaf8;--muted:#9a97b3;--faint:#6b6884;--acc:#7c6cff;--acc2:#9d8fff;--ok:#34d399;--warn:#fbbf24;--bad:#fb7185;--mono:ui-monospace,'SF Mono',SFMono-Regular,Menlo,monospace;--sans:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI',Roboto,sans-serif;--r:10px}
*{box-sizing:border-box}html,body{height:100%}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 var(--sans);-webkit-font-smoothing:antialiased}
button{font:inherit;color:var(--text);background:var(--panel2);border:1px solid var(--line2);border-radius:8px;padding:7px 14px;cursor:pointer;transition:.15s}button:hover{border-color:var(--acc);background:#1d1d2f}button.primary{background:var(--acc);border-color:var(--acc);color:#fff;font-weight:600}button.primary:hover{background:var(--acc2)}button.ghost{background:transparent;border-color:transparent;color:var(--muted)}button.ghost:hover{color:var(--text);background:var(--panel2)}button.danger:hover{border-color:var(--bad);color:var(--bad)}button:disabled{opacity:.45;cursor:default}
input,select,textarea{font:inherit;color:var(--text);background:var(--bg2);border:1px solid var(--line2);border-radius:8px;padding:8px 11px;outline:none}input:focus,select:focus,textarea:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(124,108,255,.18)}textarea{font-family:var(--mono);font-size:12.5px;width:100%}
a{color:var(--acc2)}code,.mono{font-family:var(--mono);font-size:12.5px}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;letter-spacing:-.02em}
.mark{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,var(--acc),#4f46e5);display:grid;place-items:center;color:#fff;font-size:15px;flex:none}
#auth{min-height:100vh;display:grid;place-items:center;background:radial-gradient(900px 500px at 50% -10%,rgba(124,108,255,.16),transparent)}
.authcard{width:400px;max-width:92vw;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:32px;box-shadow:0 24px 60px rgba(0,0,0,.5)}
.authcard h1{font-size:22px;margin:14px 0 4px}.authcard p.sub{color:var(--muted);margin:0 0 20px}
.field{margin-bottom:12px}.field label{display:block;font-size:12px;color:var(--muted);margin-bottom:5px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}.field input{width:100%}
.seg{display:flex;background:var(--bg2);border:1px solid var(--line);border-radius:9px;padding:3px;margin-bottom:20px}.seg button{flex:1;background:transparent;border:0;color:var(--muted)}.seg button.on{background:var(--panel2);color:var(--text);box-shadow:0 1px 4px rgba(0,0,0,.4)}
#shell{display:none;height:100vh;grid-template-columns:248px 1fr;grid-template-rows:100vh}
aside{background:var(--bg2);border-right:1px solid var(--line);display:flex;flex-direction:column;padding:16px 12px;gap:4px;overflow:auto}
aside .orgsel{width:100%;margin:14px 0 10px}
.navbtn{display:flex;align-items:center;gap:10px;width:100%;text-align:left;background:transparent;border:0;border-radius:8px;padding:8px 10px;color:var(--muted);font-weight:500}.navbtn:hover{background:var(--panel2);color:var(--text)}.navbtn.on{background:rgba(124,108,255,.14);color:var(--text)}.navbtn .ic{width:18px;text-align:center;flex:none}
.sidefoot{margin-top:auto;border-top:1px solid var(--line);padding-top:12px;color:var(--muted);font-size:12.5px}
main{overflow:auto;display:flex;flex-direction:column}
.topbar{display:flex;align-items:center;gap:12px;padding:14px 28px;border-bottom:1px solid var(--line);position:sticky;top:0;background:rgba(8,8,12,.85);backdrop-filter:blur(8px);z-index:5}
.topbar h2{font-size:17px;margin:0;letter-spacing:-.01em}.crumb{color:var(--faint)}.grow{flex:1}
.searchbox{display:flex;align-items:center;gap:8px;background:var(--bg2);border:1px solid var(--line2);border-radius:8px;padding:6px 11px;color:var(--faint);cursor:pointer;min-width:210px}.searchbox:hover{border-color:var(--acc)}kbd{font:11px var(--mono);background:var(--panel2);border:1px solid var(--line2);border-bottom-width:2px;border-radius:5px;padding:1px 5px;color:var(--muted)}
.content{padding:24px 28px 110px;max-width:1220px;width:100%;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
.appcard{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;cursor:pointer;transition:.15s}.appcard:hover{border-color:var(--acc);transform:translateY(-1px)}.appcard h3{margin:0 0 6px;font-size:15px}.appcard .meta{color:var(--muted);font-size:12.5px}
.chip{display:inline-block;font:11px var(--mono);background:var(--panel2);border:1px solid var(--line2);border-radius:99px;padding:2px 8px;margin:2px 3px 0 0;color:var(--muted)}
.envtabs{display:flex;gap:6px;flex-wrap:wrap;margin:4px 0 16px}.envtab{border-radius:99px;padding:6px 14px;font-weight:600;font-size:13px}.envtab.on{background:var(--acc);border-color:var(--acc);color:#fff}
table{width:100%;border-collapse:separate;border-spacing:0;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--faint);text-align:left;padding:10px 14px;background:var(--bg2);border-bottom:1px solid var(--line)}
td{padding:9px 14px;border-bottom:1px solid var(--line);vertical-align:middle}tr:last-child td{border-bottom:0}tbody tr:hover{background:rgba(124,108,255,.04)}
.badge{font:10.5px var(--mono);border-radius:5px;padding:2px 6px;border:1px solid}.b-secret{color:var(--acc2);border-color:rgba(124,108,255,.4)}.b-sealed{color:var(--warn);border-color:rgba(251,191,36,.4)}.b-config{color:var(--ok);border-color:rgba(52,211,153,.4)}
.iconbtn{background:transparent;border:0;padding:7px 9px;min-width:30px;min-height:30px;border-radius:6px;color:var(--muted);font-size:14px}.iconbtn:hover{color:var(--text);background:var(--panel2)}
td input{width:100%;background:transparent;border:0;padding:2px;font-family:var(--mono);font-size:12.5px}td input:focus{box-shadow:none;border-bottom:1px dashed var(--acc);border-radius:0}
.stagedot{display:inline-block;width:7px;height:7px;border-radius:99px;background:var(--warn);margin-right:6px}
#deploybar{position:fixed;left:50%;transform:translateX(-50%);bottom:26px;background:#1b1b2c;border:1px solid var(--line2);border-radius:12px;padding:12px 16px;display:none;gap:12px;align-items:center;box-shadow:0 18px 50px rgba(0,0,0,.55);z-index:40}#deploybar.show{display:flex}
.modalwrap{position:fixed;inset:0;background:rgba(4,4,8,.7);display:none;place-items:center;z-index:60;backdrop-filter:blur(3px)}.modalwrap.show{display:grid}
.modal{width:560px;max-width:94vw;max-height:88vh;overflow:auto;background:var(--panel);border:1px solid var(--line2);border-radius:16px;padding:24px}.modal h3{margin:0 0 14px;font-size:16px}
#palette{position:fixed;inset:0;background:rgba(4,4,8,.65);display:none;z-index:70;padding:12vh 16px 16px}.palettecard{max-width:620px;margin:0 auto;background:var(--panel);border:1px solid var(--line2);border-radius:14px;overflow:hidden;box-shadow:0 30px 80px rgba(0,0,0,.6)}.palettecard input{width:100%;border:0;background:transparent;font-size:16px;padding:16px}.pitem{padding:10px 16px;cursor:pointer;display:flex;gap:10px;align-items:center}.pitem:hover,.pitem.sel{background:rgba(124,108,255,.12)}
#toasts{position:fixed;right:18px;bottom:18px;z-index:90;display:flex;flex-direction:column;gap:8px}.toast{background:#1d2b22;border:1px solid #245c3f;color:#a7f3d0;border-radius:10px;padding:11px 15px;box-shadow:0 10px 30px rgba(0,0,0,.5);max-width:380px}.toast.err{background:#331d24;border-color:#5c2436;color:#fecdd3}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-bottom:18px;flex-wrap:wrap}.tabbtn{background:transparent;border:0;border-radius:8px 8px 0 0;color:var(--muted);padding:9px 13px;font-weight:600;font-size:13px}.tabbtn.on{color:var(--text);box-shadow:inset 0 -2px var(--acc)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px;margin-bottom:14px}.card h3{margin:0 0 6px;font-size:15px}.card p{color:var(--muted);margin:0 0 12px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.empty{padding:48px 20px;text-align:center;color:var(--faint);border:1px dashed var(--line2);border-radius:14px}.empty .big{font-size:22px;margin-bottom:6px}
.mut{color:var(--muted)}.small{font-size:12.5px}.val{font-family:var(--mono);font-size:12.5px;word-break:break-all}
@media(max-width:820px){#shell{grid-template-columns:1fr}aside{display:none}.content{padding:16px 14px 100px}}
</style></head>
<body>
<div id="auth">
  <div class="authcard">
    <div class="logo"><span class="mark">◆</span>OpenWarp</div>
    <h1 id="authtitle">Welcome back</h1><p class="sub">Secrets management with no tiers and no licence gates.</p>
    <div class="seg"><button id="seglogin" class="on" onclick="authMode('login')">Sign in</button><button id="segreg" onclick="authMode('register')">Create account</button></div>
    <div id="authform">
      <div class="field"><label for="email">Email</label><input id="email" type="email" autocomplete="email" placeholder="you@company.com"></div>
      <div class="field"><label for="pw">Password</label><input id="pw" type="password" autocomplete="current-password" placeholder="••••••••••" onkeydown="if(event.key==='Enter')doAuth()"></div>
      <div class="field" id="mfafield" style="display:none"><label for="mfacode">Authenticator / recovery code</label><input id="mfacode" placeholder="123456" onkeydown="if(event.key==='Enter')doMfa()"></div>
      <button class="primary" style="width:100%;padding:11px" id="authbtn" onclick="doAuth()">Sign in</button>
      <div id="social" class="row" style="margin-top:12px"></div>
      <p class="small mut" id="signupnote" style="margin:14px 0 0">Your organisation, apps and environments are unlimited. Save the recovery kit shown once at registration.</p>
    </div>
  </div>
</div>

<div id="shell">
  <aside>
    <div class="logo"><span class="mark">◆</span>OpenWarp</div>
    <select id="orgs" class="orgsel" onchange="switchOrg()"></select>
    <button class="navbtn" data-nav="apps" onclick="nav('apps')"><span class="ic">▦</span>Apps</button>
    <button class="navbtn" data-nav="access" onclick="nav('access')"><span class="ic">♟</span>Members &amp; access</button>
    <button class="navbtn" data-nav="integrations" onclick="nav('integrations')"><span class="ic">⇄</span>Integrations</button>
    <button class="navbtn" data-nav="audit" onclick="nav('audit')"><span class="ic">≡</span>Audit log</button>
    <button class="navbtn" data-nav="settings" onclick="nav('settings')"><span class="ic">⚙</span>Settings</button>
    <div class="sidefoot"><div id="whoami" class="mono"></div><button class="ghost" style="padding:4px 0" onclick="logout()">Sign out</button></div>
  </aside>
  <main>
    <div class="topbar"><h2 id="pagetitle">Apps</h2><span class="crumb" id="crumb"></span><div class="grow"></div>
      <div class="searchbox" onclick="openPalette()"><span>⌕</span><span style="flex:1">Search secrets…</span><kbd>⌘K</kbd></div>
      <button class="primary" id="topaction" onclick="newApp()">+ New app</button>
    </div>
    <div class="content" id="view"></div>
  </main>
</div>

<div id="deploybar"><span id="deploytext"></span><button class="ghost" onclick="discardStage()">Discard</button><button class="primary" onclick="deployStage()">Deploy changes</button></div>

<div class="modalwrap" id="modalwrap"><div class="modal" id="modal"></div></div>
<div id="palette"><div class="palettecard"><input id="paletteinput" placeholder="Search secrets, apps, environments…" oninput="paletteSearch()"><div id="paletteresults"></div></div></div>
<div id="toasts"></div>
<script>
let T=localStorage.getItem('owt')||'', ORG='', APP=null, ENV=null, APPS=[], ENVS=[], SECRETS=[], DRAFTS={}, VIEW='apps', MFA=null, LASTFOCUS=null, PENDING_ORG=null;
function drafts(){return (ENV&&DRAFTS[ENV.id])||{}}
function draftList(){return Object.values(drafts())}
const $=id=>document.getElementById(id);
const H=()=>({'Authorization':'Bearer '+T,'Content-Type':'application/json'});
async function api(m,u,b){let r=await fetch(u,{method:m,headers:H(),body:b!==undefined?JSON.stringify(b):undefined});let t=await r.text();let d;try{d=JSON.parse(t)}catch(e){d={error:t}}
  if(!r.ok) throw new Error(d.error||('HTTP '+r.status)); return d}
function toast(msg,err){let el=document.createElement('div');el.className='toast'+(err?' err':'');el.textContent=msg;$('toasts').appendChild(el);el.style.transition='opacity .3s';setTimeout(()=>{el.style.opacity='0';setTimeout(()=>el.remove(),320)},3000)}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
// For values interpolated into an inline handler's JS string literal. HTML
// escaping alone is not enough: the parser turns &#39; back into a quote before
// the JS is parsed, which would let a secret key break out of the string.
function jsq(s){return String(s??'').replace(/&/g,'&amp;').replace(/\\/g,'\\\\').replace(/'/g,"\\u0027").replace(/"/g,'\\u0022').replace(/</g,'\\u003c').replace(/>/g,'\\u003e').replace(/\n/g,'\\n').replace(/\r/g,'\\r')}
function modal(html,label){let m=$('modal');m.innerHTML=html;m.setAttribute('role','dialog');m.setAttribute('aria-modal','true');
  if(label)m.setAttribute('aria-label',label);else m.removeAttribute('aria-label');
  $('modalwrap').classList.add('show');LASTFOCUS=document.activeElement;
  requestAnimationFrame(()=>{let f=m.querySelector('input,textarea,select,button');if(f)f.focus()})}
function closeModal(){let w=$('modalwrap');if(!w.classList.contains('show'))return;w.classList.remove('show');
  if(LASTFOCUS&&LASTFOCUS.focus){try{LASTFOCUS.focus()}catch(e){}}LASTFOCUS=null}
function modalOpen(){return $('modalwrap').classList.contains('show')}
$('modalwrap').addEventListener('click',e=>{if(e.target.id==='modalwrap')closeModal()});
document.addEventListener('keydown',e=>{
  if((e.metaKey||e.ctrlKey)&&String(e.key).toLowerCase()==='k'){e.preventDefault();openPalette();return}
  if(e.key==='Escape'){closeModal();$('palette').style.display='none';return}
  if(e.key==='Tab'&&modalOpen()){
    let c=Array.from($('modal').querySelectorAll('input,textarea,select,button')).filter(el=>!el.disabled);
    if(!c.length)return;
    let first=c[0],last=c[c.length-1];
    if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus()}
    else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus()}
  }});

// ---------- auth ----------
async function loadProviders(){try{
  let p=await api('GET','/api/auth/providers');
  let btns=[];
  if(p.google)btns.push(`<button style="flex:1" onclick="location.href='/api/auth/social/google/start'">Continue with Google</button>`);
  if(p.github)btns.push(`<button style="flex:1" onclick="location.href='/api/auth/social/github/start'">Continue with GitHub</button>`);
  $('social').innerHTML=btns.join('');
  if(p.signups!=='open'){
    $('segreg').style.display='none';
    if(MODE==='register')authMode('login');
    $('signupnote').textContent='Signups are closed. Ask an administrator for an invitation.';
  }
}catch(e){}}
function showInvite(token){
  $('auth').style.display='grid';$('shell').style.display='none';
  $('authtitle').textContent='Accept invitation';
  $('authform').innerHTML=`<p class="mut">Choose a password for your new account.</p>
    <div class="field"><label for="inv-pw">Password</label><input id="inv-pw" type="password" autocomplete="new-password" placeholder="at least 8 characters"></div>
    <button class="primary" style="width:100%;padding:11px" onclick="acceptInvite()">Create account</button>`;
  $('authform').dataset.invite=token;}
async function acceptInvite(){try{
  let d=await api('POST','/api/auth/accept-invite',{token:$('authform').dataset.invite,password:$('inv-pw').value});
  T=d.token;localStorage.setItem('owt',T);history.replaceState(null,'',location.pathname);enterApp();
}catch(e){toast(e.message,true)}}
let MODE='login';
function authMode(m){MODE=m;$('seglogin').classList.toggle('on',m==='login');$('segreg').classList.toggle('on',m==='register');$('authtitle').textContent=m==='login'?'Welcome back':'Create your account';$('authbtn').textContent=m==='login'?'Sign in':'Create account'}
async function doAuth(){try{
  if(MODE==='register'){let d=await api('POST','/api/auth/register',{email:$('email').value,password:$('pw').value});T=d.token;localStorage.setItem('owt',T);
    modal(`<h3>Save your recovery kit</h3><p class="mut">This X25519 private key decrypts end-to-end environments and is shown once. Store it in a password manager.</p><textarea id="kit-text" aria-label="Recovery kit" rows="3" readonly>${esc(d.recovery_kit)}</textarea><div class="row" style="margin-top:12px"><button onclick="navigator.clipboard.writeText('${esc(d.recovery_kit)}');toast('Recovery kit copied')">Copy kit</button><button class="primary" onclick="closeModal();enterApp()">I saved it, continue</button></div>`);return}
  let d=await api('POST','/api/auth/login',{email:$('email').value,password:$('pw').value});
  if(d.mfa_required){MFA=d.mfa_token;$('mfafield').style.display='block';$('authbtn').textContent='Verify code';$('authbtn').onclick=doMfa;toast('Enter your authenticator or recovery code');return}
  T=d.token;localStorage.setItem('owt',T);enterApp();
}catch(e){toast(e.message,true)}}
async function doMfa(){try{let d=await api('POST','/api/auth/mfa',{mfa_token:MFA,code:$('mfacode').value});T=d.token;localStorage.setItem('owt',T);enterApp()}catch(e){toast(e.message,true)}}
async function logout(){try{await api('POST','/api/auth/logout',{})}catch(e){} T='';localStorage.removeItem('owt');location.reload()}
async function enterApp(){$('auth').style.display='none';$('shell').style.display='grid';
  let me=await api('GET','/api/me');$('whoami').textContent=me.email;
  let orgs=await api('GET','/api/orgs');ORG=(PENDING_ORG&&orgs.some(o=>o.id===PENDING_ORG))?PENDING_ORG:(orgs[0]?.id||'');PENDING_ORG=null;
  $('orgs').innerHTML=orgs.map(o=>`<option value="${o.id}">${esc(o.name)} · ${esc(o.role)}</option>`).join('');
  $('orgs').value=ORG;
  await nav('apps')}
async function switchOrg(){ORG=$('orgs').value;APP=null;ENV=null;await nav('apps')}

// ---------- navigation ----------
async function nav(v){VIEW=v;document.querySelectorAll('.navbtn').forEach(b=>b.classList.toggle('on',b.dataset.nav===v));
  $('topaction').style.display=(v==='apps')?'':'none';
  await ({apps:renderApps,access:renderAccess,integrations:renderIntegrations,audit:renderAudit,settings:renderSettings}[v]||renderApps)();
  updateDeployBar()}

// ---------- apps ----------
async function renderApps(){$('topaction').style.display='';$('pagetitle').textContent='Apps';$('crumb').textContent='';
  $('view').innerHTML='<div class="empty"><div class="big">Loading…</div></div>';
  APPS=ORG?await api('GET',`/api/orgs/${ORG}/apps`):[];
  if(!APPS.length){$('view').innerHTML=`<div class="empty"><div class="big">▦</div>No apps yet<p>Create an app to start managing secrets for a project.</p><button class="primary" onclick="newApp()">Create your first app</button></div>`;return}
  let envCounts={};for(let a of APPS){try{let es=await api('GET',`/api/apps/${a.id}/envs`);envCounts[a.id]=es}catch(e){envCounts[a.id]=[]}}
  $('view').innerHTML=`<div class="row" style="margin-bottom:14px"><input id="appfilter" placeholder="Filter apps…" style="min-width:240px" oninput="filterApps(this.value)"><span class="mut small">${APPS.length} app${APPS.length!==1?'s':''}, unlimited environments</span></div>
  <div class="grid" id="appgrid">${APPS.map(a=>appCard(a,envCounts[a.id])).join('')}</div>`}
function appCard(a,envs){return `<div class="appcard" onclick="openApp('${a.id}')"><h3>${esc(a.name)}</h3><div class="meta">${envs.length} environment${envs.length!==1?'s':''}</div><div>${envs.map(e=>`<span class="chip">${esc(e.name)}</span>`).join('')}</div></div>`}
function filterApps(q){document.querySelectorAll('.appcard').forEach((c,i)=>{c.style.display=APPS[i].name.toLowerCase().includes(q.toLowerCase())?'':'none'})}
async function newApp(){modal(`<h3>New app</h3><div class="field"><label for="na-name">App name</label><input id="na-name" placeholder="billing-api"></div><div class="field"><label for="na-readme">Readme (markdown, optional)</label><textarea id="na-readme" rows="4"></textarea></div><div class="row"><button class="primary" onclick="createApp()">Create app</button><button class="ghost" onclick="closeModal()">Cancel</button></div>
  <p class="small mut">Development, Staging and Production environments are created automatically. Add unlimited custom environments later.</p>`)}
async function createApp(){try{await api('POST',`/api/orgs/${ORG}/apps`,{name:$('na-name').value,readme:$('na-readme').value});closeModal();toast('App created');renderApps()}catch(e){toast(e.message,true)}}
async function openApp(id){APP=APPS.find(a=>a.id===id)||{id};ENVS=await api('GET',`/api/apps/${id}/envs`);
  ENV=ENVS.find(e=>e.id===ENV?.id)||ENVS[0]||null;await renderEnv()}

// ---------- environments and secrets ----------
async function renderEnv(){VIEW='env';$('topaction').style.display='none';$('pagetitle').textContent=APP?.name||'App';$('crumb').textContent='/ environments';
  if(!ENVS.length){$('view').innerHTML='<div class="empty"><div class="big">No environments</div><button class="primary" onclick="newEnv()">Create environment</button></div>';updateDeployBar();return}
  if(!ENV)ENV=ENVS[0];
  let d=await api('GET',`/api/envs/${ENV.id}/secrets`);SECRETS=d.secrets;
  $('view').innerHTML=`
  <div class="envtabs">${ENVS.map(e=>`<button class="envtab ${e.id===ENV.id?'on':''}" onclick="switchEnv('${e.id}')">${esc(e.name)}</button>`).join('')}<button class="envtab" onclick="newEnv()">+ Environment</button><button class="envtab" onclick="newE2eEnv()">+ E2E environment</button><span class="grow"></span><button class="ghost danger" onclick="delEnv()">Delete env</button></div>
  <div class="row" style="margin-bottom:12px">
    <input id="sfilter" placeholder="Filter by key or path…" style="min-width:240px" oninput="drawSecrets()">
    <button onclick="importModal()">Import .env</button><button onclick="exportEnv()">Export</button>
    <span class="grow"></span><button class="primary" onclick="addRow()">+ New secret</button>
  </div>
  <div id="stable"></div>
  ${APP?.readme?`<div class="card" style="margin-top:14px"><h3>Readme</h3><pre class="val" style="white-space:pre-wrap">${esc(APP.readme)}</pre></div>`:''}`;
  drawSecrets();updateDeployBar()}
async function switchEnv(id){let cur=ENV&&ENV.id;if(cur===id){return}
  if(cur&&Object.keys(drafts()).length&&!confirm('Discard staged changes?'))return;
  if(cur)delete DRAFTS[cur];
  ENV=ENVS.find(e=>e.id===id);await renderEnv()}
function envMode(e){return 'sse'}
async function newEnv(){modal(`<h3>New environment</h3><div class="field"><label for="ne-name">Name (letters, numbers, - or _)</label><input id="ne-name" placeholder="qa-1"></div><div class="row"><button class="primary" onclick="createEnv()">Create</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`)}
async function createEnv(){try{await api('POST',`/api/apps/${APP.id}/envs`,{name:$('ne-name').value});closeModal();ENVS=await api('GET',`/api/apps/${APP.id}/envs`);toast('Environment created');renderEnv()}catch(e){toast(e.message,true)}}
async function newE2eEnv(){modal(`<h3>New end-to-end encrypted environment</h3><p class="mut">The server stores only ciphertext and cannot read these secrets. Use the CLI or the E2E panel in Settings with your recovery kit.</p><div class="field"><label for="ne2-name">Name</label><input id="ne2-name" placeholder="vault"></div><div class="row"><button class="primary" onclick="createE2eEnv()">Create E2E env</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`)}
async function createE2eEnv(){try{let d=await api('POST',`/api/apps/${APP.id}/envs/e2e`,{name:$('ne2-name').value});closeModal();toast('E2E environment created: '+d.id);ENVS=await api('GET',`/api/apps/${APP.id}/envs`);renderEnv()}catch(e){toast(e.message,true)}}
async function delEnv(){if(!confirm(`Delete environment ${ENV.name} and all its secrets?`))return;try{let removed=ENV.id;await api('DELETE',`/api/envs/${removed}`);delete DRAFTS[removed];ENVS=await api('GET',`/api/apps/${APP.id}/envs`);ENV=ENVS[0]||null;toast('Environment deleted');await renderEnv()}catch(e){toast(e.message,true)}}
function matchesFilter(key,path){let q=($('sfilter')?.value||'').toLowerCase();return !q||String(key||'').toLowerCase().includes(q)||String(path||'').toLowerCase().includes(q)}
function drawSecrets(){
  let all=SECRETS.map(s=>({s,isNew:false,d:drafts()[s.id]})).filter(x=>matchesFilter(x.d?x.d.key:x.s.key,x.d?x.d.path:x.s.path));
  all=all.concat(draftList().filter(d=>d.isNew&&matchesFilter(d.key,d.path)).map(d=>({s:d,isNew:true,d})));
  if(!all.length){
    let any=SECRETS.length||draftList().length;
    $('stable').innerHTML=any
      ?'<div class="empty"><div class="big">No matching secrets</div>Nothing here matches that filter. Clear it to see every secret in this environment.</div>'
      :'<div class="empty"><div class="big">No secrets here yet</div>Click “+ New secret”, or import a .env file.</div>';
    return}
  $('stable').innerHTML=`<table><thead><tr><th style="width:26%">Key</th><th>Value</th><th style="width:13%">Path</th><th style="width:9%">Version</th><th style="width:15%"></th></tr></thead><tbody>
  ${all.map(({s,isNew,d})=>{let staged=d;let key=staged?staged.key:s.key;let value=staged?staged.value:s.value;let path=(staged?staged.path:s.path)||'/';
    let type=(staged?staged.type:s.type)||'secret';let sealed=!isNew&&type==='sealed';let dirty=!!staged;
    return `<tr><td>${dirty&&!isNew?'<span class="stagedot"></span>':''}<span class="mono">${esc(key)}</span> <span class="badge b-${esc(type)}">${esc(type)}</span>${isNew?' <span class="chip">new</span>':''}</td>
    <td>${sealed?'<span class="mut mono">🔒 sealed, never shown</span>':`<span class="val" data-val="${esc(value??'')}" data-show="0">••••••••••</span>`}</td>
    <td class="mono mut">${esc(path)}</td><td class="mut">${isNew?'new':'v'+(s.version||1)}</td>
    <td style="white-space:nowrap;text-align:right">
      ${sealed?'':`<button class="iconbtn" title="Reveal" aria-label="Reveal" onclick="revealVal(this)">◉</button><button class="iconbtn" title="Copy value" aria-label="Copy value" onclick="copyVal(this)">⧉</button>`}
      <button class="iconbtn" title="Edit" aria-label="Edit" onclick="editRow('${jsq(s.id)}')">✎</button>
      ${isNew?'':`<button class="iconbtn" title="History" aria-label="History" onclick="showHistory('${jsq(s.id)}')">↺</button>
      <button class="iconbtn" title="Personal override" aria-label="Personal override" onclick="overrideRow('${jsq(s.id)}','${jsq(key)}')">♟</button>`}
      <button class="iconbtn" title="Delete" aria-label="Delete" onclick="delSecret('${jsq(s.id)}','${jsq(key)}')">🗑</button></td></tr>`}).join('')}
  </tbody></table>`}
function findValEl(btn){return btn.closest('tr').querySelector('.val')}
function revealVal(btn){let el=findValEl(btn);let show=el.dataset.show==='1';el.dataset.show=show?'0':'1';el.textContent=show?'••••••••••':el.dataset.val}
function copyVal(btn){navigator.clipboard.writeText(findValEl(btn).dataset.val);toast('Value copied')}
function addRow(){if(!ENV){toast('Open an environment first',true);return}let id='new-'+Date.now();
  modal(`<h3>New secret</h3>
    <div class="field"><label for="ns-key">Key</label><input id="ns-key" placeholder="DATABASE_URL"></div>
    <div class="field"><label for="ns-val">Value</label><textarea id="ns-val" rows="3"></textarea></div>
    <div class="row"><div class="field" style="flex:1"><label for="ns-path">Path</label><input id="ns-path" value="/"></div>
    <div class="field"><label for="ns-type">Type</label><select id="ns-type"><option>secret</option><option>sealed</option><option>config</option></select></div></div>
    <div class="row"><button class="primary" onclick="stageNew('${id}')">Stage secret</button><button class="ghost" onclick="closeModal()">Cancel</button></div>
    <p class="small mut">Staged changes deploy together, like a commit. Sealed values can never be read back.</p>`,'New secret')}
function stageNew(id){let k=$('ns-key').value.trim();if(!k){toast('Key required',true);return}
  if(!DRAFTS[ENV.id])DRAFTS[ENV.id]={};
  DRAFTS[ENV.id][id]={id,key:k.toUpperCase(),value:$('ns-val').value,path:$('ns-path').value||'/',type:$('ns-type').value,comment:'',isNew:true};
  closeModal();drawSecrets();updateDeployBar()}
function editRow(id){let d=drafts()[id];let s=d||SECRETS.find(x=>x.id===id);if(!s)return;let isNew=!!d;
  modal(`<h3>Edit ${esc(s.key)}</h3><div class="field"><label for="ed-val">Value</label><textarea id="ed-val" rows="4">${esc(s.value??'')}</textarea></div>
    <div class="field"><label for="ed-comment">Comment</label><input id="ed-comment" value="${esc(s.comment||'')}"></div>
    <div class="row"><button class="primary" onclick="stageEdit('${jsq(id)}')">${isNew?'Stage secret':'Stage change'}</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`,'Edit secret')}
function stageEdit(id){let d=drafts()[id];let s=d||SECRETS.find(x=>x.id===id);if(!s)return;
  if(d){d.value=$('ed-val').value;d.comment=$('ed-comment').value}
  else{if(!DRAFTS[ENV.id])DRAFTS[ENV.id]={};DRAFTS[ENV.id][id]={id,key:s.key,value:$('ed-val').value,path:s.path,type:s.type,comment:$('ed-comment').value}}
  closeModal();drawSecrets();updateDeployBar();toast('Change staged, deploy when ready')}
async function overrideRow(id,key){modal(`<h3>Personal override: ${esc(key)}</h3><p class="mut">Only you see this value. Teammates keep the shared one.</p><div class="field"><label for="ov-val">Your value</label><textarea id="ov-val" rows="3"></textarea></div><div class="row"><button class="primary" onclick="saveOverride('${jsq(id)}')">Save override</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`,'Personal override')}
async function saveOverride(id){try{await api('POST',`/api/secrets/${id}/override`,{secrets:[{key:'x',value:$('ov-val').value}]});closeModal();toast('Override saved');renderEnv()}catch(e){toast(e.message,true)}}
async function delSecret(id,key){let d=drafts()[id];
  if(d&&d.isNew){delete drafts()[id];drawSecrets();updateDeployBar();return}
  let s=SECRETS.find(x=>x.id===id);if(s&&s.type==='sealed'&&!confirm('Delete sealed secret '+key+'? Its value cannot be recovered.'))return;
  if(!confirm('Delete '+key+'? You can restore it from history.'))return;
  try{await api('DELETE',`/api/secrets/${id}`);delete drafts()[id];toast('Secret deleted');await renderEnv()}catch(e){toast(e.message,true)}}
function updateDeployBar(){let n=draftList().length;let active=VIEW==='env'&&!!ENV&&n>0;
  $('deploybar').classList.toggle('show',active);
  $('deploytext').innerHTML=active?`<b>${n}</b>&nbsp;staged change${n!==1?'s':''}`:''}
function discardStage(){if(ENV)delete DRAFTS[ENV.id];drawSecrets();updateDeployBar()}
async function deployStage(){try{let items=draftList().map(s=>({key:s.key,value:s.value,path:s.path,type:s.type,comment:s.comment||''}));
  if(!items.length)return;let envId=ENV.id;
  let d=await api('PUT',`/api/envs/${envId}/secrets`,{secrets:items});
  if(ENV&&ENV.id===envId)delete DRAFTS[envId];
  toast(`Deployed ${d.deployed} secret${d.deployed!==1?'s':''}`);await renderEnv()}catch(e){toast(e.message,true)}}
async function showHistory(id){try{let h=await api('GET',`/api/secrets/${id}/history`);
  modal(`<h3>History</h3>${h.length?h.map(v=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:8px 0"><span><b>v${v.version}</b> <span class="mut small">${new Date(v.created_at*1000).toLocaleString()}</span><br><span class="val">${esc(v.value)}</span></span><button onclick="restoreVer('${jsq(id)}',${v.version})">Restore</button></div>`).join(''):'<p class="mut">No history.</p>'}<div class="row" style="margin-top:12px"><button class="ghost" onclick="closeModal()">Close</button></div>`,'Secret history')}catch(e){toast(e.message,true)}}
async function restoreVer(id,ver){try{await api('POST',`/api/secrets/${id}/restore/${ver}`,{});closeModal();toast('Restored version '+ver);renderEnv()}catch(e){toast(e.message,true)}}
function importModal(){modal(`<h3>Import secrets into ${esc(ENV.name)}</h3><p class="mut">Paste .env contents. Existing keys are updated and versioned.</p><textarea id="imp-text" aria-label=".env contents" rows="10" placeholder="API_KEY=...&#10;# comment&#10;DATABASE_URL=postgres://…"></textarea><div class="row" style="margin-top:12px"><button class="primary" onclick="doImport()">Import</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`)}
async function doImport(){try{let d=await api('POST',`/api/envs/${ENV.id}/import`,{text:$('imp-text').value});closeModal();toast(`Imported ${d.deployed} secrets`);renderEnv()}catch(e){toast(e.message,true)}}
async function exportEnv(){try{let d=await api('GET',`/api/envs/${ENV.id}/export`);modal(`<h3>Export ${esc(ENV.name)}</h3><textarea id="exp-text" aria-label="Exported secrets" rows="12" readonly>${esc(d.text)}</textarea><div class="row" style="margin-top:12px"><button onclick="navigator.clipboard.writeText(document.querySelector('#modal textarea').value);toast('Export copied')">Copy .env</button><button class="ghost" onclick="closeModal()">Close</button></div>`)}catch(e){toast(e.message,true)}}

// ---------- access, integrations, audit, settings ----------
function needAppEnv(){if(!APP){toast('Open an app first',true);nav('apps');return false} return true}
async function renderAccess(){if(!ORG)return;$('pagetitle').textContent='Members & access';$('crumb').textContent='';
  let teams=await api('GET',`/api/orgs/${ORG}/teams`).catch(()=>[]);let roles=await api('GET',`/api/orgs/${ORG}/roles`).catch(()=>[]);
  let props=ENV?await api('GET',`/api/envs/${ENV.id}/proposals`).catch(()=>[]):[];
  let reqs=ENV?await api('GET',`/api/envs/${ENV.id}/access-requests`).catch(()=>[]):[];
  $('view').innerHTML=`
  <div class="card"><h3>Invite member</h3><p>Existing accounts are added immediately. New addresses get a single-use link, valid for seven days, to set a password or sign in with a configured provider.</p><div class="row"><label class="small mut" for="inv-email">Email</label><input id="inv-email" type="email" placeholder="teammate@company.com" style="min-width:240px"><label class="small mut" for="inv-role">Role</label><select id="inv-role">${roles.map(r=>`<option value="${esc(r.name)}"${r.name==='developer'?' selected':''}>${esc(r.name)}</option>`).join('')}</select><button class="primary" onclick="invite()">Invite</button></div></div>
  <div class="card"><h3>Custom roles</h3><p>Comma-separated permissions, for example <span class="mono">secrets:read</span> or <span class="mono">*</span>.</p><div class="row"><input id="role-name" placeholder="deployer"><input id="role-perms" placeholder="secrets:read,secrets:write" style="min-width:260px"><button onclick="mkRole()">Create role</button></div><div>${roles.map(r=>`<span class="chip">${esc(r.name)}: ${esc((r.permissions||[]).join(', '))}${r.managed?' (managed)':''}</span>`).join('')}</div></div>
  <div class="card"><h3>Teams</h3><div class="row"><input id="team-name" placeholder="platform-team"><button onclick="mkTeam()">Create team</button></div><div>${teams.map(t=>`<span class="chip">${esc(t.name)}</span>`).join('')||'<span class="mut">No teams yet</span>'}</div></div>
  <div class="card"><h3>Secret change proposals ${ENV?('· '+esc(ENV.name)):''}</h3><p>Proposals stage secret changes for admin approval instead of deploying directly.</p>
  ${props.length?props.map(p=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:7px 0"><span class="mono small">${esc(p.id.slice(0,8))} · ${esc(p.status)} · by ${esc(String(p.author).slice(0,8))}</span>${p.status==='pending'?`<span><button onclick="decideProp('${p.id}','approve')">Approve</button> <button class="danger" onclick="decideProp('${p.id}','reject')">Reject</button></span>`:''}</div>`).join(''):'<span class="mut">No proposals</span>'}
  <div class="row" style="margin-top:12px"><button onclick="proposeModal()">New proposal</button></div></div>
  <div class="card"><h3>Access requests ${ENV?('· '+esc(ENV.name)):''}</h3>
  ${reqs.length?reqs.map(r=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:7px 0"><span class="small">${esc(r.reason||'access')} · ${esc(r.status)}</span>${r.status==='pending'?`<span><button onclick="decideAccess('${r.id}','approve')">Approve</button> <button class="danger" onclick="decideAccess('${r.id}','reject')">Reject</button></span>`:''}</div>`).join(''):'<span class="mut">No requests</span>'}
  <div class="row" style="margin-top:12px"><button onclick="requestAccess()">Request access to current env</button></div></div>
  <div class="card"><h3>Machine identities</h3><p>For CI and workloads. Universal Auth exchanges client credentials for a 1-hour token.</p><div class="row"><input id="id-name" placeholder="github-actions"><button onclick="mkIdentity()">Create identity</button></div><pre class="val" id="ident-out"></pre></div>
  <div class="card"><h3>Service tokens ${APP?('· '+esc(APP.name)):''}</h3><div class="row"><button onclick="mkToken()">Create token</button><button onclick="loadTokens()">List / revoke</button></div><pre class="val" id="tok-out"></pre><div id="tok-list"></div></div>`}
async function invite(){try{let d=await api('POST',`/api/orgs/${ORG}/members`,{email:$('inv-email').value,role:$('inv-role').value});
  if(d.invite_token){let link=location.origin+'/#invite='+encodeURIComponent(d.invite_token);
    modal(`<h3>Invitation created</h3><p class="mut">Send this single-use link to ${esc($('inv-email').value)}. It expires in 7 days.</p><textarea rows="3" readonly>${esc(link)}</textarea><div class="row" style="margin-top:12px"><button onclick="navigator.clipboard.writeText(document.querySelector('#modal textarea').value);toast('Invite link copied')">Copy link</button><button class="primary" onclick="closeModal()">Done</button></div>`);}
  else toast('Member added');
  $('inv-email').value='';renderAccess()}catch(e){toast(e.message,true)}}
async function mkRole(){try{await api('POST',`/api/orgs/${ORG}/roles`,{name:$('role-name').value,permissions:$('role-perms').value.split(',').map(s=>s.trim()).filter(Boolean)});toast('Role created');renderAccess()}catch(e){toast(e.message,true)}}
async function mkTeam(){try{await api('POST',`/api/orgs/${ORG}/teams`,{name:$('team-name').value});toast('Team created');renderAccess()}catch(e){toast(e.message,true)}}
async function decideProp(id,a){try{let d=await api('POST',`/api/proposals/${id}/${a}`,{});toast('Proposal '+d.status);renderAccess()}catch(e){toast(e.message,true)}}
function proposeModal(){modal(`<h3>New proposal for ${esc(ENV.name)}</h3><textarea id="pr-text" rows="8" placeholder="KEY=value per line"></textarea><div class="row" style="margin-top:12px"><button class="primary" onclick="submitProposal()">Submit for approval</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`)}
async function submitProposal(){try{let secrets=$('pr-text').value.split('\n').filter(l=>l.includes('=')).map(l=>{let i=l.indexOf('=');return{key:l.slice(0,i).trim(),value:l.slice(i+1)}});await api('POST',`/api/envs/${ENV.id}/proposals`,{secrets});closeModal();toast('Proposal submitted');renderAccess()}catch(e){toast(e.message,true)}}
async function decideAccess(id,a){try{await api('POST',`/api/access-requests/${id}/${a}`,{});toast('Request '+a+'d');renderAccess()}catch(e){toast(e.message,true)}}
async function requestAccess(){try{await api('POST',`/api/envs/${ENV.id}/access-requests`,{reason:'requested from console'});toast('Access requested');renderAccess()}catch(e){toast(e.message,true)}}
async function mkIdentity(){try{let d=await api('POST',`/api/orgs/${ORG}/identities`,{name:$('id-name').value||'machine'});$('ident-out').textContent=`client_id: ${d.client_id}\nclient_secret: ${d.client_secret}\nShown once. Exchange at POST /api/v1/machine/auth/universal/login`}catch(e){toast(e.message,true)}}
async function mkToken(){try{let d=await api('POST',`/api/apps/${APP.id}/tokens`,{name:'console',env_id:ENV?ENV.id:''});$('tok-out').textContent=d.token+'\nScoped to env: '+(ENV?ENV.name:'all')}catch(e){toast(e.message,true)}}
async function loadTokens(){try{let toks=await api('GET',`/api/apps/${APP.id}/tokens`);$('tok-list').innerHTML=toks.map(t=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:6px 0"><span class="mono small">${esc(t.name)} · ${esc(t.kind||'token')} · ${new Date((t.created_at||0)*1000).toLocaleDateString()}</span><button class="danger" onclick="revokeToken('${t.id}')">Revoke</button></div>`).join('')||'<span class="mut">No tokens</span>'}catch(e){toast(e.message,true)}}
async function revokeToken(id){try{await api('DELETE',`/api/tokens/${id}`);toast('Token revoked');loadTokens()}catch(e){toast(e.message,true)}}

const KINDS=['trigger','github','gitlab','vercel','netlify','cloudflare','cloudflare_pages','supabase','nomad','coolify','heroku','render','flyio','railway','digitalocean','gcp_secret_manager','azure_key_vault','kubernetes','hashicorp_vault','aws_secrets_manager','aws_parameter_store','webhook'];
async function renderIntegrations(){if(!needAppEnv())return;setTimeout(kindHint,0);$('pagetitle').textContent='Integrations';$('crumb').textContent=ENV?('/ '+ENV.name):'';
  let ints=ENV?await api('GET',`/api/envs/${ENV.id}/integrations`).catch(()=>[]):[];
  $('view').innerHTML=`<div class="card"><h3>Sync secrets to a platform</h3><p>Integrations run automatically on every deploy, or on demand. Config is stored encrypted. Trigger.dev example config: <span class="mono">{"token":"tr_pat_…","project_ref":"proj_…","target_env":"prod"}</span></p>
  <div class="row"><select id="ikind" onchange="kindHint()">${KINDS.map(k=>`<option>${k}</option>`).join('')}</select></div>
  <p class="small" id="ikind-hint"></p><textarea id="icfg" rows="4" placeholder='{"token":"…"}'></textarea>
  <div class="row" style="margin-top:10px"><button class="primary" onclick="mkIntegration()">Add integration</button></div></div>
  <div class="card"><h3>Configured ${ENV?('· '+esc(ENV.name)):''}</h3>${ints.length?ints.map(i=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:8px 0"><span><b>${esc(i.kind)}</b> <span class="mut small">${esc(i.name||'')}</span></span><span><button onclick="testInt('${i.id}')">Test</button> <button class="primary" onclick="syncInt('${i.id}')">Sync now</button></span></div>`).join(''):'<span class="mut">None yet</span>'}</div>
  <div class="card"><h3>Dynamic secrets &amp; rotation</h3><div class="row"><input id="lease-name" placeholder="lease name"><button onclick="mkLease()">New lease (1h)</button><button onclick="loadLeases()">Show leases</button></div><pre class="val" id="leases"></pre>
  <div class="row"><input id="rot-key" placeholder="KEY_TO_ROTATE"><span class="row"><input id="rot-int" value="86400" size="8"><span class="mut small">seconds between rotations</span></span><button onclick="mkRotation()">Schedule rotation</button></div></div>
  <div class="card"><h3>Lockbox: one-time secret sharing</h3><div class="row"><input id="lb-val" placeholder="value to share once" style="min-width:280px"><button onclick="mkLockbox()">Create link</button></div><pre class="val" id="lb-out"></pre></div>`}
const KIND_HINTS={trigger:'Trigger.dev: {"token":"tr_pat_… or tr_prod_sk_…","project_ref":"proj_…","target_env":"prod"}',github:'GitHub: {"token":"ghp_…","owner":"org","repo":"repo"}',gitlab:'GitLab: {"token":"glpat-…","project_id":"42"}',webhook:'Webhook: {"url":"https://…","token":"optional bearer"}',kubernetes:'Kubernetes: {"api_server":"https://…","token":"…","namespace":"default","secret_name":"app-secrets"}'};
function kindHint(){if(!$('ikind'))return;let k=$('ikind').value;$('ikind-hint').textContent=KIND_HINTS[k]||('Config for '+k+' as JSON. Common keys: token, base_url for self-hosted instances. Stored encrypted at rest.')}
async function mkIntegration(){try{await api('POST',`/api/envs/${ENV.id}/integrations`,{kind:$('ikind').value,config:JSON.parse($('icfg').value||'{}')});toast('Integration added');renderIntegrations()}catch(e){toast(e.message,true)}}
async function testInt(id){try{let d=await api('POST',`/api/integrations/${id}/test`,{});toast(d.detail)}catch(e){toast(e.message,true)}}
async function syncInt(id){try{let d=await api('POST',`/api/integrations/${id}/sync`,{});toast(d.detail)}catch(e){toast(e.message,true)}}
async function mkLease(){try{let d=await api('POST',`/api/envs/${ENV.id}/dynamic`,{name:$('lease-name').value||'lease'});$('leases').textContent=JSON.stringify(d,null,2)}catch(e){toast(e.message,true)}}
async function loadLeases(){try{let d=await api('GET',`/api/envs/${ENV.id}/dynamic`);$('leases').textContent=JSON.stringify(d,null,2)}catch(e){toast(e.message,true)}}
async function mkRotation(){try{await api('POST',`/api/envs/${ENV.id}/rotations`,{key:$('rot-key').value,interval_secs:parseInt($('rot-int').value)});toast('Rotation scheduled')}catch(e){toast(e.message,true)}}
async function mkLockbox(){try{let d=await api('POST','/api/lockbox',{text:$('lb-val').value});$('lb-out').textContent=location.origin+d.url+'\nOpens once, expires in 24h. The key is in the #fragment and never sent to the server on page load.'}catch(e){toast(e.message,true)}}

async function renderAudit(){$('pagetitle').textContent='Audit log';$('crumb').textContent='';
  let rows=await api('GET',`/api/orgs/${ORG}/audit`).catch(()=>[]);
  $('view').innerHTML=`<div class="card"><h3>Log streams</h3><p>Audit events are also forwarded to streams with HMAC-signed retries.</p><div class="row"><input id="stream-url" placeholder="https://hooks.example.com/openwarp" style="min-width:300px"><button onclick="mkStream()">Add stream</button><button onclick="loadDeliveries()">Delivery history</button></div><pre class="val" id="delivs"></pre></div>
  <table><thead><tr><th>When</th><th>Action</th><th>Actor</th><th>Detail</th></tr></thead><tbody>${rows.map(r=>`<tr><td class="mut small">${new Date((r.created_at||0)*1000).toLocaleString()}</td><td class="mono">${esc(r.action)}</td><td class="mono small">${esc(String(r.actor||'').slice(0,10))}</td><td class="mut">${esc(r.detail||'')}</td></tr>`).join('')||'<tr><td colspan="4" class="mut">No events yet</td></tr>'}</tbody></table>`}
async function mkStream(){try{await api('POST',`/api/orgs/${ORG}/log-streams`,{name:'console',url:$('stream-url').value});toast('Log stream added')}catch(e){toast(e.message,true)}}
async function loadDeliveries(){try{let d=await api('GET',`/api/orgs/${ORG}/log-streams/deliveries`);$('delivs').textContent=JSON.stringify(d.slice(0,25),null,2)}catch(e){toast(e.message,true)}}

async function renderSettings(){$('pagetitle').textContent='Settings';$('crumb').textContent='';
  let inst=await api('GET','/api/instance').catch(()=>null);
  let instanceCard=inst&&inst.instance_owner?`<div class="card"><h3>Instance</h3><p>Control who can create an account on this server.</p>
    <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="set-signups" ${inst.signups_open?'checked':''} ${inst.signups_env_locked?'disabled':''}> Allow self signup</label>
    <p class="small mut">When off, new users join only by invitation. ${inst.signups_env_locked?'Locked by OPENWARP_SIGNUPS.':''}</p>
    <button class="primary" onclick="saveSignups()" ${inst.signups_env_locked?'disabled':''}>Save signup policy</button></div>`:'';
  $('view').innerHTML=`${instanceCard}
  <div class="card"><h3>Organisation security</h3><p>IP allowlist is enforced on every API call. OIDC powers SSO and MCP OAuth discovery.</p>
  <div class="field"><label for="set-ip">IP allowlist (CIDR, comma separated, empty = allow all)</label><input id="set-ip" placeholder="203.0.113.0/24"></div>
  <div class="field"><label for="set-oidc-iss">OIDC issuer</label><input id="set-oidc-iss" placeholder="https://accounts.google.com"></div>
  <div class="row"><input id="set-oidc-cid" placeholder="OIDC client id"><input id="set-oidc-sec" type="password" placeholder="OIDC client secret"><input id="set-oidc-redir" placeholder="redirect URI" style="min-width:260px"></div>
  <div class="row" style="margin-top:10px"><button class="primary" onclick="saveSettings()">Save settings</button></div></div>
  <div class="card"><h3>Authenticator app (TOTP)</h3><p>Add a second factor to your login.</p><div class="row"><button onclick="totpSetup()">Set up TOTP</button></div><pre class="val" id="totp-out"></pre><div class="row"><input id="totp-code" placeholder="code from authenticator"><button onclick="totpVerify()">Verify and enable</button></div></div>
  <div class="card"><h3>End-to-end environments</h3><p>Paste your recovery kit to decrypt an E2E environment in this browser only. The kit never leaves this page.</p>
  <div class="row"><input id="e2e-kit" placeholder="recovery kit (base64)" style="min-width:320px"><input id="e2e-env" placeholder="E2E env ID"><button class="primary" onclick="loadE2E()">Decrypt</button></div><pre class="val" id="e2e-out"></pre></div>
  <div class="card"><h3>PKI</h3><p>Issue internal certificates from your own CA.</p><div class="row"><input id="ca-name" placeholder="internal-ca"><button onclick="mkCA()">Create CA</button></div><pre class="val" id="ca-out"></pre></div>
  <div class="card"><h3>Session</h3><div class="row"><button onclick="loadTokensSettings()">My tokens</button><button class="danger" onclick="logout()">Sign out everywhere (this device)</button></div><pre class="val" id="sess-out"></pre></div>`}
async function saveSettings(){try{await api('PUT',`/api/orgs/${ORG}/settings`,{ip_allowlist:$('set-ip').value,oidc_issuer:$('set-oidc-iss').value,oidc_client_id:$('set-oidc-cid').value,oidc_client_secret:$('set-oidc-sec').value,oidc_redirect_uri:$('set-oidc-redir').value});toast('Settings saved')}catch(e){toast(e.message,true)}}
async function saveSignups(){try{let d=await api('PUT','/api/instance/signups',{open:$('set-signups').checked});toast('Signups '+(d.signups_open?'enabled':'disabled'));renderSettings()}catch(e){toast(e.message,true)}}
async function totpSetup(){try{let d=await api('POST','/api/me/totp/setup',{});$('totp-out').textContent='Secret: '+d.secret+'\n'+d.otpauth_url+'\nRecovery codes (save once):\n'+d.recovery_codes.join('\n')}catch(e){toast(e.message,true)}}
async function totpVerify(){try{await api('POST','/api/me/totp/verify',{code:$('totp-code').value});toast('TOTP enabled')}catch(e){toast(e.message,true)}}
async function loadE2E(){try{let d=await api('GET',`/api/envs/${$('e2e-env').value}/e2e/secrets`);let k=await OW.decryptAsymmetric($('e2e-kit').value,d.wrapped_key);
  $('e2e-out').textContent=d.secrets.map(s=>new TextDecoder().decode(OW.decryptSymmetric(k,s.key_enc))+'='+new TextDecoder().decode(OW.decryptSymmetric(k,s.value_enc))).join('\n')||'(no secrets)'}catch(e){$('e2e-out').textContent='Error: '+(e.message||e)}}
async function mkCA(){try{let d=await api('POST',`/api/orgs/${ORG}/pki/cas`,{name:$('ca-name').value||'internal-ca'});$('ca-out').textContent='CA id: '+d.id+'\n'+d.certificate}catch(e){toast(e.message,true)}}
async function loadTokensSettings(){$('sess-out').textContent='Use openwarp login / MCP OAuth clients for programmatic access. Service tokens live under Members & access.'}

// ---------- command palette ----------
function openPalette(){$('palette').style.display='block';$('paletteinput').value='';$('paletteresults').innerHTML='';setTimeout(()=>$('paletteinput').focus(),30)}
async function paletteSearch(){let q=$('paletteinput').value;if(q.length<2){$('paletteresults').innerHTML='';return}
  try{let d=await api('GET','/api/search?q='+encodeURIComponent(q));$('paletteresults').innerHTML=d.results.map(r=>`<div class="pitem" onclick="paletteGo('${jsq(r.key)}')"><span class="mono">${esc(r.key)}</span><span class="mut small">${esc(r.app)} / ${esc(r.env)} ${esc(r.path||'')}</span></div>`).join('')||'<div class="pitem mut">No matches</div>'}catch(e){}}
function paletteGo(key){$('palette').style.display='none';if(APP&&ENV){nav('apps');renderEnv().then(()=>{let f=$('sfilter');if(f){f.value=key;drawSecrets()}})}}
$('palette').addEventListener('click',e=>{if(e.target.id==='palette')$('palette').style.display='none'});

loadProviders();
function boot(){
  if(typeof location==='undefined')return;
  let h=(location.hash||'').slice(1);
  if(h.startsWith('token=')){
    // The OIDC callback appends &org=<id>; the token itself never contains &.
    let parts=h.slice(6).split('&');T=decodeURIComponent(parts[0]);
    for(let p of parts.slice(1)){if(p.startsWith('org='))PENDING_ORG=decodeURIComponent(p.slice(4));}
    localStorage.setItem('owt',T);history.replaceState(null,'',location.pathname);}
  else if(h.startsWith('invite=')){showInvite(decodeURIComponent(h.slice(7).split('&')[0]));}
}
boot();
if(typeof window!=='undefined'&&window.addEventListener)window.addEventListener('hashchange',boot);
if(T){$('auth').style.display='none';enterApp().catch(()=>{T='';localStorage.removeItem('owt');$('auth').style.display='grid';$('shell').style.display='none'})}
</script>
<script src="/e2e.js"></script>
</body></html>
"##;
