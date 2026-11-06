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
#navtoggle{display:none}
@media(max-width:820px){#shell{grid-template-columns:1fr}#navtoggle{display:inline-block}aside{display:none;position:fixed;top:0;bottom:0;left:0;width:260px;z-index:80;box-shadow:0 0 60px rgba(0,0,0,.7)}aside.open{display:flex}.content{padding:16px 14px 100px}}
</style></head>
<body>
<div id="auth">
  <div class="authcard">
    <div class="logo"><span class="mark">◆</span>OpenWarp</div>
    <h1 id="authtitle">Welcome back</h1><p class="sub">Secrets management with no tiers and no licence gates.</p>
    <div class="seg"><button id="seglogin" class="on" onclick="authMode('login')">Sign in</button><button id="segreg" onclick="authMode('register')">Create account</button></div>
    <div id="authform">
      <div id="loginfields">
        <div class="field"><label for="email">Email</label><input id="email" type="email" autocomplete="email" placeholder="you@company.com"></div>
        <div class="field"><label for="pw">Password</label><input id="pw" type="password" autocomplete="current-password" placeholder="••••••••••" onkeydown="if(event.key==='Enter')doAuth()"></div>
        <button class="primary" style="width:100%;padding:11px" id="authbtn" onclick="doAuth()">Sign in</button>
        <button class="ghost" style="width:100%;margin-top:6px" id="forgotbtn" onclick="forgotPrompt()">Forgot password?</button>
      </div>
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
    <div class="topbar"><button class="iconbtn" id="navtoggle" aria-label="Open navigation" onclick="toggleNav()">☰</button><h2 id="pagetitle">Apps</h2><span class="crumb" id="crumb"></span><div class="grow"></div>
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
let T='', ORG='', APP=null, ENV=null, APPS=[], ENVS=[], SECRETS=[], DRAFTS={}, VIEW='apps', MFA=null, MFAMETHODS=[], MFA_INFO=null, LASTFOCUS=null, PENDING_ORG=null, AUTH_KEY=null, WRAP_KEY=null, WRAPPED_PRIV='', E2E_KIT='', E2E_KEYS={}, E2E_DATA={}, E2E_DRAFTS={}, E2E_META={}, E2E_GRANTS={}, E2E_LOADING={}, E2E_LOCKED={}, E2E_ERR={}, MY_PUBKEY='', MY_UID='', ORGS=[], MY_ROLE='', APP_POLICY='managed', RUNNERS=[], NEW_RUNNER=null, RUNNER_AFTER='', NEWAPP_DRAFT=null, NEWENV_DRAFT=null;
function drafts(){return (ENV&&DRAFTS[ENV.id])||{}}
function e2eDrafts(){return (ENV&&E2E_DRAFTS[ENV.id])||{}}
function e2eDraftList(){return Object.values(e2eDrafts())}
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
function b64uToBuf(s){let b=atob(String(s).replace(/-/g,'+').replace(/_/g,'/'));let u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u.buffer}
function bufToB64u(x){let u=new Uint8Array(x),s='';for(let i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function creationOptions(o){o.challenge=b64uToBuf(o.challenge);o.user.id=b64uToBuf(o.user.id);
  if(o.excludeCredentials)o.excludeCredentials=o.excludeCredentials.map(c=>{c.id=b64uToBuf(c.id);return c});return o}
function requestOptions(o){o.challenge=b64uToBuf(o.challenge);
  if(o.allowCredentials)o.allowCredentials=o.allowCredentials.map(c=>{c.id=b64uToBuf(c.id);return c});return o}
function attestationJson(c){return {id:c.id,rawId:bufToB64u(c.rawId),type:c.type,clientExtensionResults:c.getClientExtensionResults?c.getClientExtensionResults():{},
  response:{clientDataJSON:bufToB64u(c.response.clientDataJSON),attestationObject:bufToB64u(c.response.attestationObject),transports:c.response.getTransports?c.response.getTransports():[]}}}
function assertionJson(a){return {id:a.id,rawId:bufToB64u(a.rawId),type:a.type,clientExtensionResults:a.getClientExtensionResults?a.getClientExtensionResults():{},
  response:{clientDataJSON:bufToB64u(a.response.clientDataJSON),authenticatorData:bufToB64u(a.response.authenticatorData),signature:bufToB64u(a.response.signature),userHandle:a.response.userHandle?bufToB64u(a.response.userHandle):null}}}
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
  if(p.password===false){
    $('loginfields').style.display='none';$('segreg').style.display='none';$('seglogin').style.display='none';
    $('signupnote').textContent=btns.length?'Password sign-in is disabled on this instance. Use one of the providers above.':'Password sign-in is disabled and no provider is enabled. Contact the administrator.';
  }else if(p.signups!=='open'){
    $('segreg').style.display='none';
    if(MODE==='register')authMode('login');
    $('signupnote').textContent='Signups are closed. Ask an administrator for an invitation.';
  }
}catch(e){}}
function showMfa(token,methods,emailAvailable){
  MFA=token;MFAMETHODS=Array.isArray(methods)?methods:['totp'];
  $('auth').style.display='grid';$('shell').style.display='none';
  $('authtitle').textContent='Two-step verification';
  let html=`<p class="mut">Enter a code for this account.</p>
    <div class="field"><label for="mfacode">Code or recovery code</label><input id="mfacode" autocomplete="one-time-code" placeholder="123456" onkeydown="if(event.key==='Enter')doMfa()"></div>
    <button class="primary" style="width:100%;padding:11px" onclick="doMfa()">Verify</button>`;
  if(MFAMETHODS.includes('email')&&emailAvailable)html+=`<button class="ghost" style="width:100%;margin-top:6px" onclick="sendEmailCode()">Email me a code</button>`;
  if(MFAMETHODS.includes('passkey'))html+=`<button style="width:100%;margin-top:6px" onclick="usePasskey()">Use a passkey</button>`;
  $('authform').innerHTML=html}
async function showAuthMfa(){$('auth').style.display='grid';$('shell').style.display='none';
  try{let d=await api('POST','/api/auth/mfa/options',{mfa_token:MFA});showMfa(MFA,d.methods,d.email_available)}
  catch(e){$('authtitle').textContent='Sign in';$('authform').innerHTML='<p class="mut">This verification link expired.</p><button class="primary" style="width:100%" onclick="location.reload()">Sign in again</button>'}}
function showInvite(token){
  $('auth').style.display='grid';$('shell').style.display='none';
  $('authtitle').textContent='Accept invitation';
  $('authform').innerHTML=`<p class="mut">Choose a password for your new account.</p>
    <div class="field"><label for="inv-pw">Password</label><input id="inv-pw" type="password" autocomplete="new-password" placeholder="at least 8 characters"></div>
    <button class="primary" style="width:100%;padding:11px" onclick="acceptInvite()">Create account</button>`;
  $('authform').dataset.invite=token;}
function showKit(title,text,kit,cont){modal(`<h3>${esc(title)}</h3><p class="mut">${esc(text)}</p><textarea id="kit-text" aria-label="Recovery kit" rows="3" readonly>${esc(kit)}</textarea><div class="row" style="margin-top:12px"><button onclick="navigator.clipboard.writeText('${jsq(kit)}');toast('Recovery kit copied')">Copy kit</button><button class="primary" onclick="closeModal();${cont?'enterApp()':''}">${cont?'I saved it, continue':'I saved it'}</button></div>`)}
async function unlockE2E(){if(!(WRAP_KEY&&WRAPPED_PRIV))return;try{let secret=await AuthV2.unwrapPrivate(WRAP_KEY,WRAPPED_PRIV);E2E_KIT=OW.b64enc(secret)}catch(e){E2E_KIT=''}}
async function acceptInvite(){try{
  let password=$('inv-pw').value;if(password.length<8){toast('Password must be at least 8 characters',true);return}
  let salt=AuthV2.randomSalt();let keys=await AuthV2.deriveKeys(password,salt,600000);let kp=await OW.generateKeypair();
  let wrapped=await AuthV2.wrapPrivate(keys.wrap,kp.secret);
  let d=await api('POST','/api/auth/accept-invite-v2',{token:$('authform').dataset.invite,salt,iterations:600000,algo:'pbkdf2-sha256',auth_key:AuthV2.b64enc(keys.auth),public_key:kp.public,wrapped_privkey:wrapped});
  AUTH_KEY=keys.auth;WRAP_KEY=keys.wrap;WRAPPED_PRIV=wrapped;E2E_KIT=OW.b64enc(kp.secret);
  T='';history.replaceState(null,'',location.pathname);
  if(d.mfa_required){showMfa(d.mfa_token,d.methods,d.email_available);return}
  showKit('Save your recovery kit','This X25519 private key decrypts end-to-end environments and is shown once.',E2E_KIT,true);
}catch(e){toast(e.message,true)}}
function forgotPrompt(){modal(`<h3>Reset your password</h3><p class="mut">Enter your email. If an account exists, a reset link is sent.</p>
  <div class="field"><label for="fp-email">Email</label><input id="fp-email" type="email" value="${esc($('email').value)}"></div>
  <div class="row"><button class="primary" onclick="sendForgot()">Send link</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`,'Reset password')}
async function sendForgot(){try{await api('POST','/api/auth/forgot',{email:$('fp-email').value});closeModal();toast('If that address has an account, a reset link is on its way')}catch(e){toast(e.message,true)}}
function showReset(token){
  $('auth').style.display='grid';$('shell').style.display='none';$('authtitle').textContent='Choose a new password';
  $('authform').innerHTML=`<p class="mut">Enter a new password for your account.</p>
    <div class="field"><label for="rp-pw">New password</label><input id="rp-pw" type="password" autocomplete="new-password" placeholder="at least 8 characters"></div>
    <div class="field"><label for="rp-kit">Recovery kit (keeps end-to-end environments readable)</label><input id="rp-kit" placeholder="base64 recovery kit"></div>
    <label class="row small mut" style="gap:8px"><input type="checkbox" id="rp-discard"> I no longer have my kit; replace my key and lose end-to-end access</label>
    <button class="primary" style="width:100%;padding:11px;margin-top:10px" onclick="resetPassword()">Set new password</button>`;
  $('authform').dataset.reset=token}
async function resetPassword(){try{
  let password=$('rp-pw').value,kit=$('rp-kit').value.trim(),token=$('authform').dataset.reset;
  if(password.length<8){toast('Password must be at least 8 characters',true);return}
  let info=await api('POST','/api/auth/reset-info',{token});
  let secret,pubkey;
  if(kit){secret=AuthV2.b64dec(kit);pubkey=OW.b64enc(await OW.x25519Pub(secret));if(info.public_key&&pubkey!==info.public_key){toast('The recovery kit does not match this account',true);return}}
  else if($('rp-discard').checked){let kp=await OW.generateKeypair();secret=kp.secret;pubkey=kp.public}
  else{toast('Recovery kit required; tick the replacement box only if you accept losing end-to-end access',true);return}
  let salt=AuthV2.randomSalt();let keys=await AuthV2.deriveKeys(password,salt,600000);
  let wrapped=await AuthV2.wrapPrivate(keys.wrap,secret);
  let d=await api('POST','/api/auth/reset-v2',{token,salt,iterations:600000,algo:'pbkdf2-sha256',auth_key:AuthV2.b64enc(keys.auth),public_key:pubkey,wrapped_privkey:wrapped,discard_e2e_key:!!$('rp-discard').checked});
  AUTH_KEY=keys.auth;WRAP_KEY=keys.wrap;WRAPPED_PRIV=wrapped;E2E_KIT=OW.b64enc(secret);
  T='';history.replaceState(null,'',location.pathname);
  if(d.mfa_required){toast('Password set; verify your second factor');showMfa(d.mfa_token,d.methods,d.email_available);return}
  toast('Password set');enterApp();
}catch(e){toast(e.message,true)}}
let MODE='login';
function authMode(m){MODE=m;$('seglogin').classList.toggle('on',m==='login');$('segreg').classList.toggle('on',m==='register');$('authtitle').textContent=m==='login'?'Welcome back':'Create your account';$('authbtn').textContent=m==='login'?'Sign in':'Create account'}
async function doAuth(){let email=$('email').value.trim(),password=$('pw').value;AUTH_KEY=null;WRAP_KEY=null;WRAPPED_PRIV='';E2E_KIT='';
  try{
    let kdf=await AuthV2.kdf(email);
    if(MODE==='register'){
      if(kdf.version!==2){toast('This instance still uses password registration',true);return}
      if(password.length<8){toast('Password must be at least 8 characters',true);return}
      let keys=await AuthV2.deriveKeys(password,kdf.salt,kdf.iterations);let kp=await OW.generateKeypair();
      let wrapped=await AuthV2.wrapPrivate(keys.wrap,kp.secret);
      let d=await api('POST','/api/auth/register-v2',{email,salt:kdf.salt,iterations:kdf.iterations,algo:kdf.algo,auth_key:AuthV2.b64enc(keys.auth),public_key:kp.public,wrapped_privkey:wrapped});
      AUTH_KEY=keys.auth;WRAP_KEY=keys.wrap;WRAPPED_PRIV=wrapped;E2E_KIT=OW.b64enc(kp.secret);
      if(d.verification_required){showKit('Check your email',`We sent a verification link to ${email}. Save your recovery kit now; it is shown once.`,E2E_KIT,false);return}
      T='';showKit('Save your recovery kit','This X25519 private key decrypts end-to-end environments and is shown once. Store it in a password manager.',E2E_KIT,true);return;
    }
    if(kdf.version===1){
      let d=await api('POST','/api/auth/login',{email,password});
      if(d.mfa_required){showMfa(d.mfa_token,d.methods,d.email_available);return}
      T='';enterApp();return;
    }
    let keys=await AuthV2.deriveKeys(password,kdf.salt,kdf.iterations);
    let ch=await AuthV2.challenge(email);let proof=await AuthV2.proof(keys.auth,ch.challenge,ch.challenge_id);
    let d=await api('POST','/api/auth/login-v2',{email,challenge_id:ch.challenge_id,proof});
    AUTH_KEY=keys.auth;WRAP_KEY=keys.wrap;WRAPPED_PRIV=d.wrapped_privkey||'';
    if(d.mfa_required){showMfa(d.mfa_token,d.methods,d.email_available);return}
    T='';await unlockE2E();enterApp();
  }catch(e){toast(e.message,true)}}
async function doMfa(){try{await api('POST','/api/auth/mfa',{mfa_token:MFA,code:$('mfacode').value});T='';await unlockE2E();enterApp()}catch(e){toast(e.message,true)}}
async function sendEmailCode(){try{await api('POST','/api/auth/mfa/email/send',{mfa_token:MFA});toast('A code is on its way to your email')}catch(e){toast(e.message,true)}}
async function usePasskey(){try{
  let s=await api('POST','/api/auth/mfa/passkey/start',{mfa_token:MFA});
  let cred=await navigator.credentials.get({publicKey:requestOptions(s.options.publicKey)});
  await api('POST','/api/auth/mfa/passkey/finish',{mfa_token:MFA,credential:assertionJson(cred)});
  T='';await unlockE2E();enterApp();
}catch(e){toast(e.message||String(e),true)}}
async function logout(){try{await api('POST','/api/auth/logout',{})}catch(e){} T='';AUTH_KEY=null;WRAP_KEY=null;WRAPPED_PRIV='';E2E_KIT='';E2E_KEYS={};E2E_DATA={};E2E_DRAFTS={};E2E_META={};E2E_GRANTS={};E2E_LOCKED={};E2E_ERR={};MY_PUBKEY='';MY_UID='';location.reload()}
async function enterApp(){$('auth').style.display='none';$('shell').style.display='grid';
  let me=await api('GET','/api/me');$('whoami').textContent=me.email;MY_PUBKEY=me.pubkey||'';MY_UID=me.id||'';
  let orgs=await api('GET','/api/orgs');ORGS=orgs;ORG=(PENDING_ORG&&orgs.some(o=>o.id===PENDING_ORG))?PENDING_ORG:(orgs[0]?.id||'');PENDING_ORG=null;
  MY_ROLE=orgs.find(o=>o.id===ORG)?.role||'';
  $('orgs').innerHTML=orgs.map(o=>`<option value="${o.id}">${esc(o.name)} · ${esc(o.role)}</option>`).join('');
  $('orgs').value=ORG;
  await nav('apps')}
async function switchOrg(){ORG=$('orgs').value;APP=null;ENV=null;MY_ROLE=ORGS.find(o=>o.id===ORG)?.role||'';RUNNERS=[];await nav('apps')}
function isAdmin(){return MY_ROLE==='owner'||MY_ROLE==='admin'}

// ---------- navigation ----------
function toggleNav(){let a=document.querySelector('aside');if(!a)return;let open=a.classList.toggle('open');let t=$('navtoggle');if(t)t.setAttribute('aria-expanded',open?'true':'false')}
async function nav(v){VIEW=v;let a=document.querySelector('aside');if(a){a.classList.remove('open');let t=$('navtoggle');if(t)t.setAttribute('aria-expanded','false')}document.querySelectorAll('.navbtn').forEach(b=>b.classList.toggle('on',b.dataset.nav===v));
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
function appCard(a,envs){return `<div class="appcard" onclick="openApp('${a.id}')"><h3>${esc(a.name)}</h3><div class="meta">${envs.length} environment${envs.length!==1?'s':''}</div><div>${envs.map(e=>`<span class="chip">${esc(e.name)}${e.mode==='delegated'?' · delegated':isE2E(e)?' · E2E':''}</span>`).join('')}</div></div>`}
function filterApps(q){document.querySelectorAll('.appcard').forEach((c,i)=>{c.style.display=APPS[i].name.toLowerCase().includes(q.toLowerCase())?'':'none'})}
async function newApp(draft){
  if(draft)NEWAPP_DRAFT=draft;
  let inst=null;try{inst=await api('GET','/api/instance')}catch(e){}
  APP_POLICY=(inst&&inst.app_env_policy)||'managed';
  let delegated=APP_POLICY==='delegated';
  if(delegated){try{RUNNERS=await api('GET',`/api/orgs/${ORG}/runners`)}catch(e){RUNNERS=[]}}
  let runners=runnersSelect(NEW_RUNNER&&NEW_RUNNER.id);
  let canKey=!!E2E_KIT;
  let runnerField=delegated?`<div class="field"><label for="na-runner">Sync runner</label>${RUNNERS.length?runners:'<p class="small" style="color:var(--bad)">No runner exists in this organisation yet. A runner holds the key grant for provider sync, and an admin has to create one.</p>'}
    ${canKey?'':`<p class="small" style="color:var(--bad)">This session has no client-held key. Sign in with a client-derived account to create delegated apps.</p>`}
    ${isAdmin()?'<button style="margin-top:8px" onclick="newRunner(\'app\')">Create a runner</button>':''}</div>`:'';
  let d=NEWAPP_DRAFT||{};
  modal(`<h3>New app</h3>
    <p class="small mut">Instance policy: <b>${delegated?'Delegated':'Managed'}</b>. ${delegated?'Default environments are encrypted in this browser and synced by a runner.':'Default environments are encrypted by the server for CLI and sync use.'}</p>
    <div class="field"><label for="na-name">App name</label><input id="na-name" value="${esc(d.name||'')}" placeholder="billing-api"></div>
    <div class="field"><label for="na-readme">Readme (markdown, optional)</label><textarea id="na-readme" rows="4">${esc(d.readme||'')}</textarea></div>
    ${runnerField}
    <div class="row"><button class="primary" onclick="createApp()" ${delegated&&(!RUNNERS.length||!canKey)?'disabled':''}>Create app</button><button class="ghost" onclick="closeModal()">Cancel</button></div>
    <p class="small mut">Development, Staging and Production are created automatically. Add unlimited custom environments later.</p>`)}
function runnersSelect(selected){return `<select id="na-runner" style="width:100%">${RUNNERS.map(r=>`<option value="${r.id}" ${r.id===selected?'selected':''}>${esc(r.name)}</option>`).join('')}</select>`}
async function createApp(){try{
  let name=$('na-name').value.trim(),readme=$('na-readme').value;
  if(!name)throw new Error('App name required');
  let d;
  if(APP_POLICY==='delegated'){
    let rid=$('na-runner')?.value;let runner=RUNNERS.find(r=>r.id===rid);
    if(!runner)throw new Error('Select a sync runner, or ask an admin to create one');
    if(!E2E_KIT)throw new Error('this session has no client-held private key; sign in with a client-derived account first');
    if(!MY_PUBKEY)throw new Error('account public key unavailable; reload and sign in again');
    let envs=[];
    for(const n of ['Development','Staging','Production']){
      let k=crypto.getRandomValues(new Uint8Array(32));
      envs.push({name:n,wrapped_key:await OW.encryptAsymmetric(MY_PUBKEY,k),runner_wrapped_key:await OW.encryptAsymmetric(runner.pubkey,k)});
    }
    d=await api('POST',`/api/orgs/${ORG}/apps`,{name,readme,mode:'delegated',runner_id:rid,envs});
  } else { d=await api('POST',`/api/orgs/${ORG}/apps`,{name,readme}); }
  closeModal();NEWAPP_DRAFT=null;NEW_RUNNER=null;toast('App created');
  await renderApps();await openApp(d.id)
}catch(e){toast(e.message,true)}}
function newRunner(after){
  RUNNER_AFTER=after||'settings';
  if(after==='app')NEWAPP_DRAFT={name:$('na-name')?.value||'',readme:$('na-readme')?.value||''};
  if(after==='env')NEWENV_DRAFT={name:$('ne-name')?.value||'',mode:$('ne-mode')?.value||'delegated'};
  modal(`<h3>New sync runner</h3>
    <p class="mut">A runner holds a key grant for delegated environments and pushes secrets to providers from your network. Its private key and token are generated here and shown once.</p>
    <div class="field"><label for="nr-name">Runner name</label><input id="nr-name" placeholder="vpc-runner"></div>
    <div class="row"><button class="primary" onclick="createRunner()">Create runner</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`,'New runner')}
async function createRunner(){try{
  let name=$('nr-name').value.trim();if(!name)throw new Error('Runner name required');
  let kp=await OW.generateKeypair();
  let d=await api('POST',`/api/orgs/${ORG}/runners`,{name,public_key:kp.public});
  NEW_RUNNER={id:d.id,name:d.name||name,pubkey:kp.public};
  let secret=OW.b64enc(kp.secret);
  modal(`<h3>Save the runner credentials</h3>
    <p class="mut">Shown once. Put both values in the runner's environment, set <span class="mono">OPENWARP_URL</span>, then start <span class="mono">openwarp-runner</span>.</p>
    <div class="field"><label for="nr-token">OPENWARP_RUNNER_TOKEN</label><textarea id="nr-token" rows="2" readonly>${esc(d.token)}</textarea></div>
    <div class="field"><label for="nr-key">OPENWARP_RUNNER_KEY</label><textarea id="nr-key" rows="3" readonly>${esc(secret)}</textarea></div>
    <div class="row"><button onclick="copyRunnerCredentials()">Copy both</button><button class="primary" onclick="finishRunner()">I stored them</button></div>`,'Runner credentials')
}catch(e){toast(e.message,true)}}
function copyRunnerCredentials(){navigator.clipboard.writeText(`OPENWARP_RUNNER_TOKEN=${$('nr-token').value}\nOPENWARP_RUNNER_KEY=${$('nr-key').value}`);toast('Runner credentials copied')}
async function finishRunner(){
  closeModal();
  try{RUNNERS=await api('GET',`/api/orgs/${ORG}/runners`)}catch(e){RUNNERS=[]}
  if(RUNNER_AFTER==='app'){await newApp(NEWAPP_DRAFT);return}
  if(RUNNER_AFTER==='env'){await newEnv(NEWENV_DRAFT);return}
  toast('Runner created');await renderSettings()}
async function openApp(id){APP=APPS.find(a=>a.id===id)||{id};ENVS=await api('GET',`/api/apps/${id}/envs`);
  ENV=ENVS.find(e=>e.id===ENV?.id)||ENVS[0]||null;await renderEnv()}

// ---------- environments and secrets ----------
async function renderEnv(){VIEW='env';$('topaction').style.display='none';$('pagetitle').textContent=APP?.name||'App';$('crumb').textContent='/ environments';
  if(!ENVS.length){$('view').innerHTML='<div class="empty"><div class="big">No environments</div><button class="primary" onclick="newEnv()">Create environment</button></div>';updateDeployBar();return}
  if(!ENV)ENV=ENVS[0];
  if(isE2E(ENV)||isDelegated(ENV)){await renderE2eEnv();return}
  let d=await api('GET',`/api/envs/${ENV.id}/secrets`);SECRETS=d.secrets;
  $('view').innerHTML=`
  ${envTabs()}
  <div class="row" style="margin-bottom:12px">
    <input id="sfilter" placeholder="Filter by key or path…" style="min-width:240px" oninput="drawSecrets()">
    <button onclick="importModal()">Import .env</button><button onclick="exportEnv()">Export</button>
    <span class="grow"></span><button class="primary" onclick="addRow()">+ New secret</button>
  </div>
  <div id="stable"></div>
  ${APP?.readme?`<div class="card" style="margin-top:14px"><h3>Readme</h3><pre class="val" style="white-space:pre-wrap">${esc(APP.readme)}</pre></div>`:''}`;
  drawSecrets();updateDeployBar()}
function envTabs(){return `<div class="envtabs">${ENVS.map(e=>`<button class="envtab ${e.id===ENV.id?'on':''}" onclick="switchEnv('${e.id}')">${esc(e.name)}${isE2E(e)?' · E2E':''}${e.mode==='delegated'?' · delegated':''}</button>`).join('')}<button class="envtab" onclick="newEnv()">+ Environment</button><button class="envtab" onclick="newE2eEnv()">+ E2E environment</button><span class="grow"></span><button class="ghost danger" onclick="delEnv()">Delete env</button></div>`}
async function renderE2eEnv(){VIEW='env';$('topaction').style.display='none';$('pagetitle').textContent=APP?.name||'App';$('crumb').textContent='/ environments';
  let id=ENV.id,delegated=isDelegated(ENV);
  if(!E2E_DATA[id]&&E2E_LOADING[id]){$('view').innerHTML=envTabs()+'<div class="empty"><div class="big">Unlocking…</div>Decrypting this environment in the browser.</div>';updateDeployBar();return}
  if(!E2E_DATA[id]&&E2E_KIT&&!E2E_LOCKED[id]&&!E2E_LOADING[id]){
    $('view').innerHTML=envTabs()+'<div class="empty"><div class="big">Unlocking…</div>Decrypting this environment with the key from your session.</div>';
    try{await e2eLoad(id,E2E_KIT)}catch(e){E2E_ERR[id]=e.message}
  }
  if(!E2E_DATA[id]){
    let err=E2E_ERR[id]?`<p class="small" style="color:var(--bad)">${esc(E2E_ERR[id])}</p>`:'';
    $('view').innerHTML=`${envTabs()}
    <div class="card"><h3>${delegated?'Delegated':'End-to-end encrypted'} environment</h3>
      <p class="mut">The server stores only ciphertext here, so this console has to decrypt it in the browser.${delegated?' A runner you host also holds a key grant for provider sync.':''} After a client-derived sign-in your private key is already in this tab. On another session, paste the recovery kit you saved at registration.</p>
      ${err}
      <div class="field"><label for="e2e-kit">Recovery kit</label><input id="e2e-kit" type="password" autocomplete="off" placeholder="base64 recovery kit" style="width:100%"></div>
      <button class="primary" onclick="unlockE2EEnv()">Unlock environment</button>
      <p class="small mut">The kit and the decrypted key stay in this tab and are never sent to the server. A reload locks the environment again.</p></div>`;
    updateDeployBar();return}
  let meta=E2E_META[id]||{};
  let banner=meta.rekey_required?`<div class="card" style="border-color:var(--bad)"><h3>Access changed</h3>
    <p>A member's key grant was removed, but the stored ciphertext is still encrypted under the old environment key. Rotate the key to re-encrypt every secret under a new key and wrap that key to the current members${delegated?' and the runner':''}. Rotation cannot take back ciphertext someone already copied.</p>
    <button class="primary" onclick="e2eRekey()">Rotate key now</button></div>`:'';
  let runnerNote=delegated?`<div class="card"><h3>Delegated environment</h3>
    <p class="mut">Provider sync runs on <span class="mono">${esc(meta.runner?.id||'your runner')}</span>: the server forwards ciphertext and the runner decrypts it in your network. Rotating the key also re-wraps it for the runner.</p></div>`:'';
  $('view').innerHTML=`${envTabs()}${banner}${runnerNote}
  <div class="row" style="margin-bottom:12px">
    <input id="sfilter" placeholder="Filter by key or path…" style="min-width:240px" oninput="drawE2E()">
    <button onclick="e2eGrantsModal()">Access</button>
    <button onclick="renderE2eEnv()">Refresh</button>
    <button onclick="lockE2E()">Lock</button>
    <span class="grow"></span><button class="primary" onclick="e2eAddRow()">+ New secret</button>
  </div>
  <p class="small mut">Decrypted in this tab only. Staged changes deploy together and are lost if you reload before deploying.</p>
  <div id="stable"></div>`;
  drawE2E();updateDeployBar()}
function isE2E(e){return !!e&&(e.mode||'sse')==='e2e'}
function isDelegated(e){return !!e&&e.mode==='delegated'}
function isClientEnv(e){return isE2E(e)||isDelegated(e)}
function enc(s){return new TextEncoder().encode(s)}
function dec(b){return new TextDecoder().decode(b)}
async function e2eHash(path,key){let d=await crypto.subtle.digest('SHA-256',enc(String(path||'/')+':'+String(key||'').toUpperCase()));return OW.b64enc(new Uint8Array(d))}
async function e2eLoad(id,kit){E2E_LOADING[id]=true;delete E2E_ERR[id];
  try{
    let d=await api('GET',`/api/envs/${id}/e2e/secrets`);
    let key=await OW.decryptAsymmetric(kit,d.wrapped_key);
    let rows=[];
    for(const s of d.secrets){
      let name,value;
      try{name=dec(await OW.decryptSymmetric(key,s.key_enc));value=dec(await OW.decryptSymmetric(key,s.value_enc))}
      catch(e){throw new Error('a stored secret could not be decrypted under your key grant; it may predate a rotation. Ask a member with current access, or the CLI, to rekey it')}
      let path=s.path_enc?dec(await OW.decryptSymmetric(key,s.path_enc)):(s.path||'/');
      rows.push({id:s.id,key:name,value,path,key_hash:s.key_hash,version:s.version||1,updated_at:s.updated_at});
    }
    rows.sort((a,b)=>a.key.localeCompare(b.key));
    E2E_KEYS[id]=key;E2E_DATA[id]=rows;E2E_DRAFTS[id]={};
    let [meta,grants]=await Promise.all([api('GET',`/api/envs/${id}/e2e/meta`).catch(()=>null),api('GET',`/api/envs/${id}/e2e/grants`).catch(()=>[])]);
    if(meta)E2E_META[id]=meta;E2E_GRANTS[id]=grants;
  }finally{delete E2E_LOADING[id]}}
async function unlockE2EEnv(){let kit=($('e2e-kit')?.value||'').trim()||E2E_KIT;
  if(!kit){toast('Paste the recovery kit for this account',true);return}
  try{await e2eLoad(ENV.id,kit);E2E_KIT=kit;delete E2E_LOCKED[ENV.id];toast('Environment unlocked');await renderE2eEnv()}catch(e){toast('Could not unlock: '+e.message,true)}}
function lockE2E(){if(e2eDraftList().length&&!confirm('Discard staged changes and lock this environment?'))return;
  E2E_LOCKED[ENV.id]=true;delete E2E_KEYS[ENV.id];delete E2E_DATA[ENV.id];delete E2E_DRAFTS[ENV.id];delete E2E_ERR[ENV.id];renderE2eEnv()}
function drawE2E(){
  let id=ENV.id,data=E2E_DATA[id]||[],dmap=e2eDrafts();
  let rows=data.map(s=>({s,st:dmap[s.id]})).filter(x=>matchesFilter(x.st?x.st.key:x.s.key,x.st?x.st.path:x.s.path));
  let news=Object.values(dmap).filter(d=>d.isNew&&!d.deleted&&matchesFilter(d.key,d.path)).map(d=>({s:d,st:d}));
  let all=rows.concat(news);
  if(!all.length){
    let any=data.length||Object.keys(dmap).length;
    $('stable').innerHTML=any
      ?'<div class="empty"><div class="big">No matching secrets</div>Nothing here matches that filter. Clear it to see every secret in this environment.</div>'
      :'<div class="empty"><div class="big">No secrets here yet</div>Click “+ New secret” to add one. Everything is encrypted in this browser before it is sent.</div>';
    return}
  $('stable').innerHTML=`<table><thead><tr><th style="width:28%">Key</th><th>Value</th><th style="width:13%">Path</th><th style="width:10%">Version</th><th style="width:14%"></th></tr></thead><tbody>
  ${all.map(({s,st})=>{let gone=!!(st&&st.deleted);let key=st?st.key:s.key;let value=st?st.value:s.value;let path=st?st.path:s.path;let dirty=!!st&&!st.isNew;
    return `<tr${gone?' style="opacity:.55"':''}><td>${dirty&&!gone?'<span class="stagedot"></span>':''}<span class="mono">${esc(key)}</span>${st&&st.isNew?' <span class="chip">new</span>':''}${gone?' <span class="chip">delete</span>':''}</td>
    <td>${gone?'<span class="mut">deleted on deploy</span>':`<span class="val" data-val="${esc(value??'')}" data-show="0">••••••••••</span>`}</td>
    <td class="mono mut">${esc(path||'/')}</td><td class="mut">${st&&st.isNew?'new':(st&&!gone?'staged':'v'+(s.version||1))}</td>
    <td style="white-space:nowrap;text-align:right">${gone
      ?`<button class="iconbtn" title="Undo delete" aria-label="Undo delete" onclick="e2eUndoDelete('${jsq(s.id)}')">↺</button>`
      :`<button class="iconbtn" title="Reveal" aria-label="Reveal" onclick="revealVal(this)">◉</button><button class="iconbtn" title="Copy value" aria-label="Copy value" onclick="copyVal(this)">⧉</button>
        <button class="iconbtn" title="Edit" aria-label="Edit" onclick="e2eEditRow('${jsq(s.id)}')">✎</button>
        <button class="iconbtn" title="Delete" aria-label="Delete" onclick="e2eDelRow('${jsq(s.id)}','${jsq(key)}')">🗑</button>`}</td></tr>`}).join('')}
  </tbody></table>`}
function e2eAddRow(){if(!E2E_DATA[ENV.id]){toast('Unlock the environment first',true);return}let id='new-'+Date.now();
  modal(`<h3>New secret</h3>
    <div class="field"><label for="ns-key">Key</label><input id="ns-key" placeholder="DATABASE_URL"></div>
    <div class="field"><label for="ns-val">Value</label><textarea id="ns-val" rows="3"></textarea></div>
    <div class="field"><label for="ns-path">Path</label><input id="ns-path" value="/"></div>
    <div class="row"><button class="primary" onclick="e2eStageNew('${id}')">Stage secret</button><button class="ghost" onclick="closeModal()">Cancel</button></div>
    <p class="small mut">Encrypted in this browser on deploy. There is no server-readable history for this environment.</p>`,'New secret')}
function e2eStageNew(id){let k=$('ns-key').value.trim().toUpperCase(),path=$('ns-path').value||'/';
  if(!/^[A-Za-z0-9_.-]{1,128}$/.test(k)){toast('Key must match [A-Za-z0-9_.-]{1,128}',true);return}
  let dup=(E2E_DATA[ENV.id]||[]).some(s=>s.key===k&&s.path===path)||Object.values(e2eDrafts()).some(d=>!d.deleted&&d.key===k&&d.path===path);
  if(dup){toast('A secret with that key and path already exists',true);return}
  if(!E2E_DRAFTS[ENV.id])E2E_DRAFTS[ENV.id]={};
  E2E_DRAFTS[ENV.id][id]={id,key:k,value:$('ns-val').value,path,isNew:true};
  closeModal();drawE2E();updateDeployBar()}
function e2eEditRow(id){let d=e2eDrafts()[id];let s=d||(E2E_DATA[ENV.id]||[]).find(x=>x.id===id);if(!s)return;
  modal(`<h3>Edit ${esc(s.key)}</h3><div class="field"><label for="ed-val">Value</label><textarea id="ed-val" rows="4">${esc(s.value??'')}</textarea></div>
    <div class="row"><button class="primary" onclick="e2eStageEdit('${jsq(id)}')">Stage change</button><button class="ghost" onclick="closeModal()">Cancel</button></div>
    <p class="small mut">Renaming is not staged here: delete the secret and add it under the new key. Rotate the key after a delete if the old value must stop being readable.</p>`,'Edit secret')}
function e2eStageEdit(id){let d=e2eDrafts()[id];let s=d||(E2E_DATA[ENV.id]||[]).find(x=>x.id===id);if(!s)return;
  if(d){d.value=$('ed-val').value;d.deleted=false}
  else{if(!E2E_DRAFTS[ENV.id])E2E_DRAFTS[ENV.id]={};E2E_DRAFTS[ENV.id][id]={id,key:s.key,value:$('ed-val').value,path:s.path,key_hash:s.key_hash}}
  closeModal();drawE2E();updateDeployBar();toast('Change staged, deploy when ready')}
function e2eDelRow(id,key){let d=e2eDrafts()[id];
  if(d&&d.isNew){delete e2eDrafts()[id];drawE2E();updateDeployBar();return}
  if(!confirm('Delete '+key+'? The console keeps no history for this environment, so the value cannot be restored here.'))return;
  let s=(E2E_DATA[ENV.id]||[]).find(x=>x.id===id);if(!s)return;
  if(!E2E_DRAFTS[ENV.id])E2E_DRAFTS[ENV.id]={};
  E2E_DRAFTS[ENV.id][id]={id,key:s.key,value:s.value,path:s.path,key_hash:s.key_hash,deleted:true};
  drawE2E();updateDeployBar()}
function e2eUndoDelete(id){delete e2eDrafts()[id];drawE2E();updateDeployBar()}
async function deployE2E(){
  let id=ENV.id,key=E2E_KEYS[id];if(!key){toast('Unlock the environment first',true);return}
  let list=e2eDraftList();if(!list.length)return;
  let dels=list.filter(d=>d.deleted&&!d.isNew),puts=list.filter(d=>!d.deleted);
  let seen=new Set();
  for(const d of puts){let k=(d.key||'').trim().toUpperCase();
    if(!/^[A-Za-z0-9_.-]{1,128}$/.test(k)){toast('Invalid key: '+k,true);return}
    let pk=(d.path||'/')+':'+k;if(seen.has(pk)){toast('Duplicate key in this deploy: '+k,true);return}seen.add(pk)}
  try{
    let items=[],expected=new Map();
    for(const d of puts){
      let k=(d.key||'').trim().toUpperCase(),path=d.path||'/';
      let kh=d.key_hash||await e2eHash(path,k);
      items.push({key_enc:await OW.encryptSymmetric(key,enc(k)),value_enc:await OW.encryptSymmetric(key,enc(d.value??'')),key_hash:kh,path_enc:await OW.encryptSymmetric(key,enc(path))});
      expected.set(kh,[k,d.value??'']);
    }
    // Writes go first: if they fail, the staged deletes are still unapplied and
    // the user can retry. A delete is only issued once every put is stored.
    if(items.length){let r=await api('PUT',`/api/envs/${id}/e2e/secrets`,{secrets:items});
      if(r.deployed!==items.length)throw new Error(`the server stored ${r.deployed} of ${items.length} secrets`)}
    for(const d of dels)await api('DELETE',`/api/secrets/${d.id}`);
    await e2eLoad(id,E2E_KIT);
    for(const [kh,[k,v]] of expected){let row=(E2E_DATA[id]||[]).find(r=>r.key_hash===kh);
      if(!row)throw new Error('the deploy was stored but read-back could not find '+k);
      if(row.key!==k||row.value!==v)throw new Error('the deploy was stored but read-back returned a different value for '+k)}
    for(const d of dels){if((E2E_DATA[id]||[]).some(r=>r.id===d.id))throw new Error('deleted secret '+d.key+' is still present after deploy')}
    toast(`Deployed ${items.length} secret${items.length!==1?'s':''}${dels.length?` and deleted ${dels.length}`:''}`);await renderE2eEnv();
  }catch(e){toast('Deploy failed: '+e.message,true)}}
async function e2eGrantsModal(){
  let id=ENV.id;if(!E2E_KEYS[id]){toast('Unlock the environment first',true);return}
  try{let [grants,meta]=await Promise.all([api('GET',`/api/envs/${id}/e2e/grants`),api('GET',`/api/envs/${id}/e2e/meta`)]);E2E_GRANTS[id]=grants;E2E_META[id]=meta}
  catch(e){toast(e.message,true);return}
  let meta=E2E_META[id]||{};
  let rows=grants=>grants.map(g=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:8px 0">
    <span class="mono small">${esc(g.email)}${g.user_id===MY_UID?' · you':''}</span>
    ${g.user_id===MY_UID?'':`<button class="danger" onclick="e2eRevoke('${jsq(g.user_id)}','${jsq(g.email)}')">Remove access</button>`}</div>`).join('')||'<p class="mut">No key grants yet.</p>';
  modal(`<h3>Who can decrypt this environment</h3>
    <p class="mut">Each member gets the environment key wrapped to their account public key. The server never sees the key or the plaintext.</p>
    ${meta.runner?`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:8px 0"><span class="mono small">runner ${esc(meta.runner.id)} · sync only</span><span class="mut small">key grant</span></div>`:''}
    ${rows(E2E_GRANTS[id]||[])}
    <div class="field" style="margin-top:14px"><label for="eg-email">Grant access by email</label><input id="eg-email" type="email" placeholder="teammate@example.com"></div>
    <div class="row"><button class="primary" onclick="e2eGrant()">Grant access</button><button class="ghost" onclick="closeModal()">Close</button></div>
    ${meta.rekey_required?'<p class="small" style="color:var(--bad)">A grant was removed. Rotate the key from the environment banner so future secrets are not readable to the old grantee.</p>':''}`,'Environment access')}
async function e2eGrant(){
  let id=ENV.id,key=E2E_KEYS[id];if(!key)return;let email=$('eg-email').value.trim();
  if(!email){toast('Enter the email of an existing member',true);return}
  try{
    let u=await api('GET',`/api/users/lookup?email=${encodeURIComponent(email)}`);
    if(!u.pubkey)throw new Error('that account has no public key');
    let wrapped=await OW.encryptAsymmetric(u.pubkey,key);
    await api('POST',`/api/envs/${id}/e2e/grant`,{email:u.email,wrapped_key:wrapped});
    let grants=await api('GET',`/api/envs/${id}/e2e/grants`);E2E_GRANTS[id]=grants;
    if(!grants.some(g=>g.user_id===u.id))throw new Error('the grant was not stored');
    toast('Access granted to '+u.email);await e2eGrantsModal();
  }catch(e){toast('Grant failed: '+e.message,true)}}
async function e2eRevoke(uid,email){
  if(uid===MY_UID){toast('You cannot remove your own grant here; ask another member to rotate afterwards',true);return}
  if(!confirm('Remove access for '+email+'? Rotate the environment key afterwards so they cannot read future secrets.'))return;
  try{await api('DELETE',`/api/envs/${ENV.id}/e2e/grants/${uid}`);
    E2E_META[ENV.id]={...(E2E_META[ENV.id]||{}),rekey_required:true};
    E2E_GRANTS[ENV.id]=await api('GET',`/api/envs/${ENV.id}/e2e/grants`);
    await e2eGrantsModal();await renderE2eEnv();toast('Access removed; rotate the key next')
  }catch(e){toast(e.message,true)}}
async function e2eRekey(){
  let id=ENV.id,key=E2E_KEYS[id];if(!key)return;
  if(e2eDraftList().length){toast('Deploy or discard staged changes before rotating the key',true);return}
  if(!(E2E_DATA[id]||[]).length){toast('Nothing to rotate yet: add a secret first',true);return}
  let meta=E2E_META[id]||{};
  if(!confirm(`Rotate the environment key? Every secret is re-encrypted and each current member gets the new key wrapped to them${meta.runner?' and the runner':''}.`))return;
  try{
    let newKey=crypto.getRandomValues(new Uint8Array(32));
    let secrets=[];
    for(const r of E2E_DATA[id])secrets.push({key_hash:r.key_hash,key_enc:await OW.encryptSymmetric(newKey,enc(r.key)),value_enc:await OW.encryptSymmetric(newKey,enc(r.value)),path_enc:await OW.encryptSymmetric(newKey,enc(r.path||'/'))});
    let grants=await api('GET',`/api/envs/${id}/e2e/grants`);
    if(!grants.some(g=>g.user_id===MY_UID))throw new Error('your own grant is missing; refresh and try again');
    let payload=[];
    for(const g of grants){if(!g.pubkey)throw new Error('grantee '+g.email+' has no public key');payload.push({user_id:g.user_id,wrapped_key:await OW.encryptAsymmetric(g.pubkey,newKey)})}
    let body={secrets,grants:payload};
    if(meta.runner){if(!meta.runner.public_key)throw new Error('the runner public key is missing; refresh and try again');
      body.runner_wrapped_key=await OW.encryptAsymmetric(meta.runner.public_key,newKey)}
    await api('POST',`/api/envs/${id}/e2e/rekey`,body);
    E2E_KEYS[id]=newKey;await e2eLoad(id,E2E_KIT);toast('Environment key rotated');await renderE2eEnv();
  }catch(e){toast('Rotation failed: '+e.message,true)}}
async function switchEnv(id){let cur=ENV&&ENV.id;if(cur===id){return}
  if(cur&&(Object.keys(drafts()).length||Object.keys(e2eDrafts()).length)&&!confirm('Discard staged changes?'))return;
  if(cur){delete DRAFTS[cur];delete E2E_DRAFTS[cur]}
  ENV=ENVS.find(e=>e.id===id);await renderEnv()}
function envMode(e){return e&&e.mode==='e2e'?'e2e':'sse'}
async function newEnv(draft){
  if(draft)NEWENV_DRAFT=draft;
  try{RUNNERS=await api('GET',`/api/orgs/${ORG}/runners`)}catch(e){RUNNERS=[]}
  let d=NEWENV_DRAFT||{},delegated=d.mode==='delegated';
  let opts=RUNNERS.map(r=>`<option value="${r.id}" ${NEW_RUNNER&&NEW_RUNNER.id===r.id?'selected':''}>${esc(r.name)}</option>`).join('');
  modal(`<h3>New environment</h3>
    <div class="field"><label for="ne-name">Name (letters, numbers, - or _)</label><input id="ne-name" value="${esc(d.name||'')}" placeholder="qa-1"></div>
    <div class="field"><label for="ne-mode">Encryption</label><select id="ne-mode" style="width:100%" onchange="envModeHint()"><option value="sse" ${delegated?'':'selected'}>Managed (server-side encryption)</option><option value="delegated" ${delegated?'selected':''}>Delegated (client keys, synced by a runner)</option></select></div>
    <div id="ne-runner-wrap" style="display:${delegated?'':'none'}"><div class="field"><label for="ne-runner-select">Sync runner</label>${RUNNERS.length?`<select id="ne-runner-select" style="width:100%">${opts}</select>`:'<p class="small" style="color:var(--bad)">No runner exists in this organisation yet. An admin has to create one.</p>'}${E2E_KIT?'':`<p class="small" style="color:var(--bad)">This session has no client-held key. Sign in with a client-derived account to create delegated environments.</p>`}${isAdmin()?'<button style="margin-top:8px" onclick="newRunner(\'env\')">Create a runner</button>':''}</div></div>
    <div class="row"><button class="primary" id="ne-create" onclick="createEnv()" ${delegated&&(!RUNNERS.length||!E2E_KIT)?'disabled':''}>Create</button><button class="ghost" onclick="closeModal()">Cancel</button></div>
    <p class="small mut">Delegated environments are encrypted in this browser. The server stores ciphertext and the runner receives a wrapped key for provider sync.</p>`)}
function envModeHint(){let d=$('ne-mode')?.value==='delegated';if($('ne-runner-wrap'))$('ne-runner-wrap').style.display=d?'':'none';
  let b=$('ne-create');if(b)b.disabled=d&&(!RUNNERS.length||!E2E_KIT)}
async function createEnv(){try{let name=$('ne-name').value,mode=$('ne-mode').value;
  if(mode==='delegated'){
    let rid=$('ne-runner-select')?.value;let runner=RUNNERS.find(r=>r.id===rid);
    if(!runner)throw new Error('Select a sync runner, or ask an admin to create one');
    if(!E2E_KIT)throw new Error('this session has no client-held private key; sign in with a client-derived account first');
    if(!MY_PUBKEY)throw new Error('account public key unavailable; reload and sign in again');
    let k=crypto.getRandomValues(new Uint8Array(32));
    await api('POST',`/api/apps/${APP.id}/envs`,{name,mode:'delegated',runner_id:rid,wrapped_key:await OW.encryptAsymmetric(MY_PUBKEY,k),runner_wrapped_key:await OW.encryptAsymmetric(runner.pubkey,k)});
  } else { await api('POST',`/api/apps/${APP.id}/envs`,{name}); }
  closeModal();NEWENV_DRAFT=null;ENVS=await api('GET',`/api/apps/${APP.id}/envs`);toast('Environment created');renderEnv()
}catch(e){toast(e.message,true)}}
async function newE2eEnv(){modal(`<h3>New end-to-end encrypted environment</h3>
  <p class="mut">The environment key is generated in this browser and wrapped to your account key. The server stores only ciphertext and cannot read these secrets.</p>
  <div class="field"><label for="ne2-name">Name</label><input id="ne2-name" placeholder="vault"></div>
  <div class="row"><button class="primary" onclick="createE2eEnv()">Create E2E env</button><button class="ghost" onclick="closeModal()">Cancel</button></div>
  <p class="small mut">Requires a client-derived sign-in or a recovery kit in this tab. The console and CLI can edit these secrets; provider sync needs a delegated environment with a runner.</p>`)}
async function createE2eEnv(){try{
  if(!E2E_KIT)throw new Error('this session has no client-held private key. Sign in with a client-derived account, or reset your password while keeping your recovery kit, then create the environment');
  if(!MY_PUBKEY)throw new Error('account public key unavailable; reload and sign in again');
  let name=$('ne2-name').value.trim();
  let envKey=crypto.getRandomValues(new Uint8Array(32));
  let wrapped=await OW.encryptAsymmetric(MY_PUBKEY,envKey);
  let d=await api('POST',`/api/apps/${APP.id}/envs/e2e`,{name,wrapped_key:wrapped});
  if(d.server_generated)throw new Error('the server generated the key instead of using the client one; treat this environment as server-readable');
  closeModal();E2E_KEYS[d.id]=envKey;
  ENVS=await api('GET',`/api/apps/${APP.id}/envs`);ENV=ENVS.find(e=>e.id===d.id)||ENV;
  await e2eLoad(d.id,E2E_KIT);toast('E2E environment created');await renderE2eEnv()
}catch(e){toast(e.message,true)}}
async function delEnv(){if(!confirm(`Delete environment ${ENV.name} and all its secrets?`))return;try{let removed=ENV.id;await api('DELETE',`/api/envs/${removed}`);delete DRAFTS[removed];delete E2E_KEYS[removed];delete E2E_DATA[removed];delete E2E_DRAFTS[removed];delete E2E_META[removed];delete E2E_GRANTS[removed];delete E2E_LOCKED[removed];delete E2E_ERR[removed];ENVS=await api('GET',`/api/apps/${APP.id}/envs`);ENV=ENVS[0]||null;toast('Environment deleted');await renderEnv()}catch(e){toast(e.message,true)}}
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
function updateDeployBar(){let n=isClientEnv(ENV)?e2eDraftList().length:draftList().length;let active=VIEW==='env'&&!!ENV&&n>0;
  $('deploybar').classList.toggle('show',active);
  $('deploytext').innerHTML=active?`<b>${n}</b>&nbsp;staged change${n!==1?'s':''}`:''}
function discardStage(){if(!ENV)return;delete DRAFTS[ENV.id];delete E2E_DRAFTS[ENV.id];
  if(isClientEnv(ENV))drawE2E();else drawSecrets();updateDeployBar()}
async function deployStage(){if(isClientEnv(ENV))return deployE2E();try{let items=draftList().map(s=>({key:s.key,value:s.value,path:s.path,type:s.type,comment:s.comment||''}));
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

const KINDS=['trigger','github','gitlab','vercel','netlify','cloudflare','cloudflare_pages','supabase','nomad','coolify','heroku','render','flyio','railway','digitalocean','gcp_secret_manager','azure_key_vault','kubernetes','hashicorp_vault','aws_secrets_manager','aws_parameter_store','webhook','instabox','boat','daytona'];
async function renderIntegrations(){if(!needAppEnv())return;$('pagetitle').textContent='Integrations';$('crumb').textContent=ENV?('/ '+ENV.name):'';
  if(isE2E(ENV)){$('view').innerHTML=`<div class="card"><h3>Provider sync is unavailable for this environment</h3>
    <p class="mut">The server cannot decrypt end-to-end secrets, so it cannot push them to a provider. To sync secrets an integration needs, create a delegated environment and run a customer-hosted runner. Keep secrets that no integration needs in an end-to-end environment like this one.</p></div>`;return}
  let delegated=isDelegated(ENV);
  setTimeout(kindHint,0);
  let ints=ENV?await api('GET',`/api/envs/${ENV.id}/integrations`).catch(()=>[]):[];
  let notice=delegated?`<div class="card"><h3>Provider sync through your runner</h3><p class="mut">Integrations here are queued for the runner you host. Config is sealed to that runner before storage, and secrets are forwarded as ciphertext; Test and Sync run in your network. The runner sees provider credentials when it decrypts a job.</p></div>`:'';
  let dynamic=delegated?'':`<div class="card"><h3>Dynamic secrets &amp; rotation</h3><div class="row"><input id="lease-name" placeholder="lease name"><button onclick="mkLease()">New lease (1h)</button><button onclick="loadLeases()">Show leases</button></div><pre class="val" id="leases"></pre>
  <div class="row"><input id="rot-key" placeholder="KEY_TO_ROTATE"><span class="row"><input id="rot-int" value="86400" size="8"><span class="mut small">seconds between rotations</span></span><button onclick="mkRotation()">Schedule rotation</button></div></div>`;
  $('view').innerHTML=`${notice}<div class="card"><h3>Sync secrets to a platform</h3><p>Integrations run automatically on every deploy, or on demand. Config is stored encrypted. Trigger.dev example config: <span class="mono">{"token":"tr_pat_…","project_ref":"proj_…","target_env":"prod"}</span></p>
  <div class="row"><select id="ikind" onchange="kindHint()">${KINDS.map(k=>`<option>${k}</option>`).join('')}</select></div>
  <p class="small" id="ikind-hint"></p><textarea id="icfg" rows="4" placeholder='{"token":"…"}'></textarea>
  <div class="row" style="margin-top:10px"><button class="primary" onclick="mkIntegration()">Add integration</button></div></div>
  <div class="card"><h3>Configured ${ENV?('· '+esc(ENV.name)):''}</h3>${ints.length?ints.map(i=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:8px 0"><span><b>${esc(i.kind)}</b> <span class="mut small">${esc(i.name||'')}</span></span><span><button onclick="testInt('${i.id}')">Test</button> <button class="primary" onclick="syncInt('${i.id}')">Sync now</button> <button class="danger" onclick="delInt('${i.id}')">Delete</button></span></div>`).join(''):'<span class="mut">None yet</span>'}</div>
  ${dynamic}
  <div class="card"><h3>Lockbox: one-time secret sharing</h3><div class="row"><input id="lb-val" placeholder="value to share once" style="min-width:280px"><button onclick="mkLockbox()">Create link</button></div><pre class="val" id="lb-out"></pre></div>`}
const KIND_HINTS={trigger:'Trigger.dev: {"token":"tr_pat_… or tr_prod_sk_…","project_ref":"proj_…","target_env":"prod"}',github:'GitHub: {"token":"ghp_…","owner":"org","repo":"repo"}',gitlab:'GitLab: {"token":"glpat-…","project_id":"42"}',webhook:'Webhook: {"url":"https://…","token":"optional bearer"}',kubernetes:'Kubernetes: {"api_server":"https://…","token":"…","namespace":"default","secret_name":"app-secrets"}',instabox:'Instabox: {"api_key":"ibk_…","org":"team","hosts":["api.example.com"],"delivery":"proxy"}',boat:'Boat: {"api_key":"boat_…","environment":"base","upgrade":true}',daytona:'Daytona: {"api_key":"…","organization_id":"…","hosts":["api.example.com"]}'};
function kindHint(){if(!$('ikind'))return;let k=$('ikind').value;$('ikind-hint').textContent=KIND_HINTS[k]||('Config for '+k+' as JSON. Common keys: token, base_url for self-hosted instances. Stored encrypted at rest.')}
async function mkIntegration(){try{await api('POST',`/api/envs/${ENV.id}/integrations`,{kind:$('ikind').value,config:JSON.parse($('icfg').value||'{}')});toast('Integration added');renderIntegrations()}catch(e){toast(e.message,true)}}
async function testInt(id){try{let d=await api('POST',`/api/integrations/${id}/test`,{});toast(d.detail)}catch(e){toast(e.message,true)}}
async function syncInt(id){try{let d=await api('POST',`/api/integrations/${id}/sync`,{});toast(d.detail)}catch(e){toast(e.message,true)}}
async function delInt(id){if(!confirm('Delete this integration? Sync state for it is removed too.'))return;try{await api('DELETE',`/api/integrations/${id}`);toast('Integration deleted');renderIntegrations()}catch(e){toast(e.message,true)}}
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
  let s=await api('GET',`/api/orgs/${ORG}/settings`).catch(()=>null);
  let m=await api('GET','/api/me/mfa').catch(()=>null);MFA_INFO=m;
  let instanceCard='';
  if(inst&&inst.instance_owner){let configured=inst.configured||[];
    instanceCard=`<div class="card"><h3>Instance</h3><p>Control who can create an account on this server.</p>
      <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="set-signups" ${inst.signups_open?'checked':''} ${inst.signups_env_locked?'disabled':''}> Allow self signup</label>
      <p class="small mut">When off, new users join only by invitation. ${inst.signups_env_locked?'Locked by OPENWARP_SIGNUPS.':''}</p>
      <button class="primary" onclick="saveSignups()" ${inst.signups_env_locked?'disabled':''}>Save signup policy</button></div>
    <div class="card"><h3>Sign-in methods</h3><p>Choose how accounts sign in on this server. At least one method must stay on. Turning off email and password also disables password reset, so those users need a linked provider.</p>
      <label class="row" style="gap:8px;margin-bottom:6px"><input type="checkbox" id="ap-password" ${inst.password?'checked':''}> Email and password</label>
      <label class="row" style="gap:8px;margin-bottom:6px"><input type="checkbox" id="ap-google" ${inst.google?'checked':''} ${configured.includes('google')?'':'disabled'}> Google${configured.includes('google')?'':' (client credentials not configured)'}</label>
      <label class="row" style="gap:8px;margin-bottom:6px"><input type="checkbox" id="ap-github" ${inst.github?'checked':''} ${configured.includes('github')?'':'disabled'}> GitHub${configured.includes('github')?'':' (client credentials not configured)'}</label>
      <label class="row" style="gap:8px;margin-bottom:6px"><input type="checkbox" id="ap-oidc" ${inst.oidc?'checked':''} ${configured.includes('oidc')?'':'disabled'}> Organisation SSO (OIDC)${configured.includes('oidc')?'':' (configure an issuer under Organisation security first)'}</label>
      <div class="row" style="margin-top:8px"><button class="primary" onclick="saveAuthMethods()" ${inst.env_locked?'disabled':''}>Save sign-in methods</button></div>
      <p class="small mut">${inst.env_locked?'Locked by OPENWARP_AUTH_PROVIDERS.':'Every configured method is enabled until you change it here.'}</p></div>
    <div class="card"><h3>New app environments</h3><p>Managed environments are encrypted by the server so the CLI and provider sync can read them. Delegated environments are encrypted in the client and synced by a runner you host, so the server never holds the key.</p>
      <div class="field"><label for="set-app-policy">Mode for new apps</label><select id="set-app-policy" style="width:100%" ${inst.app_env_policy_locked?'disabled':''}><option value="managed" ${inst.app_env_policy!=='delegated'?'selected':''}>Managed (server-side encryption)</option><option value="delegated" ${inst.app_env_policy==='delegated'?'selected':''}>Delegated (client encryption, runner sync)</option></select></div>
      <button class="primary" onclick="saveAppPolicy()" ${inst.app_env_policy_locked?'disabled':''}>Save environment policy</button>
      <p class="small mut">${inst.app_env_policy_locked?'Locked by OPENWARP_APP_ENV_POLICY.':'Existing apps keep their current environments. Pure end-to-end environments stay an explicit per-environment choice.'}</p></div>`;}
  let pk=(m?.passkeys||[]);
  let mfaCard=`<div class="card"><h3>Two-factor authentication</h3>
    <p>${m&&m.required?'A second factor is required when you sign in.':'No second factor yet. Add one to protect this account.'}</p>
    <div class="row" style="margin-bottom:8px"><span class="chip">Authenticator: ${m?.totp?'on':'off'}</span><span class="chip">Passkeys: ${pk.length}</span><span class="chip">Email codes: ${m?.email?'on':'off'}</span><span class="chip">Recovery codes: ${m?.recovery_codes||0}</span></div>
    <div class="row"><button onclick="totpSetup()">Set up authenticator</button><button onclick="regenRecovery()">New recovery codes</button></div>
    <pre class="val" id="totp-out"></pre>
    <div class="row"><input id="totp-code" placeholder="code from authenticator"><button onclick="totpVerify()">Verify and enable</button><button class="danger" onclick="disableTotp()">Disable authenticator</button></div>
    <hr style="border:0;border-top:1px solid var(--line);margin:16px 0">
    <h3>Passkeys</h3><p>Sign in with Touch ID, Windows Hello, a security key, or a synced passkey.</p>
    ${pk.length?pk.map(p=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:6px 0"><span class="small">${esc(p.name)} <span class="mut">· added ${new Date((p.created_at||0)*1000).toLocaleDateString()}</span></span><button class="danger" onclick="delPasskey('${jsq(p.id)}')">Remove</button></div>`).join(''):'<p class="mut small">No passkeys yet.</p>'}
    <div class="row" style="margin-top:8px"><input id="pk-name" placeholder="e.g. MacBook Touch ID"><button onclick="addPasskey()">Add passkey</button></div>
    <hr style="border:0;border-top:1px solid var(--line);margin:16px 0">
    <h3>Email codes</h3><p>${m?.email_available?'Send a one-time code to your account email when you sign in.':'Set OPENWARP_EMAIL_WEBHOOK to enable emailed codes.'}</p>
    <div class="row"><button onclick="startEmailMfa()" ${m?.email_available?'':'disabled'}>Send code</button><input id="email-mfa-code" placeholder="code from email"><button onclick="verifyEmailMfa()">Enable</button><button class="danger" onclick="disableEmailMfa()">Disable</button></div></div>`;
  let runnerCard='';
  if(isAdmin()){
    let runners=await api('GET',`/api/orgs/${ORG}/runners`).catch(()=>[]);RUNNERS=runners;
    runnerCard=`<div class="card"><h3>Sync runners</h3><p>Runners hold a key grant for delegated environments and push secrets from your network. Only admins create or delete them; members can use an existing runner.</p>
      <div class="row" style="margin-bottom:8px"><button class="primary" onclick="newRunner('settings')">+ New runner</button></div>
      ${runners.length?runners.map(r=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:6px 0"><span class="small">${esc(r.name)} <span class="mut">· created ${new Date((r.created_at||0)*1000).toLocaleDateString()}</span></span><button class="danger" onclick="delRunner('${jsq(r.id)}')">Delete</button></div>`).join(''):'<p class="mut small">No runner yet. Create one before making a delegated app.</p>'}</div>`;
  }
  $('view').innerHTML=`${instanceCard}${mfaCard}
  <div class="card"><h3>Organisation security</h3><p>IP allowlist is enforced on every API call. OIDC powers SSO and MCP OAuth discovery.</p>
  <div class="field"><label for="set-ip">IP allowlist (CIDR, comma separated, empty = allow all)</label><input id="set-ip" value="${esc(s?.ip_allowlist||'')}" placeholder="203.0.113.0/24"></div>
  <div class="field"><label for="set-oidc-iss">OIDC issuer</label><input id="set-oidc-iss" value="${esc(s?.oidc_issuer||'')}" placeholder="https://accounts.google.com"></div>
  <div class="row"><input id="set-oidc-cid" value="${esc(s?.oidc_client_id||'')}" placeholder="OIDC client id"><input id="set-oidc-sec" type="password" placeholder="${s?.oidc_client_secret_set?'stored; leave blank to keep':'OIDC client secret'}"><input id="set-oidc-redir" value="${esc(s?.oidc_redirect_uri||'')}" placeholder="redirect URI" style="min-width:260px"></div>
  <div class="field"><label for="set-oidc-domains">SSO email domains (comma separated; empty = any account at the issuer may join)</label><input id="set-oidc-domains" value="${esc(s?.oidc_allowed_domains||'')}" placeholder="example.com,subsidiary.example" style="width:100%"></div>
  <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="set-oidc-auto" ${s?.oidc_auto_provision?'checked':''}> Allow first-time SSO users to join as developers</label>
  <div class="row" style="margin-top:10px"><button class="primary" onclick="saveSettings()">Save settings</button></div></div>
  <div class="card"><h3>End-to-end environments</h3><p>Open an E2E environment from its app to decrypt and edit it in this browser. The key stays in this tab; Settings no longer prints a plaintext dump of every secret.</p></div>
  ${runnerCard}
  <div class="card"><h3>PKI</h3><p>Issue internal certificates from your own CA.</p><div class="row"><input id="ca-name" placeholder="internal-ca"><button onclick="mkCA()">Create CA</button></div><pre class="val" id="ca-out"></pre></div>
  <div class="card"><h3>Session</h3><div class="row"><button onclick="loadTokensSettings()">My tokens</button><button class="danger" onclick="logout()">Sign out everywhere (this device)</button></div><pre class="val" id="sess-out"></pre></div>`}
async function saveSettings(){try{let b={ip_allowlist:$('set-ip').value,oidc_auto_provision:$('set-oidc-auto').checked,oidc_allowed_domains:$('set-oidc-domains').value};
  if($('set-oidc-iss').value)b.oidc_issuer=$('set-oidc-iss').value;
  if($('set-oidc-cid').value)b.oidc_client_id=$('set-oidc-cid').value;
  if($('set-oidc-redir').value)b.oidc_redirect_uri=$('set-oidc-redir').value;
  if($('set-oidc-sec').value)b.oidc_client_secret=$('set-oidc-sec').value;
  await api('PUT',`/api/orgs/${ORG}/settings`,b);toast('Settings saved')}catch(e){toast(e.message,true)}}
async function saveSignups(){try{let d=await api('PUT','/api/instance/signups',{open:$('set-signups').checked});toast('Signups '+(d.signups_open?'enabled':'disabled'));renderSettings()}catch(e){toast(e.message,true)}}
async function saveAuthMethods(){try{
  let body={password:$('ap-password').checked};
  for(let k of ['google','github','oidc']){let el=$('ap-'+k);if(el)body[k]=el.checked;}
  await api('PUT','/api/instance/auth',body);toast('Sign-in methods saved');renderSettings();
}catch(e){toast(e.message,true)}}
async function saveAppPolicy(){try{
  let d=await api('PUT','/api/instance/app-env-policy',{policy:$('set-app-policy').value});
  toast('New apps will use '+d.policy+' environments');renderSettings()
}catch(e){toast(e.message,true)}}
async function delRunner(id){if(!confirm('Delete this runner? Delegated environments using it must be removed or moved first.'))return;
  try{await api('DELETE',`/api/orgs/${ORG}/runners/${id}`);toast('Runner deleted');renderSettings()}catch(e){toast(e.message,true)}}
function reauthPrompt(msg){let p=prompt(msg||'Current password (leave blank if you sign in with a provider)');return p===null?null:(p||'')}
async function regenRecovery(){let pw=reauthPrompt('Current password to replace recovery codes');if(pw===null)return;
  try{let d=await api('POST','/api/me/mfa/recovery-codes',{password:pw});$('totp-out').textContent='New recovery codes (save now):\n'+d.recovery_codes.join('\n');toast('Recovery codes replaced')}catch(e){toast(e.message,true)}}
async function totpSetup(){let body={};
  if(MFA_INFO&&MFA_INFO.required){let pw=reauthPrompt('Current password to change the authenticator');if(pw===null)return;body.password=pw}
  try{let d=await api('POST','/api/me/totp/setup',body);let txt='Secret: '+d.secret+'\n'+d.otpauth_url;
    if(d.recovery_codes&&d.recovery_codes.length)txt+='\nRecovery codes (save once):\n'+d.recovery_codes.join('\n');
    else txt+='\nExisting recovery codes remain valid.';
    $('totp-out').textContent=txt}catch(e){toast(e.message,true)}}
async function totpVerify(){try{await api('POST','/api/me/totp/verify',{code:$('totp-code').value});toast('Authenticator enabled');renderSettings()}catch(e){toast(e.message,true)}}
async function disableTotp(){let pw=reauthPrompt('Current password to disable the authenticator');if(pw===null)return;
  if(!confirm('Disable the authenticator app?'))return;
  try{await api('DELETE','/api/me/totp',{password:pw});toast('Authenticator disabled');renderSettings()}catch(e){toast(e.message,true)}}
async function addPasskey(){let pw=reauthPrompt('Current password to add a passkey');if(pw===null)return;
  try{let s=await api('POST','/api/me/passkeys/start',{password:pw});
    let cred=await navigator.credentials.create({publicKey:creationOptions(s.options.publicKey)});
    let d=await api('POST','/api/me/passkeys/finish',{state_id:s.state_id,name:$('pk-name').value,credential:attestationJson(cred)});
    if(d.recovery_codes)$('totp-out').textContent='Recovery codes (save now):\n'+d.recovery_codes.join('\n');
    toast('Passkey added');renderSettings();
  }catch(e){toast(e.message||String(e),true)}}
async function delPasskey(id){let pw=reauthPrompt('Current password to remove this passkey');if(pw===null)return;
  try{await api('DELETE',`/api/me/passkeys/${id}`,{password:pw});toast('Passkey removed');renderSettings()}catch(e){toast(e.message,true)}}
async function startEmailMfa(){let pw=reauthPrompt('Current password to enable email codes');if(pw===null)return;
  try{await api('POST','/api/me/mfa/email/start',{password:pw});toast('Code sent to your email')}catch(e){toast(e.message,true)}}
async function verifyEmailMfa(){try{let d=await api('POST','/api/me/mfa/email/verify',{code:$('email-mfa-code').value});
  if(d.recovery_codes)$('totp-out').textContent='Recovery codes (save now):\n'+d.recovery_codes.join('\n');
  toast('Email codes enabled');renderSettings()}catch(e){toast(e.message,true)}}
async function disableEmailMfa(){let pw=reauthPrompt('Current password to disable email codes');if(pw===null)return;
  try{await api('DELETE','/api/me/mfa/email',{password:pw});toast('Email codes disabled');renderSettings()}catch(e){toast(e.message,true)}}
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
    history.replaceState(null,'',location.pathname);}
  else if(h.startsWith('mfa=')){
    // Social and OIDC sign-in hand the browser an MFA challenge instead of a
    // session when the account has a second factor.
    let parts=h.slice(4).split('&');MFA=decodeURIComponent(parts[0]);
    for(let p of parts.slice(1)){if(p.startsWith('org='))PENDING_ORG=decodeURIComponent(p.slice(4));}
    history.replaceState(null,'',location.pathname);showAuthMfa();}
  else if(h.startsWith('invite=')){showInvite(decodeURIComponent(h.slice(7).split('&')[0]));}
  else if(h.startsWith('reset=')){showReset(decodeURIComponent(h.slice(6).split('&')[0]));}
}
boot();
if(typeof window!=='undefined'&&window.addEventListener)window.addEventListener('hashchange',boot);
$('auth').style.display='none';enterApp().catch(()=>{T='';$('auth').style.display='grid';$('shell').style.display='none'})
</script>
<script src="/libsodium.js" integrity="sha384-3KUAqev6nUaNHDSTa/UjyEycVN8iMfq/UtzKf3ZDTuGSb+P3y9kMu/WCVqnLAxUB"></script>
<script src="/libsodium-wrappers.js" integrity="sha384-uj62oy76l27Bkf3eEP5knMYc094z6HzwAR7Rn8ZZcBBsg5nMibZXSvjRqgZMFg/L"></script>
<script src="/e2e.js"></script>
<script src="/auth-v2.js"></script>
</body></html>
"##;
