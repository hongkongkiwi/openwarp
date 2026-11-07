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
.ai-prose{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;font:inherit;line-height:1.65;margin:10px 0;max-width:100%}#ai-plan pre,#ai-answer pre{max-height:560px;overflow:auto}#ai-scope,#ai-task,#ai-compare{max-width:100%}#ai-findings-list summary{cursor:pointer;color:var(--muted);padding:6px 0}[hidden]{display:none!important}
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
@media(max-width:820px){#shell{grid-template-columns:1fr}#navtoggle{display:inline-block}aside{display:none;position:fixed;top:0;bottom:0;left:0;width:260px;z-index:80;box-shadow:0 0 60px rgba(0,0,0,.7)}aside.open{display:flex}.content{padding:16px 14px 100px}.members-table,.members-table tbody{display:block;width:100%}.members-table thead{display:none}.members-table tr{display:flex;flex-wrap:wrap;padding:10px 0;border-bottom:1px solid var(--line)}.members-table td{display:block;border:0;padding:6px 0;min-width:0}.members-table td:first-child{width:100%;overflow-wrap:anywhere}.members-table td:last-child{display:flex;flex-wrap:wrap;gap:8px;width:100%}.members-table select{max-width:100%}}
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
      <button class="ghost" style="width:100%;margin-top:6px" onclick="forgotPrompt()">Forgot password?</button>
      <button class="ghost" style="width:100%;margin-top:6px" onclick="samlPrompt()">Sign in with SAML</button>
      <div id="social" class="row" style="margin-top:12px;flex-wrap:wrap"></div>
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
    <button class="navbtn" data-nav="assistant" onclick="nav('assistant')"><span class="ic">⌕</span>Assistant</button>
    <button class="navbtn" data-nav="insights" onclick="nav('insights')"><span class="ic">◇</span>Security insights</button>
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
let T='', ORG='', APP=null, ENV=null, APPS=[], ENVS=[], SECRETS=[], DRAFTS={}, VIEW='apps', MFA=null, LASTFOCUS=null, PENDING_ORG=null, ME=null,
  E2E_KIT='', E2E_KEYS={}, E2E_DATA={}, E2E_DRAFTS={}, E2E_META={}, E2E_GRANTS={}, E2E_LOADING={}, E2E_LOCKED={}, E2E_ERR={}, MY_PUBKEY='', MY_UID='';
function drafts(){return (ENV&&DRAFTS[ENV.id])||{}}
function draftList(){return Object.values(drafts())}
function e2eDrafts(){return (ENV&&E2E_DRAFTS[ENV.id])||{}}
function e2eDraftList(){return Object.values(e2eDrafts())}
const $=id=>document.getElementById(id);
const H=()=>({'Authorization':'Bearer '+T,'Content-Type':'application/json'});
async function api(m,u,b){let r=await fetch(u,{method:m,headers:H(),body:b!==undefined?JSON.stringify(b):undefined});let t=await r.text();let d;try{d=JSON.parse(t)}catch(e){d={error:t}}
  if(!r.ok) throw new Error(d.error||('HTTP '+r.status)); return d}
// Keep the error body for deletion's ownership and credential warnings.
async function apiRaw(m,u,b){let r=await fetch(u,{method:m,headers:H(),body:b!==undefined?JSON.stringify(b):undefined});let t=await r.text();let d;try{d=JSON.parse(t)}catch(e){d={error:t}}
  return {ok:r.ok,status:r.status,body:d}}
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
  for(const [id,name] of [['google','Google'],['microsoft','Microsoft'],['apple','Apple'],['github','GitHub'],['okta','Okta'],['auth0','Auth0'],['gitlab','GitLab'],['atlassian','Atlassian'],['slack','Slack'],['salesforce','Salesforce'],['openai','OpenAI'],['x','X'],['discord','Discord'],['linkedin','LinkedIn'],['workos','WorkOS']]){
    if(p[id])btns.push(`<button style="flex:1 1 45%" onclick="location.href='/api/auth/social/${id}/start'">Continue with ${name}</button>`)}
  if(p.oidc)btns.push(`<button style="flex:1 1 45%" onclick="location.href='/api/auth/social/oidc/start'">Continue with ${esc(p.oidc_name||'SSO')}</button>`);
  if(p.ldap)btns.push(`<button style="flex:1 1 45%" onclick="ldapPrompt()">Sign in with directory (LDAP)</button>`);
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
  T='';history.replaceState(null,'',location.pathname);enterApp();
}catch(e){toast(e.message,true)}}
function forgotPrompt(){modal(`<h3>Reset your password</h3><p class="mut">Enter your email. If an account exists, a reset link is sent.</p>
  <div class="field"><label for="fp-email">Email</label><input id="fp-email" type="email" value="${esc($('email').value)}"></div>
  <div class="row"><button class="primary" onclick="sendForgot()">Send link</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`,'Reset password')}
function samlPrompt(){let org=prompt('Workspace ID for SAML sign-in');if(org)location.href='/api/auth/saml/'+encodeURIComponent(org)+'/start'}
function ldapPrompt(){modal(`<h3>Sign in with your directory</h3><p class="mut">Your password goes to this server over the API and is checked by your directory over TLS.</p>
  <div class="field"><label for="ld-org">Workspace ID</label><input id="ld-org" placeholder="workspace id"></div>
  <div class="field"><label for="ld-user">Directory username</label><input id="ld-user" autocomplete="username"></div>
  <div class="field"><label for="ld-pw">Password</label><input id="ld-pw" type="password" autocomplete="current-password"></div>
  <div class="row"><button class="primary" onclick="ldapSignIn()">Sign in</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`,'Directory sign-in')}
async function ldapSignIn(){try{
  let d=await api('POST','/api/auth/ldap',{org_id:$('ld-org').value.trim(),username:$('ld-user').value,password:$('ld-pw').value});
  if(d.mfa_required){MFA=d.mfa_token;
    $('modal').innerHTML=`<h3>Two-factor code</h3><div class="field"><label for="ld-mfa">Authenticator / recovery code</label><input id="ld-mfa" placeholder="123456"></div><div class="row"><button class="primary" onclick="ldapMfa()">Verify</button></div>`;return}
  T='';closeModal();enterApp();
}catch(e){toast(e.message,true)}}
async function ldapMfa(){try{let d=await api('POST','/api/auth/mfa',{mfa_token:MFA,code:$('ld-mfa').value});T='';closeModal();enterApp()}catch(e){toast(e.message,true)}}
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
  let d=await api('POST','/api/auth/reset',{token:$('authform').dataset.reset,password:$('rp-pw').value,recovery_kit:$('rp-kit').value,discard_e2e_key:!!$('rp-discard').checked});
  T='';history.replaceState(null,'',location.pathname);
  toast(d.e2e_key_replaced?'Password set; your key was replaced':'Password set');enterApp();
}catch(e){toast(e.message,true)}}
let MODE='login';
function authMode(m){MODE=m;$('seglogin').classList.toggle('on',m==='login');$('segreg').classList.toggle('on',m==='register');$('authtitle').textContent=m==='login'?'Welcome back':'Create your account';$('authbtn').textContent=m==='login'?'Sign in':'Create account'}
async function doAuth(){try{
  if(MODE==='register'){let d=await api('POST','/api/auth/register',{email:$('email').value,password:$('pw').value});
    if(d.verification_required){
      modal(`<h3>Check your email</h3><p class="mut">We sent a verification link to ${esc($('email').value)}. Save your recovery kit now; it is shown once.</p><textarea id="kit-text" aria-label="Recovery kit" rows="3" readonly>${esc(d.recovery_kit)}</textarea><div class="row" style="margin-top:12px"><button onclick="navigator.clipboard.writeText('${esc(d.recovery_kit)}');toast('Recovery kit copied')">Copy kit</button><button class="primary" onclick="closeModal()">I saved it</button></div>`,'Check your email');
      return}
    T='';
    modal(`<h3>Save your recovery kit</h3><p class="mut">This X25519 private key decrypts end-to-end environments and is shown once. Store it in a password manager.</p><textarea id="kit-text" aria-label="Recovery kit" rows="3" readonly>${esc(d.recovery_kit)}</textarea><div class="row" style="margin-top:12px"><button onclick="navigator.clipboard.writeText('${esc(d.recovery_kit)}');toast('Recovery kit copied')">Copy kit</button><button class="primary" onclick="closeModal();enterApp()">I saved it, continue</button></div>`,'Save your recovery kit');return}
  let d=await api('POST','/api/auth/login',{email:$('email').value,password:$('pw').value});
  if(d.mfa_required){MFA=d.mfa_token;$('mfafield').style.display='block';$('authbtn').textContent='Verify code';$('authbtn').onclick=doMfa;toast('Enter your authenticator or recovery code');return}
  T='';enterApp();
}catch(e){toast(e.message,true)}}
async function doMfa(){try{let d=await api('POST','/api/auth/mfa',{mfa_token:MFA,code:$('mfacode').value});T='';enterApp()}catch(e){toast(e.message,true)}}
async function logout(){aiReset();closeModal();try{await api('POST','/api/auth/logout',{})}catch(e){} T='';location.reload()}
async function enterApp(){$('auth').style.display='none';$('shell').style.display='grid';
  let me=await api('GET','/api/me');ME=me;$('whoami').textContent=me.email;MY_PUBKEY=me.pubkey||'';MY_UID=me.id||'';
  let orgs=await api('GET','/api/orgs');ORG=(PENDING_ORG&&orgs.some(o=>o.id===PENDING_ORG))?PENDING_ORG:(orgs[0]?.id||'');PENDING_ORG=null;
  $('orgs').innerHTML=orgs.map(o=>`<option value="${o.id}">${esc(o.name)} · ${esc(o.role)}</option>`).join('');
  $('orgs').value=ORG;
  await nav('apps')}
async function refreshOrgs(){let orgs=await api('GET','/api/orgs');$('orgs').innerHTML=orgs.map(o=>`<option value="${o.id}">${esc(o.name)} · ${esc(o.role)}</option>`).join('');$('orgs').value=ORG}
async function switchOrg(){aiReset();closeModal();ORG=$('orgs').value;APP=null;ENV=null;await nav('apps')}

// ---------- navigation ----------
function toggleNav(){let a=document.querySelector('aside');if(!a)return;let open=a.classList.toggle('open');let t=$('navtoggle');if(t)t.setAttribute('aria-expanded',open?'true':'false')}
async function nav(v){VIEW=v;let a=document.querySelector('aside');if(a){a.classList.remove('open');let t=$('navtoggle');if(t)t.setAttribute('aria-expanded','false')}document.querySelectorAll('.navbtn').forEach(b=>b.classList.toggle('on',b.dataset.nav===v));
  $('topaction').style.display=(v==='apps')?'':'none';
  if(v!=='assistant')AI_PLAN=null;
  updateDeployBar();
  await ({apps:renderApps,access:renderAccess,integrations:renderIntegrations,assistant:renderAssistant,insights:renderInsights,audit:renderAudit,settings:renderSettings}[v]||renderApps)();
  updateDeployBar()}

// ---------- apps ----------
async function renderApps(){$('topaction').style.display='';$('pagetitle').textContent='Apps';$('crumb').textContent='';
  $('view').innerHTML='<div class="empty"><div class="big">Loading…</div></div>';
  APPS=ORG?await api('GET',`/api/orgs/${ORG}/apps`):[];
  if(!APPS.length){$('view').innerHTML=`<div class="empty"><div class="big">▦</div>No apps yet<p>Create an app to start managing secrets for a project.</p><button class="primary" onclick="newApp()">Create your first app</button></div>`;return}
  let envCounts={};for(let a of APPS){try{let es=await api('GET',`/api/apps/${a.id}/envs`);envCounts[a.id]=es}catch(e){envCounts[a.id]=[]}}
  $('view').innerHTML=`<div class="row" style="margin-bottom:14px"><input id="appfilter" placeholder="Filter apps…" style="min-width:240px" oninput="filterApps(this.value)"><span class="mut small">${APPS.length} app${APPS.length!==1?'s':''}, unlimited environments</span></div>
  <div class="grid" id="appgrid">${APPS.map(a=>appCard(a,envCounts[a.id])).join('')}</div>`}
function appCard(a,envs){return `<div class="appcard" onclick="openApp('${a.id}')"><h3>${esc(a.name)}</h3><div class="meta">${envs.length} environment${envs.length!==1?'s':''}${a.reuse_check===false?' · reuse checks off':''}</div><div>${envs.map(e=>`<span class="chip">${esc(e.name)}</span>`).join('')}</div></div>`}
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
  if(isDelegated(ENV)){await renderDelegatedEnv();return}
  if(isE2E(ENV)){await renderE2eEnv();return}
  let eid=ENV.id,org=ORG;let d=await api('GET',`/api/envs/${eid}/secrets`);if(ORG!==org||ENV?.id!==eid||VIEW!=='env')return;SECRETS=d.secrets;
  let folderData=await api('GET',`/api/envs/${eid}/folders`);if(ORG!==org||ENV?.id!==eid||VIEW!=='env')return;let folders=Array.isArray(folderData)?folderData:(folderData.folders||[]);let folderPaths=[...new Set(folders.map(f=>typeof f==='string'?f:f.path).filter(Boolean))];
  $('view').innerHTML=`
  ${envTabs()}
  <div class="row" style="margin-bottom:12px">
    <input id="sfilter" placeholder="Filter by key or path…" style="min-width:240px" oninput="drawSecrets()">
    <button onclick="importModal()">Import .env</button><button onclick="exportEnv()">Export</button><button onclick="appSettings()">App settings</button>
    <span class="grow"></span><button class="primary" onclick="addRow()">+ New secret</button>
  </div>
  ${folderPaths.length?`<div class="row" style="flex-wrap:wrap;margin-bottom:12px"><span class="small mut">Folders:</span>${folderPaths.map(p=>`<button class="small mono" onclick="$('sfilter').value='${jsq(p)}';drawSecrets()">${esc(p)}</button>`).join('')}</div>`:''}
  <div id="stable"></div>
  ${APP?.readme?`<div class="card" style="margin-top:14px"><h3>Readme</h3><pre class="val" style="white-space:pre-wrap">${esc(APP.readme)}</pre></div>`:''}`;
  drawSecrets();updateDeployBar()}
function envTabs(){return `<div class="envtabs">${ENVS.map(e=>`<button class="envtab ${e.id===ENV.id?'on':''}" onclick="switchEnv('${e.id}')">${esc(e.name)}${isE2E(e)?' · E2E':''}${e.mode==='delegated'?' · delegated':''}</button>`).join('')}<button class="envtab" onclick="newEnv()">+ Environment</button><button class="envtab" onclick="newE2eEnv()">+ E2E environment</button><span class="grow"></span><button class="ghost danger" onclick="delEnv()">Delete env</button></div>`}
async function renderE2eEnv(){VIEW='env';$('topaction').style.display='none';$('pagetitle').textContent=APP?.name||'App';$('crumb').textContent='/ environments';
  let id=ENV.id;
  if(!E2E_DATA[id]&&E2E_LOADING[id]){$('view').innerHTML=envTabs()+'<div class="empty"><div class="big">Unlocking…</div>Decrypting this environment in the browser.</div>';updateDeployBar();return}
  if(!E2E_DATA[id]&&E2E_KIT&&!E2E_LOCKED[id]&&!E2E_LOADING[id]){
    $('view').innerHTML=envTabs()+'<div class="empty"><div class="big">Unlocking…</div>Decrypting this environment with the key from your session.</div>';
    try{await e2eLoad(id,E2E_KIT)}catch(e){E2E_ERR[id]=e.message}
  }
  if(!E2E_DATA[id]){
    let err=E2E_ERR[id]?`<p class="small" style="color:var(--bad)">${esc(E2E_ERR[id])}</p>`:'';
    $('view').innerHTML=`${envTabs()}
    <div class="card"><h3>End-to-end encrypted environment</h3>
      <p class="mut">The server stores only ciphertext here, so this console has to decrypt it in the browser. Paste the recovery kit you saved at registration.</p>
      ${err}
      <div class="field"><label for="e2e-kit">Recovery kit</label><input id="e2e-kit" type="password" autocomplete="off" placeholder="base64 recovery kit" style="width:100%"></div>
      <button class="primary" onclick="unlockE2EEnv()">Unlock environment</button>
      <p class="small mut">The kit and the decrypted key stay in this tab and are never sent to the server. A reload locks the environment again.</p></div>`;
    updateDeployBar();return}
  let meta=E2E_META[id]||{};
  let banner=meta.rekey_required?`<div class="card" style="border-color:var(--bad)"><h3>Access changed</h3>
    <p>A member's key grant was removed, but the stored ciphertext is still encrypted under the old environment key. Rotate the key to re-encrypt every secret under a new key and wrap that key to the current members. Rotation cannot take back ciphertext someone already copied.</p>
    <button class="primary" onclick="e2eRekey()">Rotate key now</button></div>`:'';
  $('view').innerHTML=`${envTabs()}${banner}
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
async function renderDelegatedEnv(){VIEW='env';$('topaction').style.display='none';$('pagetitle').textContent=APP?.name||'App';$('crumb').textContent='/ environments';
  $('view').innerHTML=`${envTabs()}<div class="card"><h3>Delegated environment</h3>
    <p class="mut">This environment is client-encrypted, and a runner you host holds a key grant for provider sync. The console cannot read these secrets. Manage them with the CLI (<span class="mono">openwarp e2e</span>) or an E2E-capable client; provider sync runs on the runner.</p></div>`;
  updateDeployBar()}
function isE2E(e){return !!e&&(e.mode||'sse')==='e2e'}
function isDelegated(e){return !!e&&e.mode==='delegated'}
async function switchEnv(id){let cur=ENV&&ENV.id;if(cur===id){return}
  if(cur&&(Object.keys(drafts()).length||Object.keys(e2eDrafts()).length)&&!confirm('Discard staged changes?'))return;
  if(cur){delete DRAFTS[cur];delete E2E_DRAFTS[cur]}
  ENV=ENVS.find(e=>e.id===id);await renderEnv()}
function envMode(e){return e&&e.mode==='e2e'?'e2e':'sse'}
async function newEnv(){modal(`<h3>New environment</h3><div class="field"><label for="ne-name">Name (letters, numbers, - or _)</label><input id="ne-name" placeholder="qa-1"></div><div class="row"><button class="primary" onclick="createEnv()">Create</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`)}
async function createEnv(){try{await api('POST',`/api/apps/${APP.id}/envs`,{name:$('ne-name').value});closeModal();ENVS=await api('GET',`/api/apps/${APP.id}/envs`);toast('Environment created');renderEnv()}catch(e){toast(e.message,true)}}
function appSettings(){if(!APP){toast('Open an app first',true);return}let on=APP.reuse_check!==false;
  modal(`<h3>App settings</h3><p class="mut">${esc(APP.name||'')}</p>
    <label class="row" style="gap:8px;margin:12px 0"><input type="checkbox" id="app-reuse" ${on?'checked':''}> Warn when a secret value is reused elsewhere in this workspace</label>
    <p class="small mut">The workspace setting must also be on. The warning is advisory; you can still save the value.</p>
    <div class="row"><button class="primary" onclick="saveAppSettings()">Save</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`,'App settings')}
async function saveAppSettings(){try{let on=$('app-reuse').checked;
  await api('PUT',`/api/apps/${APP.id}/settings`,{reuse_check:on});
  APP.reuse_check=on;closeModal();toast('App settings saved')}catch(e){toast(e.message,true)}}
function newE2eEnv(){modal(`<h3>New end-to-end encrypted environment</h3>
  <p class="mut">The environment key is generated in this browser and wrapped to your account key. The server stores only ciphertext and cannot read these secrets.</p>
  <div class="field"><label for="ne2-name">Name</label><input id="ne2-name" placeholder="vault"></div>
  ${E2E_KIT?'':'<div class="field"><label for="ne2-kit">Recovery kit (needed to wrap the new key)</label><input id="ne2-kit" type="password" autocomplete="off" placeholder="base64 recovery kit" style="width:100%"></div>'}
  <div class="row"><button class="primary" onclick="createE2eEnv()">Create E2E env</button><button class="ghost" onclick="closeModal()">Cancel</button></div>
  <p class="small mut">Provider sync needs a delegated environment with a runner.</p>`)}
async function createE2eEnv(){try{
  if(!E2E_KIT){let kit=($('ne2-kit')?.value||'').trim();if(!kit)throw new Error('paste the recovery kit for this account');E2E_KIT=kit}
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
function enc(s){return new TextEncoder().encode(s)}
function dec(b){return new TextDecoder().decode(b)}
async function e2eHash(path,key,envKey){
  // Match the server's blind index: HMAC under the environment key, not a bare
  // SHA-256 a database thief could test guesses against offline.
  let k=await crypto.subtle.importKey('raw',envKey,{name:'HMAC',hash:'SHA-256'},false,['sign']);
  let sig=await crypto.subtle.sign('HMAC',k,enc('ow-key-index:v1|'+String(path||'/')+'|'+String(key||'').toUpperCase()));
  return [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,'0')).join('')}
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
      let kh=d.key_hash||await e2eHash(path,k,key);
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
  if((E2E_META[id]||{}).runner){toast('Delegated environments rotate through the runner; use the CLI',true);return}
  if(!(E2E_DATA[id]||[]).length){toast('Nothing to rotate yet: add a secret first',true);return}
  if(!confirm('Rotate the environment key? Every secret is re-encrypted and each current member gets the new key wrapped to them.'))return;
  try{
    let newKey=crypto.getRandomValues(new Uint8Array(32));
    let secrets=[];
    for(const r of E2E_DATA[id])secrets.push({key_hash:r.key_hash,key_enc:await OW.encryptSymmetric(newKey,enc(r.key)),value_enc:await OW.encryptSymmetric(newKey,enc(r.value)),path_enc:await OW.encryptSymmetric(newKey,enc(r.path||'/'))});
    let grants=await api('GET',`/api/envs/${id}/e2e/grants`);
    if(!grants.some(g=>g.user_id===MY_UID))throw new Error('your own grant is missing; refresh and try again');
    let payload=[];
    for(const g of grants){if(!g.pubkey)throw new Error('grantee '+g.email+' has no public key');payload.push({user_id:g.user_id,wrapped_key:await OW.encryptAsymmetric(g.pubkey,newKey)})}
    await api('POST',`/api/envs/${id}/e2e/rekey`,{secrets,grants:payload});
    E2E_KEYS[id]=newKey;await e2eLoad(id,E2E_KIT);toast('Environment key rotated');await renderE2eEnv();
  }catch(e){toast('Rotation failed: '+e.message,true)}}
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
let REUSE_PROCEED=null,REUSE_BACK=null;
async function reusePreflight(items,exclude){if(!ENV)return[];
  try{let d=await api('POST',`/api/envs/${ENV.id}/secrets/reuse-check`,{secrets:items.map(s=>({key:s.key,value:s.value,path:s.path||'/',type:s.type||'secret'})),exclude:exclude||[]});
    return d.enabled===false?[]:(d.matches||[])}catch(e){return []}}
function reuseWarn(matches,proceed,back){
  REUSE_PROCEED=proceed;REUSE_BACK=back||null;
  let groups=matches.map(m=>`<div style="border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:10px 0">
    <div class="row" style="justify-content:space-between"><span class="mono">${esc(m.key)}</span><span class="mut small">${esc(m.path||'/')}</span></div>
    ${m.items.map(it=>`<div class="row" style="justify-content:space-between;gap:10px;padding:7px 0;border-top:1px solid var(--line)">
      <span class="small"><b>${esc(it.app_name||'app')}</b> / ${esc(it.env_name||'env')} <span class="mut">·</span> <span class="mono">${esc(it.key)}</span> <span class="mut">${esc(it.path||'/')}</span></span>
      <button onclick="reuseGo('${jsq(it.app_id)}','${jsq(it.env_id)}','${jsq(it.key)}')">Go to</button></div>`).join('')}
  </div>`).join('');
  modal(`<h3>This value is already in use</h3>
    <p class="mut">The same value is stored elsewhere in this workspace. Reusing it means one leak exposes every place it is used.</p>
    ${groups}
    <div class="row" style="margin-top:14px"><button class="primary" onclick="reuseProceed()">Use anyway</button>${REUSE_BACK?'<button class="ghost" onclick="reuseBack()">Back</button>':''}</div>`,'Reused secret value')}
function reuseProceed(){let cb=REUSE_PROCEED;REUSE_PROCEED=null;REUSE_BACK=null;closeModal();if(cb)cb()}
function reuseBack(){let cb=REUSE_BACK;REUSE_PROCEED=null;REUSE_BACK=null;closeModal();if(cb)cb()}
async function reuseGo(aid,eid,key){
  if(!aid||!eid){toast('That item is no longer available',true);return}
  let cur=ENV&&ENV.id;
  if(cur&&Object.keys(drafts()).length&&!confirm('Discard staged changes?'))return;
  if(cur)delete DRAFTS[cur];
  closeModal();REUSE_PROCEED=null;REUSE_BACK=null;
  try{
    if(!APPS.some(a=>a.id===aid))APPS=await api('GET',`/api/orgs/${ORG}/apps`);
    APP=APPS.find(a=>a.id===aid)||{id:aid};
    ENVS=await api('GET',`/api/apps/${aid}/envs`);
    ENV=ENVS.find(e=>e.id===eid)||ENVS[0]||null;
    await renderEnv();
    let f=$('sfilter');if(f){f.value=key;drawSecrets()}
    toast('Showing '+key+' in '+(ENV?ENV.name:''));
  }catch(e){toast(e.message,true)}}
function addRow(prefill){if(!ENV){toast('Open an environment first',true);return}let id='new-'+Date.now();let v=prefill||{};
  let types=['secret','sealed','ssh_key','config'];
  modal(`<h3>New secret</h3>
    <div class="field"><label for="ns-key">Key</label><input id="ns-key" placeholder="DATABASE_URL" value="${esc(v.key||'')}"></div>
    <div class="field"><label for="ns-val">Value</label><textarea id="ns-val" rows="3">${esc(v.value||'')}</textarea></div>
    <div class="row"><div class="field" style="flex:1"><label for="ns-path">Path</label><input id="ns-path" value="${esc(v.path||'/')}"></div>
    <div class="field"><label for="ns-type">Type</label><select id="ns-type">${types.map(t=>`<option${t===(v.type||'secret')?' selected':''}>${t}</option>`).join('')}</select></div></div>
    <div class="row"><button class="primary" onclick="stageNew('${id}')">Stage secret</button><button class="ghost" onclick="closeModal()">Cancel</button></div>
    <p class="small mut">Staged changes deploy together, like a commit. Sealed values can never be read back.</p>`,'New secret')}
function reuseCandidate(){let k=$('ns-key').value.trim();if(!k){toast('Key required',true);return null}
  return {key:k.toUpperCase(),value:$('ns-val').value,path:$('ns-path').value||'/',type:$('ns-type').value,comment:'',isNew:true}}
function commitNew(id,s){s.id=id;if(!DRAFTS[ENV.id])DRAFTS[ENV.id]={};DRAFTS[ENV.id][id]=s;closeModal();drawSecrets();updateDeployBar()}
async function stageNew(id){let s=reuseCandidate();if(!s)return;
  if(s.type==='secret'&&s.value){
    let matches=await reusePreflight([s],SECRETS.filter(x=>x.type==='secret'&&x.key===s.key&&(x.path||'/')===s.path&&(x.value??'')===s.value).map(x=>x.id));
    if(matches.length){reuseWarn(matches,()=>commitNew(id,s),()=>addRow(s));return}
  }
  commitNew(id,s)}
function editRow(id,prefill){let d=drafts()[id];let s=d||SECRETS.find(x=>x.id===id);if(!s)return;let isNew=!!d;
  let value=prefill?prefill.value:(s.value??'');let comment=prefill?prefill.comment:(s.comment||'');
  modal(`<h3>Edit ${esc(s.key)}</h3><div class="field"><label for="ed-val">Value</label><textarea id="ed-val" rows="4">${esc(value)}</textarea></div>
    <div class="field"><label for="ed-comment">Comment</label><input id="ed-comment" value="${esc(comment)}"></div>
    <div class="row"><button class="primary" onclick="stageEdit('${jsq(id)}')">${isNew?'Stage secret':'Stage change'}</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`,'Edit secret')}
function commitEdit(id,s,value,comment){let d=drafts()[id];
  if(d){d.value=value;d.comment=comment}
  else{if(!DRAFTS[ENV.id])DRAFTS[ENV.id]={};DRAFTS[ENV.id][id]={id,key:s.key,value,path:s.path,type:s.type,comment}}
  closeModal();drawSecrets();updateDeployBar();toast('Change staged, deploy when ready')}
async function stageEdit(id){let d=drafts()[id];let s=d||SECRETS.find(x=>x.id===id);if(!s)return;
  let value=$('ed-val').value,comment=$('ed-comment').value;
  let changed=!d||d.value!==value;
  if(changed&&(s.type||'secret')==='secret'&&value){
    let matches=await reusePreflight([{key:s.key,value,path:s.path||'/',type:'secret'}],[s.id]);
    if(matches.length){reuseWarn(matches,()=>commitEdit(id,s,value,comment),()=>editRow(id,{value,comment}));return}
  }
  commitEdit(id,s,value,comment)}
async function overrideRow(id,key){modal(`<h3>Personal override: ${esc(key)}</h3><p class="mut">Only you see this value. Teammates keep the shared one.</p><div class="field"><label for="ov-val">Your value</label><textarea id="ov-val" rows="3"></textarea></div><div class="row"><button class="primary" onclick="saveOverride('${jsq(id)}')">Save override</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`,'Personal override')}
async function saveOverride(id){try{await api('POST',`/api/secrets/${id}/override`,{secrets:[{key:'x',value:$('ov-val').value}]});closeModal();toast('Override saved');renderEnv()}catch(e){toast(e.message,true)}}
async function delSecret(id,key){let d=drafts()[id];
  if(d&&d.isNew){delete drafts()[id];drawSecrets();updateDeployBar();return}
  let s=SECRETS.find(x=>x.id===id);if(s&&s.type==='sealed'&&!confirm('Delete sealed secret '+key+'? Its value cannot be recovered.'))return;
  if(!confirm('Delete '+key+'? You can restore it from history.'))return;
  try{await api('DELETE',`/api/secrets/${id}`);delete drafts()[id];toast('Secret deleted');await renderEnv()}catch(e){toast(e.message,true)}}
function updateDeployBar(){let n=isE2E(ENV)?e2eDraftList().length:draftList().length;let active=VIEW==='env'&&!!ENV&&n>0;
  $('deploybar').classList.toggle('show',active);
  $('deploytext').innerHTML=active?`<b>${n}</b>&nbsp;staged change${n!==1?'s':''}`:''}
function discardStage(){if(!ENV)return;delete DRAFTS[ENV.id];delete E2E_DRAFTS[ENV.id];
  if(isE2E(ENV))drawE2E();else drawSecrets();updateDeployBar()}
async function deployStage(){if(isE2E(ENV))return deployE2E();try{let items=draftList().map(s=>({key:s.key,value:s.value,path:s.path,type:s.type,comment:s.comment||''}));
  if(!items.length)return;let envId=ENV.id;
  let d=await api('PUT',`/api/envs/${envId}/secrets`,{secrets:items});
  if(ENV&&ENV.id===envId)delete DRAFTS[envId];
  toast(`Deployed ${d.deployed} secret${d.deployed!==1?'s':''}`);await renderEnv()}catch(e){toast(e.message,true)}}
async function showHistory(id){try{let h=await api('GET',`/api/secrets/${id}/history`);
  modal(`<h3>History</h3>${h.length?h.map(v=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:8px 0"><span><b>v${v.version}</b> <span class="mut small">${new Date(v.created_at*1000).toLocaleString()}</span><br><span class="val">${esc(v.value)}</span></span><button onclick="restoreVer('${jsq(id)}',${v.version})">Restore</button></div>`).join(''):'<p class="mut">No history.</p>'}<div class="row" style="margin-top:12px"><button class="ghost" onclick="closeModal()">Close</button></div>`,'Secret history')}catch(e){toast(e.message,true)}}
async function restoreVer(id,ver){try{await api('POST',`/api/secrets/${id}/restore/${ver}`,{});closeModal();toast('Restored version '+ver);renderEnv()}catch(e){toast(e.message,true)}}
function importModal(text){modal(`<h3>Import secrets into ${esc(ENV.name)}</h3><p class="mut">Paste .env contents. Existing keys are updated and versioned.</p><textarea id="imp-text" aria-label=".env contents" rows="10" placeholder="API_KEY=...&#10;# comment&#10;DATABASE_URL=postgres://…">${esc(text||'')}</textarea><div class="row" style="margin-top:12px"><button class="primary" onclick="doImport()">Import</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`)}
function parseEnvLoose(text){let out=[];for(let line of String(text||'').split('\n')){let l=line.trim();if(!l||l.startsWith('#'))continue;
  if(l.startsWith('export '))l=l.slice(7).trim();let i=l.indexOf('=');if(i<1)continue;
  let value=l.slice(i+1).trim();if((value.startsWith('"')&&value.endsWith('"'))||(value.startsWith("'")&&value.endsWith("'")))value=value.slice(1,-1);
  out.push({key:l.slice(0,i).trim().toUpperCase(),value,path:'/',type:'secret'})}return out}
async function doImport(force,text){
  if(text===undefined)text=$('imp-text').value;
  if(!force){let cands=parseEnvLoose(text);
    if(cands.length){let exclude=SECRETS.filter(x=>x.type==='secret'&&cands.some(c=>c.key===x.key&&(x.path||'/')===c.path&&(x.value??'')===c.value)).map(x=>x.id);
      let matches=await reusePreflight(cands,exclude);
      if(matches.length){reuseWarn(matches,()=>doImport(true,text),()=>importModal(text));return}}}
  try{let d=await api('POST',`/api/envs/${ENV.id}/import`,{text});closeModal();toast(`Imported ${d.deployed} secrets`);renderEnv()}catch(e){toast(e.message,true)}}
async function exportEnv(){try{let d=await api('GET',`/api/envs/${ENV.id}/export`);modal(`<h3>Export ${esc(ENV.name)}</h3><textarea id="exp-text" aria-label="Exported secrets" rows="12" readonly>${esc(d.text)}</textarea><div class="row" style="margin-top:12px"><button onclick="navigator.clipboard.writeText(document.querySelector('#modal textarea').value);toast('Export copied')">Copy .env</button><button class="ghost" onclick="closeModal()">Close</button></div>`)}catch(e){toast(e.message,true)}}

// ---------- access, integrations, audit, settings ----------
function needAppEnv(){if(!APP){toast('Open an app first',true);nav('apps');return false} return true}
async function renderAccess(){if(!ORG)return;$('pagetitle').textContent='Members & access';$('crumb').textContent='';
  let teams=await api('GET',`/api/orgs/${ORG}/teams`).catch(()=>[]);let roles=await api('GET',`/api/orgs/${ORG}/roles`).catch(()=>[]);
  let members=await api('GET',`/api/orgs/${ORG}/members`).catch(()=>[]);let myRole=members.find(m=>m.id===ME?.id)?.role||'';
  let props=ENV?await api('GET',`/api/envs/${ENV.id}/proposals`).catch(()=>[]):[];
  let reqs=ENV?await api('GET',`/api/envs/${ENV.id}/access-requests`).catch(()=>[]):[];
  $('view').innerHTML=`
  <div class="card"><h3>Members</h3><p>Owners can transfer ownership; admins manage roles. A workspace always keeps at least one owner.</p>
  <table class="members-table"><thead><tr><th>Member</th><th>Role</th><th></th></tr></thead><tbody>
  ${members.map(m=>`<tr><td>${esc(m.email)}${m.id===ME?.id?' <span class="chip">you</span>':''}</td><td><select aria-label="Role for ${esc(m.email)}" onchange="setMemberRole('${jsq(m.id)}',this.value)">${roles.map(r=>`<option value="${esc(r.name)}"${r.name===m.role?' selected':''}>${esc(r.name)}</option>`).join('')}</select></td><td>${m.role!=='owner'&&myRole==='owner'?`<button onclick="transferOwner('${jsq(m.id)}','${jsq(m.email)}')">Make owner</button> `:''}${m.id!==ME?.id?`<button class="danger" onclick="removeMember('${jsq(m.id)}','${jsq(m.email)}')">Remove</button>`:''}</td></tr>`).join('')||'<tr><td colspan="3" class="mut">No members</td></tr>'}
  </tbody></table></div>
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
async function setMemberRole(uid,role){try{await api('PATCH',`/api/orgs/${ORG}/members/${uid}`,{role});toast('Role updated');renderAccess()}catch(e){toast(e.message,true);renderAccess()}}
async function removeMember(uid,email){if(!confirm(`Remove ${email} from this workspace?`))return;try{await api('DELETE',`/api/orgs/${ORG}/members/${uid}`);toast('Member removed');renderAccess()}catch(e){toast(e.message,true)}}
async function transferOwner(uid,email){if(!confirm(`Make ${email} the owner? You become an admin and lose owner controls.`))return;try{await api('POST',`/api/orgs/${ORG}/transfer`,{user_id:uid});toast('Ownership transferred');await refreshOrgs();renderAccess()}catch(e){toast(e.message,true)}}
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

const KINDS=['trigger','github','gitlab','vercel','netlify','cloudflare','cloudflare_pages','supabase','nomad','coolify','heroku','render','flyio','railway','digitalocean','gcp_secret_manager','azure_key_vault','kubernetes','hashicorp_vault','aws_secrets_manager','aws_parameter_store','1password','dokploy','caprover','portainer','docker_swarm','bitbucket','circleci','teamcity','travisci','terraform_cloud','qovery','laravel_forge','openwarp','devin','cloudflare_secrets_store','octopus_deploy','azure_devops','cursor','northflank','spacelift','rundeck','cloud66','humanitec','ovh_kms','scaleway_secret_manager','azure_app_configuration','vultr','hetzner','linode','digitalocean_ssh','ssh','keeper','oci_vault','huggingface','webhook','instabox','boat','daytona'];
async function renderIntegrations(){if(!needAppEnv())return;setTimeout(kindHint,0);$('pagetitle').textContent='Integrations';$('crumb').textContent=ENV?('/ '+ENV.name):'';
  let ints=ENV?await api('GET',`/api/envs/${ENV.id}/integrations`).catch(()=>[]):[];
  $('view').innerHTML=`<div class="card"><h3>Sync secrets to a platform</h3><p>Integrations run automatically on every deploy, or on demand. Config is stored encrypted. Trigger.dev example config: <span class="mono">{"token":"tr_pat_…","project_ref":"proj_…","target_env":"prod"}</span></p>
  <div class="row"><select id="ikind" onchange="kindHint()">${KINDS.map(k=>`<option>${k}</option>`).join('')}</select></div>
  <p class="small" id="ikind-hint"></p><textarea id="icfg" rows="4" placeholder='{"token":"…"}'></textarea>
  <div class="row" style="margin-top:10px"><button class="primary" onclick="mkIntegration()">Add integration</button></div></div>
  <div class="card"><h3>Configured ${ENV?('· '+esc(ENV.name)):''}</h3>${ints.length?ints.map(i=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:8px 0"><span><b>${esc(i.kind)}</b> <span class="mut small">${esc(i.name||'')}</span></span><span><button onclick="testInt('${i.id}')">Test</button> <button class="primary" onclick="syncInt('${i.id}')">Sync now</button> <button class="danger" onclick="delInt('${i.id}')">Delete</button></span></div>`).join(''):'<span class="mut">None yet</span>'}</div>
  <div class="card"><h3>Dynamic secrets &amp; rotation</h3><div class="row"><input id="lease-name" placeholder="lease name"><select id="lease-type"><option value="generic">generic</option><option value="openrouter">openrouter</option><option value="resend">resend</option><option value="openai">openai</option><option value="huggingface">huggingface</option><option value="fireworks">fireworks</option><option value="mistral">mistral</option><option value="perplexity">perplexity</option><option value="xai">xai</option><option value="gemini">gemini</option><option value="cloudflare">cloudflare</option><option value="deepgram">deepgram</option><option value="elevenlabs">elevenlabs</option><option value="deepinfra">deepinfra</option><option value="baseten">baseten</option><option value="fal">fal</option><option value="speechmatics">speechmatics</option><option value="chutes">chutes</option><option value="aws_iam">aws_iam</option><option value="postgres">postgres</option><option value="mysql">mysql</option></select><button onclick="mkLease()">New lease (1h)</button><button onclick="loadLeases()">Show leases</button></div><textarea id="lease-cfg" rows="2" placeholder='provider config, e.g. {"management_key":"…"} or {"connection":"mysql://…","grants":["SELECT ON app.*"]}'></textarea><pre class="val" id="leases"></pre>
  <div class="row"><input id="rot-key" placeholder="KEY_TO_ROTATE"><span class="row"><input id="rot-int" value="86400" size="8"><span class="mut small">seconds between rotations</span></span><button onclick="mkRotation()">Schedule rotation</button></div></div>
  <div class="card"><h3>Lockbox: one-time secret sharing</h3><div class="row"><input id="lb-val" placeholder="value to share once" style="min-width:280px"><button onclick="mkLockbox()">Create link</button></div><pre class="val" id="lb-out"></pre></div>`}
const KIND_HINTS={trigger:'Trigger.dev: {"token":"tr_pat_… or tr_prod_sk_…","project_ref":"proj_…","target_env":"prod"}',github:'GitHub: {"token":"ghp_…","owner":"org","repo":"repo"}',gitlab:'GitLab: {"token":"glpat-…","project_id":"42"}',webhook:'Webhook: {"url":"https://…","token":"optional bearer","signing_secret":"optional HMAC key"}',azure_app_configuration:'Azure App Configuration: {"endpoint":"https://store.azconfig.io","id":"access key id","secret":"base64 access key","label":"optional"}',scaleway_secret_manager:'Scaleway Secret Manager: {"region":"fr-par","secret_key":"…","project_id":"…","path":"/app"}',vultr:'Vultr SSH keys: {"api_key":"…"} (each secret value must be an OpenSSH public key)',hetzner:'Hetzner SSH keys: {"token":"…"} (syncs secrets of type ssh_key; a changed key is recreated)',linode:'Linode SSH keys: {"token":"…"} (syncs secrets of type ssh_key; a changed key is recreated)',digitalocean_ssh:'DigitalOcean account SSH keys: {"token":"…"} (syncs secrets of type ssh_key; distinct from digitalocean, which updates an App Platform spec)',ssh:'SSH file: {"host":"app.example.com","user":"deploy","identity_file":"/keys/deploy","known_hosts":"ssh-ed25519 AAAA…","files":[{"path":"/srv/app/.env","format":"dotenv","folders":["/app"]}]}',kubernetes:'Kubernetes: {"api_server":"https://…","token":"…","namespace":"default","secret_name":"app-secrets"}',aws_secrets_manager:'AWS Secrets Manager: {"region":"us-east-1","access_key_id":"…","secret_access_key":"…","mapping":"one_to_one"} or add "secret_id":"app/prod" for one JSON secret',aws_parameter_store:'AWS Parameter Store: {"region":"us-east-1","access_key_id":"…","secret_access_key":"…","path_prefix":"/app/prod"}','1password':'1Password Connect: {"connect_url":"https://connect.example.com","token":"…","vault_id":"…","value_label":"value"}',dokploy:'Dokploy: {"base_url":"https://dokploy.example.com","api_key":"…","application_id":"…"} or "compose_id"',caprover:'CapRover: {"base_url":"https://captain.example.com","password":"…","app_name":"app"}',portainer:'Portainer: {"base_url":"https://portainer.example.com:9443","api_key":"…","endpoint_id":1,"stack_id":1}',docker_swarm:'Docker Swarm: {"api_url":"https://docker.example.com:2376","ca_cert":"PEM","client_cert":"PEM","client_key":"PEM"}',bitbucket:'Bitbucket: {"workspace":"…","repo_slug":"…","token":"…"}',circleci:'CircleCI: {"project_slug":"gh/org/repo","token":"…"}',teamcity:'TeamCity: {"base_url":"https://teamcity.example.com","token":"…","project_locator":"_Root"}',travisci:'Travis CI: {"repo":"owner/repo","token":"…"}',terraform_cloud:'Terraform Cloud: {"token":"…","workspace_id":"ws-…","category":"env"}',qovery:'Qovery: {"token":"…","organization_id":"…","project_id":"…","environment_id":"…"}',laravel_forge:'Laravel Forge: {"token":"…","organization":"org","server_id":1,"site_id":1}',openwarp:'OpenWarp: {"base_url":"https://other-openwarp.example.com","token":"…","env_id":"…"}',devin:'Devin: {"token":"cog_…","org_id":"org-…"}',cloudflare_secrets_store:'Cloudflare Secrets Store: {"token":"…","account_id":"…","store_id":"…","scopes":["workers"]}',octopus_deploy:'Octopus Deploy: {"base_url":"https://octopus.example.com","api_key":"API-…","space_id":"Spaces-1","project_id":"Projects-123"}',azure_devops:'Azure DevOps: {"organization":"org","project":"project","group_id":"1","token":"PAT"}',cursor:'Cursor: {"token":"…","environment_id":"…"} (omit environment_id for team secrets)',northflank:'Northflank: {"token":"…","project_id":"…","secret_group_id":"…"}',spacelift:'Spacelift: {"token":"…","stack_id":"…"} (or "account":"…")',rundeck:'Rundeck: {"instance_url":"https://rundeck.example.com","api_token":"…","project":"proj"}',cloud66:'Cloud 66: {"access_token":"…","stack_id":"…"}',humanitec:'Humanitec: {"api_token":"…","org":"org","app":"app","scope":"application"}',ovh_kms:'OVHcloud KMS: {"okms_domain":"https://kms.example.com","okms_id":"…","token":"…","path":"app"}',keeper:'Keeper: {"instance_url":"https://keeper.example.com","api_key":"…","folder_uid":"…"}',huggingface:'Hugging Face Space: {"token":"hf_…","namespace":"org","repo":"space","target":"secrets"} (or "variables")',oci_vault:'OCI Vault: {"tenancy_ocid":"…","user_ocid":"…","fingerprint":"…","private_key":"PEM","region":"us-ashburn-1","compartment_id":"…","vault_id":"…","key_id":"…"}',instabox:'Instabox: {"api_key":"ibk_…","org":"team","hosts":["api.example.com"],"delivery":"proxy"}',boat:'Boat: {"api_key":"boat_…","environment":"base","upgrade":true}',daytona:'Daytona: {"api_key":"…","organization_id":"…","hosts":["api.example.com"]}'};
function kindHint(){if(!$('ikind'))return;let k=$('ikind').value;$('ikind-hint').textContent=KIND_HINTS[k]||('Config for '+k+' as JSON. Common keys: token, base_url for self-hosted instances. Stored encrypted at rest.')}
async function mkIntegration(){try{await api('POST',`/api/envs/${ENV.id}/integrations`,{kind:$('ikind').value,config:JSON.parse($('icfg').value||'{}')});toast('Integration added');renderIntegrations()}catch(e){toast(e.message,true)}}
async function testInt(id){try{let d=await api('POST',`/api/integrations/${id}/test`,{});toast(d.detail)}catch(e){toast(e.message,true)}}
async function syncInt(id){try{let d=await api('POST',`/api/integrations/${id}/sync`,{});toast(d.detail)}catch(e){toast(e.message,true)}}
async function delInt(id){if(!confirm('Delete this integration? Sync state for it is removed too.'))return;try{await api('DELETE',`/api/integrations/${id}`);toast('Integration deleted');renderIntegrations()}catch(e){toast(e.message,true)}}
async function mkLease(){try{let body={name:$('lease-name').value||'lease',type:$('lease-type').value};if($('lease-cfg').value.trim())body.config=JSON.parse($('lease-cfg').value);let d=await api('POST',`/api/envs/${ENV.id}/dynamic`,body);$('leases').textContent=JSON.stringify(d,null,2)}catch(e){toast(e.message,true)}}
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
  let saml=await api('GET',`/api/orgs/${ORG}/saml`).catch(()=>null);
  let orgs=await api('GET','/api/orgs').catch(()=>[]);let myOrg=orgs.find(o=>o.id===ORG)||{};
  let samlCard=`<div class="card"><h3>SAML SSO</h3><p>Service provider metadata: <span class="mono">${esc(saml?.sp_metadata_url||'')}</span></p>
    <div class="field"><label for="set-saml-entity">IdP entity ID</label><input id="set-saml-entity" value="${esc(saml?.idp_entity_id||'')}" placeholder="https://idp.example/metadata"></div>
    <div class="field"><label for="set-saml-url">IdP metadata URL</label><input id="set-saml-url" placeholder="https://idp.example/metadata.xml" style="width:100%"></div>
    <div class="field"><label for="set-saml-xml">or paste metadata XML</label><textarea id="set-saml-xml" rows="4">${esc(saml?.metadata_xml||'')}</textarea></div>
    <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="set-saml-unsigned" ${saml?.allow_unsigned_metadata?'checked':''}> Allow unsigned metadata (not recommended)</label>
    <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="set-saml-auto" ${saml?.auto_provision?'checked':''}> Auto-provision first-time users</label>
    <div class="field"><label for="set-saml-domains">Allowed email domains</label><input id="set-saml-domains" value="${esc(saml?.allowed_domains||'')}" placeholder="example.com" style="width:100%"></div>
    <div class="row"><button class="primary" onclick="saveSaml()">Save SAML</button></div><pre class="val" id="saml-out"></pre></div>`;
  let prov=await api('GET','/api/auth/providers').catch(()=>null);
  let ldap=prov?.ldap?await api('GET',`/api/orgs/${ORG}/ldap`).catch(()=>null):null;
  let ldapCard=prov?.ldap?`<div class="card"><h3>LDAP directory</h3><p>Users sign in with directory credentials over TLS; a service account searches for the entry, then the entry's own password is bound. Native builds only.</p>
  <div class="field"><label for="ld-url">Directory URL (ldaps:// only)</label><input id="ld-url" value="${esc(ldap?.url||'')}" placeholder="ldaps://dc01.example.com:636" style="width:100%"></div>
  <div class="row"><input id="ld-bind-dn" value="${esc(ldap?.bind_dn||'')}" placeholder="service bind DN" style="min-width:280px"><input id="ld-bind-pw" type="password" placeholder="${ldap?.bind_password_set?'stored; leave blank to keep':'service account password'}"></div>
  <div class="field"><label for="ld-base-dn">Base DN</label><input id="ld-base-dn" value="${esc(ldap?.base_dn||'')}" placeholder="OU=People,DC=example,DC=com" style="width:100%"></div>
  <div class="field"><label for="ld-filter">User filter ({username} is escaped per RFC 4515)</label><input id="ld-filter" value="${esc(ldap?.user_filter||'(uid={username})')}" style="width:100%"></div>
  <div class="row"><input id="ld-email-attr" value="${esc(ldap?.email_attr||'mail')}" placeholder="mail"><input id="ld-name-attr" value="${esc(ldap?.name_attr||'displayName')}" placeholder="displayName"><input id="ld-group-attr" value="${esc(ldap?.group_attr||'memberOf')}" placeholder="memberOf"></div>
  <div class="field"><label for="ld-roles">Group to role map (Group=role;Group=role)</label><input id="ld-roles" value="${esc(ldap?.group_roles||'')}" placeholder="Admins=admin;Developers=developer" style="width:100%"></div>
  <div class="row"><input id="ld-default-role" value="${esc(ldap?.default_role||'developer')}" placeholder="default role"><input id="ld-domains" value="${esc(ldap?.allowed_domains||'')}" placeholder="allowed email domains" style="min-width:260px"></div>
  <div class="field"><label for="ld-ca">Internal CA certificate (PEM, optional)</label><textarea id="ld-ca" rows="3">${esc(ldap?.ca_cert_pem||'')}</textarea></div>
  <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="ld-auto" ${ldap?.auto_provision?'checked':''}> Auto-provision first-time users in allowed domains</label>
  <div class="row"><button class="primary" onclick="saveLdap()">Save LDAP</button><button class="danger" onclick="removeLdap()">Remove</button></div></div>`:'';
  let instanceCard=inst&&inst.instance_owner?`<div class="card"><h3>Instance</h3><p>Control who can create an account on this server.</p>
    <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="set-signups" ${inst.signups_open?'checked':''} ${inst.signups_env_locked?'disabled':''}> Allow self signup</label>
    <p class="small mut">When off, new users join only by invitation. ${inst.signups_env_locked?'Locked by OPENWARP_SIGNUPS.':''}</p>
    <button class="primary" onclick="saveSignups()" ${inst.signups_env_locked?'disabled':''}>Save signup policy</button>
    <div class="row" style="margin-top:12px"><label for="set-instance-owner">New instance owner email</label><input id="set-instance-owner" type="email" style="min-width:260px"><button onclick="transferInstance()">Transfer instance</button></div>
    <p class="small mut" style="margin-top:6px">The new owner needs an active, verified account. A solo instance can delete its only account once its workspace is gone.</p></div>`:'';
  $('view').innerHTML=`${instanceCard}
  <div class="card"><h3>Organisation security</h3><p>IP allowlist is enforced on every API call. OIDC powers SSO and MCP OAuth discovery.</p>
  <div class="field"><label for="set-ip">IP allowlist (CIDR, comma separated, empty = allow all)</label><input id="set-ip" value="${esc(s?.ip_allowlist||'')}" placeholder="203.0.113.0/24"></div>
  <label class="row" style="gap:8px;margin:10px 0"><input type="checkbox" id="set-reuse" ${s?.reuse_check!==false?'checked':''}> Warn when a secret value is reused elsewhere in this workspace</label>
  <p class="small mut" style="margin:0 0 10px">Each app can turn the warning off. The check compares a keyed, non-reversible fingerprint and only reports items you can already open.</p>
  <div class="field"><label for="set-oidc-iss">OIDC issuer</label><input id="set-oidc-iss" value="${esc(s?.oidc_issuer||'')}" placeholder="https://accounts.google.com"></div>
  <div class="row"><input id="set-oidc-cid" value="${esc(s?.oidc_client_id||'')}" placeholder="OIDC client id"><input id="set-oidc-sec" type="password" placeholder="${s?.oidc_client_secret_set?'stored; leave blank to keep':'OIDC client secret'}"><input id="set-oidc-redir" value="${esc(s?.oidc_redirect_uri||'')}" placeholder="redirect URI" style="min-width:260px"></div>
  <div class="field"><label for="set-oidc-domains">SSO email domains (comma separated; empty = any account at the issuer may join)</label><input id="set-oidc-domains" value="${esc(s?.oidc_allowed_domains||'')}" placeholder="example.com,subsidiary.example" style="width:100%"></div>
  <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="set-oidc-auto" ${s?.oidc_auto_provision?'checked':''}> Allow first-time SSO users to join as developers</label>
  <div class="row" style="margin-top:10px"><button class="primary" onclick="saveSettings()">Save settings</button></div></div>
  ${samlCard}
  ${ldapCard}
  <div class="card"><h3>Authenticator app (TOTP)</h3><p>Add a second factor to your login.</p><div class="row"><button onclick="totpSetup()">Set up TOTP</button></div><pre class="val" id="totp-out"></pre><div class="row"><input id="totp-code" placeholder="code from authenticator"><button onclick="totpVerify()">Verify and enable</button></div></div>
  <div class="card"><h3>End-to-end environments</h3><p>Paste your recovery kit to decrypt an E2E environment in this browser only. The kit never leaves this page.</p>
  <div class="row"><input id="e2e-kit" placeholder="recovery kit (base64)" style="min-width:320px"><input id="e2e-env" placeholder="E2E env ID"><button class="primary" onclick="loadE2E()">Decrypt</button></div><pre class="val" id="e2e-out"></pre></div>
  <div class="card"><h3>PKI</h3><p>Internal X.509 certificates from your own CA, and short-lived SSH certificates for server access.</p><div class="row"><input id="ca-name" placeholder="internal-ca"><button onclick="mkCA()">Create CA</button></div><pre class="val" id="ca-out"></pre>
  <div class="row" style="margin-top:10px"><input id="ssh-ca-name" placeholder="ssh-ca"><button onclick="mkSshCA()">Create SSH CA</button></div><div id="ssh-ca-list"></div><div id="ssh-ca-detail"></div></div>
  <div class="card"><h3>Session</h3><div class="row"><button onclick="loadTokensSettings()">My tokens</button><button class="danger" onclick="logout()">Sign out everywhere (this device)</button></div><pre class="val" id="sess-out"></pre></div>
  ${myOrg.role==='owner'?`<div class="card"><h3>Delete workspace</h3><p>Type <span class="mono">${esc(myOrg.name||'')}</span> to confirm. Every app, environment, secret, token and identity in this workspace is removed.</p><div class="row"><label for="del-org-name">Workspace name</label><input id="del-org-name" style="min-width:240px"><button class="danger" onclick="deleteWorkspace('${jsq(myOrg.name||'')}')">Delete workspace</button></div></div>`:''}
  <div class="card"><h3>Account</h3><p>Signed in as <span class="mono">${esc(ME?.email||'')}</span>. Deleting your account revokes every key and signs you out everywhere. Transfer or delete each workspace you own first.</p><button class="danger" onclick="deleteAccount()">Delete account</button></div>`;loadSshCAs()}
async function saveSettings(){try{let b={ip_allowlist:$('set-ip').value,reuse_check:$('set-reuse').checked,oidc_auto_provision:$('set-oidc-auto').checked,oidc_allowed_domains:$('set-oidc-domains').value};
  if($('set-oidc-iss').value)b.oidc_issuer=$('set-oidc-iss').value;
  if($('set-oidc-cid').value)b.oidc_client_id=$('set-oidc-cid').value;
  if($('set-oidc-redir').value)b.oidc_redirect_uri=$('set-oidc-redir').value;
  if($('set-oidc-sec').value)b.oidc_client_secret=$('set-oidc-sec').value;
  await api('PUT',`/api/orgs/${ORG}/settings`,b);toast('Settings saved')}catch(e){toast(e.message,true)}}
async function saveSignups(){try{let d=await api('PUT','/api/instance/signups',{open:$('set-signups').checked});toast('Signups '+(d.signups_open?'enabled':'disabled'));renderSettings()}catch(e){toast(e.message,true)}}
async function saveSaml(){try{let b={idp_entity_id:$('set-saml-entity').value,metadata_url:$('set-saml-url').value,metadata_xml:$('set-saml-xml').value,allow_unsigned_metadata:$('set-saml-unsigned').checked,auto_provision:$('set-saml-auto').checked,allowed_domains:$('set-saml-domains').value};let d=await api('PUT',`/api/orgs/${ORG}/saml`,b);$('saml-out').textContent='SP metadata: '+d.sp_metadata_url;toast('SAML saved')}catch(e){toast(e.message,true)}}
async function saveLdap(){try{
  let b={url:$('ld-url').value,bind_dn:$('ld-bind-dn').value,base_dn:$('ld-base-dn').value,user_filter:$('ld-filter').value,email_attr:$('ld-email-attr').value,name_attr:$('ld-name-attr').value,group_attr:$('ld-group-attr').value,group_roles:$('ld-roles').value,default_role:$('ld-default-role').value,allowed_domains:$('ld-domains').value,ca_cert_pem:$('ld-ca').value,auto_provision:$('ld-auto').checked};
  if($('ld-bind-pw').value)b.bind_password=$('ld-bind-pw').value;
  await api('PUT',`/api/orgs/${ORG}/ldap`,b);toast('LDAP saved');renderSettings()}catch(e){toast(e.message,true)}}
async function removeLdap(){if(!confirm('Remove LDAP sign-in for this workspace?'))return;
  try{await api('DELETE',`/api/orgs/${ORG}/ldap`);toast('LDAP removed');renderSettings()}catch(e){toast(e.message,true)}}
async function totpSetup(){try{let d=await api('POST','/api/me/totp/setup',{});$('totp-out').textContent='Secret: '+d.secret+'\n'+d.otpauth_url+'\nRecovery codes (save once):\n'+d.recovery_codes.join('\n')}catch(e){toast(e.message,true)}}
async function totpVerify(){try{await api('POST','/api/me/totp/verify',{code:$('totp-code').value});toast('TOTP enabled')}catch(e){toast(e.message,true)}}
async function loadE2E(envId){try{let id=envId||$('e2e-env')?.value;let d=await api('GET',`/api/envs/${id}/e2e/secrets`);let k=await OW.decryptAsymmetric($('e2e-kit').value,d.wrapped_key);
  $('e2e-out').textContent=d.secrets.map(s=>new TextDecoder().decode(OW.decryptSymmetric(k,s.key_enc))+'='+new TextDecoder().decode(OW.decryptSymmetric(k,s.value_enc))).join('\n')||'(no secrets)'}catch(e){$('e2e-out').textContent='Error: '+(e.message||e)}}
async function mkCA(){try{let d=await api('POST',`/api/orgs/${ORG}/pki/cas`,{name:$('ca-name').value||'internal-ca'});$('ca-out').textContent='CA id: '+d.id+'\n'+d.certificate}catch(e){toast(e.message,true)}}
async function mkSshCA(){try{let d=await api('POST',`/api/orgs/${ORG}/ssh/cas`,{name:$('ssh-ca-name').value||'ssh-ca'});
  $('ssh-ca-name').value='';$('ca-out').textContent='SSH CA id: '+d.id+'\nFingerprint '+d.fingerprint;
  loadSshCAs();openSshCA(d.id)}catch(e){toast(e.message,true)}}
async function loadSshCAs(){let host=$('ssh-ca-list');if(!host)return;try{let d=await api('GET',`/api/orgs/${ORG}/ssh/cas`);
  host.innerHTML=d.length?`<table><thead><tr><th>SSH CA</th><th>Fingerprint</th><th></th></tr></thead><tbody>`+d.map(c=>`<tr><td>${esc(c.name)}</td><td class="mono small">${esc(c.fingerprint)}</td><td><button onclick="openSshCA('${jsq(c.id)}')">Manage</button></td></tr>`).join('')+'</tbody></table>':'<p class="mut small">No SSH CA yet. A host accepts these certificates only after TrustedUserCAKeys names this CA.</p>'}catch(e){host.textContent=e.message}}
async function openSshCA(id){let detail=$('ssh-ca-detail');if(!detail)return;try{let d=await api('GET',`/api/ssh/cas/${id}`);
  let grants=d.grants.map(g=>g.role+': '+g.principals.join(', ')+(g.max_ttl?' ('+Math.round(g.max_ttl/60)+'m)':'')).join('\n');
  detail.innerHTML=`<h4 style="margin:16px 0 6px">${esc(d.name)}</h4>
    <p class="small mut">Fingerprint <span class="mono">${esc(d.fingerprint)}</span>. Install the CA key on every host that should accept these certificates.</p>
    <pre class="val">${esc(d.sshd)}</pre>
    <div class="field"><label>Principal grants, one role per line as role: pattern, pattern (15m)</label><textarea id="ssh-grants" rows="4" placeholder="developer: web-*, db-*&#10;admin: *">${esc(grants)}</textarea></div>
    <p class="small mut" style="margin:0 0 8px">A certificate can only name a principal its role is granted. A bare * means any local account, root included, so only an owner can grant it.</p>
    <div class="row"><button class="primary" onclick="saveSshGrants('${jsq(id)}')">Save grants</button><a class="mono small" style="align-self:center" href="/api/ssh/cas/${id}/revoked-keys" download="openwarp_revoked_keys">revoked keys</a><a class="mono small" style="align-self:center" href="/api/ssh/cas/${id}/krl" download="openwarp.krl">KRL</a></div>
    <h4 style="margin:16px 0 6px">Hosts</h4>
    <p class="small mut" style="margin:0 0 8px">A host certificate is only issued for a name and key registered here, so a member can deploy one but cannot invent a host.</p>
    <div class="row"><input id="ssh-host-name" placeholder="db-1.internal"><input id="ssh-host-key" placeholder="ssh-ed25519 AAAA… host key" style="min-width:280px"><button onclick="addSshHost('${jsq(id)}')">Register host</button></div>
    <div id="ssh-hosts"></div>
    <div id="ssh-certs"></div>`;
  loadSshHosts(id);loadSshCerts(id)}catch(e){toast(e.message,true)}}
async function loadSshHosts(id){let host=$('ssh-hosts');if(!host)return;try{let d=await api('GET',`/api/ssh/cas/${id}/hosts`);
  host.innerHTML=d.length?`<table><thead><tr><th>Hostname</th><th>Key fingerprint</th><th></th></tr></thead><tbody>`+d.map(h=>`<tr><td class="mono">${esc(h.hostname)}</td><td class="mut small">${esc(h.fingerprint)}</td><td><button class="danger" onclick="deleteSshHost('${jsq(h.id)}','${jsq(id)}')">Remove</button></td></tr>`).join('')+'</tbody></table>':'<p class="mut small">No hosts registered.</p>'}catch(e){host.textContent=e.message}}
async function addSshHost(id){try{let d=await api('POST',`/api/ssh/cas/${id}/hosts`,{hostname:$('ssh-host-name').value.trim(),public_key:$('ssh-host-key').value.trim()});
  $('ssh-host-name').value='';$('ssh-host-key').value='';toast('Host registered: '+d.fingerprint);loadSshHosts(id)}catch(e){toast(e.message,true)}}
async function deleteSshHost(hid,ca){if(!confirm('Remove this host registration? Certificates already issued keep working until they expire.'))return;
  try{await api('DELETE',`/api/ssh/cas/${ca}/hosts/${hid}`);toast('Host removed');loadSshHosts(ca)}catch(e){toast(e.message,true)}}
async function saveSshGrants(id){let box=$('ssh-grants');if(!box)return;try{
  let grants=box.value.split('\n').map(l=>l.trim()).filter(Boolean).map(l=>{
    let i=l.indexOf(':'); let role=(i<0?l:l.slice(0,i)).trim(); let rest=i<0?'':l.slice(i+1);
    let minutes=null; rest=rest.replace(/\((\d+)\s*m\)\s*$/i,(m,n)=>{minutes=n;return ''});
    let patterns=rest.split(',').map(p=>p.trim()).filter(Boolean);
    return {role:role,principals:patterns,max_ttl:minutes?parseInt(minutes)*60:undefined};
  }).filter(g=>g.role&&g.principals.length);
  if(!grants.length)return toast('Format each line as role: pattern, pattern',true);
  await api('PUT',`/api/ssh/cas/${id}/grants`,{grants:grants});toast('Grants saved');openSshCA(id)}catch(e){toast(e.message,true)}}
async function loadSshCerts(id){let host=$('ssh-certs');if(!host)return;try{let d=await api('GET',`/api/ssh/cas/${id}/certs`);
  host.innerHTML=`<h4 style="margin:16px 0 6px">Issued certificates</h4><table><thead><tr><th>Type</th><th>Principal</th><th>Key id</th><th>Expires</th><th>State</th><th></th></tr></thead><tbody>`+
    (d.map(c=>`<tr><td class="mut small">${esc(c.cert_type||'user')}</td><td class="mono">${esc(c.principal)}</td><td class="mut small">${esc(c.key_id)}</td><td class="mut small">${new Date((c.valid_before||0)*1000).toLocaleString()}</td><td>${c.revoked?'<span style="color:var(--bad)">revoked</span>':'active'}</td><td>${c.revoked?'':`<button class="danger" onclick="revokeSshCert('${jsq(c.id)}','${jsq(id)}')">Revoke</button>`}</td></tr>`).join('')||'<tr><td colspan="6" class="mut">No certificates issued yet</td></tr>')+'</tbody></table>'}catch(e){host.textContent=e.message}}
async function revokeSshCert(cid,ca){if(!confirm('Revoke this certificate? A host only enforces it once its RevokedKeys file is refreshed.'))return;
  try{await api('POST',`/api/ssh/certs/${cid}/revoke`,{});toast('Revoked');openSshCA(ca)}catch(e){toast(e.message,true)}}
async function loadTokensSettings(){$('sess-out').textContent='Use openwarp login / MCP OAuth clients for programmatic access. Service tokens live under Members & access.'}
async function transferInstance(){let email=$('set-instance-owner').value.trim();if(!email){toast('Enter the new owner email',true);return}if(!confirm(`Transfer instance control to ${email}? You will lose instance owner controls.`))return;try{await api('PUT','/api/instance/owner',{email});toast('Instance ownership transferred');renderSettings()}catch(e){toast(e.message,true)}}
async function deleteWorkspace(name){try{
  if($('del-org-name').value!==name){toast('Type the workspace name exactly to confirm',true);return}
  if(!confirm(`Delete ${name} and everything in it? This cannot be undone.`))return;
  let r=await apiRaw('DELETE',`/api/orgs/${ORG}?confirm=true`);
  if(r.ok){toast('Workspace deleted');location.reload();return}
  toast(r.body.error||'Could not delete workspace',true)
}catch(e){toast(e.message,true)}}
async function deleteAccount(){try{
  if(!confirm('Delete your account? This revokes every key, ends all sessions and cannot be undone.'))return;
  let r=await apiRaw('DELETE','/api/me');
  if(r.ok){T='';location.reload();return}
  if(r.body.workspaces&&r.body.workspaces.length){
    modal(`<h3>Transfer ownership first</h3><p>You own these workspaces. Another member must become the owner before this account can be deleted, or you can delete the workspace from Settings.</p><ul>${r.body.workspaces.map(w=>`<li class="mono">${esc(w.name)}</li>`).join('')}</ul><div class="row" style="margin-top:12px"><button class="primary" onclick="closeModal();nav('access')">Open Members &amp; access</button><button class="ghost" onclick="closeModal()">Close</button></div>`,'Transfer ownership first');
    return}
  if((r.body.error||'').includes('instance ownership')){
    modal(`<h3>Transfer instance ownership first</h3><p>${esc(r.body.error)}</p><p class="small mut">Use Transfer instance above before deleting this account.</p><div class="row" style="margin-top:12px"><button class="primary" onclick="closeModal()">Close</button></div>`,'Transfer instance ownership first');
    return}
  if(r.body.confirmation_required){
    let what=[r.body.api_keys?r.body.api_keys+' API key'+(r.body.api_keys===1?'':'s'):'',r.body.oauth_sessions?r.body.oauth_sessions+' CLI/OAuth session'+(r.body.oauth_sessions===1?'':'s'):''].filter(Boolean).join(' and ');
    if(!confirm(`This account still has ${what}. Deleting it revokes them immediately, and anything using them stops working. Delete anyway?`))return;
    let r2=await apiRaw('DELETE','/api/me?confirm=true');
    if(r2.ok){T='';location.reload();return}
    toast(r2.body.error||'Could not delete account',true);return}
  toast(r.body.error||'Could not delete account',true)
}catch(e){toast(e.message,true)}}

let AI_SETTINGS=null, AI_CONTEXT={envs:[],integrations:[]}, AI_PLAN=null, AI_REFS=[], AI_OPS=[], AI_DRAFTS=[], AI_FINDINGS=[], AI_EPOCH=0;
function aiReset(){AI_EPOCH++;AI_SETTINGS=null;AI_CONTEXT={envs:[],integrations:[]};AI_PLAN=null;AI_REFS=[];AI_OPS=[];AI_DRAFTS=[];AI_FINDINGS=[]}
function aiUrl(org,suffix){return `/api/orgs/${encodeURIComponent(org)}/ai/${suffix}`}
function aiCurrent(org,epoch,view){return ORG===org&&AI_EPOCH===epoch&&VIEW===view}
function aiEnvOptions(empty=true){return (empty?'<option value="">All permitted managed environments</option>':'')+(AI_CONTEXT.envs||[]).map(e=>`<option value="${esc(e.id)}">${esc(e.app_name)} / ${esc(e.name)}</option>`).join('')}
function aiError(id,e){let el=$(id);if(el){el.textContent=e.message||String(e);el.setAttribute('role','alert')}}
async function renderAssistant(){let org=ORG,epoch=++AI_EPOCH;AI_PLAN=null;AI_REFS=[];AI_OPS=[];
  $('pagetitle').textContent='Assistant';$('crumb').textContent='';$('view').innerHTML='<p class="mut" role="status">Loading workspace AI policy...</p>';
  if(!org){$('view').innerHTML='<p class="mut">Select a workspace first.</p>';return}
  try{let s=await api('GET',aiUrl(org,'settings'));if(!aiCurrent(org,epoch,'assistant'))return;AI_SETTINGS=s;
    if(s.enabled){AI_CONTEXT=await api('GET',aiUrl(org,'context'));if(!aiCurrent(org,epoch,'assistant'))return}else AI_CONTEXT={envs:[],integrations:[]};
    $('view').innerHTML=`<div class="row" style="justify-content:space-between;flex-wrap:wrap;margin-bottom:16px"><div><h3 style="margin:0">Find records and prepare changes</h3><span class="small mut">Workspace-scoped. Stored values never enter model context.</span></div>${s.can_admin?'<button onclick="aiSettingsModal()">Assistant settings</button>':''}</div>
    ${!s.enabled?'<div class="card"><h3>Assistant is off</h3><p>A workspace administrator must enable it. Local security findings remain available in Security insights.</p></div>':`
    <div class="card"><h3>Search inside OpenWarp</h3><p>Metadata search stays on this instance. Local value matching returns references, excludes sealed secrets, and requires one environment.</p>
      <div class="field"><label for="ai-scope">Environment scope</label><select id="ai-scope" style="max-width:100%">${aiEnvOptions()}</select></div>
      <div class="field"><label for="ai-search">Name, path, or local value fragment</label><input id="ai-search" maxlength="256" onkeydown="if(event.key==='Enter')aiSearch(false)"></div>
      <div class="row" style="flex-wrap:wrap"><button id="ai-search-btn" onclick="aiSearch(false)">Search metadata</button><button id="ai-local-btn" onclick="aiSearch(true)" ${s.allow_local_search?'':'disabled'}>Match values locally</button></div><div id="ai-search-results" aria-live="polite" style="margin-top:12px"></div></div>
    <div class="card"><h3>Ask the workspace assistant</h3><p id="ai-disclosure">Your question and authorised managed-environment metadata go to <span class="mono">${esc(s.endpoint||'the configured endpoint')}</span>. Do not type passwords, keys, or connection strings here. Replies can be wrong; check the sources.</p>
      <div class="row" style="flex-wrap:wrap;align-items:flex-start"><div class="field"><label for="ai-task">Task</label><select id="ai-task" onchange="aiTaskChanged()"><option value="search">Find a secret</option><option value="troubleshoot">Troubleshoot integration</option><option value="drift">Compare environment metadata</option>${s.can_admin?'<option value="incident">Investigate activity</option><option value="access">Review access</option>':''}<option value="rotation">Plan a rotation</option><option value="import">Organise an import</option></select></div><div class="field" id="ai-compare-wrap" hidden><label for="ai-compare">Compare with environment</label><select id="ai-compare">${aiEnvOptions(false)}</select></div></div>
      <div class="field"><label for="ai-question">Question (sent to the model)</label><textarea id="ai-question" rows="3" maxlength="4000" aria-describedby="ai-disclosure" placeholder="Where is the staging database credential?"></textarea></div>
      <div class="field" id="ai-import-wrap" hidden><label for="ai-import">Import input (parsed locally, values excluded from model context)</label><textarea id="ai-import" rows="5" maxlength="32768" autocomplete="off" spellcheck="false"></textarea></div>
      <button class="primary" id="ai-ask" onclick="aiAsk()" ${s.allow_metadata&&s.inference_available!==false?'':'disabled'}>Send question and metadata</button>${s.inference_available===false?'<p class="small mut" style="margin-top:8px">Model inference is unavailable in this runtime. Local search and confirmed plans remain available.</p>':s.allow_metadata?'':'<p class="small mut" style="margin-top:8px">Metadata disclosure is disabled. Local metadata search is still available.</p>'}<div id="ai-answer" aria-live="polite" style="margin-top:16px"></div></div>
    <div class="card"><h3>Prepare setup</h3><p>Preview folders or integration drafts. Nothing contacts a provider. Every plan needs a separate confirmation.</p><div class="row" style="flex-wrap:wrap"><button onclick="aiSetupModal('create_folder')" ${s.allow_actions?'':'disabled'}>Prepare folder</button><button onclick="aiSetupModal('draft_integration')" ${s.allow_actions?'':'disabled'}>Prepare integration draft</button></div><div id="ai-plan" aria-live="polite" style="margin-top:14px"></div></div>
    <div class="card"><h3>Integration drafts</h3><p>Drafts have no credentials and cannot sync. Complete one through the normal integration form.</p><div id="ai-drafts" aria-live="polite">Loading drafts...</div></div>`}`;
    if(s.enabled){if(ENV&&AI_CONTEXT.envs.some(e=>e.id===ENV.id))$('ai-scope').value=ENV.id;await aiLoadDrafts(org,epoch)}
  }catch(e){if(aiCurrent(org,epoch,'assistant'))aiError('view',e)}}
function aiTaskChanged(){let task=$('ai-task').value;$('ai-import-wrap').hidden=task!=='import';$('ai-compare-wrap').hidden=task!=='drift'}
function aiRefMarkup(refs){let base=AI_REFS.length;AI_REFS.push(...refs);return refs.length?refs.map((r,i)=>`<div class="row" style="justify-content:space-between;gap:8px;flex-wrap:wrap;padding:8px 0;border-bottom:1px solid var(--line)"><span style="min-width:0;overflow-wrap:anywhere"><span class="mono">${esc(r.key||r.title||r.name||r.id)}</span><br><span class="small mut">${esc(r.app_name||r.app||'')} / ${esc(r.env_name||r.env||'')} ${esc(r.path||'')}</span></span><button onclick="aiOpenRef(${base+i})">${r.env_id&&r.app_id?'Open record':'View evidence'}</button></div>`).join(''):'<p class="mut">No matching records in the permitted scope.</p>'}
async function aiSearch(local){let org=ORG,epoch=AI_EPOCH,query=$('ai-search').value.trim(),eid=$('ai-scope').value;if(!query)return;
  if(local&&!eid){aiError('ai-search-results',new Error('Choose one environment before matching values.'));return}
  let btn=$(local?'ai-local-btn':'ai-search-btn');btn.disabled=true;$('ai-search-results').textContent=local?'Matching values on this instance...':'Searching metadata...';
  try{let d=local?await api('POST',aiUrl(org,'local-search'),{env_id:eid,query}):await api('GET',aiUrl(org,'search?q='+encodeURIComponent(query)+(eid?'&env_id='+encodeURIComponent(eid):'')));
    if(!aiCurrent(org,epoch,'assistant'))return;$('ai-search-results').innerHTML=aiRefMarkup(d.results||[])+(d.truncated?'<p class="small mut">Results truncated. Narrow the scope or query.</p>':'');
  }catch(e){if(aiCurrent(org,epoch,'assistant'))aiError('ai-search-results',e)}finally{if(aiCurrent(org,epoch,'assistant'))btn.disabled=false}}
async function aiAsk(){let org=ORG,epoch=AI_EPOCH,task=$('ai-task').value,body={message:$('ai-question').value.trim(),task};if(!body.message)return;
  let eid=$('ai-scope').value;if(eid)body.env_id=eid;if(task==='drift')body.compare_env_id=$('ai-compare').value;if(task==='import')body.import_text=$('ai-import').value;
  $('ai-ask').disabled=true;$('ai-answer').textContent='Waiting for the configured model...';AI_OPS=[];
  try{let d=await api('POST',aiUrl(org,'chat'),body);if(!aiCurrent(org,epoch,'assistant'))return;
    AI_OPS=(d.suggested_operations||[]).filter(o=>['create_folder','draft_integration'].includes(o.kind));
    $('ai-answer').innerHTML=`<pre class="ai-prose">${esc(d.answer||'The model returned no answer.')}</pre>${d.context_truncated?'<p class="small mut">The context was truncated. This answer does not cover every record.</p>':''}<h4>Sources</h4>${aiRefMarkup(d.citations||[])}${AI_OPS.length?`<h4>Suggested operations</h4><pre class="ai-prose mono">${esc(JSON.stringify(AI_OPS,null,2))}</pre><button onclick="aiPreviewSuggestions()" ${AI_SETTINGS.allow_actions?'':'disabled'}>Preview suggested changes</button>`:''}`;
    if(task==='import')$('ai-import').value='';
  }catch(e){if(aiCurrent(org,epoch,'assistant'))aiError('ai-answer',e)}finally{if(aiCurrent(org,epoch,'assistant'))$('ai-ask').disabled=false}}
async function aiOpenRef(index){let r=AI_REFS[index];if(!r)return;if(!r.env_id||!r.app_id){await nav('audit');return}let org=ORG,epoch=AI_EPOCH;
  try{let apps=await api('GET',`/api/orgs/${org}/apps`);if(org!==ORG||epoch!==AI_EPOCH)return;let app=apps.find(a=>a.id===r.app_id);if(!app)throw new Error('This source is no longer available.');let envs=await api('GET',`/api/apps/${app.id}/envs`);if(org!==ORG||epoch!==AI_EPOCH)return;let env=envs.find(e=>e.id===r.env_id);if(!env)throw new Error('This environment is no longer available.');APPS=apps;APP=app;ENVS=envs;ENV=env;AI_PLAN=null;await renderEnv();if($('sfilter')&&r.key){$('sfilter').value=r.key;drawSecrets()}
  }catch(e){toast(e.message,true)}}
function aiSetupModal(kind){if(!AI_SETTINGS?.allow_actions)return;let integration=kind==='draft_integration';
  modal(`<h3>${integration?'Prepare integration draft':'Prepare folder'}</h3><p class="mut">The next step shows an immutable preview. It does not execute changes.</p><div class="field"><label for="ai-op-env">Environment</label><select id="ai-op-env" style="max-width:100%">${aiEnvOptions(false)}</select></div>${integration?`<div class="field"><label for="ai-op-kind">Provider</label><select id="ai-op-kind">${(AI_CONTEXT.integration_kinds||KINDS).map(k=>`<option value="${esc(k)}">${esc(k)}</option>`).join('')}</select></div><div class="field"><label for="ai-op-name">Draft name</label><input id="ai-op-name" maxlength="128"></div>`:'<div class="field"><label for="ai-op-path">Folder path</label><input id="ai-op-path" placeholder="/payments" maxlength="256"></div>'}<div id="ai-op-error" role="alert"></div><div class="row" style="margin-top:12px"><button class="primary" onclick="aiPreviewSetup('${kind}')">Preview changes</button><button onclick="closeModal()">Cancel</button></div>`,'Prepare setup');if(ENV&&AI_CONTEXT.envs.some(e=>e.id===ENV.id))$('ai-op-env').value=ENV.id}
async function aiPreviewSetup(kind){let op={kind,env_id:$('ai-op-env').value};if(kind==='create_folder')op.path=$('ai-op-path').value.trim();else{op.provider_kind=$('ai-op-kind').value;op.name=$('ai-op-name').value.trim()||op.provider_kind}await aiCreatePlan([op],true)}
async function aiPreviewSuggestions(){await aiCreatePlan(AI_OPS,false)}
async function aiCreatePlan(operations,fromModal){let org=ORG,epoch=AI_EPOCH;try{let p=await api('POST',aiUrl(org,'plans'),{operations});if(!aiCurrent(org,epoch,'assistant'))return;AI_PLAN={...p,org,epoch};if(fromModal)closeModal();$('ai-plan').innerHTML=`<h4>Review exact changes</h4><pre class="ai-prose mono">${esc(JSON.stringify(p.operations,null,2))}</pre><p class="small mut">Expires ${esc(new Date(p.expires_at*1000).toLocaleString())}. No provider test or sync is included.</p><div class="row" style="flex-wrap:wrap"><button class="primary" id="ai-confirm" onclick="aiExecutePlan()">Confirm these changes</button><button onclick="aiCancelPlan()">Discard preview</button></div>`;$('ai-confirm').focus()}catch(e){if(aiCurrent(org,epoch,'assistant'))aiError(fromModal?'ai-op-error':'ai-plan',e)}}
function aiCancelPlan(){AI_PLAN=null;if($('ai-plan'))$('ai-plan').textContent='Preview discarded. No changes executed.'}
async function aiExecutePlan(){let p=AI_PLAN;if(!p||!aiCurrent(p.org,p.epoch,'assistant'))return;AI_PLAN=null;$('ai-confirm').disabled=true;
  try{let d=await api('POST',aiUrl(p.org,`plans/${encodeURIComponent(p.id)}/execute`),{confirm:true});if(!aiCurrent(p.org,p.epoch,'assistant'))return;$('ai-plan').innerHTML=`<h4>Execution results</h4><pre class="ai-prose mono">${esc(JSON.stringify(d,null,2))}</pre><p class="small mut">A completed local step does not mean a provider was contacted. Check each result before preparing another plan.</p>`;await aiLoadDrafts(p.org,p.epoch)}catch(e){if(aiCurrent(p.org,p.epoch,'assistant'))aiError('ai-plan',new Error(e.message+' Create a new preview before retrying.'))}}
async function aiLoadDrafts(org=ORG,epoch=AI_EPOCH){try{let d=await api('GET',aiUrl(org,'drafts'));if(!aiCurrent(org,epoch,'assistant'))return;AI_DRAFTS=d.drafts||[];$('ai-drafts').innerHTML=AI_DRAFTS.length?AI_DRAFTS.map((r,i)=>`<div class="row" style="justify-content:space-between;flex-wrap:wrap;padding:10px 0;border-bottom:1px solid var(--line)"><span style="overflow-wrap:anywhere">${esc(r.name)} <span class="chip">${esc(r.provider_kind)}</span></span><span><button onclick="aiCompleteDraft(${i})">Configure integration</button> <button onclick="aiRemoveDraft(${i})">Remove draft</button></span></div>`).join(''):'<p class="mut">No integration drafts.</p>'}catch(e){if(aiCurrent(org,epoch,'assistant'))aiError('ai-drafts',e)}}
function aiCompleteDraft(index){let d=AI_DRAFTS[index];if(!d)return;modal(`<h3>Configure ${esc(d.name)}</h3><p class="mut">${esc(KIND_HINTS[d.provider_kind]||('Configuration for '+d.provider_kind+' as JSON.'))}</p><p class="small mut">These credentials go to OpenWarp storage, not the model. Adding the integration does not test or sync it, but future normal deployments can sync configured integrations.</p><div class="field"><label for="ai-draft-config">Provider configuration</label><textarea id="ai-draft-config" rows="6" spellcheck="false" autocomplete="off"></textarea></div><div id="ai-draft-error" role="alert"></div><div class="row"><button class="primary" id="ai-draft-save" onclick="aiActivateDraft(${index})">Add configured integration</button><button onclick="closeModal()">Cancel</button></div>`,'Configure integration')}
async function aiActivateDraft(index){let d=AI_DRAFTS[index],org=ORG,epoch=AI_EPOCH;if(!d)return;let config;try{config=JSON.parse($('ai-draft-config').value||'{}')}catch(e){aiError('ai-draft-error',new Error('Enter valid JSON configuration.'));return}$('ai-draft-save').disabled=true;
  try{await api('POST',`/api/envs/${encodeURIComponent(d.env_id)}/integrations`,{kind:d.provider_kind,name:d.name,config});if(!aiCurrent(org,epoch,'assistant'))return;closeModal();try{await api('DELETE',aiUrl(org,'drafts/'+encodeURIComponent(d.id)))}catch(e){toast('Integration added, but draft cleanup failed. Remove the draft manually; do not add it again.',true)}await aiLoadDrafts(org,epoch);toast('Integration added. Test or sync it separately in Integrations.')}catch(e){if(aiCurrent(org,epoch,'assistant')){aiError('ai-draft-error',e);if($('ai-draft-save'))$('ai-draft-save').disabled=false}}}
async function aiRemoveDraft(index){let d=AI_DRAFTS[index],org=ORG,epoch=AI_EPOCH;if(!d||!confirm('Remove this unconfigured integration draft?'))return;try{await api('DELETE',aiUrl(org,'drafts/'+encodeURIComponent(d.id)));await aiLoadDrafts(org,epoch)}catch(e){if(aiCurrent(org,epoch,'assistant'))aiError('ai-drafts',e)}}
function aiSettingsModal(){let s=AI_SETTINGS;if(!s?.can_admin)return;let endpoints=s.allowed_endpoints||[];let toggles=[['enabled','Enable workspace assistant'],['allow_metadata','Allow questions and authorised metadata to reach the model'],['allow_actions','Allow separately confirmed folder and integration-draft plans'],['allow_local_search','Allow local non-sealed value matching (no model request)'],['monitoring_enabled','Enable background deterministic monitoring']];
  modal(`<h3>Assistant settings</h3><p class="mut">BYOK does not mean local processing. Only choose an endpoint whose data policy you accept. Stored values and provider configuration are excluded from model context.</p>${toggles.map(([k,label])=>`<label class="row" style="gap:8px;margin:10px 0;align-items:flex-start"><input id="ai-set-${k}" type="checkbox" ${s[k]?'checked':''}> ${esc(label)}</label>`).join('')}<div class="field"><label for="ai-set-endpoint">Operator-approved completion endpoint</label><select id="ai-set-endpoint" style="width:100%"><option value="">No endpoint</option>${endpoints.map(u=>`<option value="${esc(u)}" ${u===s.endpoint?'selected':''}>${esc(u)}</option>`).join('')}</select></div>${endpoints.length?'':'<p class="small mut">The operator has not configured OPENWARP_AI_ENDPOINTS. Local features can still work.</p>'}<div class="field"><label for="ai-set-model">Model identifier</label><input id="ai-set-model" value="${esc(s.model||'')}" maxlength="128"></div><div class="field"><label for="ai-set-key">Replacement provider key</label><input id="ai-set-key" type="password" autocomplete="new-password" placeholder="${s.has_api_key?'Saved key exists. Blank keeps it.':'Optional for a local endpoint'}"></div><label class="row" style="gap:8px;margin-bottom:12px"><input id="ai-set-clear" type="checkbox"> Clear saved provider key</label><div class="field"><label for="ai-set-requests">Daily request limit</label><input id="ai-set-requests" type="number" min="1" value="${esc(s.request_limit||100)}"></div><div class="field"><label for="ai-set-tokens">Daily reservation-unit limit (not provider billing)</label><input id="ai-set-tokens" type="number" min="1" value="${esc(s.token_limit||100000)}"></div><div class="field"><label for="ai-set-output">Maximum output tokens per request</label><input id="ai-set-output" type="number" min="1" value="${esc(s.max_output_tokens||1024)}"></div><div id="ai-settings-error" role="alert"></div><div class="row"><button class="primary" id="ai-settings-save" onclick="aiSaveSettings()">Save AI policy</button><button onclick="closeModal()">Cancel</button></div>`,'Assistant settings')}
async function aiSaveSettings(){let org=ORG,epoch=AI_EPOCH,view=VIEW,body={};for(let k of ['enabled','allow_metadata','allow_actions','allow_local_search','monitoring_enabled'])body[k]=$('ai-set-'+k).checked;body.endpoint=$('ai-set-endpoint').value;body.model=$('ai-set-model').value.trim();body.clear_api_key=$('ai-set-clear').checked;if($('ai-set-key').value)body.api_key=$('ai-set-key').value;for(let [field,id] of [['request_limit','requests'],['token_limit','tokens'],['max_output_tokens','output']])body[field]=Number($('ai-set-'+id).value);$('ai-settings-save').disabled=true;
  try{await api('PUT',aiUrl(org,'settings'),body);if(!aiCurrent(org,epoch,view))return;closeModal();toast('AI policy saved');if(VIEW==='insights')await renderInsights();else await renderAssistant()}catch(e){if(org===ORG&&epoch===AI_EPOCH){aiError('ai-settings-error',e);if($('ai-settings-save'))$('ai-settings-save').disabled=false}}}
async function renderInsights(){let org=ORG,epoch=++AI_EPOCH;AI_PLAN=null;$('pagetitle').textContent='Security insights';$('crumb').textContent='';$('view').innerHTML='<p class="mut" role="status">Checking available activity evidence...</p>';if(!org)return;
  try{let d=await api('GET',aiUrl(org,'findings'));if(!aiCurrent(org,epoch,'insights'))return;AI_FINDINGS=d.findings||[];AI_SETTINGS=await api('GET',aiUrl(org,'settings'));if(!aiCurrent(org,epoch,'insights'))return;
    $('view').innerHTML=`<div class="row" style="justify-content:space-between;flex-wrap:wrap;margin-bottom:16px"><div><h3 style="margin:0">Evidence-backed findings</h3><span class="small mut">Rules run without a model. No automatic revocation or remote actions.</span></div><div class="row"><button onclick="renderInsights()">Refresh findings</button><button onclick="aiSettingsModal()">AI and monitoring settings</button></div></div><div class="card"><h3>Coverage and history</h3><p>Missing history is not evidence of safe activity. New baselines can be insufficient, and earlier audit events may be incomplete.</p><pre class="ai-prose mono">${esc(JSON.stringify(d.coverage||{},null,2))}</pre></div><div id="ai-findings-list">${AI_FINDINGS.length?AI_FINDINGS.map((f,i)=>`<section class="card"><div class="row" style="flex-wrap:wrap"><span class="chip">${esc(f.severity)}</span><span class="chip">${esc(f.status||'open')}</span><h3 style="margin:0">${esc(f.title)}</h3></div><p style="margin-top:12px;white-space:pre-wrap">${esc(f.rationale)}</p><p class="small mono">Rule: ${esc(f.rule)}</p>${f.exception_until?`<p class="small mut">Exception expires ${esc(new Date(f.exception_until*1000).toLocaleString())}</p>`:''}${f.maintenance_note?`<p class="small">${esc(f.maintenance_note)}</p>`:''}<details><summary>Evidence (${(f.evidence||[]).length})</summary>${(f.evidence||[]).map(e=>`<div class="small mono" style="overflow-wrap:anywhere;padding:7px 0">${esc(new Date(e.created_at*1000).toLocaleString())} ${esc(e.action)}<br>Event ${esc(e.id)} ${esc(e.env_id||'')}</div>`).join('')}</details><div class="row" style="margin-top:12px;flex-wrap:wrap"><button onclick="aiFindingState(${i},'acknowledged')">Acknowledge</button><button onclick="aiExceptionModal(${i})">Set expiring exception</button><button onclick="aiFindingState(${i},'open')">Reopen</button><button onclick="aiExplainFinding(${i})" ${AI_SETTINGS.enabled&&AI_SETTINGS.allow_metadata&&AI_SETTINGS.inference_available!==false?'':'disabled'}>Ask AI to explain</button></div><div id="ai-finding-${i}" aria-live="polite" style="margin-top:12px"></div></section>`).join(''):'<div class="card"><h3>No findings in the available window</h3><p>This does not establish complete monitoring coverage. Review the history limits above.</p></div>'}</div>`;
  }catch(e){if(aiCurrent(org,epoch,'insights'))aiError('view',e)}}
async function aiFindingState(index,status,extra={}){let f=AI_FINDINGS[index],org=ORG,epoch=AI_EPOCH;if(!f)return;try{await api('PUT',aiUrl(org,'findings/'+encodeURIComponent(f.id)),{status,...extra});if(!aiCurrent(org,epoch,'insights'))return;closeModal();await renderInsights()}catch(e){if(aiCurrent(org,epoch,'insights')){if($('ai-exception-error'))aiError('ai-exception-error',e);else aiError('ai-finding-'+index,e)}}}
function aiExceptionModal(index){if(!AI_FINDINGS[index])return;modal(`<h3>Expiring finding exception</h3><p class="mut">This applies to one finding. The maintenance note stays out of model context.</p><div class="field"><label for="ai-exception-hours">Duration in hours</label><input id="ai-exception-hours" type="number" min="1" max="168" value="1"></div><div class="field"><label for="ai-exception-note">Maintenance or investigation note</label><textarea id="ai-exception-note" rows="3" maxlength="500"></textarea></div><div id="ai-exception-error" role="alert"></div><div class="row"><button class="primary" onclick="aiSaveException(${index})">Save exception</button><button onclick="closeModal()">Cancel</button></div>`,'Finding exception')}
async function aiSaveException(index){let hours=Number($('ai-exception-hours').value);if(!Number.isFinite(hours)||hours<1||hours>168){aiError('ai-exception-error',new Error('Choose a duration between 1 and 168 hours.'));return}await aiFindingState(index,'exception',{exception_until:Math.floor(Date.now()/1000+hours*3600),maintenance_note:$('ai-exception-note').value})}
async function aiExplainFinding(index){let f=AI_FINDINGS[index],org=ORG,epoch=AI_EPOCH;if(!f)return;$('ai-finding-'+index).textContent='Sending selected finding evidence to the configured model...';try{let d=await api('POST',aiUrl(org,'chat'),{task:'explain',finding_id:f.id,message:'Explain this finding and suggest investigation steps. Separate evidence from hypotheses.'});if(aiCurrent(org,epoch,'insights'))$('ai-finding-'+index).innerHTML=`<pre class="ai-prose">${esc(d.answer||'No explanation returned.')}</pre>`}catch(e){if(aiCurrent(org,epoch,'insights'))aiError('ai-finding-'+index,e)}}

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
    history.replaceState(null,'',location.pathname);
    $('auth').style.display='grid';$('shell').style.display='none';
    $('authtitle').textContent='Two-step verification';$('mfafield').style.display='block';
    $('authbtn').textContent='Verify code';$('authbtn').onclick=doMfa;}
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
