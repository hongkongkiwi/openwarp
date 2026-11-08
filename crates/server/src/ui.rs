pub const INDEX: &str = r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenWarp Console</title><link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>◆</text></svg>">
<script>(function(){try{
// Resolve the theme before first paint: stored preference, else the system scheme.
var pref;try{pref=localStorage.getItem('ow_theme')}catch(e){}
if(pref!=='light'&&pref!=='dark'&&pref!=='system')pref='system';
var de=document.documentElement;if(!de)return;
de.dataset.themePref=pref;
var mq=window.matchMedia?window.matchMedia('(prefers-color-scheme: dark)'):null;
var apply=function(){var p=de.dataset.themePref;de.dataset.theme=p==='system'?((mq&&mq.matches)?'dark':'light'):p};
apply();
if(mq&&mq.addEventListener)mq.addEventListener('change',apply);
}catch(e){}})();
</script>
<style>
:root{color-scheme:light;--bg:#f4f5f9;--bg2:#ebecf3;--panel:#ffffff;--panel2:#f0f0f7;--line:#dcdee9;--line2:#c7cadd;--text:#1d1c2e;--muted:#5f5d78;--faint:#696684;--acc:#6a5bff;--acc2:#5243e0;--on-acc:#ffffff;--ok:#149668;--warn:#b7791f;--bad:#d8426c;--hover:#e4e3f2;--ring:rgba(106,91,255,.18);--mark2:#4f46e5;--sel:rgba(106,91,255,.12);--row:rgba(106,91,255,.05);--glow:rgba(106,91,255,.10);--topbar:rgba(244,245,249,.85);--deploy:#ffffff;--backdrop:rgba(23,23,46,.38);--toast-bg:#e7f6ef;--toast-bd:#b7e4d0;--toast-tx:#0c5e42;--toast-ebg:#fdeff2;--toast-ebd:#f2c3cf;--toast-etx:#8e2044;--sh-auth:0 24px 60px rgba(30,30,70,.16);--sh-deploy:0 18px 50px rgba(30,30,70,.18);--sh-palette:0 30px 80px rgba(30,30,70,.22);--sh-sm:0 1px 4px rgba(30,30,70,.18);--sh-side:0 0 60px rgba(30,30,70,.25);--sh-toast:0 10px 30px rgba(30,30,70,.15);--mono:ui-monospace,'SF Mono',SFMono-Regular,Menlo,monospace;--sans:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI',Roboto,sans-serif;--r:10px}
:root[data-theme=dark]{color-scheme:dark;--bg:#08080c;--bg2:#0e0e14;--panel:#12121b;--panel2:#171724;--line:#23233a;--line2:#2e2e4a;--text:#eceaf8;--muted:#a4a1bf;--faint:#8a87a6;--acc:#7c6cff;--acc2:#9d8fff;--on-acc:#0b0918;--ok:#34d399;--warn:#fbbf24;--bad:#fb7185;--hover:#1d1d2f;--ring:rgba(124,108,255,.18);--mark2:#4f46e5;--sel:rgba(124,108,255,.14);--row:rgba(124,108,255,.04);--glow:rgba(124,108,255,.16);--topbar:rgba(8,8,12,.85);--deploy:#1b1b2c;--backdrop:rgba(4,4,8,.7);--toast-bg:#1d2b22;--toast-bd:#245c3f;--toast-tx:#a7f3d0;--toast-ebg:#331d24;--toast-ebd:#5c2436;--toast-etx:#fecdd3;--sh-auth:0 24px 60px rgba(0,0,0,.5);--sh-deploy:0 18px 50px rgba(0,0,0,.55);--sh-palette:0 30px 80px rgba(0,0,0,.6);--sh-sm:0 1px 4px rgba(0,0,0,.4);--sh-side:0 0 60px rgba(0,0,0,.7);--sh-toast:0 10px 30px rgba(0,0,0,.5)}
*{box-sizing:border-box}html,body{height:100%}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 var(--sans);-webkit-font-smoothing:antialiased}
button{font:inherit;color:var(--text);background:var(--panel2);border:1px solid var(--line2);border-radius:8px;padding:7px 14px;cursor:pointer;transition:.15s}button:hover{border-color:var(--acc);background:var(--hover)}button.primary{background:var(--acc);border-color:var(--acc);color:var(--on-acc);font-weight:600}button.primary:hover{background:var(--acc2)}button.ghost{background:transparent;border-color:transparent;color:var(--muted)}button.ghost:hover{color:var(--text);background:var(--panel2)}button.danger:hover{border-color:var(--bad);color:var(--bad)}button:disabled{opacity:.45;cursor:default}
input,select,textarea{font:inherit;color:var(--text);background:var(--bg2);border:1px solid var(--line2);border-radius:8px;padding:8px 11px;outline:none}input:focus,select:focus,textarea:focus{border-color:var(--acc);box-shadow:0 0 0 3px var(--ring)}textarea{font-family:var(--mono);font-size:12.5px;width:100%}
a{color:var(--acc2)}code,.mono{font-family:var(--mono);font-size:12.5px}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;letter-spacing:-.02em}
.mark{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,var(--acc),var(--mark2));display:grid;place-items:center;color:#fff;font-size:15px;flex:none}
#auth{min-height:100vh;display:grid;place-items:center;background:radial-gradient(900px 500px at 50% -10%,var(--glow),transparent)}
.authcard{width:400px;max-width:92vw;background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:32px;box-shadow:var(--sh-auth);position:relative}
.authcard h1{font-size:22px;margin:14px 0 4px}.authcard p.sub{color:var(--muted);margin:0 0 20px}
.field{margin-bottom:12px}.field label{display:block;font-size:12px;color:var(--muted);margin-bottom:5px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}.field input{width:100%}
.seg{display:flex;background:var(--bg2);border:1px solid var(--line);border-radius:9px;padding:3px;margin-bottom:20px}.seg button{flex:1;background:transparent;border:0;color:var(--muted)}.seg button.on{background:var(--panel2);color:var(--text);box-shadow:var(--sh-sm)}
#shell{display:none;height:100vh;grid-template-columns:248px 1fr;grid-template-rows:100vh}
aside{background:var(--bg2);border-right:1px solid var(--line);display:flex;flex-direction:column;padding:16px 12px;gap:4px;overflow:auto}
#picker{min-height:100vh;display:none;place-items:center;background:radial-gradient(900px 500px at 50% -10%,var(--glow),transparent)}
.picklist{display:flex;flex-direction:column;gap:8px}
.pickrow{display:flex;align-items:center;gap:10px;width:100%;text-align:left;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:11px 12px;color:var(--text);font-weight:600}
.pickrow:hover{border-color:var(--line2)}.pickrow .pn{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.pickrow .pm{color:var(--muted);font-size:12.5px;font-weight:500;white-space:nowrap;flex:none}
.regionline{margin:14px 0 0;text-align:center}.regionline a{color:var(--muted)}
.orgbtn{display:flex;align-items:center;gap:8px;width:100%;text-align:left;background:var(--panel2);border:1px solid var(--line);border-radius:9px;padding:8px 10px;color:var(--text);font-weight:600;margin:14px 0 10px}
.orgbtn .grow{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.orgmenu{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:5px;box-shadow:var(--sh-side);display:flex;flex-direction:column;gap:1px;margin-bottom:10px}
.orgmenu[hidden]{display:none}
.orgitem{display:flex;align-items:center;gap:8px;width:100%;text-align:left;background:transparent;border:0;border-radius:7px;padding:7px 8px;color:var(--muted);font-size:13px;font-weight:500}
.orgitem:hover{background:var(--panel2);color:var(--text)}.orgitem .ck{width:14px;flex:none;color:var(--acc)}.orgitem .grow{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.orgitem .pm{color:var(--faint);font-size:12px}.orgsep{height:1px;background:var(--line);margin:4px 2px}
.navbtn{display:flex;align-items:center;gap:10px;width:100%;text-align:left;background:transparent;border:0;border-radius:8px;padding:8px 10px;color:var(--muted);font-weight:500}.navbtn:hover{background:var(--panel2);color:var(--text)}.navbtn.on{background:var(--sel);color:var(--text)}.navbtn .ic{width:18px;text-align:center;flex:none}
.sidefoot{margin-top:auto;border-top:1px solid var(--line);padding-top:12px;color:var(--muted);font-size:12.5px}
main{overflow:auto;display:flex;flex-direction:column}
.topbar{display:flex;align-items:center;gap:12px;padding:14px 28px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--topbar);backdrop-filter:blur(8px);z-index:5}
.topbar h2{font-size:17px;margin:0;letter-spacing:-.01em}.crumb{color:var(--faint)}.grow{flex:1}
.searchbox{display:flex;align-items:center;gap:8px;background:var(--bg2);border:1px solid var(--line2);border-radius:8px;padding:6px 11px;color:var(--faint);cursor:pointer;min-width:210px}.searchbox:hover{border-color:var(--acc)}kbd{font:11px var(--mono);background:var(--panel2);border:1px solid var(--line2);border-bottom-width:2px;border-radius:5px;padding:1px 5px;color:var(--muted)}
.content{padding:24px 28px 110px;max-width:1220px;width:100%;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
.appcard{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;cursor:pointer;transition:.15s}.appcard:hover{border-color:var(--acc);transform:translateY(-1px)}.appcard h3{margin:0 0 6px;font-size:15px}.appcard .meta{color:var(--muted);font-size:12.5px}
.chip{display:inline-block;font:11px var(--mono);background:var(--panel2);border:1px solid var(--line2);border-radius:99px;padding:2px 8px;margin:2px 3px 0 0;color:var(--muted)}
.envtabs{display:flex;gap:6px;flex-wrap:wrap;margin:4px 0 16px}.envtab{border-radius:99px;padding:6px 14px;font-weight:600;font-size:13px}.envtab.on{background:var(--acc);border-color:var(--acc);color:var(--on-acc)}
table{width:100%;border-collapse:separate;border-spacing:0;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--faint);text-align:left;padding:10px 14px;background:var(--bg2);border-bottom:1px solid var(--line)}
td{padding:9px 14px;border-bottom:1px solid var(--line);vertical-align:middle}tr:last-child td{border-bottom:0}tbody tr:hover{background:var(--row)}
.badge{font:10.5px var(--mono);border-radius:5px;padding:2px 6px;border:1px solid}.b-secret{color:var(--acc2);border-color:rgba(124,108,255,.4)}.b-sealed{color:var(--warn);border-color:rgba(251,191,36,.4)}.b-config{color:var(--ok);border-color:rgba(52,211,153,.4)}
.iconbtn{background:transparent;border:0;padding:7px 9px;min-width:30px;min-height:30px;border-radius:6px;color:var(--muted);font-size:14px}.iconbtn:hover{color:var(--text);background:var(--panel2)}
td input{width:100%;background:transparent;border:0;padding:2px;font-family:var(--mono);font-size:12.5px}td input:focus{box-shadow:none;border-bottom:1px dashed var(--acc);border-radius:0}
.stagedot{display:inline-block;width:7px;height:7px;border-radius:99px;background:var(--warn);margin-right:6px}
#deploybar{position:fixed;left:50%;transform:translateX(-50%);bottom:26px;background:var(--deploy);border:1px solid var(--line2);border-radius:12px;padding:12px 16px;display:none;gap:12px;align-items:center;box-shadow:var(--sh-deploy);z-index:40}#deploybar.show{display:flex}
.modalwrap{position:fixed;inset:0;background:var(--backdrop);display:none;place-items:center;z-index:60;backdrop-filter:blur(3px)}.modalwrap.show{display:grid}
.modal{width:560px;max-width:94vw;max-height:88vh;overflow:auto;background:var(--panel);border:1px solid var(--line2);border-radius:16px;padding:24px}.modal h3{margin:0 0 14px;font-size:16px}
#palette{position:fixed;inset:0;background:var(--backdrop);display:none;z-index:70;padding:12vh 16px 16px}.palettecard{max-width:620px;margin:0 auto;background:var(--panel);border:1px solid var(--line2);border-radius:14px;overflow:hidden;box-shadow:var(--sh-palette)}.palettecard input{width:100%;border:0;background:transparent;font-size:16px;padding:16px}.pitem{padding:10px 16px;cursor:pointer;display:flex;gap:10px;align-items:center}.pitem:hover,.pitem.sel{background:var(--sel)}
#toasts{position:fixed;right:18px;bottom:18px;z-index:90;display:flex;flex-direction:column;gap:8px}.toast{background:var(--toast-bg);border:1px solid var(--toast-bd);color:var(--toast-tx);border-radius:10px;padding:11px 15px;box-shadow:var(--sh-toast);max-width:380px}.toast.err{background:var(--toast-ebg);border-color:var(--toast-ebd);color:var(--toast-etx)}
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-bottom:18px;flex-wrap:wrap}.tabbtn{background:transparent;border:0;border-radius:8px 8px 0 0;color:var(--muted);padding:9px 13px;font-weight:600;font-size:13px}.tabbtn.on{color:var(--text);box-shadow:inset 0 -2px var(--acc)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px;margin-bottom:14px}.card h3{margin:0 0 6px;font-size:15px}.card p{color:var(--muted);margin:0 0 12px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.empty{padding:48px 20px;text-align:center;color:var(--faint);border:1px dashed var(--line2);border-radius:14px}.empty .big{font-size:22px;margin-bottom:6px}
.mut{color:var(--muted)}.small{font-size:12.5px}.val{font-family:var(--mono);font-size:12.5px;word-break:break-all}
#navtoggle{display:none}
.langsel{padding:6px 8px;font-size:12.5px;color:var(--muted);max-width:150px}.langsel option{color:var(--text);background:var(--panel)}.authprefs{position:absolute;top:18px;right:18px;display:flex;gap:6px;align-items:center}
@media(max-width:820px){#shell{grid-template-columns:1fr}#navtoggle{display:inline-block}aside{display:none;position:fixed;top:0;bottom:0;left:0;width:260px;z-index:80;box-shadow:var(--sh-side)}aside.open{display:flex}.content{padding:16px 14px 100px}.members-table,.members-table tbody{display:block;width:100%}.members-table thead{display:none}.members-table tr{display:flex;flex-wrap:wrap;padding:10px 0;border-bottom:1px solid var(--line)}.members-table td{display:block;border:0;padding:6px 0;min-width:0}.members-table td:first-child{width:100%;overflow-wrap:anywhere}.members-table td:last-child{display:flex;flex-wrap:wrap;gap:8px;width:100%}.members-table select{max-width:100%}}
</style></head>
<body>
<div id="auth">
  <div class="authcard">
    <div class="authprefs"><button class="iconbtn" data-themetoggle type="button" onclick="cycleTheme()" aria-label="Switch theme"></button><select class="langsel" data-langsel onchange="owSetLang(this.value)" aria-label="Language" data-i18n-aria-label="Language"></select></div>
    <div class="logo"><span class="mark">◆</span>OpenWarp</div>
    <h1 id="authtitle" data-i18n="Welcome back">Welcome back</h1><p class="sub" data-i18n="Secrets management with no tiers and no licence gates.">Secrets management with no tiers and no licence gates.</p>
    <div class="seg"><button id="seglogin" class="on" onclick="authMode('login')" data-i18n="Sign in">Sign in</button><button id="segreg" onclick="authMode('register')" data-i18n="Create account">Create account</button></div>
    <div id="authform">
      <div class="field"><label for="email" data-i18n="Email">Email</label><input id="email" type="email" autocomplete="email" placeholder="you@company.com"></div>
      <div class="field"><label for="pw" data-i18n="Password">Password</label><input id="pw" type="password" autocomplete="current-password" placeholder="••••••••••" onkeydown="if(event.key==='Enter')doAuth()"></div>
      <div class="field" id="mfafield" style="display:none"><label for="mfacode" data-i18n="Authenticator / recovery code">Authenticator / recovery code</label><input id="mfacode" placeholder="123456" onkeydown="if(event.key==='Enter')doMfa()"></div>
      <button class="primary" style="width:100%;padding:11px" id="authbtn" onclick="doAuth()" data-i18n="Sign in">Sign in</button>
      <button class="ghost" style="width:100%;margin-top:6px" onclick="forgotPrompt()" data-i18n="Forgot password?">Forgot password?</button>
      <button class="ghost" style="width:100%;margin-top:6px" onclick="workspaceSsoPrompt()" data-i18n="Sign in with SAML">Sign in with SAML</button>
      <div id="social" class="row" style="margin-top:12px;flex-wrap:wrap"></div>
      <p class="small mut" id="signupnote" style="margin:14px 0 0" data-i18n="Your organisation, apps and environments are unlimited. Save the recovery kit shown once at registration.">Your organisation, apps and environments are unlimited. Save the recovery kit shown once at registration.</p>
      <p class="small mut regionline" id="regionline"></p>
    </div>
  </div>
</div>

<div id="picker">
  <div class="authcard">
    <div class="logo"><span class="mark">◆</span>OpenWarp</div>
    <h1 data-i18n="Choose your workspace">Choose your workspace</h1>
    <p class="sub" data-i18n="You belong to more than one workspace. Pick the one to open; you can switch at any time.">You belong to more than one workspace. Pick the one to open; you can switch at any time.</p>
    <div id="pickerlist" class="picklist"></div>
    <p class="small mut" style="margin:14px 0 0" data-i18n="Missing a workspace? Ask an owner for an invitation.">Missing a workspace? Ask an owner for an invitation.</p>
  </div>
</div>

<div id="shell">
  <aside>
    <div class="logo"><span class="mark">◆</span>OpenWarp</div>
    <button class="orgbtn" id="orgbtn" aria-haspopup="menu" aria-expanded="false" onclick="toggleOrgMenu(event)"><span class="grow" id="orgname"></span><span aria-hidden="true">▾</span></button>
    <div class="orgmenu" id="orgmenu" role="menu" aria-label="Workspace menu" hidden onkeydown="orgMenuKey(event)"></div>
    <button class="navbtn" data-nav="apps" onclick="nav('apps')"><span class="ic">▦</span><span data-i18n="Apps">Apps</span></button>
    <button class="navbtn" data-nav="access" onclick="nav('access')"><span class="ic">♟</span><span data-i18n="Members &amp; access">Members &amp; access</span></button>
    <button class="navbtn" data-nav="integrations" onclick="nav('integrations')"><span class="ic">⇄</span><span data-i18n="Integrations">Integrations</span></button>
    <button class="navbtn" data-nav="audit" onclick="nav('audit')"><span class="ic">≡</span><span data-i18n="Audit log">Audit log</span></button>
    <button class="navbtn" data-nav="settings" onclick="nav('settings')"><span class="ic">⚙</span><span data-i18n="Settings">Settings</span></button>
  </aside>
  <main>
    <div class="topbar"><button class="iconbtn" id="navtoggle" aria-label="Open navigation" data-i18n-aria-label="Open navigation" onclick="toggleNav()">☰</button><h2 id="pagetitle" data-i18n="Apps">Apps</h2><span class="crumb" id="crumb"></span><div class="grow"></div>
      <button class="iconbtn" data-themetoggle type="button" onclick="cycleTheme()" aria-label="Switch theme"></button><select class="langsel" data-langsel onchange="owSetLang(this.value)" aria-label="Language" data-i18n-aria-label="Language"></select>
      <div class="searchbox" onclick="openPalette()"><span>⌕</span><span style="flex:1" data-i18n="Search secrets…">Search secrets…</span><kbd>⌘K</kbd></div>
      <button class="primary" id="topaction" onclick="newApp()" data-i18n="+ New app">+ New app</button>
    </div>
    <div class="content" id="emergency-banner" role="status" hidden></div>
    <div class="content" id="view"></div>
  </main>
</div>

<div id="deploybar"><span id="deploytext"></span><button class="ghost" onclick="discardStage()" data-i18n="Discard">Discard</button><button class="primary" onclick="deployStage()" data-i18n="Deploy changes">Deploy changes</button></div>

<div class="modalwrap" id="modalwrap"><div class="modal" id="modal"></div></div>
<div id="palette"><div class="palettecard"><input id="paletteinput" placeholder="Search secrets, apps, environments…" data-i18n-placeholder="Search secrets, apps, environments…" oninput="paletteSearch()"><div id="paletteresults"></div></div></div>
<div id="toasts"></div>
<script src="/i18n.js" integrity="sha384-6OSyUiXCr5GoTa4vLRlbjgKAOYEU3zHAndnRTqDofsfODI3ItN479UkKKtJQo2gL"></script>
<script>
let EMERGENCY=false, PROJECT_EMERGENCY=false, PROJECT_DIRECT=false, EMERGENCY_OWNER=false, EMERGENCY_POLL=null, AUTH_READY=false, SECRET_EPOCH=0, EMERGENCY_REQUEST=0;
let T='', ORG='', ORGS=[], REGIONS=[], APP=null, ENV=null, APPS=[], ENVS=[], SECRETS=[], DRAFTS={}, VIEW='apps', MFA=null, LASTFOCUS=null, PENDING_ORG=null, ME=null,
  E2E_KIT='', E2E_KEYS={}, E2E_DATA={}, E2E_DRAFTS={}, E2E_META={}, E2E_GRANTS={}, E2E_LOADING={}, E2E_LOCKED={}, E2E_ERR={}, MY_PUBKEY='', MY_UID='';
function drafts(){return (ENV&&DRAFTS[ENV.id])||{}}
function draftList(){return Object.values(drafts())}
function e2eDrafts(){return (ENV&&E2E_DRAFTS[ENV.id])||{}}
function e2eDraftList(){return Object.values(e2eDrafts())}
const $=id=>document.getElementById(id);
const H=()=>({'Content-Type':'application/json'});
function emergencyAllowed(m,u){if(u===`/api/orgs/${ORG}/emergency`||u===`/api/apps/${APP?.id}/emergency`||u==='/api/auth/logout')return true;
  return m==='GET'&&!/\/(secrets|export|e2e|leases|search)(\/|\?|$)/.test(u)}
async function api(m,u,b){if((EMERGENCY||PROJECT_EMERGENCY)&&!emergencyAllowed(m,u))throw new Error('Selected scope is in emergency lockdown');
  let active=AUTH_READY,org=ORG;let r=await fetch(u,{method:m,headers:H(),body:b!==undefined?JSON.stringify(b):undefined});let t=await r.text();let d;try{d=JSON.parse(t)}catch(e){d={error:t}}
  if(active&&(!AUTH_READY||org!==ORG))throw new Error('Session or workspace changed');
  if((EMERGENCY||PROJECT_EMERGENCY)&&!emergencyAllowed(m,u))throw new Error('Selected scope is in emergency lockdown');
  if(r.status===401&&AUTH_READY)sessionEnded();
  if(AUTH_READY&&(r.status===423||(r.status===403&&String(d.error||'').includes('emergency lockdown')))){clearSecretState();refreshEmergency()}
  if(!r.ok) throw new Error(d.error||('HTTP '+r.status)); return d}
function toastUI(key,args,err){if(typeof args==='boolean'){err=args;args=undefined}return toast(owT(key,args),err,key,args)}
function clearSecretState(){SECRET_EPOCH++;SECRETS=[];DRAFTS={};E2E_KIT='';E2E_KEYS={};E2E_DATA={};E2E_DRAFTS={};E2E_META={};E2E_GRANTS={};E2E_LOADING={};E2E_LOCKED={};E2E_ERR={};clearPkiState();
  closeModal();$('modal').innerHTML='';$('palette').style.display='none';$('paletteresults').innerHTML='';$('deploybar').classList.remove('show')}
function sessionEnded(){AUTH_READY=false;EMERGENCY_REQUEST++;clearInterval(EMERGENCY_POLL);T='';clearSecretState();applyEmergency(false,false);PROJECT_DIRECT=false;EMERGENCY_OWNER=false;APP=null;ENV=null;APPS=[];ENVS=[];MY_PUBKEY='';MY_UID='';
  $('view').innerHTML='';$('shell').style.display='none';$('auth').style.display='grid';$('pw').value='';toastUI('Your session ended. Sign in again.', true)}
function emergencyCard(project=false){let locked=project?PROJECT_EMERGENCY:EMERGENCY,direct=project?PROJECT_DIRECT:EMERGENCY,scope=project?'project':'workspace';return `<div class="card" style="border-color:var(--bad)"><h3>${locked?'Emergency lockdown active':(project?'Project lockdown':'Emergency lockdown')}</h3>
  <p>${locked?'The web console is read-only. Secrets are hidden, syncs are paused, and all automation reads and writes for this scope are rejected.':`Halt this ${scope}, sign out non-owner members, and block secret access, changes and automation requests.`}</p>
  ${project&&EMERGENCY?'<p>The workspace lockdown also applies. Only restoring the workspace can lift that restriction.</p>':''}
  <p class="small mut">Previously copied values and dispatched remote requests cannot be recalled. Revoked sessions stay revoked.</p>
  ${EMERGENCY_OWNER?`<button class="${direct?'primary':'danger'}" onclick="confirmEmergency(${!direct},${project})">${direct?`Restore ${scope} access`:`Activate ${scope} lockdown`}</button>`:'<p>Only a workspace owner can restore access.</p>'}</div>`}
function applyEmergency(locked,project=PROJECT_EMERGENCY){let changed=EMERGENCY!==locked||PROJECT_EMERGENCY!==project;EMERGENCY=locked;PROJECT_EMERGENCY=project;let halted=locked||project,banner=$('emergency-banner');banner.hidden=!halted;
  banner.innerHTML=halted?`<div class="card" style="border-color:var(--bad)"><strong>Emergency lockdown active: ${locked?'workspace':'project'}</strong><p>The console is read-only. Secrets are hidden and automation requests are rejected.</p></div>`:'';
  if(halted){if(changed)clearSecretState();$('topaction').style.display='none';if(changed)$('view').innerHTML=emergencyCard(!locked)}}
async function refreshEmergency(){let org=ORG,app=APP?.id,request=++EMERGENCY_REQUEST;if(!org)return;try{let d=await api('GET',`/api/orgs/${org}/emergency`),p=app?await api('GET',`/api/apps/${app}/emergency`):null;
  if(AUTH_READY&&org===ORG&&app===APP?.id&&request===EMERGENCY_REQUEST){PROJECT_DIRECT=!!p?.direct_locked;applyEmergency(!!d.locked,!!p?.locked)}}catch(e){if(AUTH_READY&&org===ORG&&request===EMERGENCY_REQUEST&&(EMERGENCY||PROJECT_EMERGENCY)){$('view').innerHTML=emergencyCard(!EMERGENCY)}}}
function confirmEmergency(locked,project=false){let org=ORG,app=APP?.id,scope=project?'project':'workspace';modal(`<h3>${locked?`Activate ${scope} lockdown?`:`Restore ${scope} access?`}</h3><p>${locked?'Non-owner members will be signed out. The console will be read-only, secrets hidden and automation reads and writes rejected for this scope.':`The direct ${scope} lockdown will be lifted. Other lockdowns still apply. Revoked sessions stay revoked.`}</p><div class="row"><button class="${locked?'danger':'primary'}" id="emergency-confirm">${locked?'Activate lockdown':'Restore access'}</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`,'Confirm emergency lockdown');
  $('emergency-confirm').onclick=async()=>{if(ORG!==org||(project&&APP?.id!==app)){closeModal();return}try{EMERGENCY_REQUEST++;await api('PUT',project?`/api/apps/${app}/emergency`:`/api/orgs/${org}/emergency`,{locked});await refreshEmergency();closeModal();if(project){$('view').innerHTML=emergencyCard(true)}else await nav('settings')}catch(e){toast(e.message,true)}}}
// Keep the error body for deletion's ownership and credential warnings.
async function apiRaw(m,u,b){if((EMERGENCY||PROJECT_EMERGENCY)&&!emergencyAllowed(m,u))throw new Error('Selected scope is in emergency lockdown');let r=await fetch(u,{method:m,headers:H(),body:b!==undefined?JSON.stringify(b):undefined});let t=await r.text();let d;try{d=JSON.parse(t)}catch(e){d={error:t}}
  return {ok:r.ok,status:r.status,body:d}}
function toast(msg,err,key,args){let el=document.createElement('div');el.className='toast'+(err?' err':'');if(key)owText(el,key,args);else el.textContent=msg;$('toasts').appendChild(el);el.style.transition='opacity .3s';setTimeout(()=>{el.style.opacity='0';setTimeout(()=>el.remove(),320)},3000)}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
// For values interpolated into an inline handler's JS string literal. HTML
// escaping alone is not enough: the parser turns &#39; back into a quote before
// the JS is parsed, which would let a secret key break out of the string.
function jsq(s){return String(s??'').replace(/&/g,'&amp;').replace(/\\/g,'\\\\').replace(/'/g,"\\u0027").replace(/"/g,'\\u0022').replace(/</g,'\\u003c').replace(/>/g,'\\u003e').replace(/\n/g,'\\n').replace(/\r/g,'\\r')}
let PRODUCT_DIALOG=null, PRODUCT_SERIAL=0;
function modal(html,label){PRODUCT_SERIAL++;PRODUCT_DIALOG=null;let m=$('modal');m.innerHTML=html;m.setAttribute('role','dialog');m.setAttribute('aria-modal','true');
  if(label)owAttr(m,'aria-label',label);else{m.removeAttribute('aria-label');m.removeAttribute('data-i18n-aria-label')}owApply(m);
  $('modalwrap').classList.add('show');LASTFOCUS=document.activeElement;
  requestAnimationFrame(()=>{let f=m.querySelector('input,textarea,select,button');if(f)f.focus()})}
function closeModal(){let w=$('modalwrap');if(!w.classList.contains('show'))return;w.classList.remove('show');
  if(PRODUCT_DIALOG){$('modal').innerHTML='';PRODUCT_DIALOG=null}PRODUCT_SERIAL++;
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

// ---------- appearance ----------
// The head boot script owns first paint; these change the choice afterwards.
function themePref(){let de=document.documentElement;return (de&&de.dataset.themePref)||'system'}
function setTheme(p){try{localStorage.setItem('ow_theme',p)}catch(e){}
  let de=document.documentElement;if(!de)return;
  de.dataset.themePref=p;
  let mq=window.matchMedia?window.matchMedia('(prefers-color-scheme: dark)'):null;
  de.dataset.theme=p==='system'?((mq&&mq.matches)?'dark':'light'):p;
  applyThemeIcons()}
function cycleTheme(){let p=themePref();setTheme(p==='system'?'light':p==='light'?'dark':'system')}
function applyThemeIcons(){let p=themePref();let ic=p==='system'?'◐':p==='light'?'☀':'☾';let label=owT('Theme: '+p);
  document.querySelectorAll('[data-themetoggle]').forEach(b=>{b.textContent=ic;b.title=label;b.setAttribute('aria-label',label)})}

// ---------- auth ----------
async function loadProviders(){try{
  let p=await api('GET','/api/auth/providers');
  renderRegion(p);
  let btns=[];
  for(const [id,name] of [['google','Google'],['microsoft','Microsoft'],['apple','Apple'],['github','GitHub'],['okta','Okta'],['auth0','Auth0'],['gitlab','GitLab'],['atlassian','Atlassian'],['slack','Slack'],['salesforce','Salesforce'],['openai','OpenAI'],['x','X'],['discord','Discord'],['linkedin','LinkedIn'],['workos','WorkOS']]){
    if(p[id])btns.push(`<button style="flex:1 1 45%" onclick="location.href='/api/auth/social/${id}/start'">${owHTML('Continue with {x}',{x:name})}</button>`)}
  if(p.oidc)btns.push(`<button style="flex:1 1 45%" onclick="location.href='/api/auth/social/oidc/start'">${owHTML('Continue with {x}',{x:p.oidc_name||'SSO'})}</button>`);
  if(p.ldap)btns.push(`<button style="flex:1 1 45%" onclick="ldapPrompt()" data-i18n="Sign in with directory (LDAP)">Sign in with directory (LDAP)</button>`);
  $('social').innerHTML=btns.join('');
  if(p.signups!=='open'){
    $('segreg').style.display='none';
    if(MODE==='register')authMode('login');
    owText($('signupnote'),'Signups are closed. Ask an administrator for an invitation.');
  }
}catch(e){}}
function showInvite(token){
  $('auth').style.display='grid';$('shell').style.display='none';
  owText($('authtitle'),'Accept invitation');
  $('authform').innerHTML=`<p class="mut" data-i18n="Choose a password for your new account.">Choose a password for your new account.</p>
    <div class="field"><label for="inv-pw" data-i18n="Password">Password</label><input id="inv-pw" type="password" autocomplete="new-password" placeholder="at least 8 characters" data-i18n-placeholder="at least 8 characters"></div>
    <button class="primary" style="width:100%;padding:11px" onclick="acceptInvite()" data-i18n="Create account">Create account</button>`;
  $('authform').dataset.invite=token;}
async function acceptInvite(){try{
  let d=await api('POST','/api/auth/accept-invite',{token:$('authform').dataset.invite,password:$('inv-pw').value});
  T='';history.replaceState(null,'',location.pathname);await enterApp();
}catch(e){toast(e.message,true)}}
function forgotPrompt(){modal(`<h3 data-i18n="Reset your password">Reset your password</h3><p class="mut" data-i18n="Enter your email. If an account exists, a reset link is sent.">Enter your email. If an account exists, a reset link is sent.</p>
  <div class="field"><label for="fp-email" data-i18n="Email">Email</label><input id="fp-email" type="email" value="${esc($('email').value)}"></div>
  <div class="row"><button class="primary" onclick="sendForgot()" data-i18n="Send link">Send link</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>`,'Reset password')}
function workspaceSsoPrompt(){modal(`<h3>Sign in to a workspace</h3><p class="mut">Single sign-on is configured per workspace, and an address alone cannot reveal which workspace you mean.</p>
  <div class="field"><label for="saml-org">Workspace ID</label><input id="saml-org" placeholder="workspace id" autocomplete="off" onkeydown="if(event.key==='Enter')samlGo('saml')"></div>
  <p class="small mut">An owner can copy it from Members and access.</p>
  <div class="row" style="margin-top:12px"><button class="primary" onclick="samlGo('saml')">Continue with SAML</button><button onclick="samlGo('oidc')">Continue with OIDC</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>`,'Workspace sign-in')}
function samlGo(method){let org=$('saml-org').value.trim();if(!org){toast('Enter the workspace ID',true);return}
  location.href='/api/auth/'+(method==='oidc'?'oidc':'saml')+'/'+encodeURIComponent(org)+'/start'}
// The jurisdiction is a deployment, so the console can only report the one
// serving this page and offer a hand-off to another origin. It never switches
// region server-side, because a region is not a tenant preference.
function renderRegion(p){
  let line=$('regionline');if(!line)return;
  REGIONS=(p&&p.regions)||[];
  let here=(p&&p.region)||'global';
  let others=REGIONS.filter(r=>r.label!==here);
  line.innerHTML='<span id="regtext"></span><span id="regsw"></span>';
  owText($('regtext'),'Signing in to {x}',{x:here});
  if(others.length)$('regsw').innerHTML=' · <a href="#" role="button" onclick="regionPick(event);return false" data-i18n="Change region">Change region</a>'}
function regionPick(e){if(e)e.preventDefault();
  let rows=REGIONS.map((r,i)=>`<button class="pickrow" onclick="location.href=this.getAttribute('data-origin')" data-origin="${esc(r.origin)}"><span>${esc(String(r.label).toUpperCase())}</span><span class="grow"></span><span class="pm">${esc(r.origin)}</span></button>`).join('');
  modal(`<h3 data-i18n="Choose a jurisdiction">Choose a jurisdiction</h3><p class="mut" data-i18n="Sign in where your workspace stores its data.">Sign in where your workspace stores its data.</p><div class="picklist">${rows}</div><div class="row" style="margin-top:12px"><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>`,'Jurisdiction')}
function ldapPrompt(){modal(`<h3 data-i18n="Sign in with your directory">Sign in with your directory</h3><p class="mut" data-i18n="Your password goes to this server over the API and is checked by your directory over TLS.">Your password goes to this server over the API and is checked by your directory over TLS.</p>
  <div class="field"><label for="ld-org" data-i18n="Workspace ID">Workspace ID</label><input id="ld-org" placeholder="workspace id" data-i18n-placeholder="workspace id"></div>
  <div class="field"><label for="ld-user" data-i18n="Directory username">Directory username</label><input id="ld-user" autocomplete="username"></div>
  <div class="field"><label for="ld-pw" data-i18n="Password">Password</label><input id="ld-pw" type="password" autocomplete="current-password"></div>
  <div class="row"><button class="primary" onclick="ldapSignIn()" data-i18n="Sign in">Sign in</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>`,'Directory sign-in')}
async function ldapSignIn(){try{
  let d=await api('POST','/api/auth/ldap',{org_id:$('ld-org').value.trim(),username:$('ld-user').value,password:$('ld-pw').value});
  if(d.mfa_required){MFA=d.mfa_token;
    $('modal').innerHTML=`<h3 data-i18n="Two-factor code">Two-factor code</h3><div class="field"><label for="ld-mfa" data-i18n="Authenticator / recovery code">Authenticator / recovery code</label><input id="ld-mfa" placeholder="123456"></div><div class="row"><button class="primary" onclick="ldapMfa()" data-i18n="Verify">Verify</button></div>`;return}
  T='';closeModal();await enterApp();
}catch(e){toast(e.message,true)}}
async function ldapMfa(){try{let d=await api('POST','/api/auth/mfa',{mfa_token:MFA,code:$('ld-mfa').value});T='';closeModal();await enterApp()}catch(e){toast(e.message,true)}}
async function sendForgot(){try{await api('POST','/api/auth/forgot',{email:$('fp-email').value});closeModal();toastUI('If that address has an account, a reset link is on its way', false)}catch(e){toast(e.message,true)}}
function showReset(token){
  $('auth').style.display='grid';$('shell').style.display='none';owText($('authtitle'),'Choose a new password');
  $('authform').innerHTML=`<p class="mut" data-i18n="Enter a new password for your account.">Enter a new password for your account.</p>
    <div class="field"><label for="rp-pw" data-i18n="New password">New password</label><input id="rp-pw" type="password" autocomplete="new-password" placeholder="at least 8 characters" data-i18n-placeholder="at least 8 characters"></div>
    <div class="field"><label for="rp-kit" data-i18n="Recovery kit (keeps end-to-end environments readable)">Recovery kit (keeps end-to-end environments readable)</label><input id="rp-kit" placeholder="base64 recovery kit" data-i18n-placeholder="base64 recovery kit"></div>
    <label class="row small mut" style="gap:8px"><input type="checkbox" id="rp-discard"> <span data-i18n="I no longer have my kit; replace my key and lose end-to-end access">I no longer have my kit; replace my key and lose end-to-end access</span></label>
    <button class="primary" style="width:100%;padding:11px;margin-top:10px" onclick="resetPassword()" data-i18n="Set new password">Set new password</button>`;
  $('authform').dataset.reset=token}
async function resetPassword(){try{
  let d=await api('POST','/api/auth/reset',{token:$('authform').dataset.reset,password:$('rp-pw').value,recovery_kit:$('rp-kit').value,discard_e2e_key:!!$('rp-discard').checked});
  T='';history.replaceState(null,'',location.pathname);
  toastUI(d.e2e_key_replaced?'Password set; your key was replaced':'Password set', false);await enterApp();
}catch(e){toast(e.message,true)}}
let MODE='login';
function authMode(m){MODE=m;$('seglogin').classList.toggle('on',m==='login');$('segreg').classList.toggle('on',m==='register');owText($('authtitle'),m==='login'?'Welcome back':'Create your account');owText($('authbtn'),m==='login'?'Sign in':'Create account')}
async function doAuth(){try{
  if(MODE==='register'){let d=await api('POST','/api/auth/register',{email:$('email').value,password:$('pw').value});
    if(d.verification_required){
      modal(`<h3 data-i18n="Check your email">Check your email</h3><p class="mut">${owHTML('We sent a verification link to {x}. Save your recovery kit now; it is shown once.',{x:$('email').value})}</p><textarea id="kit-text" aria-label="Recovery kit" data-i18n-aria-label="Recovery kit" rows="3" readonly>${esc(d.recovery_kit)}</textarea><div class="row" style="margin-top:12px"><button onclick="navigator.clipboard.writeText('${esc(d.recovery_kit)}');toastUI('Recovery kit copied', false)" data-i18n="Copy kit">Copy kit</button><button class="primary" onclick="closeModal()" data-i18n="I saved it">I saved it</button></div>`,'Check your email');
      return}
    T='';
    modal(`<h3 data-i18n="Save your recovery kit">Save your recovery kit</h3><p class="mut" data-i18n="This X25519 private key decrypts end-to-end environments and is shown once. Store it in a password manager.">This X25519 private key decrypts end-to-end environments and is shown once. Store it in a password manager.</p><textarea id="kit-text" aria-label="Recovery kit" data-i18n-aria-label="Recovery kit" rows="3" readonly>${esc(d.recovery_kit)}</textarea><div class="row" style="margin-top:12px"><button onclick="navigator.clipboard.writeText('${esc(d.recovery_kit)}');toastUI('Recovery kit copied', false)" data-i18n="Copy kit">Copy kit</button><button class="primary" onclick="closeModal();enterApp().catch(e=>toast(e.message,true))" data-i18n="I saved it, continue">I saved it, continue</button></div>`,'Save your recovery kit');return}
  let d=await api('POST','/api/auth/login',{email:$('email').value,password:$('pw').value});
  if(d.mfa_required){MFA=d.mfa_token;$('mfafield').style.display='block';owText($('authbtn'),'Verify code');$('authbtn').onclick=doMfa;toastUI('Enter your authenticator or recovery code', false);return}
  T='';await enterApp();
}catch(e){toast(e.message,true)}}
async function doMfa(){try{let d=await api('POST','/api/auth/mfa',{mfa_token:MFA,code:$('mfacode').value});T='';await enterApp()}catch(e){toast(e.message,true)}}
async function logout(){try{await api('POST','/api/auth/logout',{})}catch(e){} T='';clearPkiState();location.reload()}
// The last workspace is remembered per account, so a shared browser does not
// carry one person's choice into the next person's session.
function orgMemoryKey(){return 'ow.org.'+((ME&&(ME.id||ME.email))||'')}
function rememberedOrg(){try{return localStorage.getItem(orgMemoryKey())||''}catch(e){return ''}}
function rememberOrg(id){try{localStorage.setItem(orgMemoryKey(),id)}catch(e){}}
// Restore a usable surface if the workspace list cannot be loaded. Leaving the
// sign-in card hidden turns a failed request into a blank page.
async function enterApp(){$('auth').style.display='none';
  try{await enterAppInner()}
  catch(e){T='';$('auth').style.display='grid';$('shell').style.display='none';$('picker').style.display='none';throw e}}
async function enterAppInner(){
  let me=await api('GET','/api/me');ME=me;MY_PUBKEY=me.pubkey||'';MY_UID=me.id||'';
  ORGS=await api('GET','/api/orgs');
  let want=(PENDING_ORG&&ORGS.some(o=>o.id===PENDING_ORG))?PENDING_ORG:rememberedOrg();PENDING_ORG=null;
  if(want&&!ORGS.some(o=>o.id===want))want='';
  ORG=want||(ORGS.length===1?(ORGS[0].id||''):'');
  if(!ORG&&ORGS.length>1){$('shell').style.display='none';$('picker').style.display='grid';showPicker();return}
  if(ORG)rememberOrg(ORG);
  $('shell').style.display='grid';
  await startWorkspace()}
function memberLabel(o){let n=Number(o.members)||0;return n+' '+(n===1?'member':'members')}
function showPicker(){$('pickerlist').innerHTML=ORGS.map(o=>`<button class="pickrow" onclick="pickOrg(this.getAttribute('data-id'))" data-id="${esc(o.id)}"><span class="pn">${esc(o.name)}</span><span class="grow"></span><span class="pm">${memberLabel(o)} · ${esc(o.role)}</span></button>`).join('')}
async function pickOrg(id){ORG=id;rememberOrg(id);$('picker').style.display='none';$('shell').style.display='grid';await startWorkspace()}
async function startWorkspace(){
  renderOrgMenu();
  EMERGENCY_OWNER=ORGS.find(o=>o.id===ORG)?.role==='owner';AUTH_READY=true;
  await refreshEmergency();clearInterval(EMERGENCY_POLL);EMERGENCY_POLL=setInterval(refreshEmergency,5000);
  await nav(EMERGENCY?'settings':'apps')}
function renderOrgMenu(){
  let cur=ORGS.find(o=>o.id===ORG);
  if(cur)owDataText($('orgname'),cur.name);else owText($('orgname'),'No workspace');
  let rows=ORGS.map(o=>`<button class="orgitem" role="menuitem" onclick="closeOrgMenu();switchOrg(this.getAttribute('data-id'))" data-id="${esc(o.id)}"><span class="ck" aria-hidden="true">${o.id===ORG?'✓':''}</span><span class="grow">${esc(o.name)}</span><span class="pm">${esc(o.role)}</span></button>`);
  let who=esc((ME&&ME.email)||'');
  $('orgmenu').innerHTML=rows.join('')+'<div class="orgsep"></div>'
    +`<div class="orgitem" role="none" style="cursor:default"><span class="ck" aria-hidden="true">◆</span><span class="grow small">${who}</span></div>`
    +`<button class="orgitem" role="menuitem" onclick="closeOrgMenu();nav('settings')"><span class="ck" aria-hidden="true"></span><span class="grow" data-i18n="Account settings">Account settings</span></button>`
    +`<button class="orgitem" role="menuitem" onclick="closeOrgMenu();logout()"><span class="ck" aria-hidden="true"></span><span class="grow" data-i18n="Sign out">Sign out</span></button>`}
function orgMenuOpen(){return $('orgbtn').getAttribute('aria-expanded')==='true'}
function orgMenuItems(){return Array.from($('orgmenu').querySelectorAll('button.orgitem'))}
function toggleOrgMenu(e){if(e&&e.stopPropagation)e.stopPropagation();let open=!orgMenuOpen();$('orgmenu').hidden=!open;$('orgbtn').setAttribute('aria-expanded',open?'true':'false');
  if(open){let first=orgMenuItems()[0];if(first)first.focus()}}
function closeOrgMenu(){let m=$('orgmenu');if(m)m.hidden=true;let b=$('orgbtn');if(b)b.setAttribute('aria-expanded','false')}
function orgMenuKey(e){if(!orgMenuOpen())return;let items=orgMenuItems();if(!items.length)return;
  let i=items.indexOf(document.activeElement);
  if(e.key==='ArrowDown'){e.preventDefault();items[(i+1)%items.length].focus()}
  else if(e.key==='ArrowUp'){e.preventDefault();items[(i-1+items.length)%items.length].focus()}
  else if(e.key==='Home'){e.preventDefault();items[0].focus()}
  else if(e.key==='End'){e.preventDefault();items[items.length-1].focus()}}
async function switchOrg(id){if(PRODUCT_DIALOG)closeModal();PRODUCT_SERIAL++;SECRET_EPOCH++;SECRETS=[];ORG=id||ORG;clearPkiState();APP=null;ENV=null;EMERGENCY_OWNER=ORGS.find(o=>o.id===ORG)?.role==='owner';PROJECT_DIRECT=false;rememberOrg(ORG);renderOrgMenu();applyEmergency(false,false);await refreshEmergency();await nav(EMERGENCY?'settings':'apps')}
async function refreshOrgs(){ORGS=await api('GET','/api/orgs');renderOrgMenu();EMERGENCY_OWNER=ORGS.find(o=>o.id===ORG)?.role==='owner'}

// ---------- navigation ----------
function toggleNav(){let a=document.querySelector('aside');if(!a)return;let open=a.classList.toggle('open');let t=$('navtoggle');if(t)t.setAttribute('aria-expanded',open?'true':'false')}
async function nav(v){if(PRODUCT_DIALOG)closeModal();PRODUCT_SERIAL++;VIEW=v;let a=document.querySelector('aside');if(a){a.classList.remove('open');let t=$('navtoggle');if(t)t.setAttribute('aria-expanded','false')}document.querySelectorAll('.navbtn').forEach(b=>b.classList.toggle('on',b.dataset.nav===v));
  $('topaction').style.display=(v==='apps'&&!EMERGENCY)?'':'none';
  updateDeployBar();
  if((EMERGENCY||PROJECT_EMERGENCY)&&['access','integrations'].includes(v)){$('pagetitle').textContent='Read-only inspection';$('crumb').textContent='';$('view').innerHTML=emergencyCard(!EMERGENCY);return}
  await ({apps:renderApps,access:renderAccess,integrations:renderIntegrations,audit:renderAudit,settings:renderSettings}[v]||renderApps)();
  updateDeployBar()}

// ---------- apps ----------
async function renderApps(){$('topaction').style.display=EMERGENCY?'none':'';owText($('pagetitle'),'Apps');owDataText($('crumb'),'');
  $('view').innerHTML='<div class="empty"><div class="big" data-i18n="Loading…">Loading…</div></div>';
  APPS=ORG?await api('GET',`/api/orgs/${ORG}/apps`):[];
  if(!APPS.length){$('view').innerHTML=`<div class="empty"><div class="big">▦</div><span data-i18n="No apps yet">No apps yet</span><p data-i18n="Create an app to start managing secrets for a project.">Create an app to start managing secrets for a project.</p><button class="primary" onclick="newApp()" data-i18n="Create your first app">Create your first app</button></div>`;return}
  let envCounts={};for(let a of APPS){try{let es=await api('GET',`/api/apps/${a.id}/envs`);envCounts[a.id]=es}catch(e){envCounts[a.id]=[]}}
  $('view').innerHTML=`<div class="row" style="margin-bottom:14px"><input id="appfilter" placeholder="Filter apps…" data-i18n-placeholder="Filter apps…" style="min-width:240px" oninput="filterApps(this.value)"><span class="mut small">${owHTML(APPS.length===1?'{N} app, unlimited environments':'{N} apps, unlimited environments',{N:APPS.length})}</span></div>
  <div class="grid" id="appgrid">${APPS.map(a=>appCard(a,envCounts[a.id])).join('')}</div>`}
function appCard(a,envs){return `<div class="appcard" onclick="openApp('${a.id}')"><h3 data-i18n-skip>${esc(a.name)}</h3><div class="meta">${owHTML(envs.length===1?'{n} environment':'{n} environments',{n:envs.length})}${a.reuse_check===false?owHTML(' · reuse checks off'):''}${a.emergency_locked?owHTML(' · lockdown'):''}</div><div>${envs.map(e=>`<span class="chip">${esc(e.name)}</span>`).join('')}</div>${EMERGENCY_OWNER?`<button class="ghost" onclick="event.stopPropagation();projectLockSettings('${a.id}')" data-i18n="Project lockdown">Project lockdown</button>`:''}</div>`}
async function projectLockSettings(id){try{APP=APPS.find(a=>a.id===id)||{id};ENV=null;await refreshEmergency();owDataText($('pagetitle'),APP.name||'Project');$('view').innerHTML=emergencyCard(true);$('topaction').style.display='none'}catch(e){toast(e.message,true)}}
function filterApps(q){document.querySelectorAll('.appcard').forEach((c,i)=>{c.style.display=APPS[i].name.toLowerCase().includes(q.toLowerCase())?'':'none'})}
async function newApp(){modal(`<h3 data-i18n="New app">New app</h3><div class="field"><label for="na-name" data-i18n="App name">App name</label><input id="na-name" placeholder="billing-api"></div><div class="field"><label for="na-readme" data-i18n="Readme (markdown, optional)">Readme (markdown, optional)</label><textarea id="na-readme" rows="4"></textarea></div><div class="row"><button class="primary" onclick="createApp()" data-i18n="Create app">Create app</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>
  <p class="small mut" data-i18n="Development, Staging and Production environments are created automatically. Add unlimited custom environments later.">Development, Staging and Production environments are created automatically. Add unlimited custom environments later.</p>`)}
async function createApp(){try{await api('POST',`/api/orgs/${ORG}/apps`,{name:$('na-name').value,readme:$('na-readme').value});closeModal();toastUI('App created', false);renderApps()}catch(e){toast(e.message,true)}}
async function openApp(id){APP=APPS.find(a=>a.id===id)||{id};PROJECT_DIRECT=false;applyEmergency(EMERGENCY,false);await refreshEmergency();ENVS=await api('GET',`/api/apps/${id}/envs`);
  ENV=ENVS.find(e=>e.id===ENV?.id)||ENVS[0]||null;await renderEnv()}

// ---------- environments and secrets ----------
async function renderEnv(){VIEW='env';$('topaction').style.display='none';owDataText($('pagetitle'),APP?.name||'App');owText($('crumb'),'/ environments');
  if(EMERGENCY||PROJECT_EMERGENCY){$('view').innerHTML=emergencyCard(true)+'<p class="mut" data-i18n="Environment names remain visible. Secret values are unavailable during lockdown.">Environment names remain visible. Secret values are unavailable during lockdown.</p><div class="row">'+ENVS.map(e=>`<span class="chip">${esc(e.name)}</span>`).join('')+'</div>';updateDeployBar();return}
  if(!ENVS.length){$('view').innerHTML='<div class="empty"><div class="big" data-i18n="No environments">No environments</div><button class="primary" onclick="newEnv()" data-i18n="Create environment">Create environment</button></div>';updateDeployBar();return}
  if(!ENV)ENV=ENVS[0];
  if(isDelegated(ENV)){await renderDelegatedEnv();return}
  if(isE2E(ENV)){await renderE2eEnv();return}
  let d=await api('GET',`/api/envs/${ENV.id}/secrets`);SECRETS=d.secrets;
  $('view').innerHTML=`
  ${envTabs()}
  <div class="row" style="margin-bottom:12px">
    <input id="sfilter" placeholder="Filter by key or path…" data-i18n-placeholder="Filter by key or path…" style="min-width:240px" oninput="drawSecrets()">
    <button onclick="importModal()" data-i18n="Import .env">Import .env</button><button onclick="exportEnv()" data-i18n="Export">Export</button><button onclick="appSettings()" data-i18n="App settings">App settings</button>
    <span class="grow"></span><button class="primary" onclick="addRow()" data-i18n="+ New secret">+ New secret</button>
  </div>
  <div id="stable"></div>
  ${APP?.readme?`<div class="card" style="margin-top:14px"><h3 data-i18n="Readme">Readme</h3><pre class="val" style="white-space:pre-wrap">${esc(APP.readme)}</pre></div>`:''}`;
  drawSecrets();updateDeployBar()}
function envTabs(){return `<div class="envtabs">${ENVS.map(e=>`<button class="envtab ${e.id===ENV.id?'on':''}" onclick="switchEnv('${e.id}')">${esc(e.name)}${isE2E(e)?owHTML(' · E2E'):''}${e.mode==='delegated'?owHTML(' · delegated'):''}</button>`).join('')}<button class="envtab" onclick="newEnv()" data-i18n="+ Environment">+ Environment</button><button class="envtab" onclick="newE2eEnv()" data-i18n="+ E2E environment">+ E2E environment</button><span class="grow"></span><button class="ghost danger" onclick="delEnv()" data-i18n="Delete env">Delete env</button></div>`}
async function renderE2eEnv(){VIEW='env';$('topaction').style.display='none';owDataText($('pagetitle'),APP?.name||'App');owText($('crumb'),'/ environments');
  let id=ENV.id;
  if(!E2E_DATA[id]&&E2E_LOADING[id]){$('view').innerHTML=envTabs()+'<div class="empty"><div class="big" data-i18n="Unlocking…">Unlocking…</div><span data-i18n="Decrypting this environment in the browser.">Decrypting this environment in the browser.</span></div>';updateDeployBar();return}
  if(!E2E_DATA[id]&&E2E_KIT&&!E2E_LOCKED[id]&&!E2E_LOADING[id]){
    $('view').innerHTML=envTabs()+'<div class="empty"><div class="big" data-i18n="Unlocking…">Unlocking…</div><span data-i18n="Decrypting this environment with the key from your session.">Decrypting this environment with the key from your session.</span></div>';
    try{await e2eLoad(id,E2E_KIT)}catch(e){E2E_ERR[id]=e.message}
  }
  if(!E2E_DATA[id]){
    let err=E2E_ERR[id]?`<p class="small" style="color:var(--bad)">${esc(E2E_ERR[id])}</p>`:'';
    $('view').innerHTML=`${envTabs()}
    <div class="card"><h3 data-i18n="End-to-end encrypted environment">End-to-end encrypted environment</h3>
      <p class="mut" data-i18n="The server stores only ciphertext here, so this console has to decrypt it in the browser. Paste the recovery kit you saved at registration.">The server stores only ciphertext here, so this console has to decrypt it in the browser. Paste the recovery kit you saved at registration.</p>
      ${err}
      <div class="field"><label for="e2e-kit" data-i18n="Recovery kit">Recovery kit</label><input id="e2e-kit" type="password" autocomplete="off" placeholder="base64 recovery kit" data-i18n-placeholder="base64 recovery kit" style="width:100%"></div>
      <button class="primary" onclick="unlockE2EEnv()" data-i18n="Unlock environment">Unlock environment</button>
      <p class="small mut" data-i18n="The kit and the decrypted key stay in this tab and are never sent to the server. A reload locks the environment again.">The kit and the decrypted key stay in this tab and are never sent to the server. A reload locks the environment again.</p></div>`;
    updateDeployBar();return}
  let meta=E2E_META[id]||{};
  let banner=meta.rekey_required?`<div class="card" style="border-color:var(--bad)"><h3 data-i18n="Access changed">Access changed</h3>
    <p data-i18n="A member&#39;s key grant was removed, but the stored ciphertext is still encrypted under the old environment key. Rotate the key to re-encrypt every secret under a new key and wrap that key to the current members. Rotation cannot take back ciphertext someone already copied.">A member's key grant was removed, but the stored ciphertext is still encrypted under the old environment key. Rotate the key to re-encrypt every secret under a new key and wrap that key to the current members. Rotation cannot take back ciphertext someone already copied.</p>
    <button class="primary" onclick="e2eRekey()" data-i18n="Rotate key now">Rotate key now</button></div>`:'';
  $('view').innerHTML=`${envTabs()}${banner}
  <div class="row" style="margin-bottom:12px">
    <input id="sfilter" placeholder="Filter by key or path…" data-i18n-placeholder="Filter by key or path…" style="min-width:240px" oninput="drawE2E()">
    <button onclick="e2eGrantsModal()" data-i18n="Access">Access</button>
    <button onclick="renderE2eEnv()" data-i18n="Refresh">Refresh</button>
    <button onclick="lockE2E()" data-i18n="Lock">Lock</button>
    <span class="grow"></span><button class="primary" onclick="e2eAddRow()" data-i18n="+ New secret">+ New secret</button>
  </div>
  <p class="small mut" data-i18n="Decrypted in this tab only. Staged changes deploy together and are lost if you reload before deploying.">Decrypted in this tab only. Staged changes deploy together and are lost if you reload before deploying.</p>
  <div id="stable"></div>`;
  drawE2E();updateDeployBar()}
async function renderDelegatedEnv(){VIEW='env';$('topaction').style.display='none';owDataText($('pagetitle'),APP?.name||'App');owText($('crumb'),'/ environments');
  $('view').innerHTML=`${envTabs()}<div class="card"><h3 data-i18n="Delegated environment">Delegated environment</h3>
    <p class="mut"><span data-i18n="This environment is client-encrypted, and a runner you host holds a key grant for provider sync. The console cannot read these secrets. Manage them with the CLI (">This environment is client-encrypted, and a runner you host holds a key grant for provider sync. The console cannot read these secrets. Manage them with the CLI (</span><span class="mono">openwarp e2e</span><span data-i18n=") or an E2E-capable client; provider sync runs on the runner.">) or an E2E-capable client; provider sync runs on the runner.</span></p></div>`;
  updateDeployBar()}
function isE2E(e){return !!e&&(e.mode||'sse')==='e2e'}
function isDelegated(e){return !!e&&e.mode==='delegated'}
async function switchEnv(id){let cur=ENV&&ENV.id;if(cur===id){return}
  if(cur&&(Object.keys(drafts()).length||Object.keys(e2eDrafts()).length)&&!confirm(owT('Discard staged changes?')))return;
  if(cur){delete DRAFTS[cur];delete E2E_DRAFTS[cur]}
  ENV=ENVS.find(e=>e.id===id);await renderEnv()}
function envMode(e){return e&&e.mode==='e2e'?'e2e':'sse'}
async function newEnv(){modal(`<h3 data-i18n="New environment">New environment</h3><div class="field"><label for="ne-name" data-i18n="Name (letters, numbers, - or _)">Name (letters, numbers, - or _)</label><input id="ne-name" placeholder="qa-1"></div><div class="row"><button class="primary" onclick="createEnv()" data-i18n="Create">Create</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>`)}
async function createEnv(){try{await api('POST',`/api/apps/${APP.id}/envs`,{name:$('ne-name').value});closeModal();ENVS=await api('GET',`/api/apps/${APP.id}/envs`);toastUI('Environment created', false);renderEnv()}catch(e){toast(e.message,true)}}
function appSettings(){if(!APP){toastUI('Open an app first', true);return}let on=APP.reuse_check!==false;
  modal(`<h3 data-i18n="App settings">App settings</h3><p class="mut">${esc(APP.name||'')}</p>
    <label class="row" style="gap:8px;margin:12px 0"><input type="checkbox" id="app-reuse" ${on?'checked':''}> <span data-i18n="Warn when a secret value is reused elsewhere in this workspace">Warn when a secret value is reused elsewhere in this workspace</span></label>
    <p class="small mut" data-i18n="The workspace setting must also be on. The warning is advisory; you can still save the value.">The workspace setting must also be on. The warning is advisory; you can still save the value.</p>
    <div class="row"><button class="primary" onclick="saveAppSettings()" data-i18n="Save">Save</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>`,'App settings')}
async function saveAppSettings(){try{let on=$('app-reuse').checked;
  await api('PUT',`/api/apps/${APP.id}/settings`,{reuse_check:on});
  APP.reuse_check=on;closeModal();toastUI('App settings saved', false)}catch(e){toast(e.message,true)}}
function newE2eEnv(){modal(`<h3 data-i18n="New end-to-end encrypted environment">New end-to-end encrypted environment</h3>
  <p class="mut" data-i18n="The environment key is generated in this browser and wrapped to your account key. The server stores only ciphertext and cannot read these secrets.">The environment key is generated in this browser and wrapped to your account key. The server stores only ciphertext and cannot read these secrets.</p>
  <div class="field"><label for="ne2-name" data-i18n="Name">Name</label><input id="ne2-name" placeholder="vault"></div>
  ${E2E_KIT?'':'<div class="field"><label for="ne2-kit" data-i18n="Recovery kit (needed to wrap the new key)">Recovery kit (needed to wrap the new key)</label><input id="ne2-kit" type="password" autocomplete="off" placeholder="base64 recovery kit" data-i18n-placeholder="base64 recovery kit" style="width:100%"></div>'}
  <div class="row"><button class="primary" onclick="createE2eEnv()" data-i18n="Create E2E env">Create E2E env</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>
  <p class="small mut" data-i18n="Provider sync needs a delegated environment with a runner.">Provider sync needs a delegated environment with a runner.</p>`)}
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
  await e2eLoad(d.id,E2E_KIT);toastUI('E2E environment created', false);await renderE2eEnv()
}catch(e){toast(e.message,true)}}
async function delEnv(){if(!confirm(owT('Delete environment {x} and all its secrets?',{x:ENV.name})))return;try{let removed=ENV.id;await api('DELETE',`/api/envs/${removed}`);delete DRAFTS[removed];delete E2E_KEYS[removed];delete E2E_DATA[removed];delete E2E_DRAFTS[removed];delete E2E_META[removed];delete E2E_GRANTS[removed];delete E2E_LOCKED[removed];delete E2E_ERR[removed];ENVS=await api('GET',`/api/apps/${APP.id}/envs`);ENV=ENVS[0]||null;toastUI('Environment deleted', false);await renderEnv()}catch(e){toast(e.message,true)}}
function enc(s){return new TextEncoder().encode(s)}
function dec(b){return new TextDecoder().decode(b)}
async function e2eHash(path,key,envKey){
  // Match the server's blind index: HMAC under the environment key, not a bare
  // SHA-256 a database thief could test guesses against offline.
  let k=await crypto.subtle.importKey('raw',envKey,{name:'HMAC',hash:'SHA-256'},false,['sign']);
  let sig=await crypto.subtle.sign('HMAC',k,enc('ow-key-index:v1|'+String(path||'/')+'|'+String(key||'').toUpperCase()));
  return [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,'0')).join('')}
async function e2eLoad(id,kit){let epoch=SECRET_EPOCH;E2E_LOADING[id]=true;delete E2E_ERR[id];
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
    let [meta,grants]=await Promise.all([api('GET',`/api/envs/${id}/e2e/meta`).catch(()=>null),api('GET',`/api/envs/${id}/e2e/grants`).catch(()=>[])]);
    if(epoch!==SECRET_EPOCH||EMERGENCY||PROJECT_EMERGENCY)throw new Error('Secret access ended');
    E2E_KEYS[id]=key;E2E_DATA[id]=rows;E2E_DRAFTS[id]={};
    if(meta)E2E_META[id]=meta;E2E_GRANTS[id]=grants;
  }finally{delete E2E_LOADING[id]}}
async function unlockE2EEnv(){let kit=($('e2e-kit')?.value||'').trim()||E2E_KIT;
  if(!kit){toastUI('Paste the recovery kit for this account', true);return}
  try{await e2eLoad(ENV.id,kit);E2E_KIT=kit;delete E2E_LOCKED[ENV.id];toastUI('Environment unlocked', false);await renderE2eEnv()}catch(e){toastUI('Could not unlock: {x}',{x:e.message}, true)}}
function lockE2E(){if(e2eDraftList().length&&!confirm(owT('Discard staged changes and lock this environment?')))return;
  E2E_LOCKED[ENV.id]=true;delete E2E_KEYS[ENV.id];delete E2E_DATA[ENV.id];delete E2E_DRAFTS[ENV.id];delete E2E_ERR[ENV.id];renderE2eEnv()}
function drawE2E(){
  let id=ENV.id,data=E2E_DATA[id]||[],dmap=e2eDrafts();
  let rows=data.map(s=>({s,st:dmap[s.id]})).filter(x=>matchesFilter(x.st?x.st.key:x.s.key,x.st?x.st.path:x.s.path));
  let news=Object.values(dmap).filter(d=>d.isNew&&!d.deleted&&matchesFilter(d.key,d.path)).map(d=>({s:d,st:d}));
  let all=rows.concat(news);
  if(!all.length){
    let any=data.length||Object.keys(dmap).length;
    $('stable').innerHTML=any
      ?'<div class="empty"><div class="big" data-i18n="No matching secrets">No matching secrets</div><span data-i18n="Nothing here matches that filter. Clear it to see every secret in this environment.">Nothing here matches that filter. Clear it to see every secret in this environment.</span></div>'
      :'<div class="empty"><div class="big" data-i18n="No secrets here yet">No secrets here yet</div><span data-i18n="Click “+ New secret” to add one. Everything is encrypted in this browser before it is sent.">Click “+ New secret” to add one. Everything is encrypted in this browser before it is sent.</span></div>';
    return}
  $('stable').innerHTML=`<table><thead><tr><th style="width:28%" data-i18n="Key">Key</th><th data-i18n="Value">Value</th><th style="width:13%" data-i18n="Path">Path</th><th style="width:10%" data-i18n="Version">Version</th><th style="width:14%"></th></tr></thead><tbody>
  ${all.map(({s,st})=>{let gone=!!(st&&st.deleted);let key=st?st.key:s.key;let value=st?st.value:s.value;let path=st?st.path:s.path;let dirty=!!st&&!st.isNew;
    return `<tr${gone?' style="opacity:.55"':''}><td>${dirty&&!gone?'<span class="stagedot"></span>':''}<span class="mono">${esc(key)}</span>${st&&st.isNew?' <span class="chip">new</span>':''}${gone?' <span class="chip">delete</span>':''}</td>
    <td>${gone?'<span class="mut" data-i18n="deleted on deploy">deleted on deploy</span>':`<span class="val" data-val="${esc(value??'')}" data-show="0">••••••••••</span>`}</td>
    <td class="mono mut">${esc(path||'/')}</td><td class="mut">${st&&st.isNew?'new':(st&&!gone?'staged':'v'+(s.version||1))}</td>
    <td style="white-space:nowrap;text-align:right">${gone
      ?`<button class="iconbtn" title="Undo delete" data-i18n-title="Undo delete" aria-label="Undo delete" data-i18n-aria-label="Undo delete" onclick="e2eUndoDelete('${jsq(s.id)}')">↺</button>`
      :`<button class="iconbtn" title="Reveal" data-i18n-title="Reveal" aria-label="Reveal" data-i18n-aria-label="Reveal" onclick="revealVal(this)">◉</button><button class="iconbtn" title="Copy value" data-i18n-title="Copy value" aria-label="Copy value" data-i18n-aria-label="Copy value" onclick="copyVal(this)">⧉</button>
        <button class="iconbtn" title="Edit" data-i18n-title="Edit" aria-label="Edit" data-i18n-aria-label="Edit" onclick="e2eEditRow('${jsq(s.id)}')">✎</button>
        <button class="iconbtn" title="Delete" data-i18n-title="Delete" aria-label="Delete" data-i18n-aria-label="Delete" onclick="e2eDelRow('${jsq(s.id)}','${jsq(key)}')">🗑</button>`}</td></tr>`}).join('')}
  </tbody></table>`}
function e2eAddRow(){if(!E2E_DATA[ENV.id]){toastUI('Unlock the environment first', true);return}let id='new-'+Date.now();
  modal(`<h3 data-i18n="New secret">New secret</h3>
    <div class="field"><label for="ns-key" data-i18n="Key">Key</label><input id="ns-key" placeholder="DATABASE_URL"></div>
    <div class="field"><label for="ns-val" data-i18n="Value">Value</label><textarea id="ns-val" rows="3"></textarea></div>
    <div class="field"><label for="ns-path" data-i18n="Path">Path</label><input id="ns-path" value="/"></div>
    <div class="row"><button class="primary" onclick="e2eStageNew('${id}')" data-i18n="Stage secret">Stage secret</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>
    <p class="small mut" data-i18n="Encrypted in this browser on deploy. There is no server-readable history for this environment.">Encrypted in this browser on deploy. There is no server-readable history for this environment.</p>`,'New secret')}
function e2eStageNew(id){let k=$('ns-key').value.trim().toUpperCase(),path=$('ns-path').value||'/';
  if(!/^[A-Za-z0-9_.-]{1,128}$/.test(k)){toastUI('Key must match [A-Za-z0-9_.-]{1,128}', true);return}
  let dup=(E2E_DATA[ENV.id]||[]).some(s=>s.key===k&&s.path===path)||Object.values(e2eDrafts()).some(d=>!d.deleted&&d.key===k&&d.path===path);
  if(dup){toastUI('A secret with that key and path already exists', true);return}
  if(!E2E_DRAFTS[ENV.id])E2E_DRAFTS[ENV.id]={};
  E2E_DRAFTS[ENV.id][id]={id,key:k,value:$('ns-val').value,path,isNew:true};
  closeModal();drawE2E();updateDeployBar()}
function e2eEditRow(id){let d=e2eDrafts()[id];let s=d||(E2E_DATA[ENV.id]||[]).find(x=>x.id===id);if(!s)return;
  modal(`<h3>${owHTML('Edit {x}',{x:s.key})}</h3><div class="field"><label for="ed-val" data-i18n="Value">Value</label><textarea id="ed-val" rows="4">${esc(s.value??'')}</textarea></div>
    <div class="row"><button class="primary" onclick="e2eStageEdit('${jsq(id)}')" data-i18n="Stage change">Stage change</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>
    <p class="small mut" data-i18n="Renaming is not staged here: delete the secret and add it under the new key. Rotate the key after a delete if the old value must stop being readable.">Renaming is not staged here: delete the secret and add it under the new key. Rotate the key after a delete if the old value must stop being readable.</p>`,'Edit secret')}
function e2eStageEdit(id){let d=e2eDrafts()[id];let s=d||(E2E_DATA[ENV.id]||[]).find(x=>x.id===id);if(!s)return;
  if(d){d.value=$('ed-val').value;d.deleted=false}
  else{if(!E2E_DRAFTS[ENV.id])E2E_DRAFTS[ENV.id]={};E2E_DRAFTS[ENV.id][id]={id,key:s.key,value:$('ed-val').value,path:s.path,key_hash:s.key_hash}}
  closeModal();drawE2E();updateDeployBar();toastUI('Change staged, deploy when ready', false)}
function e2eDelRow(id,key){let d=e2eDrafts()[id];
  if(d&&d.isNew){delete e2eDrafts()[id];drawE2E();updateDeployBar();return}
  if(!confirm(owT('Delete {x}? The console keeps no history for this environment, so the value cannot be restored here.',{x:key})))return;
  let s=(E2E_DATA[ENV.id]||[]).find(x=>x.id===id);if(!s)return;
  if(!E2E_DRAFTS[ENV.id])E2E_DRAFTS[ENV.id]={};
  E2E_DRAFTS[ENV.id][id]={id,key:s.key,value:s.value,path:s.path,key_hash:s.key_hash,deleted:true};
  drawE2E();updateDeployBar()}
function e2eUndoDelete(id){delete e2eDrafts()[id];drawE2E();updateDeployBar()}
async function deployE2E(){
  let id=ENV.id,key=E2E_KEYS[id];if(!key){toastUI('Unlock the environment first', true);return}
  let list=e2eDraftList();if(!list.length)return;
  let dels=list.filter(d=>d.deleted&&!d.isNew),puts=list.filter(d=>!d.deleted);
  let seen=new Set();
  for(const d of puts){let k=(d.key||'').trim().toUpperCase();
    if(!/^[A-Za-z0-9_.-]{1,128}$/.test(k)){toastUI('Invalid key: {x}',{x:k}, true);return}
    let pk=(d.path||'/')+':'+k;if(seen.has(pk)){toastUI('Duplicate key in this deploy: {x}',{x:k}, true);return}seen.add(pk)}
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
      if(r.deployed!==items.length)throw new Error(owT('the server stored {n} of {m} secrets',{n:r.deployed,m:items.length}))}
    for(const d of dels)await api('DELETE',`/api/secrets/${d.id}`);
    await e2eLoad(id,E2E_KIT);
    for(const [kh,[k,v]] of expected){let row=(E2E_DATA[id]||[]).find(r=>r.key_hash===kh);
      if(!row)throw new Error(owT('the deploy was stored but read-back could not find {x}',{x:k}));
      if(row.key!==k||row.value!==v)throw new Error(owT('the deploy was stored but read-back returned a different value for {x}',{x:k}))}
    for(const d of dels){if((E2E_DATA[id]||[]).some(r=>r.id===d.id))throw new Error(owT('deleted secret {x} is still present after deploy',{x:d.key}))}
    toast(owT(items.length===1?'Deployed {n} secret':'Deployed {n} secrets',{n:items.length})+(dels.length?' '+owT(dels.length===1?'and deleted {n} secret':'and deleted {n} secrets',{n:dels.length}):''));await renderE2eEnv();
  }catch(e){toastUI('Deploy failed: {x}',{x:e.message}, true)}}
async function e2eGrantsModal(){
  let id=ENV.id;if(!E2E_KEYS[id]){toastUI('Unlock the environment first', true);return}
  try{let [grants,meta]=await Promise.all([api('GET',`/api/envs/${id}/e2e/grants`),api('GET',`/api/envs/${id}/e2e/meta`)]);E2E_GRANTS[id]=grants;E2E_META[id]=meta}
  catch(e){toast(e.message,true);return}
  let meta=E2E_META[id]||{};
  let rows=grants=>grants.map(g=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:8px 0">
    <span class="mono small">${esc(g.email)}${g.user_id===MY_UID?' '+owHTML('· you'):''}</span>
    ${g.user_id===MY_UID?'':`<button class="danger" onclick="e2eRevoke('${jsq(g.user_id)}','${jsq(g.email)}')" data-i18n="Remove access">Remove access</button>`}</div>`).join('')||'<p class="mut" data-i18n="No key grants yet.">No key grants yet.</p>';
  modal(`<h3 data-i18n="Who can decrypt this environment">Who can decrypt this environment</h3>
    <p class="mut" data-i18n="Each member gets the environment key wrapped to their account public key. The server never sees the key or the plaintext.">Each member gets the environment key wrapped to their account public key. The server never sees the key or the plaintext.</p>
    ${rows(E2E_GRANTS[id]||[])}
    <div class="field" style="margin-top:14px"><label for="eg-email" data-i18n="Grant access by email">Grant access by email</label><input id="eg-email" type="email" placeholder="teammate@example.com"></div>
    <div class="row"><button class="primary" onclick="e2eGrant()" data-i18n="Grant access">Grant access</button><button class="ghost" onclick="closeModal()" data-i18n="Close">Close</button></div>
    ${meta.rekey_required?'<p class="small" style="color:var(--bad)" data-i18n="A grant was removed. Rotate the key from the environment banner so future secrets are not readable to the old grantee.">A grant was removed. Rotate the key from the environment banner so future secrets are not readable to the old grantee.</p>':''}`,'Environment access')}
async function e2eGrant(){
  let id=ENV.id,key=E2E_KEYS[id];if(!key)return;let email=$('eg-email').value.trim();
  if(!email){toastUI('Enter the email of an existing member', true);return}
  try{
    let u=await api('GET',`/api/users/lookup?email=${encodeURIComponent(email)}`);
    if(!u.pubkey)throw new Error('that account has no public key');
    let wrapped=await OW.encryptAsymmetric(u.pubkey,key);
    await api('POST',`/api/envs/${id}/e2e/grant`,{email:u.email,wrapped_key:wrapped});
    let grants=await api('GET',`/api/envs/${id}/e2e/grants`);E2E_GRANTS[id]=grants;
    if(!grants.some(g=>g.user_id===u.id))throw new Error('the grant was not stored');
    toastUI('Access granted to {x}',{x:u.email}, false);await e2eGrantsModal();
  }catch(e){toastUI('Grant failed: {x}',{x:e.message}, true)}}
async function e2eRevoke(uid,email){
  if(uid===MY_UID){toastUI('You cannot remove your own grant here; ask another member to rotate afterwards', true);return}
  if(!confirm(owT('Remove access for {x}? Rotate the environment key afterwards so they cannot read future secrets.',{x:email})))return;
  try{await api('DELETE',`/api/envs/${ENV.id}/e2e/grants/${uid}`);
    E2E_META[ENV.id]={...(E2E_META[ENV.id]||{}),rekey_required:true};
    E2E_GRANTS[ENV.id]=await api('GET',`/api/envs/${ENV.id}/e2e/grants`);
    await e2eGrantsModal();await renderE2eEnv();toastUI('Access removed; rotate the key next', false)
  }catch(e){toast(e.message,true)}}
async function e2eRekey(){
  let id=ENV.id,key=E2E_KEYS[id];if(!key)return;
  if(e2eDraftList().length){toastUI('Deploy or discard staged changes before rotating the key', true);return}
  if((E2E_META[id]||{}).runner){toastUI('Delegated environments rotate through the runner; use the CLI', true);return}
  if(!(E2E_DATA[id]||[]).length){toastUI('Nothing to rotate yet: add a secret first', true);return}
  if(!confirm(owT('Rotate the environment key? Every secret is re-encrypted and each current member gets the new key wrapped to them.')))return;
  try{
    let newKey=crypto.getRandomValues(new Uint8Array(32));
    let secrets=[];
    for(const r of E2E_DATA[id])secrets.push({key_hash:r.key_hash,key_enc:await OW.encryptSymmetric(newKey,enc(r.key)),value_enc:await OW.encryptSymmetric(newKey,enc(r.value)),path_enc:await OW.encryptSymmetric(newKey,enc(r.path||'/'))});
    let grants=await api('GET',`/api/envs/${id}/e2e/grants`);
    if(!grants.some(g=>g.user_id===MY_UID))throw new Error('your own grant is missing; refresh and try again');
    let payload=[];
    for(const g of grants){if(!g.pubkey)throw new Error(owT('grantee {x} has no public key',{x:g.email}));payload.push({user_id:g.user_id,wrapped_key:await OW.encryptAsymmetric(g.pubkey,newKey)})}
    await api('POST',`/api/envs/${id}/e2e/rekey`,{secrets,grants:payload});
    E2E_KEYS[id]=newKey;await e2eLoad(id,E2E_KIT);toastUI('Environment key rotated', false);await renderE2eEnv();
  }catch(e){toastUI('Rotation failed: {x}',{x:e.message}, true)}}
function matchesFilter(key,path){let q=($('sfilter')?.value||'').toLowerCase();return !q||String(key||'').toLowerCase().includes(q)||String(path||'').toLowerCase().includes(q)}
function drawSecrets(){
  let all=SECRETS.map(s=>({s,isNew:false,d:drafts()[s.id]})).filter(x=>matchesFilter(x.d?x.d.key:x.s.key,x.d?x.d.path:x.s.path));
  all=all.concat(draftList().filter(d=>d.isNew&&matchesFilter(d.key,d.path)).map(d=>({s:d,isNew:true,d})));
  if(!all.length){
    let any=SECRETS.length||draftList().length;
    $('stable').innerHTML=any
      ?'<div class="empty"><div class="big" data-i18n="No matching secrets">No matching secrets</div><span data-i18n="Nothing here matches that filter. Clear it to see every secret in this environment.">Nothing here matches that filter. Clear it to see every secret in this environment.</span></div>'
      :'<div class="empty"><div class="big" data-i18n="No secrets here yet">No secrets here yet</div><span data-i18n="Click “+ New secret”, or import a .env file.">Click “+ New secret”, or import a .env file.</span></div>';
    return}
  $('stable').innerHTML=`<table><thead><tr><th style="width:26%" data-i18n="Key">Key</th><th data-i18n="Value">Value</th><th style="width:13%" data-i18n="Path">Path</th><th style="width:9%" data-i18n="Version">Version</th><th style="width:15%"></th></tr></thead><tbody>
  ${all.map(({s,isNew,d})=>{let staged=d;let key=staged?staged.key:s.key;let value=staged?staged.value:s.value;let path=(staged?staged.path:s.path)||'/';
    let type=(staged?staged.type:s.type)||'secret';let sealed=!isNew&&type==='sealed';let dirty=!!staged;
    return `<tr><td>${dirty&&!isNew?'<span class="stagedot"></span>':''}<span class="mono">${esc(key)}</span> <span class="badge b-${esc(type)}">${esc(type)}</span>${isNew?' <span class="chip">new</span>':''}</td>
    <td>${sealed?'<span class="mut mono" data-i18n="🔒 sealed, never shown">🔒 sealed, never shown</span>':`<span class="val" data-val="${esc(value??'')}" data-show="0">••••••••••</span>`}</td>
    <td class="mono mut">${esc(path)}</td><td class="mut">${isNew?'new':'v'+(s.version||1)}</td>
    <td style="white-space:nowrap;text-align:right">
      ${sealed?'':`<button class="iconbtn" title="Reveal" data-i18n-title="Reveal" aria-label="Reveal" data-i18n-aria-label="Reveal" onclick="revealVal(this)">◉</button><button class="iconbtn" title="Copy value" data-i18n-title="Copy value" aria-label="Copy value" data-i18n-aria-label="Copy value" onclick="copyVal(this)">⧉</button>`}
      <button class="iconbtn" title="Edit" data-i18n-title="Edit" aria-label="Edit" data-i18n-aria-label="Edit" onclick="editRow('${jsq(s.id)}')">✎</button>
      ${isNew?'':`<button class="iconbtn" title="History" data-i18n-title="History" aria-label="History" data-i18n-aria-label="History" onclick="showHistory('${jsq(s.id)}')">↺</button>
      <button class="iconbtn" title="Personal override" data-i18n-title="Personal override" aria-label="Personal override" data-i18n-aria-label="Personal override" onclick="overrideRow('${jsq(s.id)}','${jsq(key)}')">♟</button>`}
      <button class="iconbtn" title="Delete" data-i18n-title="Delete" aria-label="Delete" data-i18n-aria-label="Delete" onclick="delSecret('${jsq(s.id)}','${jsq(key)}')">🗑</button></td></tr>`}).join('')}
  </tbody></table>`}
function findValEl(btn){return btn.closest('tr').querySelector('.val')}
function revealVal(btn){let el=findValEl(btn);let show=el.dataset.show==='1';el.dataset.show=show?'0':'1';el.textContent=show?'••••••••••':el.dataset.val}
function copyVal(btn){navigator.clipboard.writeText(findValEl(btn).dataset.val);toastUI('Value copied', false)}
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
      <button onclick="reuseGo('${jsq(it.app_id)}','${jsq(it.env_id)}','${jsq(it.key)}')" data-i18n="Go to">Go to</button></div>`).join('')}
  </div>`).join('');
  modal(`<h3 data-i18n="This value is already in use">This value is already in use</h3>
    <p class="mut" data-i18n="The same value is stored elsewhere in this workspace. Reusing it means one leak exposes every place it is used.">The same value is stored elsewhere in this workspace. Reusing it means one leak exposes every place it is used.</p>
    ${groups}
    <div class="row" style="margin-top:14px"><button class="primary" onclick="reuseProceed()" data-i18n="Use anyway">Use anyway</button>${REUSE_BACK?'<button class="ghost" onclick="reuseBack()" data-i18n="Back">Back</button>':''}</div>`,'Reused secret value')}
function reuseProceed(){let cb=REUSE_PROCEED;REUSE_PROCEED=null;REUSE_BACK=null;closeModal();if(cb)cb()}
function reuseBack(){let cb=REUSE_BACK;REUSE_PROCEED=null;REUSE_BACK=null;closeModal();if(cb)cb()}
async function reuseGo(aid,eid,key){
  if(!aid||!eid){toastUI('That item is no longer available', true);return}
  let cur=ENV&&ENV.id;
  if(cur&&Object.keys(drafts()).length&&!confirm(owT('Discard staged changes?')))return;
  if(cur)delete DRAFTS[cur];
  closeModal();REUSE_PROCEED=null;REUSE_BACK=null;
  try{
    if(!APPS.some(a=>a.id===aid))APPS=await api('GET',`/api/orgs/${ORG}/apps`);
    APP=APPS.find(a=>a.id===aid)||{id:aid};
    ENVS=await api('GET',`/api/apps/${aid}/envs`);
    ENV=ENVS.find(e=>e.id===eid)||ENVS[0]||null;
    await renderEnv();
    let f=$('sfilter');if(f){f.value=key;drawSecrets()}
    toastUI('Showing {x} in {y}',{x:key,y:ENV?ENV.name:''}, false);
  }catch(e){toast(e.message,true)}}
function addRow(prefill){if(!ENV){toastUI('Open an environment first', true);return}let id='new-'+Date.now();let v=prefill||{};
  let types=['secret','sealed','ssh_key','config'];
  modal(`<h3 data-i18n="New secret">New secret</h3>
    <div class="field"><label for="ns-key" data-i18n="Key">Key</label><input id="ns-key" placeholder="DATABASE_URL" value="${esc(v.key||'')}"></div>
    <div class="field"><label for="ns-val" data-i18n="Value">Value</label><textarea id="ns-val" rows="3">${esc(v.value||'')}</textarea></div>
    <div class="row"><div class="field" style="flex:1"><label for="ns-path" data-i18n="Path">Path</label><input id="ns-path" value="${esc(v.path||'/')}"></div>
    <div class="field"><label for="ns-type" data-i18n="Type">Type</label><select id="ns-type">${types.map(t=>`<option${t===(v.type||'secret')?' selected':''}>${t}</option>`).join('')}</select></div></div>
    <div class="row"><button class="primary" onclick="stageNew('${id}')" data-i18n="Stage secret">Stage secret</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>
    <p class="small mut" data-i18n="Staged changes deploy together, like a commit. Sealed values can never be read back.">Staged changes deploy together, like a commit. Sealed values can never be read back.</p>`,'New secret')}
function reuseCandidate(){let k=$('ns-key').value.trim();if(!k){toastUI('Key required', true);return null}
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
  modal(`<h3>${owHTML('Edit {x}',{x:s.key})}</h3><div class="field"><label for="ed-val" data-i18n="Value">Value</label><textarea id="ed-val" rows="4">${esc(value)}</textarea></div>
    <div class="field"><label for="ed-comment" data-i18n="Comment">Comment</label><input id="ed-comment" value="${esc(comment)}"></div>
    <div class="row"><button class="primary" onclick="stageEdit('${jsq(id)}')">${owHTML(isNew?'Stage secret':'Stage change')}</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>`,'Edit secret')}
function commitEdit(id,s,value,comment){let d=drafts()[id];
  if(d){d.value=value;d.comment=comment}
  else{if(!DRAFTS[ENV.id])DRAFTS[ENV.id]={};DRAFTS[ENV.id][id]={id,key:s.key,value,path:s.path,type:s.type,comment}}
  closeModal();drawSecrets();updateDeployBar();toastUI('Change staged, deploy when ready', false)}
async function stageEdit(id){let d=drafts()[id];let s=d||SECRETS.find(x=>x.id===id);if(!s)return;
  let value=$('ed-val').value,comment=$('ed-comment').value;
  let changed=!d||d.value!==value;
  if(changed&&(s.type||'secret')==='secret'&&value){
    let matches=await reusePreflight([{key:s.key,value,path:s.path||'/',type:'secret'}],[s.id]);
    if(matches.length){reuseWarn(matches,()=>commitEdit(id,s,value,comment),()=>editRow(id,{value,comment}));return}
  }
  commitEdit(id,s,value,comment)}
async function overrideRow(id,key){modal(`<h3>${owHTML('Personal override: {x}',{x:key})}</h3><p class="mut" data-i18n="Only you see this value. Teammates keep the shared one.">Only you see this value. Teammates keep the shared one.</p><div class="field"><label for="ov-val" data-i18n="Your value">Your value</label><textarea id="ov-val" rows="3"></textarea></div><div class="row"><button class="primary" onclick="saveOverride('${jsq(id)}')" data-i18n="Save override">Save override</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>`,'Personal override')}
async function saveOverride(id){try{await api('POST',`/api/secrets/${id}/override`,{secrets:[{key:'x',value:$('ov-val').value}]});closeModal();toastUI('Override saved', false);renderEnv()}catch(e){toast(e.message,true)}}
async function delSecret(id,key){let d=drafts()[id];
  if(d&&d.isNew){delete drafts()[id];drawSecrets();updateDeployBar();return}
  let s=SECRETS.find(x=>x.id===id);if(s&&s.type==='sealed'&&!confirm(owT('Delete sealed secret {x}? Its value cannot be recovered.',{x:key})))return;
  if(!confirm(owT('Delete {x}? You can restore it from history.',{x:key})))return;
  try{await api('DELETE',`/api/secrets/${id}`);delete drafts()[id];toastUI('Secret deleted', false);await renderEnv()}catch(e){toast(e.message,true)}}
function updateDeployBar(){let n=isE2E(ENV)?e2eDraftList().length:draftList().length;let active=VIEW==='env'&&!!ENV&&n>0&&!EMERGENCY&&!PROJECT_EMERGENCY;
  $('deploybar').classList.toggle('show',active);
  $('deploytext').innerHTML=active?(n===1?`<b>${n}</b>&nbsp;${owHTML('staged change')}`:owHTML('{n} staged changes',{n})):''}
function discardStage(){if(!ENV)return;delete DRAFTS[ENV.id];delete E2E_DRAFTS[ENV.id];
  if(isE2E(ENV))drawE2E();else drawSecrets();updateDeployBar()}
async function deployStage(){if(isE2E(ENV))return deployE2E();try{let items=draftList().map(s=>({key:s.key,value:s.value,path:s.path,type:s.type,comment:s.comment||''}));
  if(!items.length)return;let envId=ENV.id;
  let d=await api('PUT',`/api/envs/${envId}/secrets`,{secrets:items});
  if(ENV&&ENV.id===envId)delete DRAFTS[envId];
  toastUI(d.deployed===1?'Deployed {n} secret':'Deployed {n} secrets',{n:d.deployed}, false);await renderEnv()}catch(e){toast(e.message,true)}}
async function showHistory(id){try{let h=await api('GET',`/api/secrets/${id}/history`);
  modal(`<h3 data-i18n="History">History</h3>${h.length?h.map(v=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:8px 0"><span><b>v${v.version}</b> <span class="mut small">${new Date(v.created_at*1000).toLocaleString()}</span><br><span class="val">${esc(v.value)}</span></span><button onclick="restoreVer('${jsq(id)}',${v.version})" data-i18n="Restore">Restore</button></div>`).join(''):'<p class="mut" data-i18n="No history.">No history.</p>'}<div class="row" style="margin-top:12px"><button class="ghost" onclick="closeModal()" data-i18n="Close">Close</button></div>`,'Secret history')}catch(e){toast(e.message,true)}}
async function restoreVer(id,ver){try{await api('POST',`/api/secrets/${id}/restore/${ver}`,{});closeModal();toastUI('Restored version {n}',{n:ver}, false);renderEnv()}catch(e){toast(e.message,true)}}
function importModal(text){modal(`<h3>${owHTML('Import secrets into {x}',{x:ENV.name})}</h3><p class="mut" data-i18n="Paste .env contents. Existing keys are updated and versioned.">Paste .env contents. Existing keys are updated and versioned.</p><textarea id="imp-text" aria-label=".env contents" data-i18n-aria-label=".env contents" rows="10" placeholder="API_KEY=...&#10;# comment&#10;DATABASE_URL=postgres://…">${esc(text||'')}</textarea><div class="row" style="margin-top:12px"><button class="primary" onclick="doImport()" data-i18n="Import">Import</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>`)}
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
  try{let d=await api('POST',`/api/envs/${ENV.id}/import`,{text});closeModal();toastUI('Imported {n} secrets',{n:d.deployed}, false);renderEnv()}catch(e){toast(e.message,true)}}
async function exportEnv(){try{let d=await api('GET',`/api/envs/${ENV.id}/export`);modal(`<h3>${owHTML('Export {x}',{x:ENV.name})}</h3><textarea id="exp-text" aria-label="Exported secrets" data-i18n-aria-label="Exported secrets" rows="12" readonly>${esc(d.text)}</textarea><div class="row" style="margin-top:12px"><button onclick="navigator.clipboard.writeText(document.querySelector('#modal textarea').value);toastUI('Export copied', false)" data-i18n="Copy .env">Copy .env</button><button class="ghost" onclick="closeModal()" data-i18n="Close">Close</button></div>`)}catch(e){toast(e.message,true)}}

// ---------- access, integrations, audit, settings ----------
function needAppEnv(){if(!APP){toastUI('Open an app first', true);nav('apps');return false} return true}
async function renderAccess(){if(!ORG)return;let org=ORG,view=VIEW,accessSerial=++PRODUCT_RENDER;owText($('pagetitle'),'Members & access');owDataText($('crumb'),'');
  let teams=await api('GET',`/api/orgs/${org}/teams`).catch(()=>[]);let roles=await api('GET',`/api/orgs/${org}/roles`).catch(()=>[]);
  let members=await api('GET',`/api/orgs/${org}/members`).catch(()=>[]);let myRole=members.find(m=>m.id===ME?.id)?.role||'';
  let props=ENV?await api('GET',`/api/envs/${ENV.id}/proposals`).catch(()=>[]):[];
  let reqs=ENV?await api('GET',`/api/envs/${ENV.id}/access-requests`).catch(()=>[]):[];
  if(ORG!==org||accessSerial!==PRODUCT_RENDER||(view==='access'&&VIEW!=='access'))return;
  $('view').innerHTML=`
  <div class="card"><h3 data-i18n="Members">Members</h3><p data-i18n="Owners can transfer ownership; admins manage roles. A workspace always keeps at least one owner.">Owners can transfer ownership; admins manage roles. A workspace always keeps at least one owner.</p>
  <table class="members-table"><thead><tr><th data-i18n="Member">Member</th><th data-i18n="Role">Role</th><th></th></tr></thead><tbody>
  ${members.map(m=>`<tr><td>${esc(m.email)}${m.id===ME?.id?' <span class="chip" data-i18n="you">you</span>':''}</td><td><select aria-label="Role for ${esc(m.email)}" onchange="setMemberRole('${jsq(m.id)}',this.value)">${roles.map(r=>`<option value="${esc(r.name)}"${r.name===m.role?' selected':''}>${esc(r.name)}</option>`).join('')}</select></td><td>${m.role!=='owner'&&myRole==='owner'?`<button onclick="transferOwner('${jsq(m.id)}','${jsq(m.email)}')" data-i18n="Make owner">Make owner</button> `:''}${m.id!==ME?.id?`<button class="danger" onclick="removeMember('${jsq(m.id)}','${jsq(m.email)}')" data-i18n="Remove">Remove</button>`:''}</td></tr>`).join('')||'<tr><td colspan="3" class="mut" data-i18n="No members">No members</td></tr>'}
  </tbody></table></div>
  <div class="card"><h3 data-i18n="Invite member">Invite member</h3><p data-i18n="Existing accounts are added immediately. New addresses get a single-use link, valid for seven days, to set a password or sign in with a configured provider.">Existing accounts are added immediately. New addresses get a single-use link, valid for seven days, to set a password or sign in with a configured provider.</p><div class="row"><label class="small mut" for="inv-email" data-i18n="Email">Email</label><input id="inv-email" type="email" placeholder="teammate@company.com" style="min-width:240px"><label class="small mut" for="inv-role" data-i18n="Role">Role</label><select id="inv-role">${roles.map(r=>`<option value="${esc(r.name)}"${r.name==='developer'?' selected':''}>${esc(r.name)}</option>`).join('')}</select><button class="primary" onclick="invite()" data-i18n="Invite">Invite</button></div></div>
  <div class="card"><h3 data-i18n="Custom roles">Custom roles</h3><p><span data-i18n="Comma-separated permissions, for example">Comma-separated permissions, for example</span> <span class="mono">secrets:read</span> <span data-i18n="or">or</span> <span class="mono">*</span>.</p><div class="row"><input id="role-name" placeholder="deployer"><input id="role-perms" placeholder="secrets:read,secrets:write" style="min-width:260px"><button onclick="mkRole()" data-i18n="Create role">Create role</button></div><div>${roles.map(r=>`<span class="chip">${esc(r.name)}: ${esc((r.permissions||[]).join(', '))}${r.managed?' '+owHTML('(managed)'):''}</span>`).join('')}</div></div>
  <div class="card"><h3 data-i18n="Teams">Teams</h3><div class="row"><input id="team-name" placeholder="platform-team"><button onclick="mkTeam()" data-i18n="Create team">Create team</button></div><div>${teams.map(t=>`<span class="chip">${esc(t.name)}</span>`).join('')||'<span class="mut" data-i18n="No teams yet">No teams yet</span>'}</div></div>
  <div class="card"><h3><span data-i18n="Secret change proposals">Secret change proposals</span> ${ENV?('· '+esc(ENV.name)):''}</h3><p data-i18n="Proposals stage secret changes for admin approval instead of deploying directly.">Proposals stage secret changes for admin approval instead of deploying directly.</p>
  ${props.length?props.map(p=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:7px 0"><span class="mono small">${esc(p.id.slice(0,8))} · ${esc(p.status)} · by ${esc(String(p.author).slice(0,8))}</span>${p.status==='pending'?`<span><button onclick="decideProp('${p.id}','approve')" data-i18n="Approve">Approve</button> <button class="danger" onclick="decideProp('${p.id}','reject')" data-i18n="Reject">Reject</button></span>`:''}</div>`).join(''):'<span class="mut" data-i18n="No proposals">No proposals</span>'}
  <div class="row" style="margin-top:12px"><button onclick="proposeModal()" data-i18n="New proposal">New proposal</button></div></div>
  <div class="card"><h3><span data-i18n="Access requests">Access requests</span> ${ENV?('· '+esc(ENV.name)):''}</h3>
  ${reqs.length?reqs.map(r=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:7px 0"><span class="small">${esc(r.reason||'access')} · ${esc(r.status)}</span>${r.status==='pending'?`<span><button onclick="decideAccess('${r.id}','approve')" data-i18n="Approve">Approve</button> <button class="danger" onclick="decideAccess('${r.id}','reject')" data-i18n="Reject">Reject</button></span>`:''}</div>`).join(''):'<span class="mut" data-i18n="No requests">No requests</span>'}
  <div class="row" style="margin-top:12px"><button onclick="requestAccess()" data-i18n="Request access to current env">Request access to current env</button></div></div>
  <div class="card"><h3 data-i18n="Machine identities">Machine identities</h3><p data-i18n="For CI and workloads. Universal Auth exchanges client credentials for a 1-hour token.">For CI and workloads. Universal Auth exchanges client credentials for a 1-hour token.</p><div class="row"><input id="id-name" placeholder="github-actions"><button onclick="mkIdentity()" data-i18n="Create identity">Create identity</button></div><pre class="val" id="ident-out"></pre></div>
  <div class="card"><h3><span data-i18n="Service tokens">Service tokens</span> ${APP?('· '+esc(APP.name)):''}</h3><div class="row"><button onclick="mkToken()" data-i18n="Create token">Create token</button><button onclick="loadTokens()" data-i18n="List / revoke">List / revoke</button></div><pre class="val" id="tok-out"></pre><div id="tok-list"></div></div><div id="product-tools"></div>`;await renderProductTools(org,myRole)}
let PRODUCT_ROLE='', PRODUCT_RENDER=0;
function productActive(d){return d&&PRODUCT_DIALOG===d&&d.org===ORG&&modalOpen()}
function productModal(html,label,context){modal(html,label);PRODUCT_DIALOG=context}
async function renderProductTools(org,role){
  // Direct renderAccess() callers outside the access view must not fetch product data.
  if(VIEW!=='access')return;
  let serial=++PRODUCT_RENDER;PRODUCT_ROLE=role||PRODUCT_ROLE;let admin=['owner','admin'].includes(PRODUCT_ROLE);
  let [requests,identities,keys]=await Promise.all([api('GET',`/api/orgs/${org}/change-requests`).catch(()=>[]),api('GET',`/api/orgs/${org}/identities`).catch(()=>[]),api('GET',`/api/orgs/${org}/transit/keys`).catch(()=>[])]);
  if(org!==ORG||VIEW!=='access'||serial!==PRODUCT_RENDER||!$('product-tools'))return;
  $('product-tools').innerHTML=`<div class="card"><h3>Batched change requests</h3><p>Stage changes across server-readable environments for separate review and approval.</p>${requests.map(r=>`<div class="row"><span>${esc(r.title)} · ${esc(r.status)} · revision ${esc(r.revision)}</span><button onclick="productRequestModal('${jsq(r.id)}')">Review</button></div>`).join('')||'<p class="mut">No change requests.</p>'}<button onclick="productRequestModal()">New change request</button></div>
  <div class="card"><h3>Workload trust</h3><p>Bind a workload identity to one environment and explicit claims.</p>${admin?(identities.map(i=>`<div class="row"><span>${esc(i.name)}</span><button onclick="productTrustModal('${jsq(i.id)}')">Manage trust</button></div>`).join('')||'<p class="mut">No machine identities yet. Create one in the Machine identities card above, then bind its trust here.</p><button onclick="focusIdentityCreate()">Create machine identity</button>'):'<p class="mut">Workspace administrators manage trust.</p>'}</div>
  <div class="card"><h3>Transit encryption</h3><p>Encrypt, decrypt or rewrap with a workspace key.</p>${keys.map(k=>`<div class="row"><span>${esc(k.name)} · version ${esc(k.current_version)}</span><button onclick="productTransitModal('${jsq(k.id)}')">Operate</button>${admin?`<button onclick="rotateProductKey('${jsq(k.id)}')">Rotate</button>`:''}</div>`).join('')}${admin?'<button onclick="newProductKey()">New transit key</button>':''}<button onclick="productTransitModal('')">Use key ID</button></div>`}
function focusIdentityCreate(){let i=$('id-name');if(!i)return;i.scrollIntoView({block:'center'});i.focus();toastUI('Name the identity, then choose Create identity', false)}
function productRequestEditor(d,title,changes){productModal(`<h3>${d.id?'Edit revision':'New change request'}</h3><div class="field"><label for="product-title">Title</label><input id="product-title" value="${esc(title||'')}"></div><div class="field"><label for="product-changes">Changes JSON</label><textarea id="product-changes" rows="10">${esc(changes||'[]')}</textarea></div><p class="small mut">Array of environments: [{"env_id":"...","secrets":[{"key":"NAME","value":"...","path":"/"}],"deletes":[]}]. Server-readable environments only.</p><div class="row"><button class="primary" onclick="saveProductRequest()">Save</button><button onclick="closeModal()">Cancel</button></div>`,'Change request',d)}
async function productRequestModal(id){let org=ORG,serial=++PRODUCT_SERIAL;if(!id){productRequestEditor({org},'', '[]');return}try{
  let r=await api('GET',`/api/change-requests/${encodeURIComponent(id)}`);if(org!==ORG||serial!==PRODUCT_SERIAL||VIEW!=='access')return;
  let d={org,id,revision:r.revision};let admin=['owner','admin'].includes(PRODUCT_ROLE),editable=r.author===MY_UID&&['pending','approved'].includes(r.status);
  let items=(r.changes||[]).map(c=>`<h4>Environment ${esc(c.env_id)}</h4>${(c.items||[]).map(i=>`<div class="field"><b>${esc(i.key)} · ${esc(i.path)}</b><div>Before: ${i.before===null?'Absent':esc(i.before?.value===null?'Sealed / redacted':i.before?.value)}</div><div>After: ${i.after===null?'Deleted':esc(i.after?.value===null?'Sealed / redacted':i.after?.value)}</div></div>`).join('')}`).join('');
  d.changes=(r.changes||[]).map(c=>({env_id:c.env_id,secrets:(c.items||[]).filter(i=>i.after!==null).map(i=>({...i.after,key:i.key,path:i.path})),deletes:(c.items||[]).filter(i=>i.after===null).map(i=>({key:i.key,path:i.path}))}));d.sealed=(r.changes||[]).some(c=>(c.items||[]).some(i=>i.after!==null&&i.after?.value===null));
  productModal(`<h3>${esc(r.title)}</h3><p>Revision ${esc(r.revision)} · ${esc(r.status)}</p>${items}<div class="row">${editable?`<button onclick="editProductRequest()">Edit revision</button>`:''}${admin&&r.author!==MY_UID&&r.status==='pending'?`<button onclick="productRequestAction('${jsq(id)}',${Number(r.revision)},'approve')">Approve</button>`:''}${admin&&r.author!==MY_UID&&r.status==='approved'?`<button onclick="productRequestAction('${jsq(id)}',${Number(r.revision)},'apply')">Apply</button>`:''}${admin&&['pending','approved'].includes(r.status)?`<button onclick="productRequestAction('${jsq(id)}',${Number(r.revision)},'reject')">Reject</button>`:''}<button onclick="closeModal()">Close</button></div>`,'Review change request',d);d.title=r.title;
}catch(e){if(org===ORG&&serial===PRODUCT_SERIAL)toast(e.message,true)}}
function editProductRequest(){let d=PRODUCT_DIALOG;if(!productActive(d))return;if(d.sealed)toast('Sealed values are redacted. Re-enter them in the revised changes.',true);productRequestEditor(d,d.title,JSON.stringify(d.changes,null,2))}
async function saveProductRequest(){let d=PRODUCT_DIALOG;if(!productActive(d))return;try{let changes=JSON.parse($('product-changes').value),body={title:$('product-title').value,changes};if(d.id)body.revision=d.revision;await api(d.id?'PUT':'POST',d.id?`/api/change-requests/${encodeURIComponent(d.id)}`:`/api/orgs/${d.org}/change-requests`,body);if(!productActive(d))return;closeModal();toast('Change request saved');await renderAccess()}catch(e){if(productActive(d))toast(e.message,true)}}
async function productRequestAction(id,revision,action){let org=ORG,d=PRODUCT_DIALOG;if(d&&(!productActive(d)||d.id!==id||d.revision!==revision))return;try{let result=await api('POST',`/api/change-requests/${encodeURIComponent(id)}/${action}`,{revision});if(org!==ORG||(d&&PRODUCT_DIALOG!==d))return;if(d)closeModal();toast(result.sync_errors&&Object.values(result.sync_errors).some(x=>Array.isArray(x)&&x.length)?'Applied; provider sync reported errors':'Request '+result.status);await renderAccess()}catch(e){if(org===ORG&&(!d||PRODUCT_DIALOG===d))toast(e.message,true)}}
async function productTrustModal(identity){let org=ORG,serial=++PRODUCT_SERIAL;try{
  let [trusts,apps]=await Promise.all([api('GET',`/api/orgs/${org}/identities/${encodeURIComponent(identity)}/workload-trust`),api('GET',`/api/orgs/${org}/apps`)]);let envs=[];for(let app of apps){let list=await api('GET',`/api/apps/${encodeURIComponent(app.id)}/envs`);envs.push(...list.map(e=>({id:e.id,name:app.name+' / '+e.name})))}
  if(org!==ORG||serial!==PRODUCT_SERIAL||VIEW!=='access')return;let d={org,identity};
  productModal(`<h3>Workload trust</h3>${trusts.map(t=>`<div class="row"><span>${esc(t.issuer)} · ${esc(t.subject)} · ${esc(t.env_id)} ${t.revoked?'(revoked)':''}</span>${!t.revoked?`<button onclick="revokeProductTrust('${jsq(identity)}','${jsq(t.id)}')">Revoke trust</button>`:''}</div>`).join('')}<div class="field"><label for="pt-env">Environment</label><select id="pt-env"><option value="">Choose environment</option>${envs.map(e=>`<option value="${esc(e.id)}">${esc(e.name)}</option>`).join('')}</select></div>${[['issuer','Issuer'],['audience','Audience'],['subject','Subject'],['scopes','Scopes (comma separated)'],['ttl','TTL seconds']].map(([id,label])=>`<div class="field"><label for="pt-${id}">${label}</label><input id="pt-${id}" ${id==='ttl'?'value="300"':''}></div>`).join('')}<div class="field"><label for="pt-jwks">Public JWKS JSON</label><textarea id="pt-jwks" rows="4"></textarea></div><div class="field"><label for="pt-claims">Bound claims JSON</label><textarea id="pt-claims" rows="3">{}</textarea></div><div class="row"><button class="primary" onclick="saveProductTrust()">Create trust</button><button onclick="closeModal()">Close</button></div>`,'Workload trust',d)
}catch(e){if(org===ORG&&serial===PRODUCT_SERIAL)toast(e.message,true)}}
async function saveProductTrust(){let d=PRODUCT_DIALOG;if(!productActive(d)||!d.identity)return;try{let body={issuer:$('pt-issuer').value,audience:$('pt-audience').value,subject:$('pt-subject').value,env_id:$('pt-env').value,scopes:$('pt-scopes').value.split(/[\s,]+/).filter(Boolean),ttl:Number($('pt-ttl').value),jwks:JSON.parse($('pt-jwks').value),bound_claims:JSON.parse($('pt-claims').value)};if(!body.env_id)throw Error('Choose an environment');await api('POST',`/api/orgs/${d.org}/identities/${encodeURIComponent(d.identity)}/workload-trust`,body);if(!productActive(d))return;toast('Trust created');await productTrustModal(d.identity)}catch(e){if(productActive(d))toast(e.message,true)}}
async function revokeProductTrust(identity,id){let d=PRODUCT_DIALOG;if(!productActive(d)||d.identity!==identity)return;try{await api('DELETE',`/api/orgs/${d.org}/identities/${encodeURIComponent(identity)}/workload-trust/${encodeURIComponent(id)}`);if(!productActive(d))return;toast('Trust revoked');await productTrustModal(identity)}catch(e){if(productActive(d))toast(e.message,true)}}
function newProductKey(){let d={org:ORG};productModal(`<h3>New transit key</h3><div class="field"><label for="pk-name">Name</label><input id="pk-name"></div><div class="row"><button onclick="saveProductKey()">Create key</button><button onclick="closeModal()">Cancel</button></div>`,'New transit key',d)}
async function saveProductKey(){let d=PRODUCT_DIALOG;if(!productActive(d))return;try{await api('POST',`/api/orgs/${d.org}/transit/keys`,{name:$('pk-name').value});if(!productActive(d))return;closeModal();toast('Key created');await renderAccess()}catch(e){if(productActive(d))toast(e.message,true)}}
async function rotateProductKey(key){let org=ORG;try{await api('POST',`/api/orgs/${org}/transit/keys/${encodeURIComponent(key)}/rotate`,{});if(org!==ORG)return;toast('Key rotated');await renderAccess()}catch(e){if(org===ORG)toast(e.message,true)}}
function productTransitModal(key){let d={org:ORG,key};productModal(`<h3>Transit operation</h3><div class="field"><label for="tr-key">Key ID</label><input id="tr-key" oninput="invalidateProductTransit()" onchange="invalidateProductTransit()" value="${esc(key||'')}" ${key?'readonly':''}></div><div class="field"><label for="tr-action">Operation</label><select id="tr-action" onchange="clearProductTransit()"><option value="encrypt">Encrypt</option><option value="decrypt">Decrypt</option><option value="rewrap">Rewrap</option></select></div><div class="field"><label for="tr-context">Context</label><input id="tr-context" oninput="invalidateProductTransit()" onchange="invalidateProductTransit()"></div><div class="field"><label for="tr-input">Input (base64 plaintext for encrypt; ciphertext otherwise)</label><textarea id="tr-input" rows="4" oninput="invalidateProductTransit()" onchange="invalidateProductTransit()"></textarea></div><p class="small mut">Use the same context for encryption and decryption. Plaintext is base64 encoded.</p><div class="row"><button onclick="runProductTransit()">Run operation</button><button onclick="closeModal()">Close</button></div><pre class="val" id="tr-output"></pre>`,'Transit operation',d)}
function invalidateProductTransit(){let d=PRODUCT_DIALOG;if(!productActive(d))return;d.operation=(d.operation||0)+1;if($('tr-output'))$('tr-output').textContent=''}
function clearProductTransit(){invalidateProductTransit();if($('tr-input'))$('tr-input').value=''}
async function runProductTransit(){let d=PRODUCT_DIALOG;if(!productActive(d)||!$('tr-action'))return;invalidateProductTransit();let operation=d.operation,action=$('tr-action').value,key=$('tr-key').value,context=$('tr-context').value,input=$('tr-input').value;let current=()=>productActive(d)&&d.operation===operation&&$('tr-action').value===action&&$('tr-key').value===key&&$('tr-context').value===context&&$('tr-input').value===input;try{let body={context};body[action==='encrypt'?'plaintext':'ciphertext']=input;let result=await api('POST',`/api/orgs/${d.org}/transit/keys/${encodeURIComponent(key)}/${action}`,body);if(!current())return;$('tr-output').textContent=result.plaintext??result.ciphertext}catch(e){if(current())toast(e.message,true)}}
async function invite(){try{let d=await api('POST',`/api/orgs/${ORG}/members`,{email:$('inv-email').value,role:$('inv-role').value});
  if(d.invite_token){let link=location.origin+'/#invite='+encodeURIComponent(d.invite_token);
    modal(`<h3 data-i18n="Invitation created">Invitation created</h3><p class="mut">${owHTML('Send this single-use link to {x}. It expires in 7 days.',{x:$('inv-email').value})}</p><textarea rows="3" readonly>${esc(link)}</textarea><div class="row" style="margin-top:12px"><button onclick="navigator.clipboard.writeText(document.querySelector('#modal textarea').value);toastUI('Invite link copied', false)" data-i18n="Copy link">Copy link</button><button class="primary" onclick="closeModal()" data-i18n="Done">Done</button></div>`);}
  else toastUI('Member added', false);
  $('inv-email').value='';renderAccess()}catch(e){toast(e.message,true)}}
async function setMemberRole(uid,role){try{await api('PATCH',`/api/orgs/${ORG}/members/${uid}`,{role});toastUI('Role updated', false);renderAccess()}catch(e){toast(e.message,true);renderAccess()}}
async function removeMember(uid,email){if(!confirm(`Remove ${email} from this workspace?`))return;try{await api('DELETE',`/api/orgs/${ORG}/members/${uid}`);toastUI('Member removed', false);renderAccess()}catch(e){toast(e.message,true)}}
async function transferOwner(uid,email){if(!confirm(`Make ${email} the owner? You become an admin and lose owner controls.`))return;try{await api('POST',`/api/orgs/${ORG}/transfer`,{user_id:uid});toastUI('Ownership transferred', false);await refreshOrgs();renderAccess()}catch(e){toast(e.message,true)}}
async function mkRole(){try{await api('POST',`/api/orgs/${ORG}/roles`,{name:$('role-name').value,permissions:$('role-perms').value.split(',').map(s=>s.trim()).filter(Boolean)});toastUI('Role created', false);renderAccess()}catch(e){toast(e.message,true)}}
async function mkTeam(){try{await api('POST',`/api/orgs/${ORG}/teams`,{name:$('team-name').value});toastUI('Team created', false);renderAccess()}catch(e){toast(e.message,true)}}
async function decideProp(id,a){try{let d=await api('POST',`/api/proposals/${id}/${a}`,{});toastUI('Proposal {x}',{x:d.status}, false);renderAccess()}catch(e){toast(e.message,true)}}
function proposeModal(){modal(`<h3>${owHTML('New proposal for {x}',{x:ENV.name})}</h3><textarea id="pr-text" rows="8" placeholder="KEY=value per line" data-i18n-placeholder="KEY=value per line"></textarea><div class="row" style="margin-top:12px"><button class="primary" onclick="submitProposal()" data-i18n="Submit for approval">Submit for approval</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>`)}
async function submitProposal(){try{let secrets=$('pr-text').value.split('\n').filter(l=>l.includes('=')).map(l=>{let i=l.indexOf('=');return{key:l.slice(0,i).trim(),value:l.slice(i+1)}});await api('POST',`/api/envs/${ENV.id}/proposals`,{secrets});closeModal();toastUI('Proposal submitted', false);renderAccess()}catch(e){toast(e.message,true)}}
async function decideAccess(id,a){try{await api('POST',`/api/access-requests/${id}/${a}`,{});toastUI('Request '+a+'d', false);renderAccess()}catch(e){toast(e.message,true)}}
async function requestAccess(){try{await api('POST',`/api/envs/${ENV.id}/access-requests`,{reason:'requested from console'});toastUI('Access requested', false);renderAccess()}catch(e){toast(e.message,true)}}
async function mkIdentity(){try{let d=await api('POST',`/api/orgs/${ORG}/identities`,{name:$('id-name').value||'machine'});$('ident-out').textContent=`client_id: ${d.client_id}\nclient_secret: ${d.client_secret}\nShown once. Exchange at POST /api/v1/machine/auth/universal/login`}catch(e){toast(e.message,true)}}
async function mkToken(){try{let d=await api('POST',`/api/apps/${APP.id}/tokens`,{name:'console',env_id:ENV?ENV.id:''});$('tok-out').innerHTML=esc(d.token)+'\n'+owHTML('Scoped to env: {x}',{x:ENV?ENV.name:'all'})}catch(e){toast(e.message,true)}}
async function loadTokens(){try{let toks=await api('GET',`/api/apps/${APP.id}/tokens`);$('tok-list').innerHTML=toks.map(t=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:6px 0"><span class="mono small">${esc(t.name)} · ${esc(t.kind||'token')} · ${new Date((t.created_at||0)*1000).toLocaleDateString()}</span><button class="danger" onclick="revokeToken('${t.id}')" data-i18n="Revoke">Revoke</button></div>`).join('')||'<span class="mut" data-i18n="No tokens">No tokens</span>'}catch(e){toast(e.message,true)}}
async function revokeToken(id){try{await api('DELETE',`/api/tokens/${id}`);toastUI('Token revoked', false);loadTokens()}catch(e){toast(e.message,true)}}

const KINDS=['trigger','github','gitlab','vercel','netlify','cloudflare','cloudflare_pages','supabase','nomad','coolify','heroku','render','flyio','railway','digitalocean','gcp_secret_manager','azure_key_vault','kubernetes','hashicorp_vault','aws_secrets_manager','aws_parameter_store','1password','dokploy','caprover','portainer','docker_swarm','bitbucket','circleci','teamcity','travisci','terraform_cloud','qovery','laravel_forge','openwarp','devin','cloudflare_secrets_store','octopus_deploy','azure_devops','cursor','northflank','spacelift','rundeck','cloud66','humanitec','ovh_kms','scaleway_secret_manager','azure_app_configuration','vultr','hetzner','linode','digitalocean_ssh','ssh','keeper','oci_vault','huggingface','webhook','instabox','boat','daytona'];
async function renderIntegrations(){if(!needAppEnv())return;setTimeout(kindHint,0);owText($('pagetitle'),'Integrations');owDataText($('crumb'),ENV?('/ '+ENV.name):'');
  let ints=ENV?await api('GET',`/api/envs/${ENV.id}/integrations`).catch(()=>[]):[];
  $('view').innerHTML=`<div class="card"><h3 data-i18n="Sync secrets to a platform">Sync secrets to a platform</h3><p><span data-i18n="Integrations run automatically on every deploy, or on demand. Config is stored encrypted. Trigger.dev example config:">Integrations run automatically on every deploy, or on demand. Config is stored encrypted. Trigger.dev example config:</span> <span class="mono">{"token":"tr_pat_…","project_ref":"proj_…","target_env":"prod"}</span></p>
  <div class="row"><select id="ikind" onchange="kindHint()">${KINDS.map(k=>`<option>${k}</option>`).join('')}</select></div>
  <p class="small" id="ikind-hint"></p><textarea id="icfg" rows="4" placeholder='{"token":"…"}'></textarea>
  <div class="row" style="margin-top:10px"><button class="primary" onclick="mkIntegration()" data-i18n="Add integration">Add integration</button></div></div>
  <div class="card"><h3><span data-i18n="Configured">Configured</span> ${ENV?('· '+esc(ENV.name)):''}</h3>${ints.length?ints.map(i=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:8px 0"><span><b>${esc(i.kind)}</b> <span class="mut small">${esc(i.name||'')}</span></span><span><button onclick="testInt('${i.id}')" data-i18n="Test">Test</button> <button class="primary" onclick="syncInt('${i.id}')" data-i18n="Sync now">Sync now</button> <button class="danger" onclick="delInt('${i.id}')" data-i18n="Delete">Delete</button></span></div>`).join(''):'<span class="mut" data-i18n="None yet">None yet</span>'}</div>
  <div class="card"><h3 data-i18n="Dynamic secrets &amp; rotation">Dynamic secrets &amp; rotation</h3><div class="row"><input id="lease-name" placeholder="lease name"><select id="lease-type"><option value="generic">generic</option><option value="openrouter">openrouter</option><option value="resend">resend</option><option value="openai">openai</option><option value="huggingface">huggingface</option><option value="fireworks">fireworks</option><option value="mistral">mistral</option><option value="perplexity">perplexity</option><option value="xai">xai</option><option value="gemini">gemini</option><option value="cloudflare">cloudflare</option><option value="deepgram">deepgram</option><option value="elevenlabs">elevenlabs</option><option value="deepinfra">deepinfra</option><option value="baseten">baseten</option><option value="fal">fal</option><option value="speechmatics">speechmatics</option><option value="chutes">chutes</option><option value="aws_iam">aws_iam</option><option value="postgres">postgres</option><option value="mysql">mysql</option></select><button onclick="mkLease()" data-i18n="New lease (1h)">New lease (1h)</button><button onclick="loadLeases()" data-i18n="Show leases">Show leases</button></div><textarea id="lease-cfg" rows="2" placeholder='provider config, e.g. {"management_key":"…"} or {"connection":"mysql://…","grants":["SELECT ON app.*"]}'></textarea><pre class="val" id="leases"></pre>
  <div class="row"><input id="rot-key" placeholder="KEY_TO_ROTATE"><span class="row"><input id="rot-int" value="86400" size="8"><span class="mut small" data-i18n="seconds between rotations">seconds between rotations</span></span><button onclick="mkRotation()" data-i18n="Schedule rotation">Schedule rotation</button></div></div>
  <div class="card"><h3 data-i18n="Lockbox: one-time secret sharing">Lockbox: one-time secret sharing</h3><div class="row"><input id="lb-val" placeholder="value to share once" style="min-width:280px"><button onclick="mkLockbox()" data-i18n="Create link">Create link</button></div><pre class="val" id="lb-out"></pre></div>`}
const KIND_HINTS={trigger:'Trigger.dev: {"token":"tr_pat_… or tr_prod_sk_…","project_ref":"proj_…","target_env":"prod"}',github:'GitHub: {"token":"ghp_…","owner":"org","repo":"repo"}',gitlab:'GitLab: {"token":"glpat-…","project_id":"42"}',webhook:'Webhook: {"url":"https://…","token":"optional bearer","signing_secret":"optional HMAC key"}',azure_app_configuration:'Azure App Configuration: {"endpoint":"https://store.azconfig.io","id":"access key id","secret":"base64 access key","label":"optional"}',scaleway_secret_manager:'Scaleway Secret Manager: {"region":"fr-par","secret_key":"…","project_id":"…","path":"/app"}',vultr:'Vultr SSH keys: {"api_key":"…"} (each secret value must be an OpenSSH public key)',hetzner:'Hetzner SSH keys: {"token":"…"} (syncs secrets of type ssh_key; a changed key is recreated)',linode:'Linode SSH keys: {"token":"…"} (syncs secrets of type ssh_key; a changed key is recreated)',digitalocean_ssh:'DigitalOcean account SSH keys: {"token":"…"} (syncs secrets of type ssh_key; distinct from digitalocean, which updates an App Platform spec)',ssh:'SSH file: {"host":"app.example.com","user":"deploy","identity_file":"/keys/deploy","known_hosts":"ssh-ed25519 AAAA…","files":[{"path":"/srv/app/.env","format":"dotenv","folders":["/app"]}]}',kubernetes:'Kubernetes: {"api_server":"https://…","token":"…","namespace":"default","secret_name":"app-secrets"}',aws_secrets_manager:'AWS Secrets Manager: {"region":"us-east-1","access_key_id":"…","secret_access_key":"…","mapping":"one_to_one"} or add "secret_id":"app/prod" for one JSON secret',aws_parameter_store:'AWS Parameter Store: {"region":"us-east-1","access_key_id":"…","secret_access_key":"…","path_prefix":"/app/prod"}','1password':'1Password Connect: {"connect_url":"https://connect.example.com","token":"…","vault_id":"…","value_label":"value"}',dokploy:'Dokploy: {"base_url":"https://dokploy.example.com","api_key":"…","application_id":"…"} or "compose_id"',caprover:'CapRover: {"base_url":"https://captain.example.com","password":"…","app_name":"app"}',portainer:'Portainer: {"base_url":"https://portainer.example.com:9443","api_key":"…","endpoint_id":1,"stack_id":1}',docker_swarm:'Docker Swarm: {"api_url":"https://docker.example.com:2376","ca_cert":"PEM","client_cert":"PEM","client_key":"PEM"}',bitbucket:'Bitbucket: {"workspace":"…","repo_slug":"…","token":"…"}',circleci:'CircleCI: {"project_slug":"gh/org/repo","token":"…"}',teamcity:'TeamCity: {"base_url":"https://teamcity.example.com","token":"…","project_locator":"_Root"}',travisci:'Travis CI: {"repo":"owner/repo","token":"…"}',terraform_cloud:'Terraform Cloud: {"token":"…","workspace_id":"ws-…","category":"env"}',qovery:'Qovery: {"token":"…","organization_id":"…","project_id":"…","environment_id":"…"}',laravel_forge:'Laravel Forge: {"token":"…","organization":"org","server_id":1,"site_id":1}',openwarp:'OpenWarp: {"base_url":"https://other-openwarp.example.com","token":"…","env_id":"…"}',devin:'Devin: {"token":"cog_…","org_id":"org-…"}',cloudflare_secrets_store:'Cloudflare Secrets Store: {"token":"…","account_id":"…","store_id":"…","scopes":["workers"]}',octopus_deploy:'Octopus Deploy: {"base_url":"https://octopus.example.com","api_key":"API-…","space_id":"Spaces-1","project_id":"Projects-123"}',azure_devops:'Azure DevOps: {"organization":"org","project":"project","group_id":"1","token":"PAT"}',cursor:'Cursor: {"token":"…","environment_id":"…"} (omit environment_id for team secrets)',northflank:'Northflank: {"token":"…","project_id":"…","secret_group_id":"…"}',spacelift:'Spacelift: {"token":"…","stack_id":"…"} (or "account":"…")',rundeck:'Rundeck: {"instance_url":"https://rundeck.example.com","api_token":"…","project":"proj"}',cloud66:'Cloud 66: {"access_token":"…","stack_id":"…"}',humanitec:'Humanitec: {"api_token":"…","org":"org","app":"app","scope":"application"}',ovh_kms:'OVHcloud KMS: {"okms_domain":"https://kms.example.com","okms_id":"…","token":"…","path":"app"}',keeper:'Keeper: {"instance_url":"https://keeper.example.com","api_key":"…","folder_uid":"…"}',huggingface:'Hugging Face Space: {"token":"hf_…","namespace":"org","repo":"space","target":"secrets"} (or "variables")',oci_vault:'OCI Vault: {"tenancy_ocid":"…","user_ocid":"…","fingerprint":"…","private_key":"PEM","region":"us-ashburn-1","compartment_id":"…","vault_id":"…","key_id":"…"}',instabox:'Instabox: {"api_key":"ibk_…","org":"team","hosts":["api.example.com"],"delivery":"proxy"}',boat:'Boat: {"api_key":"boat_…","environment":"base","upgrade":true}',daytona:'Daytona: {"api_key":"…","organization_id":"…","hosts":["api.example.com"]}'};
function kindHint(){if(!$('ikind'))return;let k=$('ikind').value;KIND_HINTS[k]?owDataText($('ikind-hint'),KIND_HINTS[k]):owText($('ikind-hint'),'Config for {x} as JSON. Common keys: token, base_url for self-hosted instances. Stored encrypted at rest.',{x:k})}
async function mkIntegration(){try{await api('POST',`/api/envs/${ENV.id}/integrations`,{kind:$('ikind').value,config:JSON.parse($('icfg').value||'{}')});toastUI('Integration added', false);renderIntegrations()}catch(e){toast(e.message,true)}}
async function testInt(id){try{let d=await api('POST',`/api/integrations/${id}/test`,{});toast(d.detail)}catch(e){toast(e.message,true)}}
async function syncInt(id){try{let d=await api('POST',`/api/integrations/${id}/sync`,{});toast(d.detail)}catch(e){toast(e.message,true)}}
async function delInt(id){if(!confirm(owT('Delete this integration? Sync state for it is removed too.')))return;try{await api('DELETE',`/api/integrations/${id}`);toastUI('Integration deleted', false);renderIntegrations()}catch(e){toast(e.message,true)}}
async function mkLease(){try{let body={name:$('lease-name').value||'lease',type:$('lease-type').value};if($('lease-cfg').value.trim())body.config=JSON.parse($('lease-cfg').value);let d=await api('POST',`/api/envs/${ENV.id}/dynamic`,body);$('leases').textContent=JSON.stringify(d,null,2)}catch(e){toast(e.message,true)}}
async function loadLeases(){try{let d=await api('GET',`/api/envs/${ENV.id}/dynamic`);$('leases').textContent=JSON.stringify(d,null,2)}catch(e){toast(e.message,true)}}
async function mkRotation(){try{await api('POST',`/api/envs/${ENV.id}/rotations`,{key:$('rot-key').value,interval_secs:parseInt($('rot-int').value)});toastUI('Rotation scheduled', false)}catch(e){toast(e.message,true)}}
async function mkLockbox(){try{let d=await api('POST','/api/lockbox',{text:$('lb-val').value});$('lb-out').textContent=location.origin+d.url+'\nOpens once, expires in 24h. The key is in the #fragment and never sent to the server on page load.'}catch(e){toast(e.message,true)}}

async function renderAudit(){owText($('pagetitle'),'Audit log');owDataText($('crumb'),'');
  let rows=await api('GET',`/api/orgs/${ORG}/audit`).catch(()=>[]);
  $('view').innerHTML=`<div class="card"><h3 data-i18n="Log streams">Log streams</h3><p data-i18n="Audit events are also forwarded to streams with HMAC-signed retries.">Audit events are also forwarded to streams with HMAC-signed retries.</p><div class="row"><input id="stream-url" placeholder="https://hooks.example.com/openwarp" style="min-width:300px"><button onclick="mkStream()" data-i18n="Add stream">Add stream</button><button onclick="loadDeliveries()" data-i18n="Delivery history">Delivery history</button></div><pre class="val" id="delivs"></pre></div>
  <table><thead><tr><th data-i18n="When">When</th><th data-i18n="Action">Action</th><th data-i18n="Actor">Actor</th><th data-i18n="Detail">Detail</th></tr></thead><tbody>${rows.map(r=>`<tr><td class="mut small">${new Date((r.created_at||0)*1000).toLocaleString()}</td><td class="mono">${esc(r.action)}</td><td class="mono small">${esc(String(r.actor||'').slice(0,10))}</td><td class="mut">${esc(r.detail||'')}</td></tr>`).join('')||'<tr><td colspan="4" class="mut" data-i18n="No events yet">No events yet</td></tr>'}</tbody></table>`}
async function mkStream(){try{await api('POST',`/api/orgs/${ORG}/log-streams`,{name:'console',url:$('stream-url').value});toastUI('Log stream added', false)}catch(e){toast(e.message,true)}}
async function loadDeliveries(){try{let d=await api('GET',`/api/orgs/${ORG}/log-streams/deliveries`);$('delivs').textContent=JSON.stringify(d.slice(0,25),null,2)}catch(e){toast(e.message,true)}}

async function renderSettings(){owText($('pagetitle'),'Settings');owDataText($('crumb'),'');
  if(EMERGENCY||PROJECT_EMERGENCY){$('view').innerHTML=emergencyCard()+(APP?emergencyCard(true):'');return}
  let inst=await api('GET','/api/instance').catch(()=>null);
  let s=await api('GET',`/api/orgs/${ORG}/settings`).catch(()=>null);
  let saml=await api('GET',`/api/orgs/${ORG}/saml`).catch(()=>null);
  let orgs=await api('GET','/api/orgs').catch(()=>[]);let myOrg=orgs.find(o=>o.id===ORG)||{};
  let samlCard=`<div class="card"><h3 data-i18n="SAML SSO">SAML SSO</h3><p><span data-i18n="Service provider metadata:">Service provider metadata:</span> <span class="mono">${esc(saml?.sp_metadata_url||'')}</span></p>
    <div class="field"><label for="set-saml-entity" data-i18n="IdP entity ID">IdP entity ID</label><input id="set-saml-entity" value="${esc(saml?.idp_entity_id||'')}" placeholder="https://idp.example/metadata"></div>
    <div class="field"><label for="set-saml-url" data-i18n="IdP metadata URL">IdP metadata URL</label><input id="set-saml-url" placeholder="https://idp.example/metadata.xml" style="width:100%"></div>
    <div class="field"><label for="set-saml-xml" data-i18n="or paste metadata XML">or paste metadata XML</label><textarea id="set-saml-xml" rows="4">${esc(saml?.metadata_xml||'')}</textarea></div>
    <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="set-saml-unsigned" ${saml?.allow_unsigned_metadata?'checked':''}> <span data-i18n="Allow unsigned metadata (not recommended)">Allow unsigned metadata (not recommended)</span></label>
    <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="set-saml-auto" ${saml?.auto_provision?'checked':''}> <span data-i18n="Auto-provision first-time users">Auto-provision first-time users</span></label>
    <div class="field"><label for="set-saml-domains" data-i18n="Allowed email domains">Allowed email domains</label><input id="set-saml-domains" value="${esc(saml?.allowed_domains||'')}" placeholder="example.com" style="width:100%"></div>
    <div class="row"><button class="primary" onclick="saveSaml()" data-i18n="Save SAML">Save SAML</button></div><pre class="val" id="saml-out"></pre></div>`;
  let prov=await api('GET','/api/auth/providers').catch(()=>null);
  let ldap=prov?.ldap?await api('GET',`/api/orgs/${ORG}/ldap`).catch(()=>null):null;
  let ldapCard=prov?.ldap?`<div class="card"><h3 data-i18n="LDAP directory">LDAP directory</h3><p data-i18n="Users sign in with directory credentials over TLS; a service account searches for the entry, then the entry&#39;s own password is bound. Native builds only.">Users sign in with directory credentials over TLS; a service account searches for the entry, then the entry's own password is bound. Native builds only.</p>
  <div class="field"><label for="ld-url" data-i18n="Directory URL (ldaps:// only)">Directory URL (ldaps:// only)</label><input id="ld-url" value="${esc(ldap?.url||'')}" placeholder="ldaps://dc01.example.com:636" style="width:100%"></div>
  <div class="row"><input id="ld-bind-dn" value="${esc(ldap?.bind_dn||'')}" placeholder="service bind DN" data-i18n-placeholder="service bind DN" style="min-width:280px"><input id="ld-bind-pw" type="password" placeholder="${ldap?.bind_password_set?'stored; leave blank to keep':'service account password'}" data-i18n-placeholder="${ldap?.bind_password_set?'stored; leave blank to keep':'service account password'}"></div>
  <div class="field"><label for="ld-base-dn" data-i18n="Base DN">Base DN</label><input id="ld-base-dn" value="${esc(ldap?.base_dn||'')}" placeholder="OU=People,DC=example,DC=com" style="width:100%"></div>
  <div class="field"><label for="ld-filter" data-i18n="User filter ({username} is escaped per RFC 4515)">User filter ({username} is escaped per RFC 4515)</label><input id="ld-filter" value="${esc(ldap?.user_filter||'(uid={username})')}" style="width:100%"></div>
  <div class="row"><input id="ld-email-attr" value="${esc(ldap?.email_attr||'mail')}" placeholder="mail"><input id="ld-name-attr" value="${esc(ldap?.name_attr||'displayName')}" placeholder="displayName"><input id="ld-group-attr" value="${esc(ldap?.group_attr||'memberOf')}" placeholder="memberOf"></div>
  <div class="field"><label for="ld-roles">Group to role map (Group=role;Group=role)</label><input id="ld-roles" value="${esc(ldap?.group_roles||'')}" placeholder="Admins=admin;Developers=developer" style="width:100%"></div>
  <div class="row"><input id="ld-default-role" value="${esc(ldap?.default_role||'developer')}" placeholder="default role"><input id="ld-domains" value="${esc(ldap?.allowed_domains||'')}" placeholder="allowed email domains" style="min-width:260px"></div>
  <div class="field"><label for="ld-ca" data-i18n="Internal CA certificate (PEM, optional)">Internal CA certificate (PEM, optional)</label><textarea id="ld-ca" rows="3">${esc(ldap?.ca_cert_pem||'')}</textarea></div>
  <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="ld-auto" ${ldap?.auto_provision?'checked':''}> <span data-i18n="Auto-provision first-time users in allowed domains">Auto-provision first-time users in allowed domains</span></label>
  <div class="row"><button class="primary" onclick="saveLdap()" data-i18n="Save LDAP">Save LDAP</button><button class="danger" onclick="removeLdap()" data-i18n="Remove">Remove</button></div></div>`:'';
  let instanceCard=inst&&inst.instance_owner?`<div class="card"><h3 data-i18n="Instance">Instance</h3><p data-i18n="Control who can create an account on this server.">Control who can create an account on this server.</p>
    <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="set-signups" ${inst.signups_open?'checked':''} ${inst.signups_env_locked?'disabled':''}> <span data-i18n="Allow self signup">Allow self signup</span></label>
    <p class="small mut"><span data-i18n="When off, new users join only by invitation.">When off, new users join only by invitation.</span> ${inst.signups_env_locked?owHTML('Locked by OPENWARP_SIGNUPS.'):''}</p>
    <button class="primary" onclick="saveSignups()" ${inst.signups_env_locked?'disabled':''} data-i18n="Save signup policy">Save signup policy</button>
    <div class="row" style="margin-top:12px"><label for="set-instance-owner" data-i18n="New instance owner email">New instance owner email</label><input id="set-instance-owner" type="email" style="min-width:260px"><button onclick="transferInstance()" data-i18n="Transfer instance">Transfer instance</button></div>
    <p class="small mut" style="margin-top:6px" data-i18n="The new owner needs an active, verified account. A solo instance can delete its only account once its workspace is gone.">The new owner needs an active, verified account. A solo instance can delete its only account once its workspace is gone.</p></div>`:'';
  let tp=themePref();
  let appearanceCard=`<div class="card"><h3 data-i18n="Appearance &amp; language">Appearance & language</h3><p data-i18n="Theme and language preferences are stored in this browser.">Theme and language preferences are stored in this browser.</p>
    <div class="row"><label class="small mut" for="set-theme" data-i18n="Theme">Theme</label><select id="set-theme" onchange="setTheme(this.value)">
    <option value="system"${tp==='system'?' selected':''} data-i18n="System">System</option>
    <option value="light"${tp==='light'?' selected':''} data-i18n="Light">Light</option>
    <option value="dark"${tp==='dark'?' selected':''} data-i18n="Dark">Dark</option></select>
    <label class="small mut" for="set-lang" data-i18n="Language">Language</label><select id="set-lang" class="langsel" data-langsel onchange="owSetLang(this.value)"></select></div></div>`;
  if(!AUTH_READY)return;if(EMERGENCY||PROJECT_EMERGENCY){$('view').innerHTML=emergencyCard()+(APP?emergencyCard(true):'');return}
  $('view').innerHTML=`${EMERGENCY_OWNER?emergencyCard():''}${instanceCard}${appearanceCard}
  <div class="card"><h3 data-i18n="Organisation security">Organisation security</h3><p data-i18n="IP allowlist is enforced on every API call. OIDC powers SSO and MCP OAuth discovery.">IP allowlist is enforced on every API call. OIDC powers SSO and MCP OAuth discovery.</p>
  <div class="field"><label for="set-ip" data-i18n="IP allowlist (CIDR, comma separated, empty = allow all)">IP allowlist (CIDR, comma separated, empty = allow all)</label><input id="set-ip" value="${esc(s?.ip_allowlist||'')}" placeholder="203.0.113.0/24"></div>
  <label class="row" style="gap:8px;margin:10px 0"><input type="checkbox" id="set-reuse" ${s?.reuse_check!==false?'checked':''}> <span data-i18n="Warn when a secret value is reused elsewhere in this workspace">Warn when a secret value is reused elsewhere in this workspace</span></label>
  <p class="small mut" style="margin:0 0 10px" data-i18n="Each app can turn the warning off. The check compares a keyed, non-reversible fingerprint and only reports items you can already open.">Each app can turn the warning off. The check compares a keyed, non-reversible fingerprint and only reports items you can already open.</p>
  <div class="field"><label for="set-oidc-iss" data-i18n="OIDC issuer">OIDC issuer</label><input id="set-oidc-iss" value="${esc(s?.oidc_issuer||'')}" placeholder="https://accounts.google.com"></div>
  <div class="row"><input id="set-oidc-cid" value="${esc(s?.oidc_client_id||'')}" placeholder="OIDC client id" data-i18n-placeholder="OIDC client id"><input id="set-oidc-sec" type="password" placeholder="${s?.oidc_client_secret_set?'stored; leave blank to keep':'OIDC client secret'}" data-i18n-placeholder="${s?.oidc_client_secret_set?'stored; leave blank to keep':'OIDC client secret'}"><input id="set-oidc-redir" value="${esc(s?.oidc_redirect_uri||'')}" placeholder="redirect URI" data-i18n-placeholder="redirect URI" style="min-width:260px"></div>
  <div class="field"><label for="set-oidc-domains" data-i18n="SSO email domains (comma separated; empty = any account at the issuer may join)">SSO email domains (comma separated; empty = any account at the issuer may join)</label><input id="set-oidc-domains" value="${esc(s?.oidc_allowed_domains||'')}" placeholder="example.com,subsidiary.example" style="width:100%"></div>
  <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="set-oidc-auto" ${s?.oidc_auto_provision?'checked':''}> <span data-i18n="Allow first-time SSO users to join as developers">Allow first-time SSO users to join as developers</span></label>
  <div class="row" style="margin-top:10px"><button class="primary" onclick="saveSettings()" data-i18n="Save settings">Save settings</button></div></div>
  ${samlCard}
  ${ldapCard}
  <div class="card"><h3 data-i18n="Authenticator app (TOTP)">Authenticator app (TOTP)</h3><p data-i18n="Add a second factor to your login.">Add a second factor to your login.</p><div class="row"><button onclick="totpSetup()" data-i18n="Set up TOTP">Set up TOTP</button></div><pre class="val" id="totp-out"></pre><div class="row"><input id="totp-code" placeholder="code from authenticator" data-i18n-placeholder="code from authenticator"><button onclick="totpVerify()" data-i18n="Verify and enable">Verify and enable</button></div></div>
  <div class="card"><h3 data-i18n="End-to-end environments">End-to-end environments</h3><p data-i18n="Paste your recovery kit to decrypt an E2E environment in this browser only. The kit never leaves this page.">Paste your recovery kit to decrypt an E2E environment in this browser only. The kit never leaves this page.</p>
  <div class="row"><input id="e2e-kit" placeholder="recovery kit (base64)" data-i18n-placeholder="recovery kit (base64)" style="min-width:320px"><input id="e2e-env" placeholder="E2E env ID" data-i18n-placeholder="E2E env ID"><button class="primary" onclick="loadE2E()" data-i18n="Decrypt">Decrypt</button></div><pre class="val" id="e2e-out"></pre></div>
  <div class="card"><h3 data-i18n="Device certificates">Device certificates</h3><p data-i18n="Client certificates for devices and services, issued from your own CA after a CSR.">Client certificates for devices and services, issued from your own CA after a CSR.</p><p data-i18n="CSR enrollment and signed renewal work without a TPM on the server or device. Hardware attestation is optional.">CSR enrollment and signed renewal work without a TPM on the server or device. Hardware attestation is optional.</p><div id="pki-body" class="small mut" data-i18n="Loading…">Loading…</div></div>
  <div class="card"><h3 data-i18n="SSH certificates">SSH certificates</h3><div class="row"><input id="ssh-ca-name" placeholder="ssh-ca"><button onclick="mkSshCA()" data-i18n="Create SSH CA">Create SSH CA</button></div><pre class="val" id="ssh-ca-out"></pre><div id="ssh-ca-list"></div><div id="ssh-ca-detail"></div></div>
  <div class="card"><h3 data-i18n="Session">Session</h3><div class="row"><button onclick="loadTokensSettings()" data-i18n="My tokens">My tokens</button><button class="danger" onclick="logout()" data-i18n="Sign out everywhere (this device)">Sign out everywhere (this device)</button></div><pre class="val" id="sess-out"></pre></div>
  ${myOrg.role==='owner'?`<div class="card"><h3 data-i18n="Delete workspace">Delete workspace</h3><p><span data-i18n="Type">Type</span> <span class="mono">${esc(myOrg.name||'')}</span> <span data-i18n="to confirm. Every app, environment, secret, token and identity in this workspace is removed.">to confirm. Every app, environment, secret, token and identity in this workspace is removed.</span></p><div class="row"><label for="del-org-name" data-i18n="Workspace name">Workspace name</label><input id="del-org-name" style="min-width:240px"><button class="danger" onclick="deleteWorkspace('${jsq(myOrg.name||'')}')" data-i18n="Delete workspace">Delete workspace</button></div></div>`:''}
  <div class="card"><h3 data-i18n="Account">Account</h3><p><span data-i18n="Signed in as">Signed in as</span> <span class="mono">${esc(ME?.email||'')}</span>. <span data-i18n="Deleting your account revokes every key and signs you out everywhere. Transfer or delete each workspace you own first.">Deleting your account revokes every key and signs you out everywhere. Transfer or delete each workspace you own first.</span></p><button class="danger" onclick="deleteAccount()" data-i18n="Delete account">Delete account</button></div>`;loadSshCAs();renderPki()}
async function saveSettings(){try{let b={ip_allowlist:$('set-ip').value,reuse_check:$('set-reuse').checked,oidc_auto_provision:$('set-oidc-auto').checked,oidc_allowed_domains:$('set-oidc-domains').value};
  if($('set-oidc-iss').value)b.oidc_issuer=$('set-oidc-iss').value;
  if($('set-oidc-cid').value)b.oidc_client_id=$('set-oidc-cid').value;
  if($('set-oidc-redir').value)b.oidc_redirect_uri=$('set-oidc-redir').value;
  if($('set-oidc-sec').value)b.oidc_client_secret=$('set-oidc-sec').value;
  await api('PUT',`/api/orgs/${ORG}/settings`,b);toastUI('Settings saved', false)}catch(e){toast(e.message,true)}}
async function saveSignups(){try{let d=await api('PUT','/api/instance/signups',{open:$('set-signups').checked});toastUI('Signups '+(d.signups_open?'enabled':'disabled'), false);renderSettings()}catch(e){toast(e.message,true)}}
async function saveSaml(){try{let b={idp_entity_id:$('set-saml-entity').value,metadata_url:$('set-saml-url').value,metadata_xml:$('set-saml-xml').value,allow_unsigned_metadata:$('set-saml-unsigned').checked,auto_provision:$('set-saml-auto').checked,allowed_domains:$('set-saml-domains').value};let d=await api('PUT',`/api/orgs/${ORG}/saml`,b);$('saml-out').textContent='SP metadata: '+d.sp_metadata_url;toastUI('SAML saved', false)}catch(e){toast(e.message,true)}}
async function saveLdap(){try{
  let b={url:$('ld-url').value,bind_dn:$('ld-bind-dn').value,base_dn:$('ld-base-dn').value,user_filter:$('ld-filter').value,email_attr:$('ld-email-attr').value,name_attr:$('ld-name-attr').value,group_attr:$('ld-group-attr').value,group_roles:$('ld-roles').value,default_role:$('ld-default-role').value,allowed_domains:$('ld-domains').value,ca_cert_pem:$('ld-ca').value,auto_provision:$('ld-auto').checked};
  if($('ld-bind-pw').value)b.bind_password=$('ld-bind-pw').value;
  await api('PUT',`/api/orgs/${ORG}/ldap`,b);toastUI('LDAP saved', false);renderSettings()}catch(e){toast(e.message,true)}}
async function removeLdap(){if(!confirm(owT('Remove LDAP sign-in for this workspace?')))return;
  try{await api('DELETE',`/api/orgs/${ORG}/ldap`);toastUI('LDAP removed', false);renderSettings()}catch(e){toast(e.message,true)}}
async function totpSetup(){try{let d=await api('POST','/api/me/totp/setup',{});$('totp-out').textContent='Secret: '+d.secret+'\n'+d.otpauth_url+'\nRecovery codes (save once):\n'+d.recovery_codes.join('\n')}catch(e){toast(e.message,true)}}
async function totpVerify(){try{await api('POST','/api/me/totp/verify',{code:$('totp-code').value});toastUI('TOTP enabled', false)}catch(e){toast(e.message,true)}}
async function loadE2E(envId){try{let id=envId||$('e2e-env')?.value;let d=await api('GET',`/api/envs/${id}/e2e/secrets`);let k=await OW.decryptAsymmetric($('e2e-kit').value,d.wrapped_key);
  $('e2e-out').textContent=d.secrets.map(s=>new TextDecoder().decode(OW.decryptSymmetric(k,s.key_enc))+'='+new TextDecoder().decode(OW.decryptSymmetric(k,s.value_enc))).join('\n')||'(no secrets)'}catch(e){$('e2e-out').textContent='Error: '+(e.message||e)}}
let PKI_CAS=[],PKI_CA='',PKI_GROUPS=[],PKI_IMPORT_OUT='',PKI_SELECTED=new Set(),PKI_SELECTION_CA='',PKI_CODE_RESULTS=[],PKI_RENDER=0,PKI_HOOK=null,PKI_ATT=null;
function clearPkiState(){PKI_RENDER++;PKI_CAS=[];PKI_CA='';PKI_GROUPS=[];PKI_IMPORT_OUT='';PKI_SELECTED=new Set();PKI_SELECTION_CA='';PKI_CODE_RESULTS=[];PKI_HOOK=null;PKI_ATT=null;let el=$('pki-body');if(el)el.innerHTML='Loading…'}
function switchPkiCA(id){PKI_CA=id;PKI_SELECTED.clear();PKI_CODE_RESULTS=[];PKI_IMPORT_OUT='';PKI_SELECTION_CA='';PKI_HOOK=null;PKI_ATT=null;let el=$('pki-body');if(el)el.innerHTML='Loading…';renderPki()}
async function renderPki(){let el=$('pki-body');if(!el)return;let org=ORG,render=++PKI_RENDER;let current=()=>ORG===org&&render===PKI_RENDER&&$('pki-body')===el;
  try{let cas=await api('GET',`/api/orgs/${org}/pki/cas`);if(!current())return;PKI_CAS=cas;
    if(!PKI_CAS.some(c=>c.id===PKI_CA))PKI_CA=PKI_CAS.length?PKI_CAS[0].id:'';
    let ca=PKI_CAS.find(c=>c.id===PKI_CA);
    let caSel=PKI_CAS.length?`<select id="pki-ca" onchange="switchPkiCA(this.value)" style="min-width:220px">${PKI_CAS.map(c=>`<option value="${esc(c.id)}"${c.id===PKI_CA?' selected':''}>${esc(c.name)} (${esc(c.kind||'root')}${c.revoked?' revoked':''})</option>`).join('')}</select>`:'';
    let roots=PKI_CAS.filter(c=>(c.kind||'root')==='root'&&!c.revoked);
    let parentSel=roots.length?`<select id="ca-parent" style="min-width:180px">${roots.map(c=>`<option value="${esc(c.id)}">${esc(c.name)}</option>`).join('')}</select><input id="int-name" placeholder="intermediate-ca"><button onclick="mkIntermediate()">Create intermediate</button>`:'';
    let devices=PKI_CA?await api('GET',`/api/pki/cas/${PKI_CA}/devices`):[];if(!current())return;
    if(PKI_SELECTION_CA!==PKI_CA){PKI_SELECTED.clear();PKI_CODE_RESULTS=[];PKI_IMPORT_OUT='';PKI_SELECTION_CA=PKI_CA;}
    PKI_SELECTED=new Set([...PKI_SELECTED].filter(id=>devices.some(d=>d.id===id)));
    let groups=PKI_CA?await api('GET',`/api/pki/cas/${PKI_CA}/groups`):[];if(!current())return;PKI_GROUPS=groups;
    let expiring=PKI_CA?await api('GET',`/api/orgs/${org}/pki/expiring?days=30`).catch(()=>null):null;if(!current())return;
    let expLine=expiring?`<span class="chip">Expiring: ${expiring.counts['7']} in 7d, ${expiring.counts['14']} in 14d, ${expiring.counts['30']} in 30d</span>`:'';
    let groupOpts=PKI_GROUPS.map(g=>`<option value="${esc(g.id)}">${esc(g.name)}</option>`).join('');
    let rows=devices.map(d=>`<tr><td><input type="checkbox" class="pki-select" data-device="${esc(d.id)}" aria-label="Select ${esc(d.name)}"${PKI_SELECTED.has(d.id)?' checked':''} onchange="selectPkiDevice(this)"></td><td class="mono">${esc(d.name)}</td><td class="small mut">${esc(d.env_id||'-')}</td><td class="small mut">${esc((PKI_GROUPS.find(g=>g.id===d.group_id)||{}).name||'-')}</td><td class="small">${d.active_cert?esc(d.active_cert.revoked?'revoked':'active')+' '+esc((d.active_cert.serial||'').slice(0,12)):'none'}</td><td class="small mut">${d.active_cert?new Date(d.active_cert.expires_at*1000).toLocaleDateString():'-'}</td><td class="small">${d.attested?'attested':'not attested'}</td><td class="row"><button onclick="mintEnrollment('${esc(d.id)}')">Enroll</button><button onclick="renewDevice('${esc(d.id)}')">Renew</button><button class="danger" onclick="revokeDevice('${esc(d.id)}')">Revoke</button></td></tr>`).join('')||'<tr><td colspan="8" class="mut small">No devices yet.</td></tr>';
    el.innerHTML=`<div class="row">${caSel}<input id="ca-name" placeholder="internal-ca"><button onclick="mkCA()" data-i18n="Create CA">Create CA</button></div>
      ${parentSel?`<div class="row" style="margin-top:8px">${parentSel}</div>`:''}
      ${ca?`<p class="small mut" style="margin:8px 0">${esc(ca.kind||'root')} CA${ca.revoked?' · revoked':''} ${expLine} ${ca.revoked?'':'<button class="danger" onclick="revokeCA()">Revoke CA</button>'}</p>`:''}
      ${PKI_CA?`<div class="row" style="margin-top:10px"><input id="dev-name" placeholder="device name (CN)"><input id="dev-env" placeholder="environment id (optional)" style="min-width:170px"><select id="dev-group" style="min-width:140px"><option value="">no group</option>${groupOpts}</select><button class="primary" onclick="mkDevice()">Add device</button></div>
      <div class="row" style="margin-top:8px"><button onclick="selectAllPki()">Select all</button><button onclick="clearPkiSelection()">Clear selection</button><span id="pki-selection-count" role="status">${PKI_SELECTED.size} selected</span><button id="pki-mint-selected" onclick="mintSelectedPki()"${PKI_SELECTED.size?'':' disabled'}>Mint selected codes</button><button id="pki-download-codes" onclick="downloadPkiCodes()"${PKI_CODE_RESULTS.some(r=>r.code)?'':' disabled'}>Download codes CSV</button></div>
      <pre class="val" id="pki-codes-out" aria-live="polite" style="white-space:pre-wrap;overflow-wrap:anywhere"></pre>
      <table class="table"><thead><tr><th>Select</th><th>Device</th><th>Environment</th><th>Group</th><th>Certificate</th><th>Expires</th><th>Key</th><th></th></tr></thead><tbody>${rows}</tbody></table>
      <details style="margin-top:10px"${PKI_IMPORT_OUT?' open':''}><summary class="small mut">Bulk import and export (export headers name,model,hardware_serial,tags,env_id,group_id,sans,cert_days are honoured; SANs separated by semicolons or commas)</summary>
        <textarea id="pki-import" rows="4" style="width:100%;margin-top:8px" placeholder="sensor-1,model-a,S123,site=a,ENV_ID,gw.local;192.0.2.10,45"></textarea>
        <div class="row"><button onclick="importDevices()">Import and mint codes</button><button onclick="downloadDevices()">Download CSV</button></div><pre class="val" id="pki-import-out"></pre></details>
      <details style="margin-top:8px"><summary class="small mut">Groups (defaults for SANs, lifetime, environment and tags)</summary>
        <div class="row" style="margin-top:8px"><input id="grp-name" placeholder="group name"><input id="grp-env" placeholder="environment id (optional)"><input id="grp-sans" placeholder="gw.local"><input id="grp-days" type="number" value="90" style="width:80px"><button onclick="mkGroup()">Add group</button></div>
        <div class="row">${PKI_GROUPS.map(g=>`<span class="chip">${esc(g.name)} · ${g.device_count} device(s)</span><button onclick="revokeGroup('${esc(g.id)}')">Revoke</button><button class="danger" onclick="deleteGroup('${esc(g.id)}')">Delete</button>`).join(' ')||'<span class="small mut">No groups yet.</span>'}</div></details>
      <details style="margin-top:8px"><summary class="small mut">Enrollment policy hook</summary>
        <div class="row" style="margin-top:8px"><input id="hook-url" placeholder="https://inventory.example/pki/enroll" style="min-width:320px" disabled><input id="hook-secret" type="password" placeholder="HMAC secret (blank keeps)" disabled><button id="hook-save" onclick="saveHook()" disabled>Save hook</button></div>
        <p class="small mut">Called before every issuance. A deny, an error or a timeout blocks enrollment and leaves the code usable.</p></details>
      <details style="margin-top:8px"><summary class="small mut">Optional hardware attestation</summary>
        <p class="small mut">No TPM is required on the server or device. Leave attestation optional for ordinary CSR enrollment and signed renewal. Enable a requirement only for a fleet provisioned for it.</p>
        <div class="row" style="margin-top:8px"><input id="att-issuer" placeholder="attestation issuer" disabled><input id="att-alg" value="ES256" style="width:90px" disabled><label class="row" style="gap:6px"><input type="checkbox" id="att-required" disabled> required</label><button id="att-save" onclick="saveAttestation()" disabled>Save</button></div>
        <textarea id="att-key" rows="3" style="width:100%;margin-top:6px" placeholder="attestation service public key (PEM)" disabled></textarea></details>
      <pre class="val" id="ca-out"></pre>`:''}`;
    if(PKI_CA&&ca){$('ca-out').textContent='CA certificate (trust this in the broker):\n'+ca.certificate;}
    if(PKI_IMPORT_OUT&&$('pki-import-out'))$('pki-import-out').textContent=PKI_IMPORT_OUT;
    if(PKI_CA&&$('pki-codes-out'))$('pki-codes-out').textContent=pkiCodesText();
    if($('pki-download-codes'))$('pki-download-codes').disabled=!PKI_CODE_RESULTS.some(r=>r.code);
    PKI_HOOK=null;PKI_ATT=null;
    if(PKI_CA){let caId=PKI_CA;
      try{let hook=await api('GET',`/api/pki/cas/${caId}/hook`);if(!current()||PKI_CA!==caId)return;PKI_HOOK={ca:caId,render,url:(hook&&hook.url)||''};
        if($('hook-url')){$('hook-url').value=PKI_HOOK.url;$('hook-url').disabled=false}
        if($('hook-secret'))$('hook-secret').disabled=false;
        if($('hook-save'))$('hook-save').disabled=false;
      }catch(e){if(current()&&PKI_CA===caId)toast('Enrollment hook settings failed to load: '+(e.message||e),true)}
      try{let att=await api('GET',`/api/pki/cas/${caId}/attestation`);if(!current()||PKI_CA!==caId)return;
        PKI_ATT={ca:caId,render,mode:typeof att?.mode==='string'?att.mode:''};
        if($('att-issuer')){$('att-issuer').value=(att&&att.issuer)||'';$('att-alg').value=(att&&att.algorithm)||'ES256';$('att-required').checked=!!(att&&att.required)}
        for(let id of ['att-issuer','att-alg','att-required','att-key','att-save']){let f=$(id);if(f)f.disabled=false}
      }catch(e){if(current()&&PKI_CA===caId)toast('Attestation settings failed to load: '+(e.message||e),true)}
    }
  }catch(e){if(current()){el.textContent='PKI unavailable: '+(e.message||e);PKI_HOOK=null;PKI_ATT=null}}}
async function mkCA(){try{let d=await api('POST',`/api/orgs/${ORG}/pki/cas`,{name:$('ca-name').value||'internal-ca'});PKI_CA=d.id;toast('CA created');renderPki()}catch(e){toast(e.message,true)}}
async function mkIntermediate(){try{let d=await api('POST',`/api/orgs/${ORG}/pki/cas`,{name:$('int-name').value||'intermediate-ca',parent_id:$('ca-parent').value});PKI_CA=d.id;toast('Intermediate created');renderPki()}catch(e){toast(e.message,true)}}
async function revokeCA(){if(!confirm('Revoke this CA and every certificate it issued?'))return;try{await api('POST',`/api/pki/cas/${PKI_CA}/revoke`,{});toast('CA revoked');renderPki()}catch(e){toast(e.message,true)}}
async function mkDevice(){try{let b={name:$('dev-name').value};if($('dev-env').value)b.env_id=$('dev-env').value;if($('dev-group').value)b.group_id=$('dev-group').value;await api('POST',`/api/pki/cas/${PKI_CA}/devices`,b);toast('Device added');renderPki()}catch(e){toast(e.message,true)}}
function syncPkiSelection(){let count=$('pki-selection-count');if(count)count.textContent=PKI_SELECTED.size+' selected';let mint=$('pki-mint-selected');if(mint)mint.disabled=!PKI_SELECTED.size;document.querySelectorAll('.pki-select').forEach(el=>{el.checked=PKI_SELECTED.has(el.getAttribute('data-device'))})}
function selectPkiDevice(el){let id=el.getAttribute('data-device');if(el.checked)PKI_SELECTED.add(id);else PKI_SELECTED.delete(id);syncPkiSelection()}
function selectAllPki(){document.querySelectorAll('.pki-select').forEach(el=>PKI_SELECTED.add(el.getAttribute('data-device')));syncPkiSelection()}
function clearPkiSelection(){PKI_SELECTED.clear();syncPkiSelection()}
async function mintSelectedPki(){if(!PKI_SELECTED.size)return;let ca=PKI_CA,org=ORG,render=PKI_RENDER,el=$('pki-body');try{if(PKI_SELECTED.size>500)throw Error('Select at most 500 devices per request');let d=await api('POST',`/api/pki/cas/${ca}/devices/codes`,{device_ids:[...PKI_SELECTED],ttl_seconds:3600});if(PKI_CA!==ca||ORG!==org||PKI_RENDER!==render||$('pki-body')!==el)return;PKI_CODE_RESULTS=d.codes||[];$('pki-codes-out').textContent=pkiCodesText();$('pki-download-codes').disabled=!PKI_CODE_RESULTS.some(r=>r.code)}catch(e){toast(e.message,true)}}
function pkiCodesText(){return PKI_CODE_RESULTS.map(r=>r.error?(r.name||r.id)+': '+r.error:(r.name||r.id)+': '+r.code+' (nonce '+r.nonce+')').join('\n')}
function pkiCsvField(value){let s=String(value??'');if(/^[=+@\-\t\r]/.test(s))s="'"+s;return '"'+s.replace(/"/g,'""')+'"'}
function downloadPkiCodes(){let rows=PKI_CODE_RESULTS.filter(r=>r.code);if(!rows.length)return;let csv='device_id,name,code,nonce,expires_at\r\n'+rows.map(r=>[r.id,r.name,r.code,r.nonce,r.expires_at].map(pkiCsvField).join(',')).join('\r\n');let url=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));let a=document.createElement('a');a.href=url;a.download='openwarp-enrollment-codes.csv';a.click();URL.revokeObjectURL(url)}
function enrollmentText(d,prefix){return prefix+' (valid until '+new Date(d.expires_at*1000).toLocaleString()+'):\n'+d.code+'\nnonce: '+d.nonce+'\n\nPOST '+location.origin+'/api/pki/enroll from the device with JSON {"code":"<code>","csr":"<PEM CSR>"}.\nNo TPM is required. Supply attestation only when configured by your fleet administrator.\nThe code is single use; only its hash is stored.'}
async function mintEnrollment(id){let org=ORG,ca=PKI_CA,render=PKI_RENDER,el=$('pki-body');try{let d=await api('POST',`/api/pki/devices/${id}/enrollment`,{ttl_seconds:3600});if(ORG!==org||PKI_CA!==ca||PKI_RENDER!==render||$('pki-body')!==el)return;$('ca-out').textContent=enrollmentText(d,'One-time enrollment code')}catch(e){toast(e.message,true)}}
async function renewDevice(id){let org=ORG,ca=PKI_CA,render=PKI_RENDER,el=$('pki-body');try{let d=await api('POST',`/api/pki/devices/${id}/renew`,{ttl_seconds:3600});if(ORG!==org||PKI_CA!==ca||PKI_RENDER!==render||$('pki-body')!==el)return;$('ca-out').textContent=enrollmentText(d,'Renewal code (the previous certificate is revoked on enrollment)')}catch(e){toast(e.message,true)}}
async function revokeDevice(id){if(!confirm('Revoke the active certificate for this device?'))return;try{let d=await api('POST',`/api/pki/devices/${id}/revoke`,{});toast('Revoked '+d.revoked+' certificate(s)');renderPki()}catch(e){toast(e.message,true)}}
function parseCsvRows(text){let rows=[],row=[],field='',quoted=false;for(let i=0;i<text.length;i++){let c=text[i];
  if(quoted){if(c==='"'){if(text[i+1]==='"'){field+='"';i++}else quoted=false}else field+=c}
  else if(c==='"')quoted=true;
  else if(c===','){row.push(field);field=''}
  else if(c==='\n'||c==='\r'){if(c==='\r'&&text[i+1]==='\n')i++;row.push(field);if(row.some(v=>v.trim()))rows.push(row);row=[];field=''}
  else field+=c}
  if(quoted)throw Error('Unterminated quoted CSV cell');
  row.push(field);if(row.some(v=>v.trim()))rows.push(row);return rows}
const PKI_IMPORT_FIELDS=['name','model','hardware_serial','tags','env_id','group_id','sans','cert_days'];
function deviceImportRows(text){let rows=parseCsvRows(text);if(!rows.length)return [];
  let header=rows[0].map(v=>v.trim().toLowerCase()),known=header.filter(k=>PKI_IMPORT_FIELDS.includes(k));
  let hasHeader=header.includes('name')||known.length>1;
  if(hasHeader&&!header.includes('name'))throw Error('CSV header must include a name column');
  let keys=hasHeader?header:['name','model','hardware_serial','tags','env_id','sans','cert_days'];
  return (hasHeader?rows.slice(1):rows).map((cells,index)=>{let o={};keys.forEach((k,i)=>{if(PKI_IMPORT_FIELDS.includes(k))o[k]=(cells[i]||'').trim()});
    let out={name:o.name};if(!out.name)throw Error('Row '+(index+1)+' has no device name');
    for(let k of ['model','hardware_serial','tags','env_id','group_id'])if(o[k])out[k]=o[k];
    if(o.sans)out.sans=o.sans.split(/[;,]/).map(s=>s.trim()).filter(Boolean);
    if(o.cert_days){let days=Number(o.cert_days);if(!Number.isFinite(days)||days<=0)throw Error('Row '+(index+1)+' has an invalid cert_days value');out.cert_days=days}
    return out})}
async function importDevices(){let org=ORG,ca=PKI_CA,render=PKI_RENDER,el=$('pki-body');try{let devices=deviceImportRows($('pki-import').value);
  if($('dev-group')&&$('dev-group').value)devices.forEach(o=>{if(!o.group_id)o.group_id=$('dev-group').value});
  let d=await api('POST',`/api/pki/cas/${ca}/devices/import`,{devices,mint_codes:true,ttl_seconds:3600});if(ORG!==org||PKI_CA!==ca||PKI_RENDER!==render||$('pki-body')!==el)return;PKI_IMPORT_OUT='created '+d.created+', failed '+d.failed+'\n'+d.results.map(r=>r.error?(r.name||r.id)+': '+r.error:(r.name||r.id)+': '+(r.code||'ok')).join('\n');await renderPki()}catch(e){toast(e.message,true)}}
async function downloadDevices(){try{let r=await fetch(`/api/pki/cas/${PKI_CA}/devices/export`,{headers:H()});let t=await r.text();
  if(!r.ok){let m='';try{m=JSON.parse(t).error||''}catch(e){}throw Error(m||('Could not download devices (HTTP '+r.status+')'))}
  let a=document.createElement('a');a.href=URL.createObjectURL(new Blob([t],{type:'text/csv'}));a.download='openwarp-devices.csv';a.click()}catch(e){toast(e.message,true)}}
async function mkGroup(){try{let b={name:$('grp-name').value,cert_days:Number($('grp-days').value)||90};if($('grp-env').value)b.env_id=$('grp-env').value;if($('grp-sans').value)b.sans=$('grp-sans').value.split(',').map(s=>s.trim()).filter(Boolean);await api('POST',`/api/pki/cas/${PKI_CA}/groups`,b);toast('Group added');renderPki()}catch(e){toast(e.message,true)}}
async function revokeGroup(id){if(!confirm('Revoke every certificate in this group?'))return;try{let d=await api('POST',`/api/pki/groups/${id}/revoke`,{});toast('Revoked '+d.revoked+' certificate(s)');renderPki()}catch(e){toast(e.message,true)}}
async function deleteGroup(id){if(!confirm('Delete this group? Devices stay and lose their group defaults.'))return;try{await api('DELETE',`/api/pki/groups/${id}`);toast('Group deleted');renderPki()}catch(e){toast(e.message,true)}}
async function saveHook(){let ca=PKI_CA;if(!ca||!PKI_HOOK||PKI_HOOK.ca!==ca||PKI_HOOK.render!==PKI_RENDER||!$('hook-url')){toast('Enrollment hook settings are not loaded yet',true);return}
  try{let b={url:$('hook-url').value};if($('hook-secret').value)b.secret=$('hook-secret').value;await api('PUT',`/api/pki/cas/${ca}/hook`,b);toast('Hook saved');renderPki()}catch(e){toast(e.message,true)}}
async function saveAttestation(){let ca=PKI_CA;if(!ca||!PKI_ATT||PKI_ATT.ca!==ca||PKI_ATT.render!==PKI_RENDER||!$('att-issuer')){toast('Attestation settings are not loaded yet',true);return}
  try{let b={issuer:$('att-issuer').value,algorithm:$('att-alg').value||'ES256',required:$('att-required').checked};if(PKI_ATT.mode)b.mode=PKI_ATT.mode;if($('att-key').value)b.public_key_pem=$('att-key').value;await api('PUT',`/api/pki/cas/${ca}/attestation`,b);toast('Attestation saved');renderPki()}catch(e){toast(e.message,true)}}
async function mkSshCA(){try{let d=await api('POST',`/api/orgs/${ORG}/ssh/cas`,{name:$('ssh-ca-name').value||'ssh-ca'});
  $('ssh-ca-name').value='';$('ssh-ca-out').textContent='SSH CA id: '+d.id+'\nFingerprint '+d.fingerprint;
  loadSshCAs();openSshCA(d.id)}catch(e){toast(e.message,true)}}
async function loadSshCAs(){let host=$('ssh-ca-list');if(!host)return;try{let d=await api('GET',`/api/orgs/${ORG}/ssh/cas`);
  host.innerHTML=d.length?`<table><thead><tr><th data-i18n="SSH CA">SSH CA</th><th data-i18n="Fingerprint">Fingerprint</th><th></th></tr></thead><tbody>`+d.map(c=>`<tr><td>${esc(c.name)}</td><td class="mono small">${esc(c.fingerprint)}</td><td><button onclick="openSshCA('${jsq(c.id)}')" data-i18n="Manage">Manage</button></td></tr>`).join('')+'</tbody></table>':'<p class="mut small" data-i18n="No SSH CA yet. A host accepts these certificates only after TrustedUserCAKeys names this CA.">No SSH CA yet. A host accepts these certificates only after TrustedUserCAKeys names this CA.</p>'}catch(e){host.textContent=e.message}}
async function openSshCA(id){let detail=$('ssh-ca-detail');if(!detail)return;try{let d=await api('GET',`/api/ssh/cas/${id}`);
  let grants=d.grants.map(g=>g.role+': '+g.principals.join(', ')+(g.max_ttl?' ('+Math.round(g.max_ttl/60)+'m)':'')).join('\n');
  detail.innerHTML=`<h4 style="margin:16px 0 6px">${esc(d.name)}</h4>
    <p class="small mut"><span data-i18n="Fingerprint">Fingerprint</span> <span class="mono">${esc(d.fingerprint)}</span>. Install the CA key on every host that should accept these certificates.</p>
    <pre class="val">${esc(d.sshd)}</pre>
    <div class="field"><label data-i18n="Principal grants, one role per line as role: pattern, pattern (15m)">Principal grants, one role per line as role: pattern, pattern (15m)</label><textarea id="ssh-grants" rows="4" placeholder="developer: web-*, db-*&#10;admin: *">${esc(grants)}</textarea></div>
    <p class="small mut" style="margin:0 0 8px" data-i18n="A certificate can only name a principal its role is granted. A bare * means any local account, root included, so only an owner can grant it.">A certificate can only name a principal its role is granted. A bare * means any local account, root included, so only an owner can grant it.</p>
    <div class="row"><button class="primary" onclick="saveSshGrants('${jsq(id)}')" data-i18n="Save grants">Save grants</button><a class="mono small" style="align-self:center" href="/api/ssh/cas/${id}/revoked-keys" download="openwarp_revoked_keys" data-i18n="revoked keys">revoked keys</a><a class="mono small" style="align-self:center" href="/api/ssh/cas/${id}/krl" download="openwarp.krl">KRL</a></div>
    <h4 style="margin:16px 0 6px" data-i18n="Hosts">Hosts</h4>
    <p class="small mut" style="margin:0 0 8px" data-i18n="A host certificate is only issued for a name and key registered here, so a member can deploy one but cannot invent a host.">A host certificate is only issued for a name and key registered here, so a member can deploy one but cannot invent a host.</p>
    <div class="row"><input id="ssh-host-name" placeholder="db-1.internal"><input id="ssh-host-key" placeholder="ssh-ed25519 AAAA… host key" style="min-width:280px"><button onclick="addSshHost('${jsq(id)}')" data-i18n="Register host">Register host</button></div>
    <div id="ssh-hosts"></div>
    <div id="ssh-certs"></div>`;
  loadSshHosts(id);loadSshCerts(id)}catch(e){toast(e.message,true)}}
async function loadSshHosts(id){let host=$('ssh-hosts');if(!host)return;try{let d=await api('GET',`/api/ssh/cas/${id}/hosts`);
  host.innerHTML=d.length?`<table><thead><tr><th data-i18n="Hostname">Hostname</th><th data-i18n="Key fingerprint">Key fingerprint</th><th></th></tr></thead><tbody>`+d.map(h=>`<tr><td class="mono">${esc(h.hostname)}</td><td class="mut small">${esc(h.fingerprint)}</td><td><button class="danger" onclick="deleteSshHost('${jsq(h.id)}','${jsq(id)}')" data-i18n="Remove">Remove</button></td></tr>`).join('')+'</tbody></table>':'<p class="mut small" data-i18n="No hosts registered.">No hosts registered.</p>'}catch(e){host.textContent=e.message}}
async function addSshHost(id){try{let d=await api('POST',`/api/ssh/cas/${id}/hosts`,{hostname:$('ssh-host-name').value.trim(),public_key:$('ssh-host-key').value.trim()});
  $('ssh-host-name').value='';$('ssh-host-key').value='';toastUI('Host registered: {x}',{x:d.fingerprint}, false);loadSshHosts(id)}catch(e){toast(e.message,true)}}
async function deleteSshHost(hid,ca){if(!confirm(owT('Remove this host registration? Certificates already issued keep working until they expire.')))return;
  try{await api('DELETE',`/api/ssh/cas/${ca}/hosts/${hid}`);toastUI('Host removed', false);loadSshHosts(ca)}catch(e){toast(e.message,true)}}
async function saveSshGrants(id){let box=$('ssh-grants');if(!box)return;try{
  let grants=box.value.split('\n').map(l=>l.trim()).filter(Boolean).map(l=>{
    let i=l.indexOf(':'); let role=(i<0?l:l.slice(0,i)).trim(); let rest=i<0?'':l.slice(i+1);
    let minutes=null; rest=rest.replace(/\((\d+)\s*m\)\s*$/i,(m,n)=>{minutes=n;return ''});
    let patterns=rest.split(',').map(p=>p.trim()).filter(Boolean);
    return {role:role,principals:patterns,max_ttl:minutes?parseInt(minutes)*60:undefined};
  }).filter(g=>g.role&&g.principals.length);
  if(!grants.length)return toastUI('Format each line as role: pattern, pattern', true);
  await api('PUT',`/api/ssh/cas/${id}/grants`,{grants:grants});toastUI('Grants saved', false);openSshCA(id)}catch(e){toast(e.message,true)}}
async function loadSshCerts(id){let host=$('ssh-certs');if(!host)return;try{let d=await api('GET',`/api/ssh/cas/${id}/certs`);
  host.innerHTML=`<h4 style="margin:16px 0 6px" data-i18n="Issued certificates">Issued certificates</h4><table><thead><tr><th data-i18n="Type">Type</th><th data-i18n="Principal">Principal</th><th data-i18n="Key id">Key id</th><th data-i18n="Expires">Expires</th><th data-i18n="State">State</th><th></th></tr></thead><tbody>`+
    (d.map(c=>`<tr><td class="mut small">${esc(c.cert_type||'user')}</td><td class="mono">${esc(c.principal)}</td><td class="mut small">${esc(c.key_id)}</td><td class="mut small">${new Date((c.valid_before||0)*1000).toLocaleString()}</td><td>${c.revoked?'<span style="color:var(--bad)" data-i18n="revoked">revoked</span>':owHTML('active')}</td><td>${c.revoked?'':`<button class="danger" onclick="revokeSshCert('${jsq(c.id)}','${jsq(id)}')" data-i18n="Revoke">Revoke</button>`}</td></tr>`).join('')||'<tr><td colspan="6" class="mut" data-i18n="No certificates issued yet">No certificates issued yet</td></tr>')+'</tbody></table>'}catch(e){host.textContent=e.message}}
async function revokeSshCert(cid,ca){if(!confirm(owT('Revoke this certificate? A host only enforces it once its RevokedKeys file is refreshed.')))return;
  try{await api('POST',`/api/ssh/certs/${cid}/revoke`,{});toastUI('Revoked', false);openSshCA(ca)}catch(e){toast(e.message,true)}}
async function loadTokensSettings(){owText($('sess-out'),'Use openwarp login / MCP OAuth clients for programmatic access. Service tokens live under Members & access.')}
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

// ---------- command palette ----------
function openPalette(){if(EMERGENCY||PROJECT_EMERGENCY||!AUTH_READY)return;$('palette').style.display='block';$('paletteinput').value='';$('paletteresults').innerHTML='';setTimeout(()=>$('paletteinput').focus(),30)}
async function paletteSearch(){let q=$('paletteinput').value;if(q.length<2){$('paletteresults').innerHTML='';return}
  try{let d=await api('GET','/api/search?q='+encodeURIComponent(q));$('paletteresults').innerHTML=d.results.map(r=>`<div class="pitem" onclick="paletteGo('${jsq(r.key)}')"><span class="mono">${esc(r.key)}</span><span class="mut small">${esc(r.app)} / ${esc(r.env)} ${esc(r.path||'')}</span></div>`).join('')||'<div class="pitem mut">No matches</div>'}catch(e){}}
function paletteGo(key){$('palette').style.display='none';if(APP&&ENV){nav('apps');renderEnv().then(()=>{let f=$('sfilter');if(f){f.value=key;drawSecrets()}})}}
$('palette').addEventListener('click',e=>{if(e.target.id==='palette')$('palette').style.display='none'});
document.addEventListener('click',e=>{if(!orgMenuOpen())return;let t=e.target;if(t.closest&&(t.closest('#orgmenu')||t.closest('#orgbtn')))return;closeOrgMenu()});
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeOrgMenu()});

loadProviders();
applyThemeIcons();
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
    owText($('authtitle'),'Two-step verification');$('mfafield').style.display='block';
    owText($('authbtn'),'Verify code');$('authbtn').onclick=doMfa;}
  else if(h.startsWith('invite=')){showInvite(decodeURIComponent(h.slice(7).split('&')[0]));}
  else if(h.startsWith('reset=')){showReset(decodeURIComponent(h.slice(6).split('&')[0]));}
}
boot();
if(typeof window!=='undefined'&&window.addEventListener)window.addEventListener('hashchange',boot);
$('auth').style.display='none';enterApp().catch(()=>{T='';$('auth').style.display='grid';$('shell').style.display='none';$('picker').style.display='none'})
</script>
<script src="/libsodium.js" integrity="sha384-3KUAqev6nUaNHDSTa/UjyEycVN8iMfq/UtzKf3ZDTuGSb+P3y9kMu/WCVqnLAxUB"></script>
<script src="/libsodium-wrappers.js" integrity="sha384-uj62oy76l27Bkf3eEP5knMYc094z6HzwAR7Rn8ZZcBBsg5nMibZXSvjRqgZMFg/L"></script>
<script src="/e2e.js"></script>
<script src="/auth-v2.js"></script>
</body></html>
"##;
