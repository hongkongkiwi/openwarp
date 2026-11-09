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
:root{color-scheme:light;--bg:#f4f5f9;--bg2:#ebecf3;--panel:#ffffff;--panel2:#f0f0f7;--line:#dcdee9;--line2:#c7cadd;--text:#1d1c2e;--muted:#5f5d78;--faint:#696684;--acc:#6a5bff;--acc2:#5243e0;--on-acc:#ffffff;--ok:#0f7a54;--warn:#8a5a12;--bad:#b02a52;--hover:#e4e3f2;--ring:rgba(106,91,255,.18);--mark2:#4f46e5;--sel:rgba(106,91,255,.12);--row:rgba(106,91,255,.05);--glow:rgba(106,91,255,.10);--topbar:rgba(244,245,249,.85);--deploy:#ffffff;--backdrop:rgba(23,23,46,.38);--toast-bg:#e7f6ef;--toast-bd:#b7e4d0;--toast-tx:#0c5e42;--toast-ebg:#fdeff2;--toast-ebd:#f2c3cf;--toast-etx:#8e2044;--sh-auth:0 24px 60px rgba(30,30,70,.16);--sh-deploy:0 18px 50px rgba(30,30,70,.18);--sh-palette:0 30px 80px rgba(30,30,70,.22);--sh-sm:0 1px 4px rgba(30,30,70,.18);--sh-side:0 0 60px rgba(30,30,70,.25);--sh-toast:0 10px 30px rgba(30,30,70,.15);--mono:ui-monospace,'SF Mono',SFMono-Regular,Menlo,monospace;--sans:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI',Roboto,sans-serif;--r:10px}
:root[data-theme=dark]{color-scheme:dark;--bg:#08080c;--bg2:#0e0e14;--panel:#12121b;--panel2:#171724;--line:#23233a;--line2:#2e2e4a;--text:#eceaf8;--muted:#a4a1bf;--faint:#8a87a6;--acc:#7c6cff;--acc2:#9d8fff;--on-acc:#0b0918;--ok:#34d399;--warn:#fbbf24;--bad:#fb7185;--hover:#1d1d2f;--ring:rgba(124,108,255,.18);--mark2:#4f46e5;--sel:rgba(124,108,255,.14);--row:rgba(124,108,255,.04);--glow:rgba(124,108,255,.16);--topbar:rgba(8,8,12,.85);--deploy:#1b1b2c;--backdrop:rgba(4,4,8,.7);--toast-bg:#1d2b22;--toast-bd:#245c3f;--toast-tx:#a7f3d0;--toast-ebg:#331d24;--toast-ebd:#5c2436;--toast-etx:#fecdd3;--sh-auth:0 24px 60px rgba(0,0,0,.5);--sh-deploy:0 18px 50px rgba(0,0,0,.55);--sh-palette:0 30px 80px rgba(0,0,0,.6);--sh-sm:0 1px 4px rgba(0,0,0,.4);--sh-side:0 0 60px rgba(0,0,0,.7);--sh-toast:0 10px 30px rgba(0,0,0,.5)}
*{box-sizing:border-box}html,body{height:100%}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 var(--sans);-webkit-font-smoothing:antialiased}
button{font:inherit;color:var(--text);background:var(--panel2);border:1px solid var(--line2);border-radius:8px;padding:7px 14px;cursor:pointer;transition:.15s}button:hover{border-color:var(--acc);background:var(--hover)}button.primary{background:var(--acc);border-color:var(--acc);color:var(--on-acc);font-weight:600}button.primary:hover{background:var(--acc2)}button.ghost{background:transparent;border-color:transparent;color:var(--muted)}button.ghost:hover{color:var(--text);background:var(--panel2)}button.danger:hover{border-color:var(--bad);color:var(--bad)}button:disabled{opacity:.45;cursor:default}
input,select,textarea{font:inherit;color:var(--text);background:var(--bg2);border:1px solid var(--line2);border-radius:8px;padding:8px 11px;outline:none}input:focus,select:focus,textarea:focus{border-color:var(--acc);box-shadow:0 0 0 3px var(--ring)}textarea{font-family:var(--mono);font-size:12.5px;width:100%}
a{color:var(--acc2)}code,.mono{font-family:var(--mono);font-size:12.5px}
.logo{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;letter-spacing:-.02em}
.mark{width:28px;height:28px;border-radius:8px;background:var(--acc);display:grid;place-items:center;color:var(--on-acc);font-size:15px;flex:none}
#auth{min-height:100vh;display:grid;place-items:center;background:var(--bg)}
:where(button,a,input,select,textarea,[tabindex]):focus-visible{outline:2px solid var(--acc2);outline-offset:2px}
.skip{position:fixed;left:12px;top:-60px;z-index:120;background:var(--panel);border:1px solid var(--acc);border-radius:8px;padding:10px 14px;color:var(--text);text-decoration:none}.skip:focus{top:12px}
.icon{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round;vertical-align:-3px;flex:none}
.sectionjump{position:sticky;top:58px;z-index:4;background:var(--topbar);backdrop-filter:blur(8px);padding:6px 0 10px;margin-bottom:2px}
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
main{overflow:auto;display:flex;flex-direction:column;min-width:0}
.topbar{display:flex;align-items:center;gap:12px;padding:14px 28px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--topbar);backdrop-filter:blur(8px);z-index:5}
.topbar h2{font-size:17px;margin:0;letter-spacing:-.01em}.crumb{color:var(--faint)}.grow{flex:1}
.searchbox{display:flex;align-items:center;gap:8px;background:var(--bg2);border:1px solid var(--line2);border-radius:8px;padding:6px 11px;color:var(--faint);cursor:pointer;min-width:210px}.searchbox:hover{border-color:var(--acc)}kbd{font:11px var(--mono);background:var(--panel2);border:1px solid var(--line2);border-bottom-width:2px;border-radius:5px;padding:1px 5px;color:var(--muted)}
.content{padding:24px 28px 110px;max-width:1220px;width:100%;margin:0 auto}
.ai-prose{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;font:inherit;line-height:1.65;margin:10px 0;max-width:100%}#ai-plan pre,#ai-answer pre{max-height:560px;overflow:auto}#ai-scope,#ai-task,#ai-compare{max-width:100%}#ai-findings-list summary{cursor:pointer;color:var(--muted);padding:6px 0}[hidden]{display:none!important}
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
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px;margin-bottom:14px}.card h3{margin:0 0 6px;font-size:15px}.card p{color:var(--muted);margin:0 0 12px}.card p.sublabel{font-size:12.5px;color:var(--text);margin:0 0 10px}.field [data-health-pair-label][hidden]{display:none}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.empty{padding:48px 20px;text-align:center;color:var(--faint);border:1px dashed var(--line2);border-radius:14px}.empty .big{font-size:22px;margin-bottom:6px}
.mut{color:var(--muted)}.small{font-size:12.5px}.val{font-family:var(--mono);font-size:12.5px;word-break:break-all}
#navtoggle{display:none}
.langsel{padding:6px 8px;font-size:12.5px;color:var(--muted);max-width:150px}.langsel option{color:var(--text);background:var(--panel)}.authprefs{position:absolute;top:18px;right:18px;display:flex;gap:6px;align-items:center}
@media(max-width:820px){#shell{grid-template-columns:minmax(0,1fr)}.topbar{padding:12px 14px;gap:8px;flex-wrap:wrap}.searchbox{min-width:0;flex:1}.topbar h2{min-width:0;overflow-wrap:anywhere}#topaction{flex-shrink:0}#navtoggle{display:inline-block}aside{display:none;position:fixed;top:0;bottom:0;left:0;width:260px;z-index:80;box-shadow:var(--sh-side)}aside.open{display:flex}.content{padding:16px 14px 100px}.members-table,.members-table tbody{display:block;width:100%}.members-table thead{display:none}.members-table tr{display:flex;flex-wrap:wrap;padding:10px 0;border-bottom:1px solid var(--line)}.members-table td{display:block;border:0;padding:6px 0;min-width:0}.members-table td:first-child{width:100%;overflow-wrap:anywhere}.members-table td:last-child{display:flex;flex-wrap:wrap;gap:8px;width:100%}.members-table select{max-width:100%}}
@media(max-width:820px){#shell{grid-template-columns:1fr}#navtoggle{display:inline-block}aside{display:none;position:fixed;top:0;bottom:0;left:0;width:260px;z-index:80;box-shadow:var(--sh-side)}aside.open{display:flex}.content{padding:14px 14px 100px}
  .topbar{flex-wrap:wrap;gap:8px;padding:10px 14px}.topbar h2{font-size:16px;max-width:62vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.crumb{display:none}.langsel{display:none}.searchbox{min-width:0;padding:6px 9px}.searchbox kbd{display:none}.searchbox span:nth-of-type(2){display:none}
  button,input,select,textarea{min-height:44px}.iconbtn{min-width:44px;min-height:44px}.envtabs{gap:8px}.envtab{min-height:40px}
  .members-table,.members-table tbody{display:block;width:100%}.members-table thead{display:none}.members-table tr{display:flex;flex-wrap:wrap;padding:10px 0;border-bottom:1px solid var(--line)}.members-table td{display:block;border:0;padding:6px 0;min-width:0}.members-table td:first-child{width:100%;overflow-wrap:anywhere}.members-table td:last-child{display:flex;flex-wrap:wrap;gap:8px;width:100%}.members-table select{max-width:100%}
  #stable table{background:transparent;border:0;border-radius:0}#stable thead{display:none}#stable tbody,#stable tr,#stable td{display:block;width:100%}#stable tr{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin-bottom:10px;padding:10px 12px}#stable td{border:0;padding:3px 0}#stable td:nth-child(3)::before{content:'Path';color:var(--faint);font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;margin-right:8px}#stable td:nth-child(4)::before{content:'Version';color:var(--faint);font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;margin-right:8px}#stable td:last-child{display:flex;flex-wrap:wrap;justify-content:flex-start;white-space:normal;padding-top:8px;margin-top:6px;border-top:1px solid var(--line)}
  .sectionjump{top:0;overflow-x:auto;white-space:nowrap;padding-bottom:8px}}
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
      <button class="ghost" style="width:100%;margin-top:6px" id="saml-signin" onclick="workspaceSsoPrompt()" data-i18n="Sign in with SAML">Sign in with SAML</button>
      <div id="social" class="row" style="margin-top:12px;flex-wrap:wrap"></div>
      <p class="small mut" id="signupnote" style="margin:14px 0 0" data-i18n="Your organisation, apps and environments are unlimited. Save the recovery kit shown once at registration.">Your organisation, apps and environments are unlimited. Save the recovery kit shown once at registration.</p>
      <p class="small mut regionline" id="regionline"></p>
    </div>
  </div>
</div>

<a class="skip" href="#view" data-i18n="Skip to content">Skip to content</a>
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
    <div class="row"><button id="new-workspace" onclick="newWorkspace()">New workspace</button><button onclick="joinWorkspace()">Join workspace</button></div>
    <button class="navbtn" data-nav="apps" onclick="nav('apps')"><span class="ic">▦</span><span data-i18n="Apps">Apps</span></button>
    <button class="navbtn" data-nav="access" onclick="nav('access')"><span class="ic">♟</span><span data-i18n="Members &amp; access">Members &amp; access</span></button>
    <button class="navbtn" data-nav="integrations" onclick="nav('integrations')"><span class="ic">⇄</span><span data-i18n="Integrations">Integrations</span></button>
    <button class="navbtn" data-nav="webhooks" onclick="nav('webhooks')"><span class="ic">↗</span>Webhooks</button>
    <button class="navbtn" data-nav="assistant" onclick="nav('assistant')"><span class="ic">⌕</span><span data-i18n="Assistant">Assistant</span></button>
    <button class="navbtn" data-nav="insights" onclick="nav('insights')"><span class="ic">◇</span><span data-i18n="Security insights">Security insights</span></button>
    <button class="navbtn" data-nav="audit" onclick="nav('audit')"><span class="ic">≡</span><span data-i18n="Audit log">Audit log</span></button>
    <button class="navbtn" data-nav="settings" onclick="nav('settings')"><span class="ic">⚙</span><span data-i18n="Settings">Settings</span></button>
  </aside>
  <main>
    <div class="topbar"><button class="iconbtn" id="navtoggle" aria-label="Open navigation" data-i18n-aria-label="Open navigation" onclick="toggleNav()">☰</button><h2 id="pagetitle" data-i18n="Apps">Apps</h2><span class="crumb" id="crumb"></span><div class="grow"></div>
      <button class="iconbtn" data-themetoggle type="button" onclick="cycleTheme()" aria-label="Switch theme"></button><select class="langsel" data-langsel onchange="owSetLang(this.value)" aria-label="Language" data-i18n-aria-label="Language"></select>
      <div class="searchbox" role="button" tabindex="0" onclick="openPalette()" onkeydown="if(event.key==='Enter'||event.key===' ')openPalette()"><svg class="icon" width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6"/><path d="m20 20-4.2-4.2"/></svg><span style="flex:1" data-i18n="Search secrets…">Search secrets…</span><kbd>⌘K</kbd></div>
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
<script src="/i18n.js" integrity="sha384-grOAmA6TYjv9ZZ8JCDes2Ok2+pPOWojkd8SDybUuUke1KgWv9x3Fc6PXvgkEubfe"></script>
<script>
let CREATION_OPEN=true, INVITE='', INVITE_META=null;
let EMERGENCY=false, PROJECT_EMERGENCY=false, PROJECT_DIRECT=false, EMERGENCY_OWNER=false, EMERGENCY_POLL=null, AUTH_READY=false, SECRET_EPOCH=0, EMERGENCY_REQUEST=0, EDITION=null;
let T='', ORG='', ORGS=[], REGIONS=[], APP=null, ENV=null, APPS=[], ENVS=[], SECRETS=[], DRAFTS={}, VIEW='apps', MFA=null, LASTFOCUS=null, PENDING_ORG=null, ME=null,
  E2E_KIT='', E2E_KEYS={}, E2E_DATA={}, E2E_DRAFTS={}, E2E_META={}, E2E_GRANTS={}, E2E_LOADING={}, E2E_LOCKED={}, E2E_ERR={}, MY_PUBKEY='', MY_UID='';
function drafts(){return (ENV&&DRAFTS[ENV.id])||{}}
function draftList(){return Object.values(drafts())}
function e2eDrafts(){return (ENV&&E2E_DRAFTS[ENV.id])||{}}
function e2eDraftList(){return Object.values(e2eDrafts())}
const $=id=>document.getElementById(id);
const H=(u)=>(T&&!(EMERGENCY||PROJECT_EMERGENCY)&&!/\/emergency$/.test(u||''))?{'Authorization':'Bearer '+T,'Content-Type':'application/json'}:{'Content-Type':'application/json'};
function emergencyAllowed(m,u){if(u===`/api/orgs/${ORG}/emergency`||u===`/api/apps/${APP?.id}/emergency`||u==='/api/auth/logout')return true;
  if(m==='PUT'&&(u==='/api/me/secret-health'||u==='/api/me/secret-health/enzoic'))return true;
  return m==='GET'&&!/\/(secrets|export|e2e|leases|search)(\/|\?|$)/.test(u)}
async function api(m,u,b){if((EMERGENCY||PROJECT_EMERGENCY)&&!emergencyAllowed(m,u))throw new Error('Selected scope is in emergency lockdown');
  let active=AUTH_READY,org=ORG;let r=await fetch(u,{method:m,headers:H(u),body:b!==undefined?JSON.stringify(b):undefined});let t=await r.text();let d;try{d=JSON.parse(t)}catch(e){d={error:t}}
  if(active&&(!AUTH_READY||org!==ORG))throw new Error('Session or workspace changed');
  if((EMERGENCY||PROJECT_EMERGENCY)&&!emergencyAllowed(m,u))throw new Error('Selected scope is in emergency lockdown');
  if(r.status===401&&AUTH_READY)sessionEnded();
  if(AUTH_READY&&(r.status===423||(r.status===403&&String(d.error||'').includes('emergency lockdown')))){clearSecretState();$('view').innerHTML=emergencyCard(true);refreshEmergency()}
  if(!r.ok) throw new Error(d.error||('HTTP '+r.status)); return d}
function toastUI(key,args,err){if(typeof args==='boolean'){err=args;args=undefined}return toast(owT(key,args),err,key,args)}
function clearSecretState(){aiReset();SECRET_EPOCH++;SECRETS=[];DRAFTS={};E2E_KIT='';E2E_KEYS={};E2E_DATA={};E2E_DRAFTS={};E2E_META={};E2E_GRANTS={};E2E_LOADING={};E2E_LOCKED={};E2E_ERR={};clearPkiState();
  closeModal();$('modal').innerHTML='';$('palette').style.display='none';$('paletteresults').innerHTML='';$('deploybar').classList.remove('show')}
function sessionEnded(){AUTH_READY=false;EMERGENCY_REQUEST++;clearInterval(EMERGENCY_POLL);T='';clearSecretState();applyEmergency(false,false);PROJECT_DIRECT=false;EMERGENCY_OWNER=false;APP=null;ENV=null;APPS=[];ENVS=[];MY_PUBKEY='';MY_UID='';
  $('view').innerHTML='';$('shell').style.display='none';$('auth').style.display='grid';$('pw').value='';toastUI('Your session ended. Sign in again.', true)}
function isEnterprise(){return !!(EDITION&&EDITION.enterprise)}
function enterpriseLock(title,body){return `<div class="card"><h3>${esc(title)} <span class="chip">Enterprise</span></h3><p class="mut">${esc(body)}</p><p class="small mut">Set <span class="mono">OPENWARP_LICENSE</span> to a license issued for this installation, then restart the server to enable it.</p></div>`}
function emergencyCard(project=false){let locked=project?PROJECT_EMERGENCY:EMERGENCY,direct=project?PROJECT_DIRECT:EMERGENCY,scope=project?'project':'workspace';return `<div class="card" style="border-color:var(--bad)"><h3>${locked?'Emergency lockdown active':(project?'Project lockdown':'Emergency lockdown')}</h3>
  <p>${locked?'The web console is read-only. Secrets are hidden, syncs are paused, and all automation reads and writes for this scope are rejected.':`Halt this ${scope}, sign out non-owner members, and block secret access, changes and automation requests.`}</p>
  ${project&&EMERGENCY?'<p>The workspace lockdown also applies. Only restoring the workspace can lift that restriction.</p>':''}
  <p class="small mut">Previously copied values and dispatched remote requests cannot be recalled. Revoked sessions stay revoked.</p>
  ${EMERGENCY_OWNER?`<button class="${direct?'primary':'danger'}" onclick="confirmEmergency(${!direct},${project})">${direct?`Restore ${scope} access`:`Activate ${scope} lockdown`}</button>`:'<p>Only a workspace owner can restore access.</p>'}</div>`}
function applyEmergency(locked,project=PROJECT_EMERGENCY){let changed=EMERGENCY!==locked||PROJECT_EMERGENCY!==project;EMERGENCY=locked;PROJECT_EMERGENCY=project;let halted=locked||project,banner=$('emergency-banner');banner.hidden=!halted;
  banner.innerHTML=halted?`<div class="card" style="border-color:var(--bad)"><strong>Emergency lockdown active: ${locked?'workspace':'project'}</strong><p>The console is read-only. Secrets are hidden and automation requests are rejected.</p></div>`:'';
  if(halted){if(changed)clearSecretState();$('topaction').style.display='none';if(changed)$('view').innerHTML=emergencyCard(!locked)}}
async function refreshEmergency(){let org=ORG,app=APP?.id,request=++EMERGENCY_REQUEST;if(!org)return;try{let d=await api('GET',`/api/orgs/${org}/emergency`),p=app?await api('GET',`/api/apps/${app}/emergency`):null;
  if(AUTH_READY&&org===ORG&&app===APP?.id&&request===EMERGENCY_REQUEST){PROJECT_DIRECT=!!p?.direct_locked;applyEmergency(!!d.locked,!!p?.locked);if(!d.locked&&!p?.locked&&['assistant','insights'].includes(VIEW)){let probe=await apiRaw('GET',`/api/orgs/${org}/ai/settings`);if(AUTH_READY&&org===ORG&&request===EMERGENCY_REQUEST&&probe.status===403&&String(probe.body.error||'').includes('emergency lockdown')){clearSecretState();$('view').innerHTML='<div class="card"><h3>Project emergency lockdown active</h3><p>Workspace AI is unavailable while a project is locked.</p></div>'}}}}catch(e){if(AUTH_READY&&org===ORG&&request===EMERGENCY_REQUEST&&(EMERGENCY||PROJECT_EMERGENCY)){$('view').innerHTML=emergencyCard(!EMERGENCY)}}}
function confirmEmergency(locked,project=false){let org=ORG,app=APP?.id,scope=project?'project':'workspace';modal(`<h3>${locked?`Activate ${scope} lockdown?`:`Restore ${scope} access?`}</h3><p>${locked?'Non-owner members will be signed out. The console will be read-only, secrets hidden and automation reads and writes rejected for this scope.':`The direct ${scope} lockdown will be lifted. Other lockdowns still apply. Revoked sessions stay revoked.`}</p><div class="row"><button class="${locked?'danger':'primary'}" id="emergency-confirm">${locked?'Activate lockdown':'Restore access'}</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`,'Confirm emergency lockdown');
  $('emergency-confirm').onclick=async()=>{if(ORG!==org||(project&&APP?.id!==app)){closeModal();return}try{EMERGENCY_REQUEST++;await api('PUT',project?`/api/apps/${app}/emergency`:`/api/orgs/${org}/emergency`,{locked});await refreshEmergency();closeModal();if(project){$('view').innerHTML=emergencyCard(true)}else await nav('settings')}catch(e){toast(e.message,true)}}}
// Keep the error body for deletion's ownership and credential warnings.
async function apiRaw(m,u,b){if((EMERGENCY||PROJECT_EMERGENCY)&&!emergencyAllowed(m,u))throw new Error('Selected scope is in emergency lockdown');let r=await fetch(u,{method:m,headers:H(u),body:b!==undefined?JSON.stringify(b):undefined});let t=await r.text();let d;try{d=JSON.parse(t)}catch(e){d={error:t}}
  return {ok:r.ok,status:r.status,body:d}}
function toast(msg,err,key,args){let el=document.createElement('div');el.className='toast'+(err?' err':'');if(key)owText(el,key,args);else el.textContent=msg;$('toasts').appendChild(el);el.style.transition='opacity .3s';setTimeout(()=>{el.style.opacity='0';setTimeout(()=>el.remove(),320)},3000)}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
// For values interpolated into an inline handler's JS string literal. HTML
// escaping alone is not enough: the parser turns &#39; back into a quote before
// the JS is parsed, which would let a secret key break out of the string.
function jsq(s){return String(s??'').replace(/&/g,'&amp;').replace(/\\/g,'\\\\').replace(/'/g,"\\u0027").replace(/"/g,'\\u0022').replace(/</g,'\\u003c').replace(/>/g,'\\u003e').replace(/\n/g,'\\n').replace(/\r/g,'\\r')}
let HEALTH_GENERATION=0;
function mountSecretHealth(){let input=$('ns-val')||$('ed-val');if(!input||EMERGENCY||PROJECT_EMERGENCY)return;let epoch=SECRET_EPOCH;
  let box=document.createElement('div');box.className='field';box.innerHTML=`<details><summary data-i18n="Secret health (optional)">Secret health (optional)</summary><p class="small mut" data-i18n="Human password advice only, not a rule for API tokens or SSH keys. Checks never block saving.">Human password advice only, not a rule for API tokens or SSH keys. Checks never block saving.</p><div class="row"><button type="button" data-health="local" data-i18n="Check as password">Check as password</button><button type="button" data-health="password" data-i18n="Check password breaches">Check password breaches</button><button type="button" data-health="enzoic" hidden data-i18n="Check password with Enzoic">Check password with Enzoic</button><button type="button" data-health="pair" hidden data-i18n="Check email/password pair">Check email/password pair</button><button type="button" data-health="email" hidden data-i18n="Check email exposure">Check email exposure</button><button type="button" data-health="leakcheck" hidden data-i18n="Check email with LeakCheck (free)">Check email with LeakCheck (free)</button></div><label hidden data-health-pair-label style="margin-top:12px"><span data-i18n="Email for credential-pair check">Email for credential-pair check</span><input type="email" data-health-pair-email autocomplete="off" spellcheck="false" aria-label="Email for credential-pair check" data-i18n-aria-label="Email for credential-pair check"></label><p class="small" role="status" data-health-result></p></details>`;
  input.parentElement.appendChild(box);let output=box.querySelector('[data-health-result]'),emailButton=box.querySelector('[data-health="email"]'),enzoicButton=box.querySelector('[data-health="enzoic"]'),leakButton=box.querySelector('[data-health="leakcheck"]'),keySet=false,enzoicSet=false;
  const pairButton=box.querySelector('[data-health="pair"]'),pairEmail=box.querySelector('[data-health-pair-email]'),pairLabel=box.querySelector('[data-health-pair-label]');
  pairEmail.addEventListener('input',()=>{HEALTH_GENERATION++;output.textContent=''});
  const emailLike=()=>input.value.length<=254&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.value.trim());
  leakButton.hidden=!emailLike();
  input.addEventListener('input',()=>{HEALTH_GENERATION++;output.textContent='';emailButton.hidden=!keySet||!emailLike();leakButton.hidden=!emailLike()});
  box.querySelector('details').addEventListener('toggle',()=>{if(!box.querySelector('details').open)return;api('GET','/api/me/secret-health').then(d=>{if(!box.isConnected)return;keySet=d.api_key_set===true;emailButton.hidden=!keySet||!emailLike()}).catch(()=>{});api('GET','/api/me/secret-health/enzoic').then(d=>{if(!box.isConnected)return;enzoicSet=d.configured===true;enzoicButton.hidden=!enzoicSet;pairButton.hidden=!enzoicSet;pairLabel.hidden=!enzoicSet}).catch(()=>{})});
  box.querySelectorAll('[data-health]').forEach(button=>button.onclick=async()=>{
    if(EMERGENCY||PROJECT_EMERGENCY||epoch!==SECRET_EPOCH||!box.isConnected||!modalOpen())return;
    let kind=button.dataset.health,value=input.value,pairAddress=pairEmail.value;
    if(kind==='pair'&&(!enzoicSet||!pairAddress||!confirm('Check the entered email with this secret value as the password? A stable full SHA-256 hash of the lowercased exact email and ten-character password-derived prefixes are disclosed through OpenWarp to Enzoic. These permit guessing and correlation. Plain email, password and full password-derived hashes stay in this browser. Your own applicable subscription is required.')))return;
    if(kind==='password'&&!confirm('Send only the first five characters of a locally computed SHA-1 hash to HIBP Pwned Passwords? The full value and hash stay in this browser.'))return;
    if(kind==='email'&&(!keySet||!emailLike()||!confirm('Send this full email address to the OpenWarp server and Have I Been Pwned using your paid HIBP key? This breaks server-blind handling for this disclosed value, including in E2E environments.')))return;
    if(kind==='enzoic'&&(!enzoicSet||!confirm('Send the first ten lowercase hexadecimal characters of the exact password SHA-256 hash through OpenWarp to Enzoic using your own subscription? The password and full hash stay in this browser. Prefixes can reveal guesses; this is not anonymous.')))return;
    if(kind==='leakcheck'&&(!emailLike()||!confirm('Trim and lowercase this email, then send the first 24 hexadecimal characters of its SHA-256 hash through OpenWarp to LeakCheck Public? This stable identifier is not anonymous and can reveal guesses. The full email stays in this browser.')))return;
    let generation=++HEALTH_GENERATION;output.textContent='Checking...';
    const current=()=>generation===HEALTH_GENERATION&&epoch===SECRET_EPOCH&&!EMERGENCY&&!PROJECT_EMERGENCY&&box.isConnected&&modalOpen()&&input.value===value&&(kind!=='pair'||pairEmail.value===pairAddress);
    const healthFetch=(u,o)=>{if(!current())throw new Error('Secret health check cancelled');return fetch(u,o)};
    try{let message;
      if(kind==='local'){let d=OpenWarpSecretHealth.localStrength(value);message=Number.isInteger(d.score)?`Password guessability score: ${d.score}/4 (local zxcvbn estimate).`:'Local estimate unavailable (limit: 1024 characters).'}
      else if(kind==='password'){let d=await OpenWarpSecretHealth.checkPassword(value,{enabled:true,fetch:healthFetch});message=d.status==='found'?`Found in password breach data (${d.count} occurrences).`:d.status==='not_found'?'Not found in this password dataset. This does not prove the value is safe.':'Password check unavailable.'}
      else if(kind==='pair'){let d=await OpenWarpEnzoicPairs.checkCredentials(pairAddress,value,{enabled:true,isCurrent:current,fetch:(u,o)=>healthFetch(u,{...o,headers:{...o.headers,...H()}})});message=d.status==='found'?'Found in Enzoic credential-pair exposure data.':d.status==='not_found'?'Not found in this Enzoic credential-pair dataset. This does not prove the pair is unexposed.':'Enzoic credential-pair check unavailable. Unsupported requirements, provider errors or limits cannot give a clean result.'}
      else if(kind==='enzoic'){let d=await OpenWarpSecretHealth.checkEnzoicPassword(value,{enabled:true,fetch:(u,o)=>healthFetch(u,{...o,headers:{...o.headers,...H()}})});message=d.status==='found'?`Found in Enzoic password exposure data (${d.count} exposures).`:d.status==='not_found'?'Not found in this Enzoic password dataset. This does not prove the value is safe.':'Enzoic password check unavailable.'}
      else if(kind==='leakcheck'){let d=await OpenWarpSecretHealth.checkEmailExposure(value,{enabled:true,fetch:(u,o)=>healthFetch(u,{...o,headers:{...o.headers,...H()}})});message=d.status==='found'?'Breach sources: '+d.breaches.join(', '):d.status==='not_found'?'Not found in this LeakCheck dataset. This does not prove the address is unexposed.':'LeakCheck email check unavailable.'}
      else{let d=await api('POST','/api/me/secret-health/email',{email:value,consent:true});message=d.status==='found'?'Breach names: '+d.breaches.join(', '):'Not found in this email dataset. This does not prove the address is unexposed.'}
      if(current()){output.textContent=message;if(kind==='email'){let link=document.createElement('a');link.href='https://haveibeenpwned.com/';link.textContent=' Have I Been Pwned';link.target='_blank';link.rel='noreferrer noopener';output.appendChild(link)}if(kind==='leakcheck'){let link=document.createElement('a');link.href='https://leakcheck.io/';link.textContent=' Powered by LeakCheck';link.target='_blank';link.rel='noreferrer noopener';output.appendChild(link)}}
    }catch(e){if(current())output.textContent=e.message}
  })}
async function loadHealthKeyStatus(){try{let d=await api('GET','/api/me/secret-health');if($('health-key-status'))owText($('health-key-status'),d.api_key_set?'Key stored':'No key stored')}catch(e){toast(e.message,true)}}
async function saveHealthKey(clear){let input=$('health-key'),key=input.value;input.value='';try{let d=await api('PUT','/api/me/secret-health',{api_key:clear?null:key});owText($('health-key-status'),d.api_key_set?'Key stored':'No key stored')}catch(e){toast(e.message,true)}}
async function loadEnzoicStatus(){try{let d=await api('GET','/api/me/secret-health/enzoic');if($('enzoic-status'))owText($('enzoic-status'),d.configured?'Credentials stored encrypted':'No credentials stored')}catch(e){toast(e.message,true)}}
async function saveEnzoic(clear){let key=$('enzoic-key').value,secret=$('enzoic-secret').value;$('enzoic-key').value='';$('enzoic-secret').value='';try{let d=await api('PUT','/api/me/secret-health/enzoic',{api_key:clear?null:key,api_secret:clear?null:secret});if($('enzoic-status'))owText($('enzoic-status'),d.configured?'Credentials stored encrypted':'No credentials stored')}catch(e){toast(e.message,true)}}
let PRODUCT_DIALOG=null, PRODUCT_SERIAL=0;
function modal(html,label){HEALTH_GENERATION++;PRODUCT_SERIAL++;PRODUCT_DIALOG=null;let m=$('modal');m.innerHTML=html;m.setAttribute('role','dialog');m.setAttribute('aria-modal','true');mountSecretHealth();
  if(label)owAttr(m,'aria-label',label);else{m.removeAttribute('aria-label');m.removeAttribute('data-i18n-aria-label')}owApply(m);
  $('modalwrap').classList.add('show');LASTFOCUS=document.activeElement;
  requestAnimationFrame(()=>{let f=m.querySelector('input,textarea,select,button');if(f)f.focus()})}
function closeModal(){HEALTH_GENERATION++;let w=$('modalwrap');if(!w.classList.contains('show'))return;let hookKeyInput=$('hook-key');if(hookKeyInput){hookKeyInput.value='';$('modal').innerHTML=''}w.classList.remove('show');
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
const ICONS={
  system:'<circle cx="12" cy="12" r="8"/><path d="M12 4a8 8 0 0 1 0 16Z" fill="currentColor" stroke="none"/>',
  light:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"/>',
  dark:'<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z"/>',
  eye:'<path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
  copy:'<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
  edit:'<path d="m4 20 4.5-1 10-10-3.5-3.5-10 10L4 20Z"/><path d="m14 6 3.5 3.5"/>',
  history:'<path d="M4 12a8 8 0 1 0 2.3-5.7L4 8.6"/><path d="M4 4v4.6h4.6"/><path d="M12 8v4l3 2"/>',
  override:'<circle cx="12" cy="8" r="3.2"/><path d="M5 20a7 7 0 0 1 14 0"/>',
  trash:'<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/><path d="M10 11v6M14 11v6"/>',
  apps:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>'
};
function icon(n,s=16){return `<svg class="icon" width="${s}" height="${s}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[n]||''}</svg>`}
function applyThemeIcons(){let p=themePref();let ic=icon(p,16);let label=owT('Theme: '+p);
  document.querySelectorAll('[data-themetoggle]').forEach(b=>{b.innerHTML=ic;b.title=label;b.setAttribute('aria-label',label)})}

// ---------- auth ----------
async function loadProviders(){try{
  let p=await api('GET','/api/auth/providers');
  renderRegion(p);
  // A method the binary lacks has no route at all, so its button is hidden. A
  // method the binary has stays visible even when the workspace has not
  // enabled it: the attempt explains why instead of failing silently.
  let saml=$('saml-signin');if(saml)saml.style.display=p.saml?'':'none';
  let btns=[];
  for(const [id,name] of [['google','Google'],['microsoft','Microsoft'],['apple','Apple'],['github','GitHub'],['okta','Okta'],['auth0','Auth0'],['gitlab','GitLab'],['atlassian','Atlassian'],['slack','Slack'],['salesforce','Salesforce'],['openai','OpenAI'],['x','X'],['discord','Discord'],['linkedin','LinkedIn'],['workos','WorkOS']]){
    if(p[id])btns.push(`<button style="flex:1 1 45%" onclick="location.href='/api/auth/social/${id}/start'">${owHTML('Continue with {x}',{x:name})}</button>`)}
  if(p.oidc)btns.push(`<button style="flex:1 1 45%" onclick="location.href='/api/auth/social/oidc/start'">${owHTML('Continue with {x}',{x:p.oidc_name||'SSO'})}</button>`);
  if(p.ldap)btns.push(`<button style="flex:1 1 45%" onclick="ldapPrompt()" data-i18n="Sign in with directory (LDAP)">Sign in with directory (LDAP)</button>`);
  // The invitation screen replaces the form that hosts these nodes.
  if(!$('social'))return;
  $('social').innerHTML=btns.join('');
  if(p.signups!=='open'){
    $('segreg').style.display='none';
    if(MODE==='register')authMode('login');
    owText($('signupnote'),'Signups are closed. Ask an administrator for an invitation.');
  }
}catch(e){}}
function joinWorkspace(){let value=prompt('Paste an invitation link or token');if(!value)return;let token=value.trim();try{if(token.includes('#invite='))token=decodeURIComponent(token.split('#invite=')[1].split('&')[0])}catch(e){toast('Invalid invitation link',true);return}showInvite(token)}
const AUTH_FORM=$('authform').innerHTML;
function inviteSignIn(){INVITE='';$('authform').innerHTML=AUTH_FORM;authMode('login');loadProviders();history.replaceState(null,'',location.pathname)}
async function showInvite(token){
  INVITE=token;sessionStorage.setItem('ow_pending_invite',token);
  $('auth').style.display='grid';$('shell').style.display='none';owText($('authtitle'),'Accept invitation');
  $('authform').innerHTML='<p class="mut">Loading invitation...</p>';
  try{let d=await api('GET','/api/auth/invite?token='+encodeURIComponent(token));INVITE_META=d;
    let me=await api('GET','/api/me').catch(()=>null);let matching=me&&me.email.toLowerCase()===d.email.toLowerCase();
    $('authform').innerHTML=`<p>Join <strong>${esc(d.org_name)}</strong> as ${esc(d.role)} with ${esc(d.email)}.</p><p class="small mut">Expires ${esc(new Date(d.expires_at*1000).toLocaleString())}. Joining requires your consent.</p>
      ${me&&!matching?`<p>You are signed in as ${esc(me.email)}. Sign out before accepting this invitation.</p><button onclick="logout()" data-i18n="Sign out">Sign out</button>`:matching?'<button class="primary" onclick="acceptInvite()">Join workspace</button>':d.existing_account?`<p>Sign in to the invited account, then return to this invitation.</p><button onclick="inviteSignIn()" data-i18n="Sign in">Sign in</button>`:`<div class="field"><label for="inv-pw" data-i18n="Password">Password</label><input id="inv-pw" type="password" autocomplete="new-password" placeholder="at least 8 characters" data-i18n-placeholder="at least 8 characters"></div><button class="primary" onclick="acceptInvite()">Create account and join</button><p class="small mut">Or sign in with a configured provider, then return here to join.</p><button onclick="inviteSignIn()">Sign in with a provider</button>`}
      <button class="ghost" onclick="dismissInvite()">Not now</button>`;
  }catch(e){$('authform').innerHTML=`<p>${esc(e.message)}</p><button onclick="dismissInvite()">Back to sign in</button>`}}
function dismissInvite(){INVITE='';sessionStorage.removeItem('ow_pending_invite');history.replaceState(null,'',location.pathname);location.reload()}
async function acceptInvite(){try{
  let d;
  if(INVITE_META.existing_account){d=await api('POST','/api/auth/accept-invite',{token:INVITE})}
  else {let password=$('inv-pw').value;if(password.length<8)throw new Error('Password must be at least 8 characters');
    let salt=AuthV2.randomSalt(),iterations=600000,keys=await AuthV2.deriveKeys(password,salt,iterations),kp=await OW.generateKeypair();
    d=await api('POST','/api/auth/accept-invite-v2',{token:INVITE,salt,iterations,algo:'pbkdf2-sha256',auth_key:AuthV2.b64enc(keys.auth),public_key:kp.public,wrapped_privkey:await AuthV2.wrapPrivate(keys.wrap,kp.secret)});
    E2E_KIT=AuthV2.b64enc(kp.secret);
  }
  INVITE='';sessionStorage.removeItem('ow_pending_invite');PENDING_ORG=d.org_id||INVITE_META.org_id;history.replaceState(null,'',location.pathname);if(!INVITE_META.existing_account)T='';await enterApp();
  if(E2E_KIT)modal(`<h3>Save your recovery kit</h3><p>Keep this private key offline to recover end-to-end access.</p><textarea aria-label="Recovery kit" rows="3" readonly>${esc(E2E_KIT)}</textarea><button onclick="closeModal()">I saved it</button>`,'Save recovery kit');
}catch(e){toast(e.message,true)}}
function forgotPrompt(){modal(`<h3 data-i18n="Reset your password">Reset your password</h3><p class="mut" data-i18n="Enter your email. If an account exists, a reset link is sent.">Enter your email. If an account exists, a reset link is sent.</p>
  <div class="field"><label for="fp-email" data-i18n="Email">Email</label><input id="fp-email" type="email" value="${esc($('email').value)}"></div>
  <div class="row"><button class="primary" onclick="sendForgot()" data-i18n="Send link">Send link</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>`,'Reset password')}
function workspaceSsoPrompt(){modal(`<h3 data-i18n="Sign in to a workspace">Sign in to a workspace</h3><p class="mut" data-i18n="Single sign-on is configured per workspace, and an address alone cannot reveal which workspace you mean.">Single sign-on is configured per workspace, and an address alone cannot reveal which workspace you mean.</p>
  <div class="field"><label for="saml-org" data-i18n="Workspace ID">Workspace ID</label><input id="saml-org" placeholder="workspace id" data-i18n-placeholder="workspace id" autocomplete="off" onkeydown="if(event.key==='Enter')samlGo('saml')"></div>
  <p class="small mut" data-i18n="An owner can copy it from Members and access.">An owner can copy it from Members and access.</p>
  <div class="row" style="margin-top:12px"><button class="primary" onclick="samlGo('saml')" data-i18n="Continue with SAML">Continue with SAML</button><button onclick="samlGo('oidc')" data-i18n="Continue with OIDC">Continue with OIDC</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>`,'Workspace sign-in')}
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
  let email=$('email').value.trim(),password=$('pw').value,kdf=await AuthV2.kdf(email),d;
  if(kdf.version===2){let keys=await AuthV2.deriveKeys(password,kdf.salt,kdf.iterations),challenge=await AuthV2.challenge(email);
    d=await api('POST','/api/auth/login-v2',{email,challenge_id:challenge.challenge_id,proof:await AuthV2.proof(keys.auth,challenge.challenge,challenge.challenge_id)});
  }else d=await api('POST','/api/auth/login',{email,password});
  if(d.mfa_required){MFA=d.mfa_token;$('mfafield').style.display='block';owText($('authbtn'),'Verify code');$('authbtn').onclick=doMfa;toastUI('Enter your authenticator or recovery code', false);return}
  T='';await enterApp();
}catch(e){toast(e.message,true)}}
async function doMfa(){try{let d=await api('POST','/api/auth/mfa',{mfa_token:MFA,code:$('mfacode').value});T='';await enterApp()}catch(e){toast(e.message,true)}}
async function logout(){aiReset();closeModal();try{await api('POST','/api/auth/logout',{})}catch(e){} T='';clearPkiState();location.reload()}
// The last workspace is remembered per account, so a shared browser does not
// carry one person's choice into the next person's session.
function orgMemoryKey(){return 'ow.org.'+((ME&&(ME.id||ME.email))||'')}
function rememberedOrg(){try{return localStorage.getItem(orgMemoryKey())||''}catch(e){return ''}}
function rememberOrg(id){try{localStorage.setItem(orgMemoryKey(),id)}catch(e){}}
// Restore a usable surface if the workspace list cannot be loaded. Leaving the
// sign-in card hidden turns a failed request into a blank page. A failed
// bootstrap brings back the ordinary sign-in form (AUTH_FORM), so a consumed
// invite or reset token cannot be resubmitted; an unconsumed invite preview
// keeps its own markup. PENDING_ORG survives the failure so a retry still
// opens the workspace an invitation just added.
async function enterApp(){
  let pending=sessionStorage.getItem('ow_pending_invite');
  if(pending&&!INVITE){await showInvite(pending);return}
  $('auth').style.display='none';
  try{await enterAppInner()}
  catch(e){T='';
    if(!INVITE){$('authform').innerHTML=AUTH_FORM;delete $('authform').dataset.reset;authMode('login')}
    $('auth').style.display='grid';$('shell').style.display='none';$('picker').style.display='none';throw e}}
async function enterAppInner(){
  EDITION=await api('GET','/api/instance/edition').catch(()=>null);
  let me=await api('GET','/api/me');ME=me;MY_PUBKEY=me.pubkey||'';MY_UID=me.id||'';
  let policy=await api('GET','/api/auth/providers');CREATION_OPEN=policy.workspace_creation_open!==false;$('new-workspace').style.display=CREATION_OPEN?'':'none';
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
async function pickOrg(id){ORG=id;rememberOrg(id);$('picker').style.display='none';$('shell').style.display='grid';
  try{await startWorkspace()}
  catch(e){ORG='';
    // A 401 during entry has already run sessionEnded and returned the sign-in
    // card; re-showing the picker would imply a session that no longer exists.
    if(AUTH_READY){EMERGENCY_OWNER=false;$('shell').style.display='none';$('picker').style.display='grid';showPicker();toast(e.message,true)}
    else{AUTH_READY=false;EMERGENCY_OWNER=false;$('auth').style.display='grid';$('shell').style.display='none';$('picker').style.display='none'}}}
async function startWorkspace(){
  if(PRODUCT_DIALOG)closeModal();PRODUCT_SERIAL++;SECRET_EPOCH++;SECRETS=[];clearPkiState();APP=null;ENV=null;PROJECT_DIRECT=false;applyEmergency(false,false);
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
  else if(e.key==='ArrowUp'){e.preventDefault();items[(i-1)%items.length].focus()}
  else if(e.key==='Home'){e.preventDefault();items[0].focus()}
  else if(e.key==='End'){e.preventDefault();items[items.length-1].focus()}
  else if(e.key==='Escape'){e.preventDefault();closeOrgMenu();$('orgbtn').focus()}}
async function switchOrg(id){aiReset();if(PRODUCT_DIALOG)closeModal();PRODUCT_SERIAL++;SECRET_EPOCH++;SECRETS=[];ORG=id||ORG;clearPkiState();APP=null;ENV=null;EMERGENCY_OWNER=ORGS.find(o=>o.id===ORG)?.role==='owner';PROJECT_DIRECT=false;rememberOrg(ORG);renderOrgMenu();applyEmergency(false,false);await refreshEmergency();await nav(EMERGENCY?'settings':'apps')}
async function refreshOrgs(){ORGS=await api('GET','/api/orgs');renderOrgMenu();EMERGENCY_OWNER=ORGS.find(o=>o.id===ORG)?.role==='owner'}

// ---------- navigation ----------
function toggleNav(){let a=document.querySelector('aside');if(!a)return;let open=a.classList.toggle('open');let t=$('navtoggle');if(t)t.setAttribute('aria-expanded',open?'true':'false')}
async function nav(v){if(PRODUCT_DIALOG)closeModal();PRODUCT_SERIAL++;VIEW=v;let a=document.querySelector('aside');if(a){a.classList.remove('open');let t=$('navtoggle');if(t)t.setAttribute('aria-expanded','false')}document.querySelectorAll('.navbtn').forEach(b=>b.classList.toggle('on',b.dataset.nav===v));
  $('topaction').style.display=(v==='apps'&&ORG&&!EMERGENCY)?'':'none';
  if(v!=='assistant')AI_PLAN=null;
  if(!ORG&&v!=='settings'){renderEmptyWorkspace();return}
  updateDeployBar();
  if((EMERGENCY||PROJECT_EMERGENCY)&&['access','integrations','webhooks','assistant','insights'].includes(v)){$('pagetitle').textContent='Read-only inspection';$('crumb').textContent='';$('view').innerHTML=emergencyCard(!EMERGENCY);return}
  try{await ({apps:renderApps,access:renderAccess,integrations:renderIntegrations,webhooks:renderWebhooks,assistant:renderAssistant,insights:renderInsights,audit:renderAudit,settings:renderSettings}[v]||renderApps)()}
  catch(e){$('view').innerHTML=`<div class="card" style="border-color:var(--bad)"><h3>${esc(owT('This view could not load'))}</h3><p>${esc(e&&e.message||String(e))}</p><div class="row"><button class="primary" onclick="nav(${jsq(v)})">${esc(owT('Try again'))}</button><button class="ghost" onclick="nav('apps')">${esc(owT('Back to apps'))}</button></div></div>`}
  updateDeployBar()}

function renderEmptyWorkspace(){$('topaction').style.display='none';owText($('pagetitle'),'Workspaces');owDataText($('crumb'),'');$('view').innerHTML=`<div class="empty"><h3>No workspace yet</h3><p>${CREATION_OPEN?'Create a workspace or accept an invitation.':'Workspace creation is disabled. Ask an administrator for an invitation.'}</p><div class="row">${CREATION_OPEN?'<button class="primary" onclick="newWorkspace()">Create workspace</button>':''}<button onclick="joinWorkspace()">Join workspace</button><button onclick="nav('settings')">Account and instance settings</button></div></div>`}
function newWorkspace(){if(!CREATION_OPEN){toast('Workspace creation is disabled',true);return}modal(`<h3>New workspace</h3><div class="field"><label for="nw-name">Workspace name</label><input id="nw-name"></div><button class="primary" onclick="createWorkspace()">Create workspace</button><button onclick="closeModal()">Cancel</button>`,'New workspace')}
async function createWorkspace(){try{let d=await api('POST','/api/orgs',{name:$('nw-name').value.trim()});PENDING_ORG=d.id;closeModal();await enterApp()}catch(e){toast(e.message,true)}}
async function renameWorkspace(){let name=prompt('Workspace name');if(name===null)return;try{await api('PATCH',`/api/orgs/${ORG}`,{name});await refreshOrgs();renderSettings()}catch(e){toast(e.message,true)}}
async function leaveWorkspace(){if(!confirm('Leave this workspace? An invitation is required to return.'))return;try{await api('POST',`/api/orgs/${ORG}/leave`,{});await enterApp()}catch(e){toast(e.message,true)}}

// ---------- apps ----------
async function renderApps(){if(!ORG){renderEmptyWorkspace();return}$('topaction').style.display=EMERGENCY?'none':'';owText($('pagetitle'),'Apps');owDataText($('crumb'),'');
  $('view').innerHTML='<div class="empty"><div class="big" data-i18n="Loading…">Loading…</div></div>';
  APPS=ORG?await api('GET',`/api/orgs/${ORG}/apps`):[];
  if(!APPS.length){$('view').innerHTML=`<div class="empty"><div class="big">▦</div><span data-i18n="No apps yet">No apps yet</span><p data-i18n="Create an app to start managing secrets for a project.">Create an app to start managing secrets for a project.</p><button class="primary" onclick="newApp()" data-i18n="Create your first app">Create your first app</button></div>`;return}
  let envCounts={};for(let a of APPS){try{let es=await api('GET',`/api/apps/${a.id}/envs`);envCounts[a.id]=es}catch(e){envCounts[a.id]=[]}}
  $('view').innerHTML=`<div class="row" style="margin-bottom:14px"><input id="appfilter" placeholder="Filter apps…" data-i18n-placeholder="Filter apps…" style="min-width:240px" oninput="filterApps(this.value)"><span class="mut small">${owHTML(APPS.length===1?'{N} app, unlimited environments':'{N} apps, unlimited environments',{N:APPS.length})}</span></div>
  <div class="grid" id="appgrid">${APPS.map(a=>appCard(a,envCounts[a.id])).join('')}</div>`}
function appCard(a,envs){return `<div class="appcard" onclick="openApp('${a.id}')"><h3 data-i18n-skip>${esc(a.name)}</h3><div class="meta">${owHTML(envs.length===1?'{n} environment':'{n} environments',{n:envs.length})}${a.reuse_check===false?owHTML(' · reuse checks off'):''}${a.emergency_locked?owHTML(' · lockdown'):''}</div><div>${envs.map(e=>`<span class="chip">${esc(e.name)}</span>`).join('')}</div>${EMERGENCY_OWNER?`<button class="ghost" onclick="event.stopPropagation();projectLockSettings('${a.id}')" data-i18n="Project lockdown">Project lockdown</button>`:''}</div>`}
async function projectLockSettings(id){try{APP=APPS.find(a=>a.id===id)||{id};ENV=null;await refreshEmergency();owDataText($('pagetitle'),APP.name||'Project');$('view').innerHTML=emergencyCard(true);$('topaction').style.display='none'}catch(e){toast(e.message,true)}}
function filterApps(q){document.querySelectorAll('.appcard').forEach((c,i)=>{c.style.display=APPS[i].name.toLowerCase().includes(q.toLowerCase())?'':'none'})}
async function newApp(){modal(`<h3 data-i18n="New app">New app</h3><div class="field"><label for="na-name" data-i18n="App name">App name</label><input id="na-name" placeholder="billing-api"></div><div class="field"><label for="na-readme" data-i18n="Readme (plain text, optional)">Readme (plain text, optional)</label><textarea id="na-readme" rows="4"></textarea></div><div class="row"><button class="primary" onclick="createApp()" data-i18n="Create app">Create app</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button></div>
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
  let eid=ENV.id,org=ORG;let d=await api('GET',`/api/envs/${eid}/secrets`);if(ORG!==org||ENV?.id!==eid||VIEW!=='env')return;SECRETS=d.secrets;
  // Path policy can deny the folders route; folder chips are optional, so an unavailable fetch degrades to none instead of aborting the secrets view.
  let folderData;try{folderData=await api('GET',`/api/envs/${eid}/folders`)}catch(e){folderData=[]}
  if(ORG!==org||ENV?.id!==eid||VIEW!=='env')return;let folders=Array.isArray(folderData)?folderData:(folderData.folders||[]);let folderPaths=[...new Set(folders.map(f=>typeof f==='string'?f:f.path).filter(Boolean))];
  $('view').innerHTML=`
  ${envTabs()}
  <div class="row" style="margin-bottom:12px">
    <input id="sfilter" placeholder="Filter by key or path…" data-i18n-placeholder="Filter by key or path…" style="min-width:240px" oninput="drawSecrets()">
    <button onclick="importModal()" data-i18n="Import .env">Import .env</button><button onclick="exportEnv()" data-i18n="Export">Export</button><button onclick="appSettings()" data-i18n="App settings">App settings</button><button onclick="envSettings()" data-i18n="Env settings">Env settings</button><button onclick="cloneModal()" data-i18n="Clone">Clone</button><button onclick="compareModal()" data-i18n="Compare">Compare</button>
    <span class="grow"></span><button class="primary" onclick="addRow()" data-i18n="+ New secret">+ New secret</button>
  </div>
  ${folderPaths.length?`<div class="row" style="flex-wrap:wrap;margin-bottom:12px"><span class="small mut">Folders:</span>${folderPaths.map(p=>`<button class="small mono" onclick="$('sfilter').value='${jsq(p)}';drawSecrets()">${esc(p)}</button>`).join('')}</div>`:''}
  <div id="stable"></div>
  ${APP?.readme?`<div class="card" style="margin-top:14px"><h3 data-i18n="Readme">Readme</h3><pre class="val" style="white-space:pre-wrap">${esc(APP.readme)}</pre></div>`:''}`;
  drawSecrets();updateDeployBar()}
function envTabs(){return `<div class="envtabs">${ENVS.map(e=>`<button class="envtab ${e.id===ENV.id?'on':''}" onclick="switchEnv('${e.id}')">${esc(e.name)}${isE2E(e)?owHTML(' · E2E'):''}${e.mode==='delegated'?owHTML(' · delegated'):''}</button>`).join('')}<button class="envtab" onclick="newEnv()" data-i18n="+ Environment">+ Environment</button><button class="envtab" onclick="newE2eEnv()" data-i18n="+ E2E environment">+ E2E environment</button></div>`}
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
function scrollAccess(id){let el=document.getElementById(id);if(el)el.scrollIntoView({block:'start'})}
function appSettings(){if(!APP){toastUI('Open an app first', true);return}let on=APP.reuse_check!==false;
  modal(`<h3 data-i18n="App settings">App settings</h3>
    <div class="field"><label for="app-name" data-i18n="App name">App name</label><input id="app-name" value="${esc(APP.name||'')}"></div>
    <div class="field"><label for="app-readme" data-i18n="Readme (plain text, optional)">Readme (plain text, optional)</label><textarea id="app-readme" rows="5" placeholder="Owners, purpose, runbook notes">${esc(APP.readme||'')}</textarea></div>
    <label class="row" style="gap:8px;margin:12px 0"><input type="checkbox" id="app-reuse" ${on?'checked':''}> <span data-i18n="Warn when a secret value is reused elsewhere in this workspace">Warn when a secret value is reused elsewhere in this workspace</span></label>
    <p class="small mut" data-i18n="The workspace setting must also be on. The warning is advisory; you can still save the value.">The workspace setting must also be on. The warning is advisory; you can still save the value.</p>
    <div class="row"><button class="primary" onclick="saveAppSettings()" data-i18n="Save">Save</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button><span class="grow"></span><button class="danger" onclick="deleteApp()" data-i18n="Delete app">Delete app</button></div>`,'App settings')}
async function saveAppSettings(){try{let name=$('app-name').value.trim();if(!name)throw Error(owT('App name is required'));
  let readme=$('app-readme').value; if(name!==APP.name||readme!==(APP.readme||''))await api('PATCH',`/api/apps/${APP.id}`,{name,readme});
  await api('PUT',`/api/apps/${APP.id}/settings`,{reuse_check:$('app-reuse').checked});
  APP.name=name;APP.readme=readme;APP.reuse_check=$('app-reuse').checked;closeModal();owDataText($('pagetitle'),APP.name);toastUI('App settings saved', false);renderEnv()}catch(e){toast(e.message,true)}}
async function deleteApp(){if(!APP)return;let app=APP.name||'this app';
  if(!confirm(owT('Delete {x} and all its environments and secrets? This cannot be undone.',{x:app})))return;
  try{await api('DELETE',`/api/apps/${APP.id}`);closeModal();APP=null;ENV=null;ENVS=[];toastUI('App deleted', false);await nav('apps')}catch(e){toast(e.message,true)}}
function otherEnvs(){return ENVS.filter(e=>e.id!==ENV.id&&(e.mode||'sse')==='sse')}
function envOptions(){return otherEnvs().map(e=>`<option value="${esc(e.id)}">${esc(e.name)}</option>`).join('')}
function cloneModal(){let opts=envOptions();modal(`<h3>Clone ${esc(ENV.name)}</h3><p class="mut">Copies readable secrets into another server-encrypted environment. Sealed values are skipped. Client-encrypted environments are not supported.</p>${opts?`<div class="field"><label for="clone-target">Target environment</label><select id="clone-target">${opts}</select></div><label class="row" style="gap:8px;margin:10px 0"><input type="checkbox" id="clone-overwrite"> Overwrite keys that already exist</label><div class="row"><button class="primary" onclick="doClone()">Clone secrets</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`:'<p class="small mut">This app has no other server-encrypted environment to clone into.</p><div class="row"><button class="ghost" onclick="closeModal()">Close</button></div>'}`,'Clone environment')}
async function doClone(){try{let d=await api('POST',`/api/envs/${ENV.id}/clone`,{target_env_id:$('clone-target').value,overwrite:$('clone-overwrite').checked});closeModal();toastUI('Cloned {n} secrets, skipped {s}',{n:d.cloned||0,s:d.skipped||0}, false)}catch(e){toast(e.message,true)}}
async function compareModal(){let opts=ENVS.filter(e=>e.id!==ENV.id).map(e=>`<option value="${esc(e.id)}">${esc(e.name)}</option>`).join('');modal(`<h3>Compare ${esc(ENV.name)}</h3>${opts?`<div class="field"><label for="cmp-target">Compare with</label><select id="cmp-target">${opts}</select></div><div class="row"><button class="primary" onclick="doCompare()">Compare</button><button class="ghost" onclick="closeModal()">Close</button></div><div id="cmp-out"></div>`:'<p class="small mut">This app has no other environment to compare with.</p>'}`,'Compare environments')}
async function doCompare(){try{let other=$('cmp-target').value;let d=await api('GET',`/api/envs/${ENV.id}/compare?other=${encodeURIComponent(other)}`);let list=(title,items,cls)=>`<div style="margin-top:14px"><h4>${esc(title)} (${items.length})</h4>${items.length?`<div class="row" style="gap:6px">${items.map(k=>`<span class="chip ${cls||''}">${esc(k)}</span>`).join('')}</div>`:'<p class="small mut">None</p>'}</div>`;
  $('cmp-out').innerHTML=list('Only in this environment',d.only_in_source||[])+list('Only in the other environment',d.only_in_target||[])+list('Different values',d.changed||[])+`<p class="small mut" style="margin-top:12px">${Number(d.same)||0} keys match.</p>`}catch(e){toast(e.message,true)}}
async function envSettings(){if(!APP||!ENV)return;let e=ENV;
  try{let meta=await api('GET',`/api/envs/${e.id}/meta`);let p=meta.policy||{};
    modal(`<h3 data-i18n="Environment settings">Environment settings</h3><p class="mut">${esc(APP.name||'')} / ${esc(e.name)}</p>
      <div class="field"><label for="env-name" data-i18n="Name">Name</label><input id="env-name" value="${esc(e.name||'')}"></div>
      <div class="field"><label for="env-max" data-i18n="Keep this many versions (0 keeps every version)">Keep this many versions (0 keeps every version)</label><input id="env-max" type="number" min="0" max="1000" value="${Number(p.max_versions)||0}"></div>
      <label class="row" style="gap:8px;margin:10px 0"><input type="checkbox" id="env-restricted" ${p.restricted?'checked':''}> <span data-i18n="Restrict access to explicit grants">Restrict access to explicit grants</span></label>
      <label class="row" style="gap:8px;margin:10px 0"><input type="checkbox" id="env-approval" ${p.require_approval?'checked':''}> <span data-i18n="Require an approved proposal for non-admin writes">Require an approved proposal for non-admin writes</span></label>
      <p class="small mut" data-i18n="These policy changes apply immediately. Existing sessions keep their workspace role.">These policy changes apply immediately. Existing sessions keep their workspace role.</p>
      <div class="row"><button class="primary" onclick="saveEnvSettings()">Save</button><button class="ghost" onclick="closeModal()" data-i18n="Cancel">Cancel</button><span class="grow"></span><button class="danger" onclick="delEnv()" data-i18n="Delete environment">Delete environment</button></div>`,'Environment settings');
  }catch(err){toast(err.message,true)}}
async function saveEnvSettings(){let e=ENV;try{let name=$('env-name').value.trim();let max=parseInt($('env-max').value||'0',10);
  if(!e)return;if(name&&name!==e.name)await api('PATCH',`/api/envs/${e.id}`,{name});
  await api('PUT',`/api/envs/${e.id}/policy`,{restricted:$('env-restricted').checked,require_approval:$('env-approval').checked,max_versions:Number.isFinite(max)?max:0});
  if(e===ENV&&name){e.name=name;ENVS=ENVS.map(x=>x.id===e.id?{...x,name}:x)}
  closeModal();toastUI('Environment settings saved', false);renderEnv()}catch(err){toast(err.message,true)}}
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
async function delEnv(){if(!confirm(owT('Delete environment {x} and all its secrets?',{x:ENV.name})))return;closeModal();try{let removed=ENV.id;await api('DELETE',`/api/envs/${removed}`);delete DRAFTS[removed];delete E2E_KEYS[removed];delete E2E_DATA[removed];delete E2E_DRAFTS[removed];delete E2E_META[removed];delete E2E_GRANTS[removed];delete E2E_LOCKED[removed];delete E2E_ERR[removed];ENVS=await api('GET',`/api/apps/${APP.id}/envs`);ENV=ENVS[0]||null;toastUI('Environment deleted', false);await renderEnv()}catch(e){toast(e.message,true)}}
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
    <td>${sealed?'<span class="mut mono" data-i18n="Sealed, never shown">Sealed, never shown</span>':`<span class="val" data-val="${esc(value??'')}" data-show="0">••••••••••</span>`}</td>
    <td class="mono mut">${esc(path)}</td><td class="mut">${isNew?'new':'v'+(s.version||1)}</td>
    <td style="white-space:nowrap;text-align:right">
      ${sealed?'':`<button class="iconbtn" title="Reveal" data-i18n-title="Reveal" aria-label="Reveal" data-i18n-aria-label="Reveal" onclick="revealVal(this)">${icon('eye')}</button><button class="iconbtn" title="Copy value" data-i18n-title="Copy value" aria-label="Copy value" data-i18n-aria-label="Copy value" onclick="copyVal(this)">${icon('copy')}</button>`}
      <button class="iconbtn" title="Edit" data-i18n-title="Edit" aria-label="Edit" data-i18n-aria-label="Edit" onclick="editRow('${jsq(s.id)}')">${icon('edit')}</button>
      ${isNew?'':`<button class="iconbtn" title="History" data-i18n-title="History" aria-label="History" data-i18n-aria-label="History" onclick="showHistory('${jsq(s.id)}')">${icon('history')}</button>
      <button class="iconbtn" title="Personal override" data-i18n-title="Personal override" aria-label="Personal override" data-i18n-aria-label="Personal override" onclick="overrideRow('${jsq(s.id)}','${jsq(key)}')">${icon('override')}</button>`}
      <button class="iconbtn" title="Delete" data-i18n-title="Delete" aria-label="Delete" data-i18n-aria-label="Delete" onclick="delSecret('${jsq(s.id)}','${jsq(key)}')">${icon('trash')}</button></td></tr>`}).join('')}
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
  let pending=await api('GET',`/api/orgs/${org}/invites`).catch(()=>[]);
  let members=await api('GET',`/api/orgs/${org}/members`).catch(()=>[]);let myRole=members.find(m=>m.id===ME?.id)?.role||'';
  let props=ENV?await api('GET',`/api/envs/${ENV.id}/proposals`).catch(()=>[]):[];
  let reqs=ENV?await api('GET',`/api/envs/${ENV.id}/access-requests`).catch(()=>[]):[];
  if(ORG!==org||accessSerial!==PRODUCT_RENDER||(view==='access'&&VIEW!=='access'))return;
  $('view').innerHTML=`
  <div class="row sectionjump"><button class="ghost small" onclick="scrollAccess('access-members')" data-i18n="Members">Members</button><button class="ghost small" onclick="scrollAccess('access-roles')" data-i18n="Roles &amp; teams">Roles &amp; teams</button><button class="ghost small" onclick="scrollAccess('access-approvals')" data-i18n="Approvals">Approvals</button><button class="ghost small" onclick="scrollAccess('access-identities')" data-i18n="Identities &amp; tokens">Identities &amp; tokens</button><button class="ghost small" onclick="scrollAccess('product-tools')" data-i18n="Product tools">Product tools</button></div>
  <div class="card" id="access-members"><h3 data-i18n="Members">Members</h3><p data-i18n="Owners can transfer ownership; admins manage roles. A workspace always keeps at least one owner.">Owners can transfer ownership; admins manage roles. A workspace always keeps at least one owner.</p>
  <table class="members-table"><thead><tr><th data-i18n="Member">Member</th><th data-i18n="Role">Role</th><th></th></tr></thead><tbody>
  ${members.map(m=>`<tr><td>${esc(m.email)}${m.id===ME?.id?' <span class="chip" data-i18n="you">you</span>':''}</td><td><select aria-label="Role for ${esc(m.email)}" onchange="setMemberRole('${jsq(m.id)}',this.value)">${roles.map(r=>`<option value="${esc(r.name)}"${r.name===m.role?' selected':''}>${esc(r.name)}</option>`).join('')}</select></td><td>${m.role!=='owner'&&myRole==='owner'?`<button onclick="transferOwner('${jsq(m.id)}','${jsq(m.email)}')" data-i18n="Make owner">Make owner</button> `:''}${m.id!==ME?.id?`<button class="danger" onclick="removeMember('${jsq(m.id)}','${jsq(m.email)}')" data-i18n="Remove">Remove</button>`:''}</td></tr>`).join('')||'<tr><td colspan="3" class="mut" data-i18n="No members">No members</td></tr>'}
  </tbody></table></div>
  <div class="card" id="access-invite"><h3 data-i18n="Invite member">Invite member</h3><p data-i18n="Existing accounts are added immediately. New addresses get a single-use link, valid for seven days, to set a password or sign in with a configured provider.">Existing accounts are added immediately. New addresses get a single-use link, valid for seven days, to set a password or sign in with a configured provider.</p><div class="row"><label class="small mut" for="inv-email" data-i18n="Email">Email</label><input id="inv-email" type="email" placeholder="teammate@company.com" style="min-width:240px"><label class="small mut" for="inv-role" data-i18n="Role">Role</label><select id="inv-role">${roles.map(r=>`<option value="${esc(r.name)}"${r.name==='developer'?' selected':''}>${esc(r.name)}</option>`).join('')}</select><button class="primary" onclick="invite()" data-i18n="Invite">Invite</button></div></div>
  <div class="card" id="access-roles"><h3 data-i18n="Custom roles">Custom roles</h3><p><span data-i18n="Comma-separated permissions, for example">Comma-separated permissions, for example</span> <span class="mono">secrets:read</span> <span data-i18n="or">or</span> <span class="mono">*</span>.</p><div class="row"><input id="role-name" placeholder="deployer"><input id="role-perms" placeholder="secrets:read,secrets:write" style="min-width:260px"><button onclick="mkRole()" data-i18n="Create role">Create role</button></div><div style="margin-top:12px">${roles.map(r=>`<div class="row" style="justify-content:space-between;border-top:1px solid var(--line);padding:8px 0"><span class="mono">${esc(r.name)}</span><span class="mut small" style="text-align:right">${esc(r.managed?owT('(managed)'):(r.permissions||[]).join(', '))}</span></div>`).join('')}</div></div>
  <div class="card" id="access-teams"><h3 data-i18n="Teams">Teams</h3><p data-i18n="Teams group members for one environment grant. Membership here does not change a role.">Teams group members for one environment grant. Membership here does not change a role.</p><div class="row"><input id="team-name" placeholder="platform-team"><button onclick="mkTeam()" data-i18n="Create team">Create team</button></div><div style="margin-top:10px">${teams.map(t=>`<div class="row" style="justify-content:space-between;border-top:1px solid var(--line);padding:8px 0"><span>${esc(t.name)}</span><button onclick="teamModal('${jsq(t.id)}','${jsq(t.name)}')" data-i18n="Manage">Manage</button></div>`).join('')||'<span class="mut" data-i18n="No teams yet">No teams yet</span>'}</div></div>
  <div class="card" id="access-approvals"><h3><span data-i18n="Secret change proposals">Secret change proposals</span> ${ENV?('· '+esc(ENV.name)):''}</h3><p data-i18n="Proposals stage secret changes for admin approval instead of deploying directly.">Proposals stage secret changes for admin approval instead of deploying directly.</p>
  ${props.length?props.map(p=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:7px 0"><span class="mono small">${esc(p.id.slice(0,8))} · ${esc(p.status)} · by ${esc(String(p.author).slice(0,8))}</span>${p.status==='pending'?`<span><button onclick="decideProp('${p.id}','approve')" data-i18n="Approve">Approve</button> <button class="danger" onclick="decideProp('${p.id}','reject')" data-i18n="Reject">Reject</button></span>`:''}</div>`).join(''):'<span class="mut" data-i18n="No proposals">No proposals</span>'}
  <div class="row" style="margin-top:12px"><button onclick="proposeModal()" data-i18n="New proposal">New proposal</button></div></div>
  <div class="card" id="access-requests"><h3><span data-i18n="Access requests">Access requests</span> ${ENV?('· '+esc(ENV.name)):''}</h3>
  ${reqs.length?reqs.map(r=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:7px 0"><span class="small">${esc(r.reason||'access')} · ${esc(r.status)}</span>${r.status==='pending'?`<span><button onclick="decideAccess('${r.id}','approve')" data-i18n="Approve">Approve</button> <button class="danger" onclick="decideAccess('${r.id}','reject')" data-i18n="Reject">Reject</button></span>`:''}</div>`).join(''):'<span class="mut" data-i18n="No requests">No requests</span>'}
  <div class="row" style="margin-top:12px"><button onclick="requestAccess()" data-i18n="Request access to current env">Request access to current env</button></div></div>
  <div class="card" id="access-identities"><h3 data-i18n="Machine identities">Machine identities</h3><p data-i18n="For CI and workloads. Universal Auth exchanges client credentials for a 1-hour token.">For CI and workloads. Universal Auth exchanges client credentials for a 1-hour token.</p><div class="row"><input id="id-name" placeholder="github-actions"><button onclick="mkIdentity()" data-i18n="Create identity">Create identity</button></div><pre class="val" id="ident-out"></pre></div>
  <div class="card" id="access-tokens"><h3><span data-i18n="Service tokens">Service tokens</span> ${APP?('· '+esc(APP.name)):''}</h3><div class="row"><button onclick="mkToken()" data-i18n="Create token">Create token</button><button onclick="loadTokens()" data-i18n="List / revoke">List / revoke</button></div><pre class="val" id="tok-out"></pre><div id="tok-list"></div></div><div id="product-tools"></div>`;await renderProductTools(org,myRole)}
let PRODUCT_ROLE='', PRODUCT_RENDER=0;
function productActive(d){return d&&PRODUCT_DIALOG===d&&d.org===ORG&&modalOpen()}
function productModal(html,label,context){modal(html,label);PRODUCT_DIALOG=context}
async function renderProductTools(org,role){
  // Direct renderAccess() callers outside the access view must not fetch product data.
  if(VIEW!=='access')return;
  let serial=++PRODUCT_RENDER;PRODUCT_ROLE=role||PRODUCT_ROLE;let admin=['owner','admin'].includes(PRODUCT_ROLE);
  let feat=await api('GET',`/api/orgs/${org}/features`).catch(()=>({granted:[]}));let on=n=>(feat.granted||[]).includes(n);
  let [requests,identities,keys]=await Promise.all([on('change-requests')?api('GET',`/api/orgs/${org}/change-requests`).catch(()=>[]):[],api('GET',`/api/orgs/${org}/identities`).catch(()=>[]),on('transit')?api('GET',`/api/orgs/${org}/transit/keys`).catch(()=>[]):[]]);
  if(org!==ORG||VIEW!=='access'||serial!==PRODUCT_RENDER||!$('product-tools'))return;
  let requestCard=on('change-requests')?`<div class="card"><h3>Batched change requests</h3><p>Stage changes across server-readable environments for separate review and approval.</p>${requests.map(r=>`<div class="row"><span>${esc(r.title)} · ${esc(r.status)} · revision ${esc(r.revision)}</span><button onclick="productRequestModal('${jsq(r.id)}')">Review</button></div>`).join('')||'<p class="mut">No change requests.</p>'}<button onclick="productRequestModal()">New change request</button></div>`:'';
  let trustCard=on('workload-identity')?`<div class="card"><h3>Workload trust</h3><p>Bind a workload identity to one environment and explicit claims.</p>${admin?(identities.map(i=>`<div class="row"><span>${esc(i.name)}</span><button onclick="productTrustModal('${jsq(i.id)}')">Manage trust</button></div>`).join('')||'<p class="mut">No machine identities yet. Create one in the Machine identities card above, then bind its trust here.</p><button onclick="focusIdentityCreate()">Create machine identity</button>'):'<p class="mut">Workspace administrators manage trust.</p>'}</div>`:'';
  let transitCard=on('transit')?`<div class="card"><h3>Transit encryption</h3><p>Encrypt, decrypt or rewrap with a workspace key.</p>${keys.map(k=>`<div class="row"><span>${esc(k.name)} · version ${esc(k.current_version)}</span><button onclick="productTransitModal('${jsq(k.id)}')">Operate</button>${admin?`<button onclick="rotateProductKey('${jsq(k.id)}')">Rotate</button>`:''}</div>`).join('')}${admin?'<button onclick="newProductKey()">New transit key</button>':''}<button onclick="productTransitModal('')">Use key ID</button></div>`:'';
  $('product-tools').innerHTML=requestCard+trustCard+transitCard}
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
async function teamModal(tid,name){try{let [members,org] = await Promise.all([api('GET',`/api/orgs/${ORG}/teams/${tid}/members`),api('GET',`/api/orgs/${ORG}/members`)]);let ids=new Set(members.map(m=>m.user_id));let available=org.filter(m=>!ids.has(m.id));
  modal(`<h3>${owHTML('Team {x}',{x:name})}</h3><p class="mut" data-i18n="Members of this team can use the environment grants assigned to it.">Members of this team can use the environment grants assigned to it.</p>
    ${members.length?members.map(m=>`<div class="row" style="justify-content:space-between;border-top:1px solid var(--line);padding:8px 0"><span class="small">${esc(m.email)}</span><button class="danger small" onclick="teamRemove('${jsq(tid)}','${jsq(name)}','${jsq(m.user_id)}')" data-i18n="Remove">Remove</button></div>`).join(''):'<p class="small mut" data-i18n="No members yet.">No members yet.</p>'}
    <div class="row" style="margin-top:12px"><select id="team-add" aria-label="Add member">${available.map(m=>`<option value="${esc(m.id)}">${esc(m.email)}</option>`).join('')||'<option value="">'+esc(owT('No more members to add'))+'</option>'}</select><button onclick="teamAdd('${jsq(tid)}','${jsq(name)}')" data-i18n="Add member">Add member</button><span class="grow"></span><button class="ghost" onclick="closeModal()" data-i18n="Close">Close</button></div>`,'Team members')}catch(e){toast(e.message,true)}}
async function teamAdd(tid,name){let uid=$('team-add')?.value;if(!uid)return;try{await api('POST',`/api/orgs/${ORG}/teams/${tid}/members`,{user_id:uid});toastUI('Member added to team', false);teamModal(tid,name)}catch(e){toast(e.message,true)}}
async function teamRemove(tid,name,uid){try{await api('DELETE',`/api/orgs/${ORG}/teams/${tid}/members/${uid}`);toastUI('Member removed from team', false);teamModal(tid,name)}catch(e){toast(e.message,true)}}
async function invite(){try{let d=await api('POST',`/api/orgs/${ORG}/members`,{email:$('inv-email').value,role:$('inv-role').value});
  if(d.invite_token){let link=location.origin+'/#invite='+encodeURIComponent(d.invite_token);
    modal(`<h3 data-i18n="Invitation created">Invitation created</h3><p class="mut">${owHTML('Send this single-use link to {x}. It expires in 7 days.',{x:$('inv-email').value})}</p><textarea rows="3" readonly>${esc(link)}</textarea><div class="row" style="margin-top:12px"><button onclick="navigator.clipboard.writeText(document.querySelector('#modal textarea').value);toastUI('Invite link copied', false)" data-i18n="Copy link">Copy link</button><button class="primary" onclick="closeModal()" data-i18n="Done">Done</button></div>`);}
  else toastUI('Member added', false);
  $('inv-email').value='';renderAccess()}catch(e){toast(e.message,true)}}
async function resendInvite(id){try{let d=await api('POST',`/api/orgs/${ORG}/invites/${id}/resend`,{});let link=location.origin+'/#invite='+encodeURIComponent(d.invite_token);modal(`<h3>Replacement invitation</h3><p>The previous link no longer works. Share this new link securely.</p><textarea aria-label="Invitation link" rows="3" readonly>${esc(link)}</textarea><button onclick="navigator.clipboard.writeText(document.querySelector('#modal textarea').value);toastUI('Copied', false)">Copy link</button><button onclick="closeModal()">Done</button>`,'Replacement invitation');renderAccess()}catch(e){toast(e.message,true)}}
async function revokeInvite(id){if(!confirm('Revoke this invitation?'))return;try{await api('DELETE',`/api/orgs/${ORG}/invites/${id}`);renderAccess()}catch(e){toast(e.message,true)}}
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
function jsonArea(id,rows,placeholder){return `<textarea id="${id}" rows="${rows}" oninput="jsonCheck('${id}')" placeholder="${esc(placeholder)}"></textarea><div class="small" id="${id}-err" style="color:var(--bad);min-height:16px"></div><div class="row" style="margin-top:-6px"><button class="ghost small" onclick="jsonFormat('${id}')">Format JSON</button><span class="small mut">Advanced: paste the provider configuration as JSON.</span></div>`}
function jsonCheck(id){let el=$(id),e=$(id+'-err');if(!el||!e)return;try{if(el.value.trim())JSON.parse(el.value);e.textContent=''}catch(err){e.textContent=err.message}}
function jsonFormat(id){let el=$(id),e=$(id+'-err');if(!el||!el.value.trim())return;try{el.value=JSON.stringify(JSON.parse(el.value),null,2);e.textContent=''}catch(err){e.textContent=err.message}}
function readJson(id,fallback){let el=$(id);if(!el||!el.value.trim())return fallback;try{return JSON.parse(el.value)}catch(err){$(id+'-err').textContent=err.message;throw Error('Invalid JSON: '+err.message)}}
async function renderIntegrations(){if(!needAppEnv())return;setTimeout(kindHint,0);owText($('pagetitle'),'Integrations');owDataText($('crumb'),ENV?('/ '+ENV.name):'');
  let ints=ENV?await api('GET',`/api/envs/${ENV.id}/integrations`).catch(()=>[]):[];
  $('view').innerHTML=`<div class="card"><h3 data-i18n="Sync secrets to a platform">Sync secrets to a platform</h3><p><span data-i18n="Integrations run automatically on every deploy, or on demand. Config is stored encrypted. Trigger.dev example config:">Integrations run automatically on every deploy, or on demand. Config is stored encrypted. Trigger.dev example config:</span> <span class="mono">{"token":"tr_pat_…","project_ref":"proj_…","target_env":"prod"}</span></p>
  <div class="row"><select id="ikind" onchange="kindHint()">${KINDS.map(k=>`<option>${k}</option>`).join('')}</select></div>
  <p class="small" id="ikind-hint"></p>${jsonArea('icfg',4,'{"token":"…"}')}
  <div class="row" style="margin-top:10px"><button class="primary" onclick="mkIntegration()" data-i18n="Add integration">Add integration</button></div></div>
  <div class="card"><h3><span data-i18n="Configured">Configured</span> ${ENV?('· '+esc(ENV.name)):''}</h3>${ints.length?ints.map(i=>`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--line);padding:8px 0"><span><b>${esc(i.kind)}</b> <span class="mut small">${esc(i.name||'')}</span></span><span><button onclick="incomingHooks('${jsq(i.id)}')">Incoming hooks</button> <button onclick="testInt('${i.id}')" data-i18n="Test">Test</button> <button class="primary" onclick="syncInt('${i.id}')" data-i18n="Sync now">Sync now</button> <button onclick="intHistory('${jsq(i.id)}','${jsq(i.name||i.kind)}')" data-i18n="History">History</button> <button onclick="editInt('${jsq(i.id)}','${jsq(i.kind)}','${jsq(i.name||'')}')" data-i18n="Edit">Edit</button> <button class="danger" onclick="delInt('${i.id}')" data-i18n="Delete">Delete</button></span></div>`).join(''):'<span class="mut" data-i18n="None yet">None yet</span>'}</div>
  <div class="card"><h3 data-i18n="Dynamic secrets &amp; rotation">Dynamic secrets &amp; rotation</h3><div class="row"><input id="lease-name" placeholder="lease name"><select id="lease-type"><option value="generic">generic</option><option value="openrouter">openrouter</option><option value="resend">resend</option><option value="openai">openai</option><option value="huggingface">huggingface</option><option value="fireworks">fireworks</option><option value="mistral">mistral</option><option value="perplexity">perplexity</option><option value="xai">xai</option><option value="gemini">gemini</option><option value="cloudflare">cloudflare</option><option value="deepgram">deepgram</option><option value="elevenlabs">elevenlabs</option><option value="deepinfra">deepinfra</option><option value="baseten">baseten</option><option value="fal">fal</option><option value="speechmatics">speechmatics</option><option value="chutes">chutes</option><option value="aws_iam">aws_iam</option><option value="postgres">postgres</option><option value="mysql">mysql</option></select><button onclick="mkLease()" data-i18n="New lease (1h)">New lease (1h)</button><button onclick="loadLeases()" data-i18n="Show leases">Show leases</button></div>${jsonArea('lease-cfg',3,'provider config, e.g. {"management_key":"…"} or {"connection":"mysql://…","grants":["SELECT ON app.*"]}')}<div id="leases"></div>
  <div class="row" style="margin-top:14px"><input id="rot-key" placeholder="KEY_TO_ROTATE"><span class="row"><input id="rot-int" value="86400" size="8"><span class="mut small" data-i18n="seconds between rotations">seconds between rotations</span></span><button onclick="mkRotation()" data-i18n="Schedule rotation">Schedule rotation</button><button onclick="loadRotations()" data-i18n="Show rotations">Show rotations</button></div>${jsonArea('rot-cfg',2,'optional provider rotation config, e.g. {"management_key":"…"}')}<div id="rot-list"></div></div>
  <div class="card"><h3 data-i18n="Lockbox: one-time secret sharing">Lockbox: one-time secret sharing</h3><div class="row"><input id="lb-val" placeholder="value to share once" style="min-width:280px"><button onclick="mkLockbox()" data-i18n="Create link">Create link</button></div><pre class="val" id="lb-out"></pre></div>`}
const KIND_HINTS={trigger:'Trigger.dev: {"token":"tr_pat_… or tr_prod_sk_…","project_ref":"proj_…","target_env":"prod"}',github:'GitHub: {"token":"ghp_…","owner":"org","repo":"repo"}',gitlab:'GitLab: {"token":"glpat-…","project_id":"42"}',webhook:'Webhook: {"url":"https://…","token":"optional bearer","signing_secret":"optional HMAC key"}',azure_app_configuration:'Azure App Configuration: {"endpoint":"https://store.azconfig.io","id":"access key id","secret":"base64 access key","label":"optional"}',scaleway_secret_manager:'Scaleway Secret Manager: {"region":"fr-par","secret_key":"…","project_id":"…","path":"/app"}',vultr:'Vultr SSH keys: {"api_key":"…"} (each secret value must be an OpenSSH public key)',hetzner:'Hetzner SSH keys: {"token":"…"} (syncs secrets of type ssh_key; a changed key is recreated)',linode:'Linode SSH keys: {"token":"…"} (syncs secrets of type ssh_key; a changed key is recreated)',digitalocean_ssh:'DigitalOcean account SSH keys: {"token":"…"} (syncs secrets of type ssh_key; distinct from digitalocean, which updates an App Platform spec)',ssh:'SSH file: {"host":"app.example.com","user":"deploy","identity_file":"/keys/deploy","known_hosts":"ssh-ed25519 AAAA…","files":[{"path":"/srv/app/.env","format":"dotenv","folders":["/app"]}]}',kubernetes:'Kubernetes: {"api_server":"https://…","token":"…","namespace":"default","secret_name":"app-secrets"}',aws_secrets_manager:'AWS Secrets Manager: {"region":"us-east-1","access_key_id":"…","secret_access_key":"…","mapping":"one_to_one"} or add "secret_id":"app/prod" for one JSON secret',aws_parameter_store:'AWS Parameter Store: {"region":"us-east-1","access_key_id":"…","secret_access_key":"…","path_prefix":"/app/prod"}','1password':'1Password Connect: {"connect_url":"https://connect.example.com","token":"…","vault_id":"…","value_label":"value"}',dokploy:'Dokploy: {"base_url":"https://dokploy.example.com","api_key":"…","application_id":"…"} or "compose_id"',caprover:'CapRover: {"base_url":"https://captain.example.com","password":"…","app_name":"app"}',portainer:'Portainer: {"base_url":"https://portainer.example.com:9443","api_key":"…","endpoint_id":1,"stack_id":1}',docker_swarm:'Docker Swarm: {"api_url":"https://docker.example.com:2376","ca_cert":"PEM","client_cert":"PEM","client_key":"PEM"}',bitbucket:'Bitbucket: {"workspace":"…","repo_slug":"…","token":"…"}',circleci:'CircleCI: {"project_slug":"gh/org/repo","token":"…"}',teamcity:'TeamCity: {"base_url":"https://teamcity.example.com","token":"…","project_locator":"_Root"}',travisci:'Travis CI: {"repo":"owner/repo","token":"…"}',terraform_cloud:'Terraform Cloud: {"token":"…","workspace_id":"ws-…","category":"env"}',qovery:'Qovery: {"token":"…","organization_id":"…","project_id":"…","environment_id":"…"}',laravel_forge:'Laravel Forge: {"token":"…","organization":"org","server_id":1,"site_id":1}',openwarp:'OpenWarp: {"base_url":"https://other-openwarp.example.com","token":"…","env_id":"…"}',devin:'Devin: {"token":"cog_…","org_id":"org-…"}',cloudflare_secrets_store:'Cloudflare Secrets Store: {"token":"…","account_id":"…","store_id":"…","scopes":["workers"]}',octopus_deploy:'Octopus Deploy: {"base_url":"https://octopus.example.com","api_key":"API-…","space_id":"Spaces-1","project_id":"Projects-123"}',azure_devops:'Azure DevOps: {"organization":"org","project":"project","group_id":"1","token":"PAT"}',cursor:'Cursor: {"token":"…","environment_id":"…"} (omit environment_id for team secrets)',northflank:'Northflank: {"token":"…","project_id":"…","secret_group_id":"…"}',spacelift:'Spacelift: {"token":"…","stack_id":"…"} (or "account":"…")',rundeck:'Rundeck: {"instance_url":"https://rundeck.example.com","api_token":"…","project":"proj"}',cloud66:'Cloud 66: {"access_token":"…","stack_id":"…"}',humanitec:'Humanitec: {"api_token":"…","org":"org","app":"app","scope":"application"}',ovh_kms:'OVHcloud KMS: {"okms_domain":"https://kms.example.com","okms_id":"…","token":"…","path":"app"}',keeper:'Keeper: {"instance_url":"https://keeper.example.com","api_key":"…","folder_uid":"…"}',huggingface:'Hugging Face Space: {"token":"hf_…","namespace":"org","repo":"space","target":"secrets"} (or "variables")',oci_vault:'OCI Vault: {"tenancy_ocid":"…","user_ocid":"…","fingerprint":"…","private_key":"PEM","region":"us-ashburn-1","compartment_id":"…","vault_id":"…","key_id":"…"}',instabox:'Instabox: {"api_key":"ibk_…","org":"team","hosts":["api.example.com"],"delivery":"proxy"}',boat:'Boat: {"api_key":"boat_…","environment":"base","upgrade":true}',daytona:'Daytona: {"api_key":"…","organization_id":"…","hosts":["api.example.com"]}'};
function kindHint(){if(!$('ikind'))return;let k=$('ikind').value;KIND_HINTS[k]?owDataText($('ikind-hint'),KIND_HINTS[k]):owText($('ikind-hint'),'Config for {x} as JSON. Common keys: token, base_url for self-hosted instances. Stored encrypted at rest.',{x:k})}
async function mkIntegration(){try{await api('POST',`/api/envs/${ENV.id}/integrations`,{kind:$('ikind').value,config:readJson('icfg',{})});toastUI('Integration added', false);renderIntegrations()}catch(e){toast(e.message,true)}}
async function testInt(id){try{let d=await api('POST',`/api/integrations/${id}/test`,{});toast(d.detail)}catch(e){toast(e.message,true)}}
async function syncInt(id){try{let d=await api('POST',`/api/integrations/${id}/sync`,{});toast(d.detail)}catch(e){toast(e.message,true)}}
async function delInt(id){if(!confirm(owT('Delete this integration? Sync state for it is removed too.')))return;try{await api('DELETE',`/api/integrations/${id}`);toastUI('Integration deleted', false);renderIntegrations()}catch(e){toast(e.message,true)}}
function editInt(id,kind,name){modal(`<h3>Edit integration</h3><div class="field"><label for="ie-name">Name</label><input id="ie-name" value="${esc(name)}"></div><div class="field"><label for="ie-kind">Kind</label><select id="ie-kind">${KINDS.map(k=>`<option${k===kind?' selected':''}>${k}</option>`).join('')}</select></div><div class="field"><label>Replace configuration</label>${jsonArea('ie-cfg',4,'leave empty to keep the stored configuration')}</div><p class="small mut">The stored configuration is encrypted and is never shown back here. Re-enter it only when replacing it.</p><div class="row"><button class="primary" onclick="saveInt('${jsq(id)}')">Save</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`,'Edit integration')}
async function saveInt(id){try{let body={name:$('ie-name').value,kind:$('ie-kind').value};let cfg=readJson('ie-cfg',null);if(cfg!==null)body.config=cfg;await api('PATCH',`/api/integrations/${encodeURIComponent(id)}`,body);closeModal();toastUI('Integration updated', false);renderIntegrations()}catch(e){toast(e.message,true)}}
async function intHistory(id,name){try{let rows=await api('GET',`/api/integrations/${encodeURIComponent(id)}/history`);modal(`<h3>Sync history · ${esc(name)}</h3>${rows.length?`<table><thead><tr><th>When</th><th>Outcome</th></tr></thead><tbody>${rows.map(r=>`<tr><td class="mut small">${new Date((r.created_at||0)*1000).toLocaleString()}</td><td class="${r.action==='integration.sync_failed'?'':'mut'}">${esc(String(r.detail||'').replace(id+': ',''))}</td></tr>`).join('')}</tbody></table>`:'<p class="mut">No sync attempts recorded yet.</p>'}<div class="row" style="margin-top:12px"><button class="ghost" onclick="closeModal()">Close</button></div>`,'Sync history')}catch(e){toast(e.message,true)}}
function expiryText(ts){let s=Math.max(0,Number(ts||0)-Math.floor(Date.now()/1000));if(!s)return owT('expired');if(s<3600)return owT('{n} min left',{n:Math.ceil(s/60)});if(s<86400)return owT('{n} h left',{n:Math.round(s/3600)});return owT('{n} d left',{n:Math.round(s/86400)})}
function intervalText(secs){secs=Number(secs||0);if(secs%86400===0)return owT('{n} days',{n:secs/86400});if(secs%3600===0)return owT('{n} hours',{n:secs/3600});return owT('{n} seconds',{n:secs})}
async function mkLease(){try{let body={name:$('lease-name').value||'lease',type:$('lease-type').value};let lc=readJson('lease-cfg',{});if(Object.keys(lc).length)body.config=lc;await api('POST',`/api/envs/${ENV.id}/dynamic`,body);toastUI('Lease created', false);$('lease-name').value='';$('lease-cfg').value='';loadLeases()}catch(e){toast(e.message,true)}}
async function loadLeases(){try{let d=await api('GET',`/api/envs/${ENV.id}/dynamic`);let rows=(d.leases||d||[]);
  $('leases').innerHTML=rows.length?`<table style="margin-top:12px"><thead><tr><th data-i18n="Name">Name</th><th data-i18n="Expires">Expires</th><th></th></tr></thead><tbody>${rows.map(x=>`<tr><td class="mono">${esc(x.name||'')}</td><td class="mut small">${esc(expiryText(x.expires_at))}</td><td style="text-align:right"><button class="ghost small" onclick="copyLease('${jsq(x.id)}','${jsq(x.value||'')}')" data-i18n="Copy value">Copy value</button> <button class="danger small" onclick="revokeLease('${jsq(x.id)}')" data-i18n="Revoke">Revoke</button></td></tr>`).join('')}</tbody></table>`:'<p class="small mut" style="margin-top:10px" data-i18n="No active leases in this environment.">No active leases in this environment.</p>'}catch(e){toast(e.message,true)}}
function copyLease(id,value){navigator.clipboard.writeText(value);toastUI('Lease value copied', false)}
async function revokeLease(id){if(!confirm(owT('Revoke this lease? Issued credentials stop working.')))return;try{await api('DELETE',`/api/leases/${id}`);toastUI('Lease revoked', false);loadLeases()}catch(e){toast(e.message,true)}}
async function mkRotation(){try{await api('POST',`/api/envs/${ENV.id}/rotations`,{key:$('rot-key').value,interval_secs:parseInt($('rot-int').value)});toastUI('Rotation scheduled', false);$('rot-key').value='';loadRotations()}catch(e){toast(e.message,true)}}
async function loadRotations(){try{let d=await api('GET',`/api/envs/${ENV.id}/rotations`);let rows=d.rotations||d||[];
  $('rot-list').innerHTML=rows.length?`<table style="margin-top:12px"><thead><tr><th data-i18n="Key">Key</th><th data-i18n="Every">Every</th><th data-i18n="Next run">Next run</th><th></th></tr></thead><tbody>${rows.map(x=>`<tr><td class="mono">${esc(x.key_name||x.key||'')}</td><td class="mut small">${esc(intervalText(x.interval_secs))}</td><td class="mut small">${esc(x.next_run?new Date(Number(x.next_run)*1000).toLocaleString():'-')}</td><td style="text-align:right"><button class="danger small" onclick="delRotation('${jsq(x.id)}')" data-i18n="Delete">Delete</button></td></tr>`).join('')}</tbody></table>`:'<p class="small mut" style="margin-top:10px" data-i18n="No rotation schedules in this environment.">No rotation schedules in this environment.</p>'}catch(e){toast(e.message,true)}}
async function delRotation(id){if(!confirm(owT('Delete this rotation schedule?')))return;try{await api('DELETE',`/api/rotations/${id}`);toastUI('Rotation deleted', false);loadRotations()}catch(e){toast(e.message,true)}}
async function mkLockbox(){try{let d=await api('POST','/api/lockbox',{text:$('lb-val').value});$('lb-out').textContent=location.origin+d.url+'\nOpens once, expires in 24h. The key is in the #fragment and never sent to the server on page load.'}catch(e){toast(e.message,true)}}

let HOOKS=[], HOOK_APPS=[], HOOK_IID='';
async function renderWebhooks(){$('pagetitle').textContent='Webhooks';$('crumb').textContent='';$('view').innerHTML='<p role="status">Loading webhooks…</p>';
  if(!ORG){$('view').innerHTML='<div class="empty">Select a workspace to manage webhooks.</div>';return}
  const org=ORG;try{let hooks=await api('GET',`/api/orgs/${encodeURIComponent(org)}/webhooks`);let apps=await api('GET',`/api/orgs/${encodeURIComponent(org)}/apps`);if(ORG!==org||VIEW!=='webhooks')return;HOOKS=hooks;HOOK_APPS=apps;
    $('view').innerHTML=`<div class="card"><h3>Outgoing event subscriptions</h3><p>Send signed event metadata for this workspace, or only one app. Secret values and raw response bodies are not shown here. Workspace administration is required.</p><button class="primary" onclick="hookEditor()">Create outgoing webhook</button></div>
    <div class="card"><h3>Subscriptions</h3>${hooks.length?`<div style="overflow:auto"><table><thead><tr><th>Name and destination</th><th>Scope</th><th>Status</th><th>Actions</th></tr></thead><tbody>${hooks.map(h=>`<tr><td>${esc(h.name)}<div class="val">${esc(h.url)}</div><div class="small mut">${esc((h.events||[]).join(', '))}</div></td><td>${esc(h.app_id?(apps.find(a=>a.id===h.app_id)?.name||h.app_id):'Workspace')}</td><td>${h.enabled?'Enabled':'Paused'}${h.disabled_reason?'<div class="small mut">Auto-paused after repeated delivery failures</div>':''}${h.enqueue_failures?`<div class="small" role="status">${esc(h.enqueue_failures)} enqueue failures${h.last_enqueue_error_at?' · '+esc(new Date(h.last_enqueue_error_at*1000).toLocaleString()):''}</div>`:''}</td><td><div class="row">${h.disabled_reason?`<button onclick="hookReEnable('${jsq(h.id)}')">Re-enable</button>`:''}<button onclick="hookEditor('${jsq(h.id)}')">Edit</button><button onclick="hookHistory('${jsq(h.id)}')">Deliveries</button><button onclick="hookTest('${jsq(h.id)}')">Send test</button><button onclick="hookRotate('${jsq(h.id)}',false)">Rotate key</button><button class="danger" onclick="hookDelete('${jsq(h.id)}',false)">Delete</button></div></td></tr>`).join('')}</tbody></table></div>`:'<p class="mut">No outgoing webhooks. Create a subscription to receive workspace events.</p>'}</div>
    <div id="hook-history"></div><div class="card"><h3>Incoming integration triggers</h3><p>Open an app environment, then choose Incoming hooks beside an integration. A signed request queues that configured integration for sync, including when automatic sync is disabled.</p><button onclick="nav('integrations')">Open integrations</button></div>`;
  }catch(e){if(ORG===org&&VIEW==='webhooks')$('view').innerHTML=`<div class="card" role="alert"><h3>Webhooks unavailable</h3><p>${esc(e.message)}</p><button onclick="renderWebhooks()">Retry</button></div>`}}
function hookEditor(id=''){let h=HOOKS.find(h=>h.id===id)||{};modal(`<h3>${id?'Edit':'Create'} outgoing webhook</h3><div class="field"><label for="hook-name">Name</label><input id="hook-name" value="${esc(h.name||'')}" maxlength="128"></div><div class="field"><label for="hook-url">HTTPS destination</label><input id="hook-url" type="url" value="${esc(h.url||'')}" placeholder="https://receiver.example.com/events" style="width:100%"></div><div class="field"><label for="hook-app">Event scope</label><select id="hook-app"><option value="">Entire workspace</option>${HOOK_APPS.map(a=>`<option value="${esc(a.id)}" ${a.id===h.app_id?'selected':''}>${esc(a.name)}</option>`).join('')}</select></div><div class="field"><label for="hook-events">Event types (comma separated)</label><input id="hook-events" value="${esc((h.events||['*']).join(', '))}" placeholder="secret.update, integration.sync"></div><label class="row"><input id="hook-enabled" type="checkbox" ${h.enabled!==false?'checked':''}> Enabled</label><p class="small mut">Use * for all event types. A new signing key is shown once after creation.</p><div class="row"><button class="primary" onclick="hookSave('${jsq(id)}')">Save webhook</button><button onclick="closeModal()">Cancel</button></div>`,'Outgoing webhook')}
async function hookSave(id){try{let body={name:$('hook-name').value.trim(),url:$('hook-url').value.trim(),app_id:$('hook-app').value,events:$('hook-events').value.split(',').map(s=>s.trim()).filter(Boolean),enabled:$('hook-enabled').checked};let d=await api(id?'PATCH':'POST',id?`/api/webhooks/${encodeURIComponent(id)}`:`/api/orgs/${encodeURIComponent(ORG)}/webhooks`,body);closeModal();await renderWebhooks();if(d.secret)hookKey(d);else toast('Webhook saved')}catch(e){toast(e.message,true)}}
function hookKey(d){modal(`<h3>Save the signing key</h3><p>This key is shown once. Store it in your receiver's secret configuration. Closing this dialog removes it from the page.</p><div class="field"><label for="hook-key">Signing key</label><input id="hook-key" type="password" autocomplete="off" readonly value="${esc(d.secret)}" style="width:100%"></div>${d.url?`<div class="field"><label for="hook-endpoint">Incoming endpoint</label><input id="hook-endpoint" readonly value="${esc(d.url)}" style="width:100%"></div>`:''}<p class="small mut">The receiver verifies webhook-id, webhook-timestamp and webhook-signature against the exact request bytes.</p><button class="primary" onclick="closeHookKey()">I saved the key</button>`,'One-time webhook signing key')}
function closeHookKey(){let key=$('hook-key');if(key)key.value='';closeModal();$('modal').innerHTML=''}
async function hookRotate(id,incoming){if(!confirm('Rotate this signing key? The existing key stops working. Update the receiver or sender with the new key.'))return;try{let d=await api('POST',`/api/${incoming?'incoming-webhooks':'webhooks'}/${encodeURIComponent(id)}/rotate`,{});hookKey(d)}catch(e){toast(e.message,true)}}
async function hookDelete(id,incoming){if(!confirm('Delete this webhook and stop its future deliveries or sync triggers?'))return;try{await api('DELETE',`/api/${incoming?'incoming-webhooks':'webhooks'}/${encodeURIComponent(id)}`);toast('Webhook deleted');if(incoming)await incomingHooks(HOOK_IID);else await renderWebhooks()}catch(e){toast(e.message,true)}}
async function hookReEnable(id){try{await api('PATCH',`/api/webhooks/${encodeURIComponent(id)}`,{enabled:true});toast('Webhook re-enabled');await renderWebhooks()}catch(e){toast(e.message,true)}}
async function hookTest(id){if(!confirm('Send a signed test event to this webhook destination?'))return;try{await api('POST',`/api/webhooks/${encodeURIComponent(id)}/test`,{});toast('Test event queued');await hookHistory(id)}catch(e){toast(e.message,true)}}
async function hookHistory(id,offset=0){let target=$('hook-history');if(!target)return;target.innerHTML='<p role="status">Loading delivery history…</p>';try{let rows=await api('GET',`/api/webhooks/${encodeURIComponent(id)}/deliveries?limit=25&offset=${offset}`);if(!$('hook-history')||VIEW!=='webhooks')return;target.innerHTML=`<div class="card"><h3>Delivery history</h3><p class="small mut">Delivery is at least once. Receivers must deduplicate event IDs. An HTTP timeout can occur after a receiver has processed an event.</p>${hookHistoryTable(rows,false)}<div class="row"><button ${offset?'':'disabled'} onclick="hookHistory('${jsq(id)}',${Math.max(0,offset-25)})">Previous</button><button ${rows.length===25?'':'disabled'} onclick="hookHistory('${jsq(id)}',${offset+25})">Next</button><button onclick="hookHistory('${jsq(id)}',${offset})">Refresh</button></div></div>`}catch(e){target.innerHTML=`<p role="alert">${esc(e.message)}</p>`}}
function hookHistoryTable(rows,incoming,wid){return rows.length?`<div style="overflow:auto"><table><thead><tr><th>Event / message</th><th>Status</th><th>Attempts</th><th>HTTP / duration</th><th>Updated / next retry</th><th>Detail</th>${incoming?'<th>Receipt</th>':'<th>Action</th>'}</tr></thead><tbody>${rows.map(r=>`<tr><td class="val">${esc(r.message_id||r.event_id||r.id)}</td><td>${esc(r.status)}</td><td>${esc(r.attempts||0)}</td><td>${esc(r.http_status||'')}${r.duration_ms!=null?' / '+esc(r.duration_ms)+' ms':''}</td><td class="small">${r.updated_at?esc(new Date(r.updated_at*1000).toLocaleString()):''}${r.next_attempt_at?'<div>'+esc(new Date(r.next_attempt_at*1000).toLocaleString())+'</div>':''}</td><td>${esc(r.detail||r.error_code||'')}${r.outcome?`<div class="small mut">${esc(r.outcome)}</div>`:''}</td>${incoming?`<td><button onclick="receiptInspect('${jsq(wid)}','${jsq(r.id)}')">Inspect</button>${['delivered','failed','dead_lettered'].includes(r.status)?` <button onclick="receiptReplay('${jsq(wid)}','${jsq(r.id)}')">Replay</button>`:''}</td>`:`<td><button onclick="hookAttempts('${jsq(r.id)}')">Attempts</button>${['failed','dead_lettered'].includes(r.status)?`<button onclick="hookRetry('${jsq(r.id)}')">Retry delivery</button>`:''}</td>`}</tr>`).join('')}</tbody></table></div>`:'<p class="mut">No history yet.</p>'}
async function hookAttempts(id){try{let rows=await api('GET',`/api/webhook-deliveries/${encodeURIComponent(id)}/attempts`);modal(`<h3>Delivery attempts</h3><p class="small mut">Only delivery metadata is retained. Provider response bodies and headers are not captured.</p><pre class="val" style="white-space:pre-wrap">${esc(JSON.stringify(rows,null,2))}</pre><button onclick="closeModal()">Close</button>`,'Webhook delivery attempts')}catch(e){toast(e.message,true)}}
async function hookRetry(id){if(!confirm('Retry this delivery? The receiver may already have processed the original event.'))return;try{await api('POST',`/api/webhook-deliveries/${encodeURIComponent(id)}/retry`,{});toast('Delivery queued for retry')}catch(e){toast(e.message,true)}}
async function incomingHooks(iid){HOOK_IID=iid;try{let rows=await api('GET',`/api/integrations/${encodeURIComponent(iid)}/webhooks`);modal(`<h3>Incoming sync triggers</h3><p>Each signed request queues only this integration. Requests cannot supply destinations, credentials or shell commands. Inspect receipt status to see whether sync succeeded.</p><div class="field"><label for="incoming-name">Trigger name</label><input id="incoming-name" maxlength="128"></div><button class="primary" onclick="incomingCreate('${jsq(iid)}')">Create incoming webhook</button><div style="margin-top:16px">${rows.length?rows.map(h=>`<div class="card"><h3>${esc(h.name)}</h3><p>${h.enabled?'Enabled':'Paused'}</p><div class="val">${esc(h.url||location.origin+'/hooks/integrations/'+encodeURIComponent(h.id))}</div><div class="row"><button onclick="incomingReceipts('${jsq(h.id)}')">Receipts</button><button onclick="incomingPause('${jsq(h.id)}',${!h.enabled})">${h.enabled?'Pause':'Enable'}</button><button onclick="incomingReauthorize('${jsq(h.id)}')">Reauthorize</button><button onclick="hookRotate('${jsq(h.id)}',true)">Rotate key</button><button class="danger" onclick="hookDelete('${jsq(h.id)}',true)">Delete</button></div></div>`).join(''):'<p class="mut">No incoming triggers for this integration.</p>'}</div><div id="incoming-receipts"></div><button onclick="closeModal()">Close</button>`,'Incoming integration webhooks')}catch(e){toast(e.message,true)}}
async function incomingCreate(iid){try{let d=await api('POST',`/api/integrations/${encodeURIComponent(iid)}/webhooks`,{name:$('incoming-name').value.trim()||'Sync trigger',enabled:true});hookKey(d)}catch(e){toast(e.message,true)}}
async function incomingReauthorize(id){if(!confirm('Authorize this trigger with your current credential? Pending sync requests are cancelled. The URL and signing key stay the same.'))return;try{await api('POST',`/api/incoming-webhooks/${encodeURIComponent(id)}/reauthorize`,{});toast('Trigger reauthorized with your current credential');await incomingHooks(HOOK_IID)}catch(e){toast(e.message,true)}}
async function incomingPause(id,enabled){try{await api('PATCH',`/api/incoming-webhooks/${encodeURIComponent(id)}`,{enabled});await incomingHooks(HOOK_IID)}catch(e){toast(e.message,true)}}
async function incomingReceipts(id,offset=0){try{let rows=await api('GET',`/api/incoming-webhooks/${encodeURIComponent(id)}/receipts?limit=25&offset=${offset}`);if(!$('incoming-receipts'))return;$('incoming-receipts').innerHTML=`<h3>Sync receipts</h3>${hookHistoryTable(rows,true,id)}<div class="row"><button ${offset?'':'disabled'} onclick="incomingReceipts('${jsq(id)}',${Math.max(0,offset-25)})">Previous</button><button ${rows.length===25?'':'disabled'} onclick="incomingReceipts('${jsq(id)}',${offset+25})">Next</button><button onclick="incomingReceipts('${jsq(id)}',${offset})">Refresh</button></div>`}catch(e){toast(e.message,true)}}
async function receiptInspect(wid,rid){try{let d=await api('GET',`/api/incoming-webhooks/${encodeURIComponent(wid)}/receipts/${encodeURIComponent(rid)}`);let body=d.body!=null?String(d.body):'';let pretty=body;if(body){try{pretty=JSON.stringify(JSON.parse(body),null,2)}catch(e){}}
let shown=d.body_available?pretty:'(not captured: erased by a master key rotation or older than payload capture)';
modal(`<h3>Receipt ${esc(d.message_id||rid)}</h3><p class="small mut">Status ${esc(d.status||'')} · attempts ${esc(d.attempts||0)}${d.source_ip?' · source '+esc(d.source_ip):''}${d.outcome?'<br>Sync outcome: '+esc(d.outcome):''}</p><div class="field"><label>Content type</label><span class="val">${esc(d.content_type||'')}</span></div><div class="field"><label>Payload (decrypted for this view only, never stored in plaintext)</label><pre class="val" style="white-space:pre-wrap;max-height:300px;overflow:auto">${esc(shown)}</pre></div><div class="row"><button onclick="closeModal()">Close</button></div>`,'Incoming webhook receipt')}catch(e){toast(e.message,true)}}
async function receiptReplay(wid,rid){if(!confirm('Replay this message? The configured integration syncs again with the same captured payload.'))return;try{await api('POST',`/api/incoming-webhooks/${encodeURIComponent(wid)}/receipts/${encodeURIComponent(rid)}/replay`,{});toast('Receipt queued for replay');incomingReceipts(wid)}catch(e){toast(e.message,true)}}

let AUDIT_ROWS=[], AUDIT_HAS_MORE=false, AUDIT_ACTORS={};
async function renderAudit(){owText($('pagetitle'),'Audit log');owDataText($('crumb'),'');AUDIT_ROWS=[];AUDIT_ACTORS={};
  let streamCard=`<div class="card"><h3>Event delivery</h3><p>Configure signed event subscriptions under Webhooks. Legacy log streams no longer send events; their delivery history remains below.</p><div class="row"><button onclick="nav('webhooks')">Manage webhooks</button><button onclick="loadDeliveries()">Legacy delivery history</button></div><pre class="val" id="delivs"></pre></div>`;
  $('view').innerHTML=`${streamCard}
  <div class="tabs"><button class="tabbtn ${LOG_TAB==='audit'?'on':''}" onclick="setLogTab('audit')" data-i18n="Audit">Audit</button><button class="tabbtn ${LOG_TAB==='sync'?'on':''}" onclick="setLogTab('sync')" data-i18n="Sync activity">Sync activity</button><button class="tabbtn ${LOG_TAB==='delivery'?'on':''}" onclick="setLogTab('delivery')" data-i18n="Delivery attempts">Delivery attempts</button></div>
  <div class="row" style="margin-bottom:12px"><input id="auditfilter" placeholder="Filter by action, actor or detail…" data-i18n-placeholder="Filter by action, actor or detail…" style="min-width:280px" oninput="drawLog()"><span class="mut small" id="auditcount"></span></div><div id="auditrows"><div class="empty"><div class="big" data-i18n="Loading…">Loading…</div></div></div>`;
  await auditLoad(0)}
let LOG_TAB='audit';
function setLogTab(t){LOG_TAB=t;renderAudit()}
function drawLog(){if(LOG_TAB==='sync')drawSyncLog();else if(LOG_TAB==='delivery')drawDeliveries();else drawAudit()}
async function auditLoad(offset){try{let rows=await api('GET',offset?`/api/orgs/${ORG}/audit?limit=200&offset=${offset}`:`/api/orgs/${ORG}/audit`);if(!Array.isArray(rows))rows=[];AUDIT_ROWS=offset?AUDIT_ROWS.concat(rows):rows;AUDIT_HAS_MORE=rows.length===200;drawLog()}catch(e){toast(e.message,true)}}
function drawSyncLog(){if(!$('auditrows'))return;let q=($('auditfilter')?.value||'').trim().toLowerCase();
  let rows=AUDIT_ROWS.filter(r=>/integration|runner|rotation/.test(r.action)&&(!q||[r.action,r.detail,String(r.actor||'')].join(' ').toLowerCase().includes(q)));
  if($('auditcount'))$('auditcount').textContent=owT('{n} events shown',{n:rows.length});
  $('auditrows').innerHTML=`<table><thead><tr><th data-i18n="When">When</th><th data-i18n="Event">Event</th><th data-i18n="Outcome">Outcome</th></tr></thead><tbody>${rows.map(r=>`<tr><td class="mut small">${new Date((r.created_at||0)*1000).toLocaleString()}</td><td class="mono">${esc(r.action)}</td><td class="${/_failed|error/i.test(r.action)?'':'mut'}">${esc(r.detail||'')}</td></tr>`).join('')||'<tr><td colspan="3" class="mut" data-i18n="No events yet">No events yet</td></tr>'}</tbody></table>`}
async function drawDeliveries(){if(!$('auditrows'))return;try{let rows=await api('GET',`/api/orgs/${ORG}/log-streams/deliveries`);if(!Array.isArray(rows))rows=[];
  if($('auditcount'))$('auditcount').textContent=owT('{n} attempts shown',{n:rows.length});
  $('auditrows').innerHTML=`<table><thead><tr><th data-i18n="When">When</th><th data-i18n="Stream">Stream</th><th data-i18n="Event">Event</th><th data-i18n="Status">Status</th><th data-i18n="Attempts">Attempts</th></tr></thead><tbody>${rows.map(r=>`<tr><td class="mut small">${new Date((r.created_at||0)*1000).toLocaleString()}</td><td class="small" title="${esc(r.stream_url||'')}">${esc(r.stream_name||'')}</td><td class="mono">${esc(r.event||'')}</td><td><span class="badge ${r.status==='delivered'?'b-config':'b-sealed'}">${esc(r.status||'')}</span></td><td class="mut">${Number(r.attempts)||0}</td></tr>`).join('')||'<tr><td colspan="5" class="mut" data-i18n="No deliveries yet">No deliveries yet</td></tr>'}</tbody></table>`}catch(e){toast(e.message,true)}}
function drawAudit(){if(!$('auditrows'))return;let q=($('auditfilter')?.value||'').trim().toLowerCase();
  let rows=AUDIT_ROWS.filter(r=>!q||[r.action,r.detail,AUDIT_ACTORS[r.actor]||r.actor].join(' ').toLowerCase().includes(q));
  if($('auditcount'))$('auditcount').textContent=owT('{n} events shown',{n:rows.length});
  $('auditrows').innerHTML=`<table><thead><tr><th data-i18n="When">When</th><th data-i18n="Action">Action</th><th data-i18n="Actor">Actor</th><th data-i18n="Detail">Detail</th></tr></thead><tbody>${rows.map(r=>`<tr><td class="mut small">${new Date((r.created_at||0)*1000).toLocaleString()}</td><td class="mono">${esc(r.action)}</td><td class="small" title="${esc(r.actor||'')}">${esc(String(r.actor||'').slice(0,10))}</td><td class="mut">${esc(r.detail||'')}</td></tr>`).join('')||(AUDIT_ROWS.length?'<tr><td colspan="4" class="mut">No events match this filter.</td></tr>':'<tr><td colspan="4" class="mut" data-i18n="No events yet">No events yet</td></tr>')}</tbody></table>${AUDIT_HAS_MORE?`<div class="row" style="justify-content:center;margin-top:12px"><button onclick="auditLoad(${AUDIT_ROWS.length})" data-i18n="Load older events">Load older events</button></div>`:''}`}
async function mkStream(){try{await api('POST',`/api/orgs/${ORG}/log-streams`,{name:'console',url:$('stream-url').value});toastUI('Log stream added', false)}catch(e){toast(e.message,true)}}
async function loadDeliveries(){try{let d=await api('GET',`/api/orgs/${ORG}/log-streams/deliveries`);$('delivs').textContent=JSON.stringify(d.slice(0,25),null,2)}catch(e){toast(e.message,true)}}

async function renderSettings(){owText($('pagetitle'),'Settings');owDataText($('crumb'),'');
  if(EMERGENCY||PROJECT_EMERGENCY){$('view').innerHTML=emergencyCard()+(APP?emergencyCard(true):'');return}
  let inst=await api('GET','/api/instance').catch(()=>null);
  let feat=await api('GET',`/api/orgs/${ORG}/features`).catch(()=>({granted:[],compiled:[]}));let on=n=>(feat.granted||[]).includes(n);
  let s=await api('GET',`/api/orgs/${ORG}/settings`).catch(()=>null);
  let saml=isEnterprise()&&on('saml')?await api('GET',`/api/orgs/${ORG}/saml`).catch(()=>null):null;
  let orgs=await api('GET','/api/orgs').catch(()=>[]);let myOrg=orgs.find(o=>o.id===ORG)||{};
  let ent=isEnterprise();let dis=ent?'':' disabled';
  let samlCard=!(feat.compiled||[]).includes('saml')?'':!ent?enterpriseLock('SAML SSO','SAML single sign-on for this workspace is part of OpenWarp Enterprise.'):on('saml')?`<div class="card"><h3 data-i18n="SAML SSO">SAML SSO</h3><p><span data-i18n="Service provider metadata:">Service provider metadata:</span> <span class="mono">${esc(saml?.sp_metadata_url||'')}</span></p>
    <div class="field"><label for="set-saml-entity" data-i18n="IdP entity ID">IdP entity ID</label><input id="set-saml-entity" value="${esc(saml?.idp_entity_id||'')}" placeholder="https://idp.example/metadata"></div>
    <div class="field"><label for="set-saml-url" data-i18n="IdP metadata URL">IdP metadata URL</label><input id="set-saml-url" placeholder="https://idp.example/metadata.xml" style="width:100%"></div>
    <div class="field"><label for="set-saml-xml" data-i18n="or paste metadata XML">or paste metadata XML</label><textarea id="set-saml-xml" rows="4">${esc(saml?.metadata_xml||'')}</textarea></div>
    <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="set-saml-unsigned" ${saml?.allow_unsigned_metadata?'checked':''}> <span data-i18n="Allow unsigned metadata (not recommended)">Allow unsigned metadata (not recommended)</span></label>
    <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="set-saml-auto" ${saml?.auto_provision?'checked':''}> <span data-i18n="Auto-provision first-time users">Auto-provision first-time users</span></label>
    <div class="field"><label for="set-saml-domains" data-i18n="Allowed email domains">Allowed email domains</label><input id="set-saml-domains" value="${esc(saml?.allowed_domains||'')}" placeholder="example.com" style="width:100%"></div>
    <div class="row"><button class="primary" onclick="saveSaml()" data-i18n="Save SAML">Save SAML</button></div><pre class="val" id="saml-out"></pre></div>`:'';
  let prov=await api('GET','/api/auth/providers').catch(()=>null);
  let ldap=prov?.ldap&&on('ldap')&&isEnterprise()?await api('GET',`/api/orgs/${ORG}/ldap`).catch(()=>null):null;
  let ldapCard=!prov?.ldap?'':!ent?enterpriseLock('LDAP directory','Directory sign-in and SCIM provisioning are part of OpenWarp Enterprise.'):on('ldap')?`<div class="card"><h3 data-i18n="LDAP directory">LDAP directory</h3><p data-i18n="Users sign in with directory credentials over TLS; a service account searches for the entry, then the entry&#39;s own password is bound. Native builds only.">Users sign in with directory credentials over TLS; a service account searches for the entry, then the entry's own password is bound. Native builds only.</p>
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
    <label class="row" style="gap:8px;margin-top:16px"><input type="checkbox" id="set-workspace-creation" ${inst.workspace_creation_open?'checked':''} ${inst.workspace_creation_env_locked?'disabled':''}> Allow workspace creation</label>
    <p class="small mut">Separate from account signup. When off, new accounts have no personal workspace; invitations still work. ${inst.workspace_creation_env_locked?'Locked by OPENWARP_WORKSPACE_CREATION.':''}</p>
    <button onclick="saveWorkspacePolicy()" ${inst.workspace_creation_env_locked?'disabled':''}>Save workspace policy</button>
    <div class="row" style="margin-top:12px"><label for="set-instance-owner" data-i18n="New instance owner email">New instance owner email</label><input id="set-instance-owner" type="email" style="min-width:260px"><button onclick="transferInstance()" data-i18n="Transfer instance">Transfer instance</button></div>
    <p class="small mut" style="margin-top:6px" data-i18n="The new owner needs an active, verified account. A solo instance can delete its only account once its workspace is gone.">The new owner needs an active, verified account. A solo instance can delete its only account once its workspace is gone.</p></div>`:'';
  let tp=themePref();
  let featureCard='';
  if(inst&&inst.instance_owner){
    let fm=await api('GET','/api/instance/features').catch(()=>null);
    let names=(fm&&fm.compiled)||[];
    if(names.length){
      let rows=((fm&&fm.grants)||[]).map(g=>`<tr><td>${esc(g.name||g.org_id)}</td><td>${names.map(n=>`<label class="row" style="gap:4px;margin-right:10px;display:inline-flex"><input type="checkbox" data-feat-org="${esc(g.org_id)}" data-feat-name="${esc(n)}" ${(g.features||[]).includes(n)?'checked':''}> <span class="small">${esc(n)}</span></label>`).join('')}</td><td><button onclick="saveFeatureGrants('${jsq(g.org_id)}')" data-i18n="Save">Save</button></td></tr>`).join('');
      featureCard=`<div class="card"><h3 data-i18n="Enterprise features">Enterprise features</h3><p data-i18n="These surfaces ship compiled out by default. A workspace needs a grant before it can use one, and the build must include it.">These surfaces ship compiled out by default. A workspace needs a grant before it can use one, and the build must include it.</p><table class="members-table"><thead><tr><th data-i18n="Workspace">Workspace</th><th data-i18n="Features">Features</th><th></th></tr></thead><tbody>${rows}</tbody></table><p class="small mut" data-i18n="Only features compiled into this binary are listed. Enabling one here does not install it.">Only features compiled into this binary are listed. Enabling one here does not install it.</p></div>`;
    }
  }
  let appearanceCard=`<div class="card"><h3 data-i18n="Appearance &amp; language">Appearance & language</h3><p data-i18n="Theme and language preferences are stored in this browser.">Theme and language preferences are stored in this browser.</p>
    <div class="row"><label class="small mut" for="set-theme" data-i18n="Theme">Theme</label><select id="set-theme" onchange="setTheme(this.value)">
    <option value="system"${tp==='system'?' selected':''} data-i18n="System">System</option>
    <option value="light"${tp==='light'?' selected':''} data-i18n="Light">Light</option>
    <option value="dark"${tp==='dark'?' selected':''} data-i18n="Dark">Dark</option></select>
    <label class="small mut" for="set-lang" data-i18n="Language">Language</label><select id="set-lang" class="langsel" data-langsel onchange="owSetLang(this.value)"></select></div></div>`;
  if(!AUTH_READY)return;if(EMERGENCY||PROJECT_EMERGENCY){$('view').innerHTML=emergencyCard()+(APP?emergencyCard(true):'');return}
  let planCard=`<div class="card"><h3>Plan</h3><p><span class="chip">${ent?'Enterprise':'Self-hosted'}</span> ${ent?(EDITION.customer?`Licensed to ${esc(EDITION.customer)}${EDITION.expires_at?` until ${new Date(EDITION.expires_at*1000).toLocaleDateString()}`:''}`:'Enterprise license active.'):'All core features are enabled without a license. SAML, workspace OIDC, directory sync and audit streaming need an enterprise license.'}</p>${EDITION?.warning?`<p class="small" style="color:var(--bad)">${esc(EDITION.warning)}</p>`:''}</div>`;
  $('view').innerHTML=`${EMERGENCY_OWNER?emergencyCard():''}${instanceCard}${featureCard}${appearanceCard}${planCard}
  ${ORG?`<div class="card"><h3>Workspace</h3><p>${esc(myOrg.name||'')}</p><div class="row"><button onclick="renameWorkspace()">Rename workspace</button><button onclick="leaveWorkspace()">Leave workspace</button><button onclick="joinWorkspace()">Join another workspace</button></div></div>`:''}
  ${ORG?`<div class="card"><h3 data-i18n="Organisation security">Organisation security</h3><p data-i18n="IP allowlist is enforced on every API call. OIDC powers SSO and MCP OAuth discovery.">IP allowlist is enforced on every API call. OIDC powers SSO and MCP OAuth discovery.</p>
  <div class="field"><label for="set-ip" data-i18n="IP allowlist (CIDR, comma separated, empty = allow all)">IP allowlist (CIDR, comma separated, empty = allow all)</label><input id="set-ip" value="${esc(s?.ip_allowlist||'')}" placeholder="203.0.113.0/24"></div>
  <label class="row" style="gap:8px;margin:10px 0"><input type="checkbox" id="set-reuse" ${s?.reuse_check!==false?'checked':''}> <span data-i18n="Warn when a secret value is reused elsewhere in this workspace">Warn when a secret value is reused elsewhere in this workspace</span></label>
  <p class="small mut" style="margin:0 0 10px" data-i18n="Each app can turn the warning off. The check compares a keyed, non-reversible fingerprint and only reports items you can already open.">Each app can turn the warning off. The check compares a keyed, non-reversible fingerprint and only reports items you can already open.</p>
  ${ent?'':'<p class="small mut" style="margin:0 0 10px">Workspace OIDC single sign-on requires an enterprise license. Existing configuration is shown read-only.</p>'}
  <div class="field"><label for="set-oidc-iss" data-i18n="OIDC issuer">OIDC issuer</label><input id="set-oidc-iss" value="${esc(s?.oidc_issuer||'')}" placeholder="https://accounts.google.com"${dis}></div>
  <div class="row"><input id="set-oidc-cid" value="${esc(s?.oidc_client_id||'')}" placeholder="OIDC client id" data-i18n-placeholder="OIDC client id"${dis}><input id="set-oidc-sec" type="password" placeholder="${s?.oidc_client_secret_set?'stored; leave blank to keep':'OIDC client secret'}" data-i18n-placeholder="${s?.oidc_client_secret_set?'stored; leave blank to keep':'OIDC client secret'}"${dis}><input id="set-oidc-redir" value="${esc(s?.oidc_redirect_uri||'')}" placeholder="redirect URI" data-i18n-placeholder="redirect URI" style="min-width:260px"${dis}></div>
  <div class="field"><label for="set-oidc-domains" data-i18n="SSO email domains (comma separated; empty = any account at the issuer may join)">SSO email domains (comma separated; empty = any account at the issuer may join)</label><input id="set-oidc-domains" value="${esc(s?.oidc_allowed_domains||'')}" placeholder="example.com,subsidiary.example" style="width:100%"${dis}></div>
  <label class="row" style="gap:8px;margin-bottom:8px"><input type="checkbox" id="set-oidc-auto" ${s?.oidc_auto_provision?'checked':''}${dis}> <span data-i18n="Allow first-time SSO users to join as developers">Allow first-time SSO users to join as developers</span></label>
  <div class="row" style="margin-top:10px"><button class="primary" onclick="saveSettings()" data-i18n="Save settings">Save settings</button></div></div>
  ${samlCard}
  ${ldapCard}`:''}
  <div class="card"><h3 data-i18n="Authenticator app (TOTP)">Authenticator app (TOTP)</h3><p data-i18n="Add a second factor to your login.">Add a second factor to your login.</p><div class="row"><button onclick="totpSetup()" data-i18n="Set up TOTP">Set up TOTP</button></div><pre class="val" id="totp-out"></pre><div class="row"><input id="totp-code" placeholder="code from authenticator" data-i18n-placeholder="code from authenticator"><button onclick="totpVerify()" data-i18n="Verify and enable">Verify and enable</button></div></div>
  <div class="card"><h3 data-i18n="End-to-end environments">End-to-end environments</h3><p data-i18n="Paste your recovery kit to decrypt an E2E environment in this browser only. The kit never leaves this page.">Paste your recovery kit to decrypt an E2E environment in this browser only. The kit never leaves this page.</p>
  <div class="row"><input id="e2e-kit" placeholder="recovery kit (base64)" data-i18n-placeholder="recovery kit (base64)" style="min-width:320px"><input id="e2e-env" placeholder="E2E env ID" data-i18n-placeholder="E2E env ID"><button class="primary" onclick="loadE2E()" data-i18n="Decrypt">Decrypt</button></div><pre class="val" id="e2e-out"></pre></div>
  ${ORG?`<div class="card"><h3 data-i18n="Device certificates">Device certificates</h3><p data-i18n="Client certificates for devices and services, issued from your own CA after a CSR.">Client certificates for devices and services, issued from your own CA after a CSR.</p><p data-i18n="CSR enrollment and signed renewal work without a TPM on the server or device. Hardware attestation is optional.">CSR enrollment and signed renewal work without a TPM on the server or device. Hardware attestation is optional.</p><div id="pki-body" class="small mut" data-i18n="Loading…">Loading…</div></div>
  <div class="card"><h3 data-i18n="SSH certificates">SSH certificates</h3><div class="row"><input id="ssh-ca-name" placeholder="ssh-ca"><button onclick="mkSshCA()" data-i18n="Create SSH CA">Create SSH CA</button></div><pre class="val" id="ssh-ca-out"></pre><div id="ssh-ca-list"></div><div id="ssh-ca-detail"></div></div>`:''}
  <div class="card"><h3 data-i18n="Personal secret health">Personal secret health</h3><p class="small mut" data-i18n="Optional email exposure checks use your own paid HIBP API key (Core supported). No automatic checks. Email checks require the native server.">Optional email exposure checks use your own paid HIBP API key (Core supported). No automatic checks. Email checks require the native server.</p><p class="small mut" data-i18n="Enzoic password and credential-pair checks require your own applicable subscription and the native server. Pair checks support a bounded subset of legacy hashes; unsupported requirements are unavailable.">Enzoic password and credential-pair checks require your own applicable subscription and the native server. Pair checks support a bounded subset of legacy hashes; unsupported requirements are unavailable.</p><div class="row"><button onclick="loadEnzoicStatus()" data-i18n="Show Enzoic stored status">Show Enzoic stored status</button></div><p id="enzoic-status" class="sublabel" data-i18n="Enzoic status not loaded">Enzoic status not loaded</p><div class="row"><div class="field" style="flex:1 1 260px;max-width:380px;margin:0"><label for="enzoic-key" data-i18n="Enzoic key">Enzoic key</label><input id="enzoic-key" type="password" autocomplete="off" aria-label="Personal Enzoic API key" data-i18n-aria-label="Personal Enzoic API key" placeholder="New Enzoic key (never displayed)" data-i18n-placeholder="New Enzoic key (never displayed)"></div><div class="field" style="flex:1 1 260px;max-width:380px;margin:0"><label for="enzoic-secret" data-i18n="Enzoic secret">Enzoic secret</label><input id="enzoic-secret" type="password" autocomplete="off" aria-label="Personal Enzoic API secret" data-i18n-aria-label="Personal Enzoic API secret" placeholder="New Enzoic secret (never displayed)" data-i18n-placeholder="New Enzoic secret (never displayed)"></div></div><div class="row" style="margin-top:10px"><button onclick="saveEnzoic(false)" data-i18n="Save Enzoic credentials">Save Enzoic credentials</button><button onclick="saveEnzoic(true)" data-i18n="Remove Enzoic credentials">Remove Enzoic credentials</button></div><div class="row" style="margin-top:18px"><button onclick="loadHealthKeyStatus()" data-i18n="Show stored status">Show stored status</button></div><p id="health-key-status" class="sublabel" data-i18n="Key status not loaded">Key status not loaded</p><div class="row"><div class="field" style="flex:1 1 260px;max-width:380px;margin:0"><label for="health-key" data-i18n="HIBP key">HIBP key</label><input id="health-key" type="password" autocomplete="off" aria-label="Personal HIBP API key" data-i18n-aria-label="Personal HIBP API key" placeholder="New HIBP key (never displayed)" data-i18n-placeholder="New HIBP key (never displayed)"></div></div><div class="row" style="margin-top:10px"><button onclick="saveHealthKey(false)" data-i18n="Save key">Save key</button><button onclick="saveHealthKey(true)" data-i18n="Remove key">Remove key</button></div></div>
  <div class="card"><h3 data-i18n="Session">Session</h3><div class="row"><button onclick="loadTokensSettings()" data-i18n="My tokens">My tokens</button><button class="danger" onclick="logout()" data-i18n="Sign out everywhere (this device)">Sign out everywhere (this device)</button></div><pre class="val" id="sess-out"></pre></div>
  <div class="card" id="passkeys-card"><h3>Passkeys</h3><p class="mut">Sign in without a password using a platform or security-key passkey. Adding or removing one asks for the current password.</p><div class="row"><button onclick="loadPasskeys()" data-i18n="Show passkeys">Show passkeys</button><button class="primary" onclick="addPasskeyModal()" data-i18n="Add passkey">Add passkey</button></div><div id="passkey-list"></div></div>
  <div class="card" id="sessions-card"><h3 data-i18n="Sessions">Sessions</h3><p class="mut">Browser sessions signed in with your account. Revoking one ends that browser immediately.</p><div class="row"><button onclick="loadSessions()" data-i18n="Show sessions">Show sessions</button><button onclick="loadTokensSettings()" data-i18n="My tokens">My tokens</button><button class="danger" onclick="endAllSessions()" data-i18n="End all sessions">End all sessions</button></div><div id="session-list"></div><pre class="val" id="sess-out"></pre></div>
  ${myOrg.role==='owner'?`<div class="card"><h3 data-i18n="Delete workspace">Delete workspace</h3><p><span data-i18n="Type">Type</span> <span class="mono">${esc(myOrg.name||'')}</span> <span data-i18n="to confirm. Every app, environment, secret, token and identity in this workspace is removed.">to confirm. Every app, environment, secret, token and identity in this workspace is removed.</span></p><div class="row"><label for="del-org-name" data-i18n="Workspace name">Workspace name</label><input id="del-org-name" style="min-width:240px"><button class="danger" onclick="deleteWorkspace('${jsq(myOrg.name||'')}')" data-i18n="Delete workspace">Delete workspace</button></div></div>`:''}
  <div class="card"><h3 data-i18n="Account">Account</h3><p><span data-i18n="Signed in as">Signed in as</span> <span class="mono">${esc(ME?.email||'')}</span>. <span data-i18n="Deleting your account revokes every key and signs you out everywhere. Transfer or delete each workspace you own first.">Deleting your account revokes every key and signs you out everywhere. Transfer or delete each workspace you own first.</span></p><button class="danger" onclick="deleteAccount()" data-i18n="Delete account">Delete account</button></div>`;loadSshCAs();renderPki()}
async function saveSettings(){try{let b={ip_allowlist:$('set-ip').value,reuse_check:$('set-reuse').checked};
  if(isEnterprise()){b.oidc_auto_provision=$('set-oidc-auto').checked;b.oidc_allowed_domains=$('set-oidc-domains').value;
    if($('set-oidc-iss').value)b.oidc_issuer=$('set-oidc-iss').value;
    if($('set-oidc-cid').value)b.oidc_client_id=$('set-oidc-cid').value;
    if($('set-oidc-redir').value)b.oidc_redirect_uri=$('set-oidc-redir').value;
    if($('set-oidc-sec').value)b.oidc_client_secret=$('set-oidc-sec').value;}
  await api('PUT',`/api/orgs/${ORG}/settings`,b);toastUI('Settings saved', false)}catch(e){toast(e.message,true)}}
async function saveSignups(){try{let d=await api('PUT','/api/instance/signups',{open:$('set-signups').checked});toastUI('Signups '+(d.signups_open?'enabled':'disabled'), false);renderSettings()}catch(e){toast(e.message,true)}}
async function saveFeatureGrants(org){try{
  let names=[...document.querySelectorAll('input[data-feat-org]')].filter(i=>i.dataset.featOrg===org&&i.checked).map(i=>i.dataset.featName);
  await api('PUT','/api/instance/features',{org,features:names});toastUI('Features saved', false);renderSettings()
}catch(e){toast(e.message,true)}}
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
function b64uToBuf(v){let s=String(v).replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';let bin=atob(s);let out=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)out[i]=bin.charCodeAt(i);return out.buffer}
function bufToB64u(buf){let b=new Uint8Array(buf);let s='';for(let i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
async function loadPasskeys(){try{let d=await api('GET','/api/me/mfa');let keys=d.passkeys||[];$('passkey-list').innerHTML=keys.length?`<table style="margin-top:12px"><thead><tr><th>Name</th><th data-i18n="Added">Added</th><th data-i18n="Last used">Last used</th><th></th></tr></thead><tbody>${keys.map(k=>`<tr><td>${esc(k.name||'passkey')}</td><td class="mut small">${new Date((k.created_at||0)*1000).toLocaleDateString()}</td><td class="mut small">${k.last_used_at?new Date(k.last_used_at*1000).toLocaleDateString():'—'}</td><td style="text-align:right"><button class="danger small" onclick="removePasskey('${jsq(k.id)}','${jsq(k.name||'passkey')}')" data-i18n="Remove">Remove</button></td></tr>`).join('')}</tbody></table>`:'<p class="small mut" style="margin-top:10px">No passkeys registered yet. Add one to sign in without a password.</p>'}catch(e){toast(e.message,true)}}
function addPasskeyModal(){modal(`<h3>Add passkey</h3><div class="field"><label for="pk-name">Passkey name</label><input id="pk-name" placeholder="MacBook Touch ID"></div><div class="field"><label for="pk-pw">Current password</label><input id="pk-pw" type="password" autocomplete="current-password" placeholder="required to add a sign-in method"></div><p class="small mut">The browser asks for your device authentication after this step. The key never leaves the device.</p><div class="row"><button class="primary" onclick="addPasskey()">Continue</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`,'Add passkey')}
async function addPasskey(){let name=$('pk-name').value.trim()||'passkey',pw=$('pk-pw').value;if(!pw){toast('Current password required',true);return}
  if(!navigator.credentials||!window.PublicKeyCredential){toast('This browser does not support passkeys',true);return}
  try{let start=await api('POST','/api/me/passkeys/start',{password:pw});let o=start.options;o.challenge=b64uToBuf(o.challenge);o.user.id=b64uToBuf(o.user.id);if(o.excludeCredentials)o.excludeCredentials=o.excludeCredentials.map(c=>({...c,id:b64uToBuf(c.id)}));
    let cred=await navigator.credentials.create({publicKey:o});if(!cred)throw Error('Passkey creation was cancelled');
    let json=typeof cred.toJSON==='function'?cred.toJSON():{id:cred.id,rawId:bufToB64u(cred.rawId),type:cred.type,response:{clientDataJSON:bufToB64u(cred.response.clientDataJSON),attestationObject:bufToB64u(cred.response.attestationObject)},clientExtensionResults:{}};
    let done=await api('POST','/api/me/passkeys/finish',{state_id:start.state_id,name,password:pw,credential:json});closeModal();
    if(done.recovery_codes&&done.recovery_codes.length){modal(`<h3 data-i18n="Save your recovery codes">Save your recovery codes</h3><p class="mut">Store these away from the device. Each code works once.</p><textarea readonly rows="6">${esc(done.recovery_codes.join('\n'))}</textarea><div class="row"><button class="primary" onclick="closeModal();loadPasskeys()">Done</button></div>`,'Recovery codes')}
    else{toastUI('Passkey added', false);loadPasskeys()}}
  catch(e){toast(e.message||String(e),true)}}
function removePasskey(id,name){modal(`<h3>Remove ${esc(name)}?</h3><p class="mut">This passkey stops working immediately. Keep another passkey or TOTP before removing your last one.</p><div class="field"><label for="pk-del-pw">Current password</label><input id="pk-del-pw" type="password" autocomplete="current-password"></div><div class="row"><button class="danger" onclick="removePasskeyConfirm('${jsq(id)}')">Remove passkey</button><button class="ghost" onclick="closeModal()">Cancel</button></div>`,'Remove passkey')}
async function removePasskeyConfirm(id){try{await api('DELETE',`/api/me/passkeys/${encodeURIComponent(id)}`,{password:$('pk-del-pw').value});closeModal();toastUI('Passkey removed', false);loadPasskeys()}catch(e){toast(e.message,true)}}
async function loadSessions(){try{let rows=await api('GET','/api/me/sessions');$('session-list').innerHTML=rows.length?`<table style="margin-top:12px"><thead><tr><th data-i18n="Signed in">Signed in</th><th></th><th></th></tr></thead><tbody>${rows.map(r=>`<tr><td class="mut small">${new Date((r.created_at||0)*1000).toLocaleString()}</td><td>${r.current?'<span class="chip">this session</span>':''}</td><td style="text-align:right"><button class="danger small" onclick="revokeSession('${jsq(r.id)}',${r.current?'true':'false'})" data-i18n="Revoke">Revoke</button></td></tr>`).join('')}</tbody></table>`:'<p class="small mut" style="margin-top:10px">No active browser sessions.</p>'}catch(e){toast(e.message,true)}}
async function revokeSession(id,current){if(!confirm(current?'Revoke this session? You will be signed out now.':'Revoke this session? That browser is signed out immediately.'))return;try{await api('DELETE',`/api/me/sessions/${encodeURIComponent(id)}`);if(current){sessionEnded();return}toastUI('Session revoked', false);loadSessions()}catch(e){toast(e.message,true)}}
async function endAllSessions(){if(!confirm(owT('End every browser session for this account? Every signed-in browser is signed out, including this one.')))return;try{let d=await api('DELETE','/api/me/sessions');toastUI(owT('Ended {n} sessions',{n:Number(d.revoked)||0}), false);sessionEnded()}catch(e){toast(e.message,true)}}
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

let AI_SETTINGS=null, AI_CONTEXT={envs:[],integrations:[]}, AI_PLAN=null, AI_REFS=[], AI_OPS=[], AI_DRAFTS=[], AI_FINDINGS=[], AI_EPOCH=0;
function aiReset(){AI_EPOCH++;AI_SETTINGS=null;AI_CONTEXT={envs:[],integrations:[]};AI_PLAN=null;AI_REFS=[];AI_OPS=[];AI_DRAFTS=[];AI_FINDINGS=[]}
function aiUrl(org,suffix){return `/api/orgs/${encodeURIComponent(org)}/ai/${suffix}`}
function aiCurrent(org,epoch,view){return ORG===org&&AI_EPOCH===epoch&&VIEW===view}
function aiEnvOptions(empty=true){return (empty?'<option value="">All permitted managed environments</option>':'')+(AI_CONTEXT.envs||[]).map(e=>`<option value="${esc(e.id)}">${esc(e.app_name)} / ${esc(e.name)}</option>`).join('')}
function aiError(id,e){let el=$(id);if(el){el.textContent=e.message||String(e);el.setAttribute('role','alert')}}
async function renderAssistant(){let org=ORG,epoch=++AI_EPOCH;AI_PLAN=null;AI_REFS=[];AI_OPS=[];
  owDataText($('pagetitle'),'Assistant');owDataText($('crumb'),'');$('view').innerHTML='<p class="mut" role="status">Loading workspace AI policy...</p>';
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
async function renderInsights(){let org=ORG,epoch=++AI_EPOCH;AI_PLAN=null;owDataText($('pagetitle'),'Security insights');owDataText($('crumb'),'');$('view').innerHTML='<p class="mut" role="status">Checking available activity evidence...</p>';if(!org)return;
  try{let d=await api('GET',aiUrl(org,'findings'));if(!aiCurrent(org,epoch,'insights'))return;AI_FINDINGS=d.findings||[];AI_SETTINGS=await api('GET',aiUrl(org,'settings'));if(!aiCurrent(org,epoch,'insights'))return;
    $('view').innerHTML=`<div class="row" style="justify-content:space-between;flex-wrap:wrap;margin-bottom:16px"><div><h3 style="margin:0">Evidence-backed findings</h3><span class="small mut">Rules run without a model. No automatic revocation or remote actions.</span></div><div class="row"><button onclick="renderInsights()">Refresh findings</button><button onclick="aiSettingsModal()">AI and monitoring settings</button></div></div><div class="card"><h3>Coverage and history</h3><p>Missing history is not evidence of safe activity. New baselines can be insufficient, and earlier audit events may be incomplete.</p><pre class="ai-prose mono">${esc(JSON.stringify(d.coverage||{},null,2))}</pre></div><div id="ai-findings-list">${AI_FINDINGS.length?AI_FINDINGS.map((f,i)=>`<section class="card"><div class="row" style="flex-wrap:wrap"><span class="chip">${esc(f.severity)}</span><span class="chip">${esc(f.status||'open')}</span><h3 style="margin:0">${esc(f.title)}</h3></div><p style="margin-top:12px;white-space:pre-wrap">${esc(f.rationale)}</p><p class="small mono">Rule: ${esc(f.rule)}</p>${f.exception_until?`<p class="small mut">Exception expires ${esc(new Date(f.exception_until*1000).toLocaleString())}</p>`:''}${f.maintenance_note?`<p class="small">${esc(f.maintenance_note)}</p>`:''}<details><summary>Evidence (${(f.evidence||[]).length})</summary>${(f.evidence||[]).map(e=>`<div class="small mono" style="overflow-wrap:anywhere;padding:7px 0">${esc(new Date(e.created_at*1000).toLocaleString())} ${esc(e.action)}<br>Event ${esc(e.id)} ${esc(e.env_id||'')}</div>`).join('')}</details><div class="row" style="margin-top:12px;flex-wrap:wrap"><button onclick="aiFindingState(${i},'acknowledged')">Acknowledge</button><button onclick="aiExceptionModal(${i})">Set expiring exception</button><button onclick="aiFindingState(${i},'open')">Reopen</button><button onclick="aiExplainFinding(${i})" ${AI_SETTINGS.enabled&&AI_SETTINGS.allow_metadata&&AI_SETTINGS.inference_available!==false?'':'disabled'}>Ask AI to explain</button></div><div id="ai-finding-${i}" aria-live="polite" style="margin-top:12px"></div></section>`).join(''):'<div class="card"><h3>No findings in the available window</h3><p>This does not establish complete monitoring coverage. Review the history limits above.</p></div>'}</div>`;
  }catch(e){if(aiCurrent(org,epoch,'insights'))aiError('view',e)}}
async function aiFindingState(index,status,extra={}){let f=AI_FINDINGS[index],org=ORG,epoch=AI_EPOCH;if(!f)return;try{await api('PUT',aiUrl(org,'findings/'+encodeURIComponent(f.id)),{status,...extra});if(!aiCurrent(org,epoch,'insights'))return;closeModal();await renderInsights()}catch(e){if(aiCurrent(org,epoch,'insights')){if($('ai-exception-error'))aiError('ai-exception-error',e);else aiError('ai-finding-'+index,e)}}}
function aiExceptionModal(index){if(!AI_FINDINGS[index])return;modal(`<h3>Expiring finding exception</h3><p class="mut">This applies to one finding. The maintenance note stays out of model context.</p><div class="field"><label for="ai-exception-hours">Duration in hours</label><input id="ai-exception-hours" type="number" min="1" max="168" value="1"></div><div class="field"><label for="ai-exception-note">Maintenance or investigation note</label><textarea id="ai-exception-note" rows="3" maxlength="500"></textarea></div><div id="ai-exception-error" role="alert"></div><div class="row"><button class="primary" onclick="aiSaveException(${index})">Save exception</button><button onclick="closeModal()">Cancel</button></div>`,'Finding exception')}
async function aiSaveException(index){let hours=Number($('ai-exception-hours').value);if(!Number.isFinite(hours)||hours<1||hours>168){aiError('ai-exception-error',new Error('Choose a duration between 1 and 168 hours.'));return}await aiFindingState(index,'exception',{exception_until:Math.floor(Date.now()/1000+hours*3600),maintenance_note:$('ai-exception-note').value})}
async function aiExplainFinding(index){let f=AI_FINDINGS[index],org=ORG,epoch=AI_EPOCH;if(!f)return;$('ai-finding-'+index).textContent='Sending selected finding evidence to the configured model...';try{let d=await api('POST',aiUrl(org,'chat'),{task:'explain',finding_id:f.id,message:'Explain this finding and suggest investigation steps. Separate evidence from hypotheses.'});if(aiCurrent(org,epoch,'insights'))$('ai-finding-'+index).innerHTML=`<pre class="ai-prose">${esc(d.answer||'No explanation returned.')}</pre>`}catch(e){if(aiCurrent(org,epoch,'insights'))aiError('ai-finding-'+index,e)}}

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
function hashRoute(){let h=(location.hash||'').replace(/^#\/?/,'').split('?')[0].replace(/\/$/,'');return h}
async function applyHashRoute(){if(!AUTH_READY)return;let r=hashRoute();if(!r)return;
  if(['apps','access','integrations','audit','settings'].includes(r)){await nav(r);return}
  if(r==='logs'){await nav('audit');return}
  VIEW='notfound';owText($('pagetitle'),'Not found');$('crumb').textContent='';$('topaction').style.display='none';
  $('view').innerHTML=`<div class="empty" style="padding:56px 20px"><div class="big">404</div><h2 style="margin:6px 0 8px;color:var(--text)">This page does not exist</h2><p>The address <span class="mono">#/${esc(r)}</span> is not a console view.</p><div class="row" style="justify-content:center;margin-top:14px"><button class="primary" onclick="history.replaceState(null,'',location.pathname);nav('apps')">Go to apps</button><button class="ghost" onclick="nav('access')">Members &amp; access</button></div></div>`}
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
  else if(h.startsWith('error=')){
    // A sign-in method the binary has but the workspace has not enabled sends
    // the browser back here instead of a JSON body.
    let code=decodeURIComponent(h.slice(6).split('&')[0]);
    let msg=owT(({saml_not_enabled:'SAML sign-in is not enabled for this workspace.',ldap_not_enabled:'Directory sign-in is not enabled for this workspace.'})[code]||'Sign-in failed. Ask a workspace administrator.');
    history.replaceState(null,'',location.pathname);toast(msg,true);}
}
boot();
if(typeof window!=='undefined'&&window.addEventListener)window.addEventListener('hashchange',boot);
if(!INVITE&&!MFA&&!location.hash.startsWith('#reset=')&&!location.hash.startsWith('#mfa=')){$('auth').style.display='none';enterApp().catch(e=>toast(e.message,true))}
if(typeof window!=='undefined'&&window.addEventListener){window.addEventListener('hashchange',applyHashRoute);}
</script>
<script src="/libsodium.js" integrity="sha384-3KUAqev6nUaNHDSTa/UjyEycVN8iMfq/UtzKf3ZDTuGSb+P3y9kMu/WCVqnLAxUB"></script>
<script src="/libsodium-wrappers.js" integrity="sha384-uj62oy76l27Bkf3eEP5knMYc094z6HzwAR7Rn8ZZcBBsg5nMibZXSvjRqgZMFg/L"></script>
<script src="/zxcvbn.js" integrity="sha384-jhGcGHNZytnBnH1wbEM3KxJYyRDy9Q0QLKjE65xk+aMqXFCdvFuYIjzMWAAWBBtR"></script>
<script src="/hash-wasm.js" integrity="sha384-WhGN/+/ryxZv/uL0o2LzefmqhzOUXhmKsvy+fqvSTAXn8BFXX8ERozHe9Kk4/Ssp"></script>
<script src="/enzoic-pairs.js"></script>
<script src="/secret-health.js"></script>
<script src="/e2e.js"></script>
<script src="/auth-v2.js"></script>
</body></html>
"##;
