pub const INDEX: &str = r#"<!doctype html><html><head><meta charset="utf-8"><title>OpenWarp Console</title>
<style>body{font-family:system-ui;background:#0b1020;color:#e6e9f5;margin:0;padding:24px}input,button,select,textarea{background:#151b31;color:#fff;border:1px solid #2a3358;border-radius:8px;padding:8px;margin:4px}button{cursor:pointer;background:#3b5bff}.card{background:#121830;border:1px solid #24305c;border-radius:12px;padding:16px;margin:12px 0}table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #24305c;padding:6px;text-align:left}code{color:#8ab4ff}</style></head>
<body><h1>OpenWarp</h1><p>Unrestricted secrets management. No tiers, no licence gates.</p>
<div id="auth" class="card"><h3>Login / Register</h3><input id="email" placeholder="email"><input id="pw" type="password" placeholder="password (8+)"><button onclick="login()">Login</button><button onclick="register()">Register</button><span id="authmsg"></span></div>
<div id="main" style="display:none">
<div class="card"><button onclick="loadOrgs()">Refresh</button> <input id="orgname" placeholder="New organisation"><button onclick="createOrg()">Create org</button> <select id="orgs" onchange="loadApps()"></select>
<input id="appname" placeholder="New app"><button onclick="createApp()">Create app</button> <select id="apps" onchange="loadEnvs()"></select>
<input id="envname" placeholder="Custom env (unlimited)"><button onclick="createEnv()">Add env</button> <select id="envs" onchange="loadSecrets()"></select></div>
<div class="card"><h3>Secrets</h3><div id="secrets"></div>
<input id="k" placeholder="KEY"><input id="v" placeholder="value"><input id="path" placeholder="/path" value="/"><select id="stype"><option>secret</option><option>sealed</option><option>config</option></select><button onclick="addSecret()">Deploy secret</button><br>
<textarea id="import" rows="4" cols="80" placeholder="Paste .env to import"></textarea><button onclick="importEnv()">Import .env</button><button onclick="exportEnv()">Export</button><pre id="exp"></pre>
<input id="q" placeholder="Global search"><button onclick="search()">Search</button><pre id="searchres"></pre></div>
<div class="card"><h3>End-to-end encrypted env (browser decryption, key never leaves this page)</h3>
<input id="kit" placeholder="Recovery kit (X25519 private key, base64)" size="50"><input id="e2eenv" placeholder="E2E env ID"><button onclick="loadE2E()">Decrypt E2E secrets in browser</button><pre id="e2eres"></pre></div>
<div class="card"><h3>Proposals / Access / Teams / Identities</h3>
<button onclick="loadProposals()">Proposals (selected env)</button><pre id="props"></pre>
<input id="pemail" placeholder="member email for access context">
<button onclick="loadTeams()">Teams</button><button onclick="mkTeam()">Create team</button><pre id="teams"></pre>
<input id="idname" placeholder="machine identity name"><button onclick="mkIdentity()">Create identity (Universal Auth)</button><pre id="ident"></pre></div>
<div class="card"><h3>Integrations</h3><select id="ikind"><option>trigger</option><option>github</option><option>gitlab</option><option>vercel</option><option>netlify</option><option>cloudflare</option><option>cloudflare_pages</option><option>supabase</option><option>nomad</option><option>coolify</option><option>heroku</option><option>render</option><option>flyio</option><option>railway</option><option>digitalocean</option><option>gcp_secret_manager</option><option>azure_key_vault</option><option>kubernetes</option><option>hashicorp_vault</option><option>aws_secrets_manager</option><option>aws_parameter_store</option><option>webhook</option></select>
<textarea id="icfg" rows="3" cols="70" placeholder='config JSON, e.g. {"token":"...","project_id":"42","base_url":"https://gitlab.com/api/v4"}'></textarea>
<button onclick="mkIntegration()">Add integration to env</button><button onclick="loadIntegrations()">List / sync</button><pre id="ints"></pre></div>
<div class="card"><h3>Dynamic secrets / Rotation / Lockbox / PKI / Log streams</h3>
<button onclick="mkLease()">New dynamic lease (env)</button><button onclick="loadLeases()">Leases</button><pre id="leases"></pre>
<input id="rotkey" placeholder="KEY to rotate"><input id="rotint" placeholder="interval secs" value="86400"><button onclick="mkRotation()">Schedule rotation</button>
<button onclick="mkLockbox()">Lockbox from last secret value field</button><pre id="lockres"></pre>
<input id="caname" placeholder="CA name"><button onclick="mkCA()">Create PKI CA</button><pre id="cares"></pre>
<input id="streamurl" placeholder="log stream webhook URL"><button onclick="mkStream()">Add log stream</button><button onclick="loadDeliveries()">Delivery history</button><pre id="delivs"></pre></div>
<div class="card"><h3>Integrations / Audit / Tokens</h3><button onclick="mkToken()">Create service token</button><span id="tok"></span><button onclick="loadAudit()">Audit log</button><pre id="audit"></pre></div>
</div>
<script>
let T=localStorage.getItem('owt')||''; const H=()=>({'Authorization':'Bearer '+T,'Content-Type':'application/json'});
async function api(m,u,b){let r=await fetch(u,{method:m,headers:H(),body:b?JSON.stringify(b):undefined});let t=await r.json();if(!r.ok)throw t.error||r.status;return t}
async function register(){try{let d=await api('POST','/api/auth/register',{email:email.value,password:pw.value});T=d.token;localStorage.setItem('owt',T);authmsg.textContent='Registered. Recovery kit (save offline): '+d.recovery_kit;show()}catch(e){authmsg.textContent=e}}
async function login(){try{let d=await api('POST','/api/auth/login',{email:email.value,password:pw.value});T=d.token;localStorage.setItem('owt',T);show()}catch(e){authmsg.textContent=e}}
function show(){main.style.display='block';loadOrgs()}
async function loadOrgs(){let d=await api('GET','/api/orgs');orgs.innerHTML=d.map(o=>`<option value="${o.id}">${o.name} (${o.role})</option>`).join('');loadApps()}
async function createOrg(){await api('POST','/api/orgs',{name:orgname.value});loadOrgs()}
async function loadApps(){if(!orgs.value)return;let d=await api('GET',`/api/orgs/${orgs.value}/apps`);apps.innerHTML=d.map(a=>`<option value="${a.id}">${a.name}</option>`).join('');loadEnvs()}
async function createApp(){await api('POST',`/api/orgs/${orgs.value}/apps`,{name:appname.value});loadApps()}
async function loadEnvs(){if(!apps.value)return;let d=await api('GET',`/api/apps/${apps.value}/envs`);envs.innerHTML=d.map(e=>`<option value="${e.id}">${e.name}</option>`).join('');loadSecrets()}
async function createEnv(){await api('POST',`/api/apps/${apps.value}/envs`,{name:envname.value});loadEnvs()}
async function loadSecrets(){if(!envs.value)return;let d=await api('GET',`/api/envs/${envs.value}/secrets`);secrets.innerHTML='<table><tr><th>Key</th><th>Value</th><th>Path</th><th>Type</th><th>v</th><th></th></tr>'+d.secrets.map(s=>`<tr><td>${s.key}</td><td>${s.value===null?'🔒 sealed':s.value}</td><td>${s.path}</td><td>${s.type}</td><td>${s.version}</td><td><button onclick="hist('${s.id}')">History</button><button onclick="delSecret('${s.id}')">Delete</button></td></tr>`).join('')+'</table><pre id="hist"></pre>'}
async function addSecret(){await api('PUT',`/api/envs/${envs.value}/secrets`,{secrets:[{key:k.value,value:v.value,path:path.value,type:stype.value}]});loadSecrets()}
async function delSecret(id){await api('DELETE',`/api/secrets/${id}`);loadSecrets()}
async function hist(id){let d=await api('GET',`/api/secrets/${id}/history`);document.getElementById('hist').textContent=JSON.stringify(d,null,2)}
async function importEnv(){await api('POST',`/api/envs/${envs.value}/import`,{text:import.value});loadSecrets()}
async function exportEnv(){let d=await api('GET',`/api/envs/${envs.value}/export`);exp.textContent=d.text}
async function search(){let d=await api('GET','/api/search?q='+encodeURIComponent(q.value));searchres.textContent=JSON.stringify(d,null,2)}
async function mkToken(){let d=await api('POST',`/api/apps/${apps.value}/tokens`,{name:'cli'});tok.textContent=d.token}
async function loadAudit(){let d=await api('GET',`/api/orgs/${orgs.value}/audit`);audit.textContent=JSON.stringify(d.slice(0,50),null,2)}
async function loadProposals(){let d=await api('GET',`/api/envs/${envs.value}/proposals`);props.innerHTML=d.map(p=>`${p.id} ${p.status} by ${p.author} <button onclick="approveProp('${p.id}')">Approve</button>`).join('<br>')||'none'}
async function approveProp(id){await api('POST',`/api/proposals/${id}/approve`,{});loadProposals()}
async function loadTeams(){let d=await api('GET',`/api/orgs/${orgs.value}/teams`);teams.textContent=JSON.stringify(d)}
async function mkTeam(){await api('POST',`/api/orgs/${orgs.value}/teams`,{name:'team-'+Date.now()});loadTeams()}
async function mkIdentity(){let d=await api('POST',`/api/orgs/${orgs.value}/identities`,{name:idname.value||'machine'});ident.textContent='client_id='+d.client_id+' client_secret='+d.client_secret}
async function mkIntegration(){await api('POST',`/api/envs/${envs.value}/integrations`,{kind:ikind.value,config:JSON.parse(icfg.value||'{}')});loadIntegrations()}
async function loadIntegrations(){let d=await api('GET',`/api/envs/${envs.value}/integrations`);ints.innerHTML=d.map(i=>`${i.kind} <button onclick="syncInt('${i.id}')">Sync now</button>`).join('<br>')||'none'}
async function syncInt(id){let d=await api('POST',`/api/integrations/${id}/sync`,{});alert(JSON.stringify(d))}
async function mkLease(){let d=await api('POST',`/api/envs/${envs.value}/dynamic`,{name:'lease'});leases.textContent=JSON.stringify(d)}
async function loadLeases(){let d=await api('GET',`/api/envs/${envs.value}/dynamic`);leases.textContent=JSON.stringify(d,null,2)}
async function mkRotation(){let d=await api('POST',`/api/envs/${envs.value}/rotations`,{key:rotkey.value,interval_secs:parseInt(rotint.value)});alert(JSON.stringify(d))}
async function mkLockbox(){let d=await api('POST','/api/lockbox',{text:v.value});lockres.textContent=location.origin+d.url}
async function mkCA(){let d=await api('POST',`/api/orgs/${orgs.value}/pki/cas`,{name:caname.value||'internal-ca'});cares.textContent=d.certificate}
async function mkStream(){await api('POST',`/api/orgs/${orgs.value}/log-streams`,{name:'s1',url:streamurl.value});loadDeliveries()}
async function loadDeliveries(){let d=await api('GET',`/api/orgs/${orgs.value}/log-streams/deliveries`);delivs.textContent=JSON.stringify(d.slice(0,20),null,2)}
async function loadE2E(){try{let d=await api('GET',`/api/envs/${e2eenv.value}/e2e/secrets`);let envKey=await OW.decryptAsymmetric(kit.value,d.wrapped_key);let rows=d.secrets.map(s=>new TextDecoder().decode(OW.decryptSymmetric(envKey,s.key_enc))+'='+new TextDecoder().decode(OW.decryptSymmetric(envKey,s.value_enc)));e2eres.textContent=rows.join('\n')||'(no secrets)'}catch(e){e2eres.textContent='E2E error: '+(e.message||e)}}
if(T)show();
</script><script src="/e2e.js"></script></body></html>"#;
