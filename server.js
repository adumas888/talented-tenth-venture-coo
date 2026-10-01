import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import crypto from 'crypto';
import pg from 'pg';

const { Pool } = pg;
const app = express();
app.use(helmet());
app.use(express.json({limit:'1mb'}));
app.use(express.urlencoded({extended:false}));
app.set('trust proxy', 1);
app.use(session({secret:process.env.SESSION_SECRET||'CHANGE-ME',resave:false,saveUninitialized:false,cookie:{httpOnly:true,secure:'auto',sameSite:'lax'}}));

const region=(process.env.CLIO_REGION||'US').toUpperCase();
const host={US:'https://app.clio.com',CA:'https://ca.app.clio.com',EU:'https://eu.app.clio.com',AU:'https://au.app.clio.com'}[region];
if(!host) throw new Error('Unsupported CLIO_REGION');
const api=`${host}/api/v4`;
const dbUrl=process.env.DATABASE_URL;
const pool=dbUrl?new Pool({connectionString:dbUrl,ssl:dbUrl.includes('localhost')?false:{rejectUnauthorized:false}}):null;
let memoryToken={access_token:null,refresh_token:null,expires_at:0};

function mustEnv(name){const v=process.env[name];if(!v) throw new Error(`Missing ${name}`);return v;}
function apiAuth(req,res,next){const expected=process.env.BRIDGE_API_KEY;if(!expected||req.get('x-api-key')!==expected)return res.status(401).json({error:'unauthorized'});next();}
function key32(){const raw=mustEnv('TOKEN_ENCRYPTION_KEY');try{const b=Buffer.from(raw,'base64');if(b.length===32)return b;}catch{}const h=Buffer.from(raw,'hex');if(h.length===32)return h;throw new Error('TOKEN_ENCRYPTION_KEY must be 32 bytes encoded as base64 or 64 hex characters');}
function encrypt(obj){const iv=crypto.randomBytes(12);const cipher=crypto.createCipheriv('aes-256-gcm',key32(),iv);const ct=Buffer.concat([cipher.update(JSON.stringify(obj),'utf8'),cipher.final()]);const tag=cipher.getAuthTag();return Buffer.concat([iv,tag,ct]).toString('base64');}
function decrypt(s){const b=Buffer.from(s,'base64');const iv=b.subarray(0,12),tag=b.subarray(12,28),ct=b.subarray(28);const d=crypto.createDecipheriv('aes-256-gcm',key32(),iv);d.setAuthTag(tag);return JSON.parse(Buffer.concat([d.update(ct),d.final()]).toString('utf8'));}
async function initDb(){if(!pool)return;await pool.query(`CREATE TABLE IF NOT EXISTS bridge_secrets (name TEXT PRIMARY KEY, encrypted_value TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()); CREATE TABLE IF NOT EXISTS bridge_audit (id BIGSERIAL PRIMARY KEY, event TEXT NOT NULL, detail JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()); CREATE TABLE IF NOT EXISTS oauth_clients (client_id TEXT PRIMARY KEY, redirect_uris JSONB NOT NULL, client_name TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()); CREATE TABLE IF NOT EXISTS oauth_codes (code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, code_challenge TEXT NOT NULL, resource TEXT NOT NULL, scope TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ); CREATE TABLE IF NOT EXISTS oauth_tokens (token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, resource TEXT NOT NULL, scope TEXT NOT NULL, token_type TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()); CREATE TABLE IF NOT EXISTS chief_objectives (id BIGSERIAL PRIMARY KEY, title TEXT NOT NULL, matter_id BIGINT, case_number TEXT, status TEXT NOT NULL DEFAULT 'OPEN', waiting_on TEXT, next_action TEXT, completion_condition TEXT NOT NULL, detail JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), completed_at TIMESTAMPTZ); CREATE TABLE IF NOT EXISTS venture_projects (id BIGSERIAL PRIMARY KEY,name TEXT UNIQUE NOT NULL,status TEXT NOT NULL DEFAULT 'ACTIVE',launch_goal TEXT NOT NULL,completion_condition TEXT NOT NULL,source TEXT,priority INT DEFAULT 50,detail JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMPTZ DEFAULT NOW(),updated_at TIMESTAMPTZ DEFAULT NOW()); CREATE TABLE IF NOT EXISTS venture_objectives (id BIGSERIAL PRIMARY KEY,project_id BIGINT REFERENCES venture_projects(id),title TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'OPEN',waiting_on TEXT,next_action TEXT,completion_condition TEXT NOT NULL,priority INT DEFAULT 50,detail JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMPTZ DEFAULT NOW(),updated_at TIMESTAMPTZ DEFAULT NOW(),completed_at TIMESTAMPTZ); CREATE TABLE IF NOT EXISTS venture_tasks (id BIGSERIAL PRIMARY KEY,project_id BIGINT REFERENCES venture_projects(id),objective_id BIGINT REFERENCES venture_objectives(id),title TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'OPEN',owner TEXT NOT NULL DEFAULT 'Venture COO',waiting_on TEXT,next_action TEXT,requires_antoine BOOLEAN NOT NULL DEFAULT FALSE,detail JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMPTZ DEFAULT NOW(),updated_at TIMESTAMPTZ DEFAULT NOW(),completed_at TIMESTAMPTZ); CREATE TABLE IF NOT EXISTS venture_activity (id BIGSERIAL PRIMARY KEY,project_id BIGINT REFERENCES venture_projects(id),objective_id BIGINT,task_id BIGINT,action TEXT NOT NULL,result TEXT,detail JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMPTZ DEFAULT NOW());`);}
async function audit(event,detail={}){try{if(pool)await pool.query('INSERT INTO bridge_audit(event,detail) VALUES($1,$2)',[event,detail]);else console.log(JSON.stringify({audit:event,detail}));}catch(e){console.error('audit_failed',e.message)}}
async function loadToken(){if(!pool)return memoryToken;const r=await pool.query("SELECT encrypted_value FROM bridge_secrets WHERE name='clio_oauth'");return r.rows[0]?decrypt(r.rows[0].encrypted_value):{access_token:null,refresh_token:null,expires_at:0};}
async function saveToken(t){memoryToken=t;if(pool)await pool.query("INSERT INTO bridge_secrets(name,encrypted_value,updated_at) VALUES('clio_oauth',$1,NOW()) ON CONFLICT(name) DO UPDATE SET encrypted_value=EXCLUDED.encrypted_value, updated_at=NOW()",[encrypt(t)]);}
async function tokenRequest(params){const previous=await loadToken();const r=await fetch(`${host}/oauth/token`,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(params),signal:AbortSignal.timeout(20000)});const j=await r.json();if(!r.ok)throw new Error(`Clio OAuth ${r.status}: ${JSON.stringify(j)}`);const next={...previous,...j,refresh_token:j.refresh_token||previous.refresh_token,expires_at:Date.now()+((j.expires_in||3600)-60)*1000};await saveToken(next);return next;}
async function accessToken(){const t=await loadToken();if(t.access_token&&Date.now()<t.expires_at)return t.access_token;if(!t.refresh_token)throw new Error('Clio not connected');const n=await tokenRequest({client_id:mustEnv('CLIO_CLIENT_ID'),client_secret:mustEnv('CLIO_CLIENT_SECRET'),grant_type:'refresh_token',refresh_token:t.refresh_token});await audit('clio_token_refreshed');return n.access_token;}
async function clio(path,{method='GET',body,retry=true}={}){const token=await accessToken();const r=await fetch(`${api}${path}`,{method,headers:{authorization:`Bearer ${token}`,'content-type':'application/json','accept':'application/json'},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(30000)});if(r.status===401&&retry){const t=await loadToken();if(t.refresh_token){t.expires_at=0;await saveToken(t);return clio(path,{method,body,retry:false});}}const text=await r.text();let data;try{data=JSON.parse(text)}catch{data=text}if(!r.ok)throw new Error(`Clio API ${r.status}: ${text}`);return data;}
async function clioAll(path,params={},maxPages=25){const rows=[];let next=null;let pages=0;do{let requestPath;if(next){const u=new URL(next);requestPath=u.pathname.replace('/api/v4','')+u.search;}else{const q=new URLSearchParams(params);q.set('limit','200');requestPath=`${path}?${q}`;}const out=await clio(requestPath);if(Array.isArray(out.data))rows.push(...out.data);else if(out.data)rows.push(out.data);next=out?.meta?.paging?.next||null;pages++;}while(next&&pages<maxPages);return {data:rows,meta:{pages,complete:!next,total_returned:rows.length}};}
function norm(v){return String(v||'').toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g,' ').trim();}
function matchTerms(record,query){const hay=norm(record);const terms=norm(query).split(/\s+/).filter(Boolean);return terms.length>0&&terms.every(t=>hay.includes(t));}
function writesEnabled(res){if(process.env.ENABLE_VENTURE_WRITES!=='true'){res.status(403).json({error:'writes_disabled'});return false;}return true;}

app.get('/',async(req,res)=>{const t=await loadToken();res.type('html').send(`<h1>Talented Tenth Venture COO</h1><p>Clio: ${t.refresh_token||t.access_token?'connected':'not connected'}</p><p>Persistent token store: ${pool?'configured':'NOT configured'}</p><p><a href="/oauth/clio/start">Connect Clio Manage</a></p>`)});
app.get('/health',async(req,res)=>{try{const t=await loadToken();res.json({ok:true,clio_connected:!!(t.refresh_token||t.access_token),persistent_store:!!pool,region,writes_enabled:process.env.ENABLE_VENTURE_WRITES==='true'});}catch(e){res.status(500).json({ok:false,error:'storage_unavailable'})}});
function makeOAuthState(){const payload=`${Date.now()}.${crypto.randomBytes(24).toString('hex')}`;const sig=crypto.createHmac('sha256',mustEnv('SESSION_SECRET')).update(payload).digest('hex');return `${payload}.${sig}`;}
function validOAuthState(state){if(typeof state!=='string')return false;const parts=state.split('.');if(parts.length!==3)return false;const [ts,nonce,sig]=parts;if(!/^\d+$/.test(ts)||!nonce||!sig)return false;const age=Date.now()-Number(ts);if(age<0||age>10*60*1000)return false;const expected=crypto.createHmac('sha256',mustEnv('SESSION_SECRET')).update(`${ts}.${nonce}`).digest('hex');try{return crypto.timingSafeEqual(Buffer.from(sig,'hex'),Buffer.from(expected,'hex'));}catch{return false;}}
app.get('/oauth/clio/start',(req,res)=>{const u=new URL(`${host}/oauth/authorize`);u.searchParams.set('client_id',mustEnv('CLIO_CLIENT_ID'));u.searchParams.set('response_type','code');u.searchParams.set('redirect_uri',mustEnv('CLIO_REDIRECT_URI'));u.searchParams.set('state',makeOAuthState());res.redirect(u.toString());});
app.get('/oauth/clio/callback',async(req,res)=>{try{if(!req.query.code||!validOAuthState(req.query.state))return res.status(400).send('Invalid OAuth callback/state.');await tokenRequest({client_id:mustEnv('CLIO_CLIENT_ID'),client_secret:mustEnv('CLIO_CLIENT_SECRET'),grant_type:'authorization_code',code:String(req.query.code),redirect_uri:mustEnv('CLIO_REDIRECT_URI')});await audit('clio_connected');res.send('Clio Manage connected to Talented Tenth Venture COO. You may close this tab.');}catch(e){console.error(e);res.status(500).send('OAuth connection failed. Check Render logs for details.')}});

app.get('/api/clio/status',apiAuth,async(req,res)=>{try{const who=await clio('/users/who_am_i?fields=id,name,email');res.json({connected:true,region,persistent_store:!!pool,writes_enabled:process.env.ENABLE_VENTURE_WRITES==='true',user:who.data});}catch(e){res.status(500).json({connected:false,error:e.message})}});
app.get('/api/clio/matters',apiAuth,async(req,res)=>{try{const q=new URLSearchParams({fields:'id,display_number,description,status,open_date,close_date,client{id,name},responsible_attorney{id,name}',limit:String(Math.min(Number(req.query.limit)||200,200))});if(req.query.status)q.set('status',String(req.query.status));res.json(await clio(`/matters?${q}`));}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/clio/matters/:id',apiAuth,async(req,res)=>{try{res.json(await clio(`/matters/${req.params.id}?fields=id,display_number,description,status,open_date,close_date,client{id,name},responsible_attorney{id,name}`));}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/clio/tasks',apiAuth,async(req,res)=>{try{const q=new URLSearchParams({fields:'id,name,due_at,description,matter{id,display_number,description},assignee{id,name}',limit:'200'});if(req.query.matter_id)q.set('matter_id',req.query.matter_id);res.json(await clio(`/tasks?${q}`));}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/clio/activities',apiAuth,async(req,res)=>{try{const q=new URLSearchParams({fields:'id,type,date,quantity,quantity_in_hours,note,status,matter{id,display_number,description},user{id,name}',limit:'200'});if(req.query.matter_id)q.set('matter_id',req.query.matter_id);if(req.query.start_date)q.set('start_date',req.query.start_date);res.json(await clio(`/activities?${q}`));}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/clio/contacts',apiAuth,async(req,res)=>{try{const q=new URLSearchParams({fields:'id,name,type,primary_email_address,primary_phone_number',limit:'200'});res.json(await clio(`/contacts?${q}`));}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/clio/users',apiAuth,async(req,res)=>{try{res.json(await clio('/users?fields=id,name,email,enabled&limit=200'));}catch(e){res.status(500).json({error:e.message})}});

app.post('/api/clio/tasks',apiAuth,async(req,res)=>{try{if(!writesEnabled(res))return;if(req.body.approved!==true)return res.status(400).json({error:'approval_required'});const {name,description,due_at,matter_id,assignee_id,assignee_type='User'}=req.body;if(!assignee_id)return res.status(400).json({error:'assignee_id_required'});if(!['User','Contact'].includes(assignee_type))return res.status(400).json({error:'assignee_type_must_be_User_or_Contact'});const out=await clio('/tasks',{method:'POST',body:{data:{name,description,due_at,matter:{id:matter_id},assignee:{id:Number(assignee_id),type:assignee_type}}}});await audit('write_task_created',{matter_id,clio_task_id:out?.data?.id});res.json(out);}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/clio/time-entries',apiAuth,async(req,res)=>{try{if(!writesEnabled(res))return;if(req.body.approved!==true)return res.status(400).json({error:'approval_required'});const {matter_id,user_id,date,seconds,note,non_billable=false}=req.body;if(!matter_id||!user_id||!date||!Number.isFinite(seconds))return res.status(400).json({error:'matter_id, user_id, date, seconds required'});const out=await clio('/activities',{method:'POST',body:{data:{type:'TimeEntry',date,quantity:seconds,note,non_billable,matter:{id:matter_id},user:{id:user_id}}}});await audit('write_time_entry_created',{matter_id,clio_activity_id:out?.data?.id});res.json(out);}catch(e){res.status(500).json({error:e.message})}});

await initDb();


// --- OAuth 2.1 authorization server for ChatGPT MCP -------------------------
const BASE_URL=(process.env.APP_BASE_URL||'').replace(/\/$/,'');
if(!BASE_URL)throw new Error('Missing APP_BASE_URL');
const OAUTH_ISSUER=BASE_URL;
const MCP_RESOURCE=`${BASE_URL}/mcp`;
const MCP_SCOPE='clio:read';
function sha256hex(v){return crypto.createHash('sha256').update(String(v)).digest('hex');}
function b64url(v){return Buffer.from(v).toString('base64url');}
function safeEq(a,b){const A=Buffer.from(String(a)),B=Buffer.from(String(b));return A.length===B.length&&crypto.timingSafeEqual(A,B);}
function oauthError(res,status,error,description){return res.status(status).json({error,error_description:description});}
function validHttpsRedirect(uri){try{const u=new URL(uri);return u.protocol==='https:'&&!u.username&&!u.password;}catch{return false;}}
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function hidden(n,v){return `<input type="hidden" name="${esc(n)}" value="${esc(v)}">`;}
async function getOAuthClient(id){if(!pool)return null;const r=await pool.query('SELECT client_id,redirect_uris,client_name FROM oauth_clients WHERE client_id=$1',[id]);return r.rows[0]||null;}
async function validateAuthRequest(q){
 const clientId=String(q.client_id||''),redirectUri=String(q.redirect_uri||''),challenge=String(q.code_challenge||''),method=String(q.code_challenge_method||''),resource=String(q.resource||''),scope=String(q.scope||MCP_SCOPE),state=String(q.state||'');
 if(!clientId||!redirectUri||String(q.response_type||'')!=='code'||!challenge||method!=='S256')throw new Error('Invalid OAuth authorization request.');
 if(resource!==MCP_RESOURCE)throw new Error('Invalid OAuth resource.');
 if(!scope.split(/\s+/).includes(MCP_SCOPE))throw new Error('Required clio:read scope missing.');
 const client=await getOAuthClient(clientId); if(!client)throw new Error('Unknown OAuth client.');
 if(!Array.isArray(client.redirect_uris)||!client.redirect_uris.includes(redirectUri))throw new Error('Redirect URI is not registered.');
 return {clientId,redirectUri,challenge,resource,scope:MCP_SCOPE,state,client};
}
app.get('/.well-known/oauth-protected-resource',(req,res)=>res.json({resource:MCP_RESOURCE,authorization_servers:[OAUTH_ISSUER],scopes_supported:[MCP_SCOPE],resource_documentation:`${BASE_URL}/`}));
app.get('/.well-known/oauth-protected-resource/mcp',(req,res)=>res.json({resource:MCP_RESOURCE,authorization_servers:[OAUTH_ISSUER],scopes_supported:[MCP_SCOPE],resource_documentation:`${BASE_URL}/`}));
const authMetadata=()=>({issuer:OAUTH_ISSUER,authorization_endpoint:`${BASE_URL}/oauth/authorize`,token_endpoint:`${BASE_URL}/oauth/token`,registration_endpoint:`${BASE_URL}/oauth/register`,response_types_supported:['code'],grant_types_supported:['authorization_code','refresh_token'],code_challenge_methods_supported:['S256'],scopes_supported:[MCP_SCOPE],token_endpoint_auth_methods_supported:['none'],authorization_response_iss_parameter_supported:true});
app.get('/.well-known/oauth-authorization-server',(req,res)=>res.json(authMetadata()));
app.get('/.well-known/openid-configuration',(req,res)=>res.json(authMetadata()));

app.post('/oauth/register',async(req,res)=>{try{
 if(!pool)return oauthError(res,503,'temporarily_unavailable','Persistent store required.');
 const uris=req.body?.redirect_uris;
 if(!Array.isArray(uris)||!uris.length||uris.length>10||!uris.every(validHttpsRedirect))return oauthError(res,400,'invalid_redirect_uri','HTTPS redirect_uris required.');
 const clientId=`tt_${b64url(crypto.randomBytes(24))}`,clientName=String(req.body?.client_name||'ChatGPT MCP Client').slice(0,200);
 await pool.query('INSERT INTO oauth_clients(client_id,redirect_uris,client_name) VALUES($1,$2,$3)',[clientId,JSON.stringify(uris),clientName]);
 await audit('oauth_client_registered',{client_id:clientId,client_name:clientName});
 res.status(201).json({client_id:clientId,client_name:clientName,redirect_uris:uris,grant_types:['authorization_code','refresh_token'],response_types:['code'],token_endpoint_auth_method:'none'});
}catch(e){console.error(e);oauthError(res,500,'server_error','Client registration failed.')}});

app.get('/oauth/authorize',async(req,res)=>{try{
 const a=await validateAuthRequest(req.query);
 const fields=['client_id','redirect_uri','response_type','code_challenge','code_challenge_method','resource','scope','state'].map(k=>hidden(k,req.query[k]||'')).join('');
 // Override Helmet's default form-action policy on this OAuth consent page.
 // Some embedded/connector browser flows treat the document origin unusually and
 // block form-action 'self'. Pinning the exact HTTPS origin keeps the POST narrowly scoped.
 res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https:; base-uri 'none'; frame-ancestors 'none'");
 res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Authorize Talented Tenth</title></head><body style="font-family:system-ui;max-width:640px;margin:48px auto;padding:0 20px"><h1>Talented Tenth Venture COO</h1><p><strong>${esc(a.client.client_name||'ChatGPT')}</strong> requests read-only access to Talented Tenth Law's Clio matters, tasks, contacts, users, and activity/time-entry data.</p><p>No Clio write tools are exposed.</p><form method="post" action="${BASE_URL}/oauth/authorize">${fields}<label>Bridge admin authorization secret<br><input type="password" name="admin_secret" required autocomplete="current-password" style="width:100%;padding:10px;margin:8px 0 16px"></label><button type="submit" style="padding:10px 18px">Authorize read-only access</button></form></body></html>`);
}catch(e){res.status(400).type('html').send(`<h1>Invalid OAuth request</h1><p>${esc(e.message)}</p>`)}});

app.post('/oauth/authorize',async(req,res)=>{try{
 const a=await validateAuthRequest(req.body);
 if(!safeEq(req.body.admin_secret||'',mustEnv('OAUTH_ADMIN_SECRET'))){await audit('oauth_authorization_denied',{client_id:a.clientId});return res.status(403).send('Authorization denied.');}
 const code=b64url(crypto.randomBytes(32));
 await pool.query("INSERT INTO oauth_codes(code_hash,client_id,redirect_uri,code_challenge,resource,scope,expires_at) VALUES($1,$2,$3,$4,$5,$6,NOW()+INTERVAL '5 minutes')",[sha256hex(code),a.clientId,a.redirectUri,a.challenge,a.resource,a.scope]);
 await audit('oauth_authorization_approved',{client_id:a.clientId});
 const u=new URL(a.redirectUri);u.searchParams.set('code',code);if(a.state)u.searchParams.set('state',a.state);u.searchParams.set('iss',OAUTH_ISSUER);res.redirect(u.toString());
}catch(e){console.error(e);res.status(400).send('Authorization failed.')}});

async function issueOAuthTokens(clientId,resource,scope){
 const access=b64url(crypto.randomBytes(32)),refresh=b64url(crypto.randomBytes(32));
 await pool.query("INSERT INTO oauth_tokens(token_hash,client_id,resource,scope,token_type,expires_at) VALUES($1,$2,$3,$4,'access',NOW()+INTERVAL '1 hour'),($5,$2,$3,$4,'refresh',NOW()+INTERVAL '30 days')",[sha256hex(access),clientId,resource,scope,sha256hex(refresh)]);
 return {access_token:access,token_type:'Bearer',expires_in:3600,refresh_token:refresh,scope};
}
app.post('/oauth/token',async(req,res)=>{try{
 const grant=String(req.body.grant_type||''),clientId=String(req.body.client_id||''),resource=String(req.body.resource||'');
 if(!clientId||!(await getOAuthClient(clientId)))return oauthError(res,401,'invalid_client','Unknown client.');
 if(resource!==MCP_RESOURCE)return oauthError(res,400,'invalid_target','Invalid resource.');
 if(grant==='authorization_code'){
  const code=String(req.body.code||''),redirect=String(req.body.redirect_uri||''),verifier=String(req.body.code_verifier||'');
  const r=await pool.query('SELECT * FROM oauth_codes WHERE code_hash=$1 AND client_id=$2 AND used_at IS NULL AND expires_at>NOW()',[sha256hex(code),clientId]);const row=r.rows[0];
  if(!row||row.redirect_uri!==redirect||row.resource!==resource)return oauthError(res,400,'invalid_grant','Authorization code invalid.');
  const calc=b64url(crypto.createHash('sha256').update(verifier).digest());if(!safeEq(calc,row.code_challenge))return oauthError(res,400,'invalid_grant','PKCE verification failed.');
  await pool.query('UPDATE oauth_codes SET used_at=NOW() WHERE code_hash=$1',[row.code_hash]);return res.json(await issueOAuthTokens(clientId,resource,row.scope));
 }
 if(grant==='refresh_token'){
  const refresh=String(req.body.refresh_token||'');const r=await pool.query("SELECT * FROM oauth_tokens WHERE token_hash=$1 AND client_id=$2 AND token_type='refresh' AND revoked_at IS NULL AND expires_at>NOW()",[sha256hex(refresh),clientId]);const row=r.rows[0];
  if(!row||row.resource!==resource)return oauthError(res,400,'invalid_grant','Refresh token invalid.');
  await pool.query('UPDATE oauth_tokens SET revoked_at=NOW() WHERE token_hash=$1',[row.token_hash]);return res.json(await issueOAuthTokens(clientId,resource,row.scope));
 }
 oauthError(res,400,'unsupported_grant_type','Unsupported grant.');
}catch(e){console.error(e);oauthError(res,500,'server_error','Token request failed.')}});

async function oauthAccess(req){
 const bearer=(req.get('authorization')||'').match(/^Bearer\s+(.+)$/i)?.[1];if(!bearer||!pool)return null;
 const r=await pool.query("SELECT client_id,resource,scope FROM oauth_tokens WHERE token_hash=$1 AND token_type='access' AND revoked_at IS NULL AND expires_at>NOW()",[sha256hex(bearer)]);const row=r.rows[0];
 return row&&row.resource===MCP_RESOURCE&&String(row.scope).split(/\s+/).includes(MCP_SCOPE)?row:null;
}
function oauthChallenge(res){return res.set('WWW-Authenticate',`Bearer resource_metadata="${BASE_URL}/.well-known/oauth-protected-resource", scope="${MCP_SCOPE}"`);}

// --- Read-only MCP interface -------------------------------------------------
const MCP_LEGACY_VERSION='2025-11-25',MCP_MODERN_VERSION='2026-07-28';
const MCP_SERVER_INFO={name:'talented-tenth-venture-coo',version:'1.5.0'};
const MCP_INSTRUCTIONS='Talented Tenth Venture COO. Persistent venture tools are available. Controlled writes require ENABLE_VENTURE_WRITES=true and explicit approved=true. Never infer approval.';
function localBridgeKey(req){const expected=process.env.BRIDGE_API_KEY;if(!expected)return false;const bearer=(req.get('authorization')||'').match(/^Bearer\s+(.+)$/i)?.[1],supplied=bearer||req.get('x-api-key');return supplied&&safeEq(supplied,expected);}
function mcpError(id,code,message,data){return {jsonrpc:'2.0',id:id??null,error:{code,message,...(data===undefined?{}:{data})}};}
function mcpResult(id,result,modern=false){const out={jsonrpc:'2.0',id,result};if(modern)out._meta={'io.modelcontextprotocol/serverInfo':MCP_SERVER_INFO};return out;}
function toolResult(data){return {content:[{type:'text',text:JSON.stringify(data)}],structuredContent:data,isError:false};}
function clampInt(v,def=100,max=200){const n=Number(v);return Number.isFinite(n)?Math.max(1,Math.min(Math.trunc(n),max)):def;}
const SECURITY=[{type:'oauth2',scopes:[MCP_SCOPE]}];
const RO={readOnlyHint:true,destructiveHint:false,openWorldHint:false};
const WRITE={readOnlyHint:false,destructiveHint:false,openWorldHint:false};
const DESTRUCTIVE={readOnlyHint:false,destructiveHint:true,openWorldHint:false};
function requireWriteApproval(args){if(process.env.ENABLE_VENTURE_WRITES!=='true')throw new Error('Venture COO writes are disabled. Set ENABLE_VENTURE_WRITES=true in Render.');if(args?.approved!==true)throw new Error('Explicit approval required: approved=true.');}
function cleanData(obj){return Object.fromEntries(Object.entries(obj).filter(([,v])=>v!==undefined&&v!==null&&v!==''));}
const MCP_TOOLS=[
{name:'coo_status',title:'Venture COO Status',description:'Check Venture COO database and write status.',inputSchema:{type:'object',properties:{},additionalProperties:false},securitySchemes:SECURITY,annotations:RO},
{name:'list_projects',title:'List Venture Projects',description:'List venture workstreams and launch goals.',inputSchema:{type:'object',properties:{},additionalProperties:false},securitySchemes:SECURITY,annotations:RO},
{name:'get_dashboard',title:'Venture Command Center',description:'Return projects, open objectives, blockers, waiting-on items and Antoine-required tasks.',inputSchema:{type:'object',properties:{},additionalProperties:false},securitySchemes:SECURITY,annotations:RO},
{name:'list_objectives',title:'List Venture Objectives',description:'List persistent venture objectives.',inputSchema:{type:'object',properties:{project_id:{type:['string','integer']},status:{type:'string'}},additionalProperties:false},securitySchemes:SECURITY,annotations:RO},
{name:'create_objective',title:'Create Venture Objective',description:'Create a persistent venture objective after explicit approval.',inputSchema:{type:'object',properties:{approved:{type:'boolean'},project_id:{type:['string','integer']},title:{type:'string'},completion_condition:{type:'string'},priority:{type:'integer'},next_action:{type:'string'},waiting_on:{type:'string'},detail:{type:'object'}},required:['approved','project_id','title','completion_condition'],additionalProperties:false},securitySchemes:SECURITY,annotations:WRITE},
{name:'update_objective',title:'Update Venture Objective',description:'Update objective. COMPLETE requires detail.completion_verified=true.',inputSchema:{type:'object',properties:{approved:{type:'boolean'},objective_id:{type:['string','integer']},status:{type:'string'},next_action:{type:'string'},waiting_on:{type:'string'},detail:{type:'object'}},required:['approved','objective_id'],additionalProperties:false},securitySchemes:SECURITY,annotations:WRITE},
{name:'list_tasks',title:'List Venture Tasks',description:'List persistent venture tasks.',inputSchema:{type:'object',properties:{project_id:{type:['string','integer']},status:{type:'string'}},additionalProperties:false},securitySchemes:SECURITY,annotations:RO},
{name:'create_task',title:'Create Venture Task',description:'Create operating task after explicit approval.',inputSchema:{type:'object',properties:{approved:{type:'boolean'},project_id:{type:['string','integer']},objective_id:{type:['string','integer']},title:{type:'string'},owner:{type:'string'},waiting_on:{type:'string'},next_action:{type:'string'},requires_antoine:{type:'boolean'},detail:{type:'object'}},required:['approved','project_id','title'],additionalProperties:false},securitySchemes:SECURITY,annotations:WRITE},
{name:'update_task',title:'Update Venture Task',description:'Update task. COMPLETE requires detail.completion_verified=true.',inputSchema:{type:'object',properties:{approved:{type:'boolean'},task_id:{type:['string','integer']},status:{type:'string'},waiting_on:{type:'string'},next_action:{type:'string'},requires_antoine:{type:'boolean'},detail:{type:'object'}},required:['approved','task_id'],additionalProperties:false},securitySchemes:SECURITY,annotations:WRITE},
{name:'log_activity',title:'Log Venture Activity',description:'Record work performed, result, blocker, or handoff.',inputSchema:{type:'object',properties:{approved:{type:'boolean'},project_id:{type:['string','integer']},objective_id:{type:['string','integer']},task_id:{type:['string','integer']},action:{type:'string'},result:{type:'string'},detail:{type:'object'}},required:['approved','project_id','action'],additionalProperties:false},securitySchemes:SECURITY,annotations:WRITE},
{name:'bootstrap_launch_system',title:'Bootstrap Launch System',description:'Seed GoVibe, ACE, Citadelle and Liberation Law from the uploaded launch checklists. Idempotent.',inputSchema:{type:'object',properties:{approved:{type:'boolean'}},required:['approved'],additionalProperties:false},securitySchemes:SECURITY,annotations:WRITE}
];
async function callMcpTool(name,args={}){
 const rows=async(q,v=[])=>(await pool.query(q,v)).rows, one=async(q,v=[])=>(await pool.query(q,v)).rows[0];
 if(!pool&&name!=='coo_status')throw new Error('Persistent DATABASE_URL required');
 switch(name){
 case 'coo_status':return toolResult({persistent_store:!!pool,writes_enabled:process.env.ENABLE_VENTURE_WRITES==='true'});
 case 'list_projects':return toolResult({data:await rows('SELECT * FROM venture_projects ORDER BY priority,id')});
 case 'get_dashboard':return toolResult({projects:await rows('SELECT id,name,status,launch_goal,priority FROM venture_projects ORDER BY priority'),objectives:await rows("SELECT o.*,p.name project_name FROM venture_objectives o JOIN venture_projects p ON p.id=o.project_id WHERE o.status<>'COMPLETE' ORDER BY o.priority,o.updated_at"),antoine_required:await rows("SELECT t.*,p.name project_name FROM venture_tasks t JOIN venture_projects p ON p.id=t.project_id WHERE t.status<>'COMPLETE' AND t.requires_antoine=true ORDER BY t.updated_at"),waiting_on:await rows("SELECT t.*,p.name project_name FROM venture_tasks t JOIN venture_projects p ON p.id=t.project_id WHERE t.status<>'COMPLETE' AND t.waiting_on IS NOT NULL ORDER BY t.updated_at")});
 case 'list_objectives':{let q='SELECT * FROM venture_objectives',v=[];if(args.project_id!=null){q+=' WHERE project_id=$1';v=[Number(args.project_id)]}return toolResult({data:await rows(q+' ORDER BY priority,id',v)});}
 case 'create_objective':{requireWriteApproval(args);const r=await one('INSERT INTO venture_objectives(project_id,title,completion_condition,priority,next_action,waiting_on,detail) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[Number(args.project_id),args.title,args.completion_condition,args.priority??50,args.next_action||null,args.waiting_on||null,args.detail||{}]);return toolResult({data:r});}
 case 'update_objective':{requireWriteApproval(args);const c=await one('SELECT * FROM venture_objectives WHERE id=$1',[Number(args.objective_id)]);if(!c)throw new Error('objective not found');const st=args.status??c.status;if(String(st).toUpperCase()==='COMPLETE'&&!args.detail?.completion_verified)throw new Error('COMPLETE requires detail.completion_verified=true');const d={...(c.detail||{}),...(args.detail||{})};return toolResult({data:await one("UPDATE venture_objectives SET status=$2,next_action=$3,waiting_on=$4,detail=$5,updated_at=NOW(),completed_at=CASE WHEN UPPER($2)='COMPLETE' THEN COALESCE(completed_at,NOW()) ELSE NULL END WHERE id=$1 RETURNING *",[c.id,st,args.next_action??c.next_action,args.waiting_on??c.waiting_on,d])});}
 case 'list_tasks':{let q='SELECT * FROM venture_tasks',v=[];if(args.project_id!=null){q+=' WHERE project_id=$1';v=[Number(args.project_id)]}return toolResult({data:await rows(q+' ORDER BY id',v)});}
 case 'create_task':{requireWriteApproval(args);const r=await one('INSERT INTO venture_tasks(project_id,objective_id,title,owner,waiting_on,next_action,requires_antoine,detail) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',[Number(args.project_id),args.objective_id?Number(args.objective_id):null,args.title,args.owner||'Venture COO',args.waiting_on||null,args.next_action||null,args.requires_antoine===true,args.detail||{}]);return toolResult({data:r});}
 case 'update_task':{requireWriteApproval(args);const c=await one('SELECT * FROM venture_tasks WHERE id=$1',[Number(args.task_id)]);if(!c)throw new Error('task not found');const st=args.status??c.status;if(String(st).toUpperCase()==='COMPLETE'&&!args.detail?.completion_verified)throw new Error('COMPLETE requires detail.completion_verified=true');const d={...(c.detail||{}),...(args.detail||{})};return toolResult({data:await one("UPDATE venture_tasks SET status=$2,waiting_on=$3,next_action=$4,requires_antoine=$5,detail=$6,updated_at=NOW(),completed_at=CASE WHEN UPPER($2)='COMPLETE' THEN COALESCE(completed_at,NOW()) ELSE NULL END WHERE id=$1 RETURNING *",[c.id,st,args.waiting_on??c.waiting_on,args.next_action??c.next_action,args.requires_antoine??c.requires_antoine,d])});}
 case 'log_activity':{requireWriteApproval(args);return toolResult({data:await one('INSERT INTO venture_activity(project_id,objective_id,task_id,action,result,detail) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',[Number(args.project_id),args.objective_id?Number(args.objective_id):null,args.task_id?Number(args.task_id):null,args.action,args.result||null,args.detail||{}])});}
 case 'bootstrap_launch_system':{requireWriteApproval(args);const seeds=[
 ['GoVibe',20,'Launch first compliant, profitable paid ride.','Compliance gates cleared; authorized vehicle secured; booking/payment and passenger documents work; actual break-even known; sufficient riders booked; inaugural ride completed and reviewed.','GoVibe Launch Master Checklist',['Sign founders MOU','Form GoVibe LLC / EIN / bank / processor','Resolve transportation authorization + commercial insurance','Secure authorized vehicle','Lock chef pricing + actual trip costs','Calculate break-even','Finish booking/payment workflow','Finish passenger legal documents','Reach minimum confirmed bookings','Run inaugural ride']],
 ['Ace Website Design',10,'Sell first two $500 Founding Client websites.','Storefront/intake usable; agreement/workflow ready; portfolio proof available; two $500 Founding Client projects sold.','ACE Website Design Launch Checklist',['Build acewebsitedesign.net','Draft Antoine/Asa MOU','Draft ACE Website Design Agreement','Build HoneyBook intake/revision workflow','Create MadeThis master build prompt','Fix Talented Tenth site as showcase','Build Citadelle site','Build IBC concept redesign','Record Asa founder video','Sell first two $500 Founding Client spots']],
 ['Citadelle Law',30,'Launch compliant DUI acquisition-to-handoff system.','JVA/compliance resolved; website/landing live; direct-mail/vendor ready; answering service/CRM tested; intake/payment tested; Roosevelt handoff tested; tracking operational.','Citadelle Law Master Launch Checklist',['Finalize JVA and compliance','Confirm logo and website redesign','Select CRM/phone stack','Set up answering service','Build Antoine intake/conversion workflow','Build Roosevelt/paralegal handoff','Prepare direct-mail test','Build social funnel','Set economics/reporting','Run end-to-end mock client']],
 ['Liberation Law',15,'Sign and activate first church partnership.','First church can sign, pay, onboard and send a member; routing works; attorney work tracked; church reporting/billing works; controlled first 30 days launched.','Liberation Law Launch Checklist',['Final ethics/regulatory review','Finish liberation-law.com and test intake','Finalize/onboard partner firm','Sign Gigi operations agreement and train','Sign Gerly/Djenane affiliate agreements and train','Set up church billing/IDs/CRM/utilization','Build first 25-church target list and presentations','Sign and activate first church']]
 ];
 for(const [n,pri,goal,cc,source,path] of seeds){let p=await one('SELECT * FROM venture_projects WHERE name=$1',[n]);if(!p)p=await one('INSERT INTO venture_projects(name,launch_goal,completion_condition,source,priority,detail) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',[n,goal,cc,source,pri,{critical_path:path}]);let o=await one('SELECT * FROM venture_objectives WHERE project_id=$1 AND title=$2',[p.id,`Launch ${n}`]);if(!o)o=await one('INSERT INTO venture_objectives(project_id,title,completion_condition,priority,next_action,detail) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',[p.id,`Launch ${n}`,cc,pri,path[0],{critical_path:path}]);for(const title of path){const ex=await one('SELECT id FROM venture_tasks WHERE project_id=$1 AND title=$2',[p.id,title]);if(!ex)await pool.query('INSERT INTO venture_tasks(project_id,objective_id,title,requires_antoine,detail) VALUES($1,$2,$3,$4,$5)',[p.id,o.id,title,/sign|form|ein|bank|insurance|final ethics|record asa|sell first|partner firm/i.test(title),{source}]);}}
 return toolResult({data:await rows('SELECT id,name,status,launch_goal,source FROM venture_projects ORDER BY priority')});}
 default:throw new Error(`Unknown tool: ${name}`);
 }}
app.get('/mcp',(req,res)=>res.status(405).set('Allow','POST').end());
app.post('/mcp',async(req,res)=>{
 const auth=localBridgeKey(req)?{local:true}:await oauthAccess(req);
 if(!auth){oauthChallenge(res);return res.status(401).json(mcpError(req.body?.id,-32001,'OAuth authorization required'));}
 const msg=req.body;if(!msg||msg.jsonrpc!=='2.0'||typeof msg.method!=='string')return res.status(400).json(mcpError(msg?.id,-32600,'Invalid Request'));
 const modern=req.get('MCP-Protocol-Version')===MCP_MODERN_VERSION;
 try{
  if(msg.method==='initialize'){const requested=String(msg.params?.protocolVersion||'');const pv=[MCP_LEGACY_VERSION,'2025-06-18','2025-03-26'].includes(requested)?requested:MCP_LEGACY_VERSION;return res.json(mcpResult(msg.id,{protocolVersion:pv,capabilities:{tools:{}},serverInfo:MCP_SERVER_INFO,instructions:MCP_INSTRUCTIONS}));}
  if(msg.method==='notifications/initialized')return res.status(202).end();
  if(msg.method==='ping')return res.json(mcpResult(msg.id,{},modern));
  if(msg.method==='tools/list')return res.json(mcpResult(msg.id,{tools:MCP_TOOLS},modern));
  if(msg.method==='tools/call'){const name=msg.params?.name,args=msg.params?.arguments||{};try{const result=await callMcpTool(name,args);await audit('mcp_tool_called',{tool:name,client_id:auth.client_id||'local'});return res.json(mcpResult(msg.id,result,modern));}catch(e){return res.json(mcpResult(msg.id,{content:[{type:'text',text:`Tool error: ${e.message}`}],isError:true},modern));}}
  return res.status(404).json(mcpError(msg.id,-32601,'Method not found'));
 }catch(e){console.error(e);return res.status(500).json(mcpError(msg.id,-32603,'Internal error'));}
});

await initDb();

app.listen(Number(process.env.PORT)||3000,()=>console.log(`Talented Tenth Venture COO v1.6.1 listening on ${process.env.PORT||3000}; persistent_store=${!!pool}; writes=${process.env.ENABLE_VENTURE_WRITES==='true'}; mcp=/mcp; oauth=enabled`));
