'use strict';
// Timeline Aktivitas Karyawan - server tanpa dependensi (Node 18+)
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=+process.env.PORT||3000,DIR=process.env.DATA_DIR||path.join(__dirname,'data'),FILE=path.join(DIR,'db.json'),SECURE=process.env.COOKIE_SECURE==='1';
fs.mkdirSync(DIR,{recursive:true});
let db={users:[],sessions:{},activities:[],ver:0};
try{db=Object.assign(db,JSON.parse(fs.readFileSync(FILE,'utf8')))}catch(e){}
let tmr=null;function snap(){const d=path.join(DIR,'backup-'+new Date().toISOString().slice(0,10)+'.json');if(!fs.existsSync(d)&&fs.existsSync(FILE)){try{fs.copyFileSync(FILE,d);fs.readdirSync(DIR).filter(f=>f.startsWith('backup-')).sort().slice(0,-14).forEach(f=>fs.unlinkSync(path.join(DIR,f)))}catch(e){}}}
function persist(){snap();clearTimeout(tmr);tmr=setTimeout(()=>{const t=FILE+'.tmp';fs.writeFileSync(t,JSON.stringify(db));fs.renameSync(t,FILE)},150)}
const OPEN=process.env.REQUIRE_LOGIN!=='1',RANK={viewer:0,member:1,admin:2,superadmin:3},sse=new Set(),tries=new Map();
const hp=(p,s)=>crypto.scryptSync(p,s,64).toString('hex');
const chk=(p,u)=>{const a=Buffer.from(hp(p,u.salt)),b=Buffer.from(u.hash);return a.length===b.length&&crypto.timingSafeEqual(a,b)};
function bump(){db.ver++;persist();for(const r of sse)r.write('data: '+db.ver+'\n\n')}
function send(res,code,obj,h){res.writeHead(code,Object.assign({'Content-Type':'application/json','Cache-Control':'no-store'},h||{}));res.end(JSON.stringify(obj))}
function body(req){return new Promise((ok,no)=>{let d='';req.on('data',c=>{d+=c;if(d.length>1e6){no(new Error('Terlalu besar'));req.destroy()}});req.on('end',()=>{try{ok(d?JSON.parse(d):{})}catch(e){no(new Error('JSON tidak valid'))}})})}
function authed(req){if(OPEN){let n='Tamu';try{n=decodeURIComponent(req.headers['x-nama']||'').trim().slice(0,40)||'Tamu'}catch(e){}return{id:'open',name:n,role:'admin'}}
 const m=/(?:^|; )sid=([a-f0-9]+)/.exec(req.headers.cookie||'');const s=m&&db.sessions[m[1]];if(!s||s.exp<Date.now())return null;return db.users.find(u=>u.id===s.uid)||null}
function sid(res,uid){const t=crypto.randomBytes(32).toString('hex');db.sessions[t]={uid,exp:Date.now()+30*864e5};persist();return{'Set-Cookie':`sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30*86400}${SECURE?'; Secure':''}`}}
const pub=u=>({id:u.id,name:u.name,email:u.email,role:u.role});
const str=(v,n)=>String(v==null?'':v).slice(0,n);
function cleanRec(r){r=r||{};return r.done?{done:true,actual:+r.actual||0,sat:Math.max(0,Math.min(5,+r.sat||0)),result:str(r.result,2000)}:{done:false}}
function cleanAct(a,u){if(!a||typeof a.id!=='string'||!a.name)throw new Error('Data agenda tidak valid');const rec={};for(const k of Object.keys(a.rec||{}).slice(0,400)){const old=a.rec[k]||{};rec[k]=cleanRec(old);if(rec[k].done){rec[k].by=str(old.by,60)||u.name}}
 return{id:str(a.id,40).replace(/[^\w-]/g,''),name:str(a.name,80),cat:str(a.cat,40),pic:str(a.pic,40),type:['event','weekly','monthly','quarterly','annually'].includes(a.type)?a.type:'event',start:str(a.start,10),end:str(a.end,10),budget:+a.budget||0,impact:str(a.impact,500),rec}}
const need=(u,r)=>{if(!u)throw Object.assign(new Error('Silakan login'),{c:401});if(RANK[u.role]<RANK[r])throw Object.assign(new Error('Tidak punya izin untuk aksi ini'),{c:403})};
const MIME={'.html':'text/html; charset=utf-8'};
http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://x'),p=url.pathname,m=req.method;
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');
 res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:");
 if(m==='GET'&&(p==='/'||p==='/index.html')){res.writeHead(200,{'Content-Type':MIME['.html']});return res.end(fs.readFileSync(path.join(__dirname,'public','index.html')))}
 if(!p.startsWith('/api/')){res.writeHead(404);return res.end('Not found')}
 try{
  const u=authed(req);
  if(m!=='GET'&&!/application\/json/.test(req.headers['content-type']||''))throw Object.assign(new Error('Content-Type harus JSON'),{c:415});
  if(p==='/api/me')return send(res,200,{user:u?pub(u):null,setup:db.users.length===0,open:OPEN});
  if(p==='/api/register'&&m==='POST'){const b=await body(req),email=str(b.email,120).trim().toLowerCase(),name=str(b.name,60).trim();
   if(!name)throw new Error('Nama wajib diisi');if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))throw new Error('Format email tidak valid');if(str(b.password,200).length<8)throw new Error('Password minimal 8 karakter');
   if(db.users.some(x=>x.email===email))throw new Error('Email sudah terdaftar');
   const salt=crypto.randomBytes(16).toString('hex'),nu={id:crypto.randomBytes(8).toString('hex'),name,email,salt,hash:hp(b.password,salt),role:db.users.length?'viewer':'superadmin',created:Date.now()};
   db.users.push(nu);return send(res,200,{user:pub(nu)},sid(res,nu.id))}
  if(p==='/api/login'&&m==='POST'){const b=await body(req),email=str(b.email,120).trim().toLowerCase(),key=req.socket.remoteAddress+email,t=tries.get(key)||{n:0,r:0};
   if(t.n>=8&&Date.now()<t.r)throw Object.assign(new Error('Terlalu banyak percobaan, coba lagi 10 menit lagi'),{c:429});
   const x=db.users.find(y=>y.email===email);if(!x||!chk(str(b.password,200),x)){tries.set(key,{n:t.n+1,r:Date.now()+6e5});throw Object.assign(new Error('Email atau password salah'),{c:401})}
   tries.delete(key);return send(res,200,{user:pub(x)},sid(res,x.id))}
  if(p==='/api/logout'&&m==='POST'){const c=/sid=([a-f0-9]+)/.exec(req.headers.cookie||'');if(c)delete db.sessions[c[1]];persist();return send(res,200,{ok:1},{'Set-Cookie':'sid=; Path=/; Max-Age=0'})}
  need(u,'viewer');
  if(p==='/api/events'){res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-store',Connection:'keep-alive'});res.write('retry: 2000\n\n');sse.add(res);const ka=setInterval(()=>res.write(': ka\n\n'),25000);return req.on('close',()=>{sse.delete(res);clearInterval(ka)})}
  if(p==='/api/state'&&m==='GET')return send(res,200,{activities:db.activities,ver:db.ver});
  if(p==='/api/activity'&&m==='PUT'){need(u,'admin');const a=cleanAct(await body(req),u),i=db.activities.findIndex(x=>x.id===a.id);if(i>-1)db.activities[i]=a;else db.activities.push(a);bump();return send(res,200,{ok:1})}
  if(p.startsWith('/api/activity/')&&m==='DELETE'){need(u,'admin');const id=p.split('/').pop();db.activities=db.activities.filter(x=>x.id!==id);bump();return send(res,200,{ok:1})}
  if(p==='/api/rec'&&m==='POST'){need(u,'member');const b=await body(req),a=db.activities.find(x=>x.id===b.id),k=Math.floor(+b.k);if(!a||!(k>=0&&k<400))throw new Error('Agenda tidak ditemukan');const r=cleanRec(b.rec);if(r.done)r.by=u.name;a.rec[k]=r;bump();return send(res,200,{ok:1})}
  if(p==='/api/bulk'&&m==='PUT'){need(u,'admin');const b=await body(req);if(!Array.isArray(b.activities)||b.activities.length>500)throw new Error('Data tidak valid');db.activities=b.activities.map(a=>cleanAct(a,u));bump();return send(res,200,{ok:1})}
  if(p==='/api/users'&&m==='GET'){need(u,'superadmin');return send(res,200,{users:db.users.map(pub)})}
  if(p==='/api/users'&&m==='PATCH'){need(u,'superadmin');const b=await body(req),x=db.users.find(y=>y.id===b.id);if(!x||x.id===u.id||!(b.role in RANK)||b.role==='superadmin')throw new Error('Perubahan tidak diizinkan');x.role=b.role;persist();return send(res,200,{ok:1})}
  if(p.startsWith('/api/users/')&&m==='DELETE'){need(u,'superadmin');const id=p.split('/').pop();if(id===u.id)throw new Error('Tidak bisa menghapus akun sendiri');db.users=db.users.filter(x=>x.id!==id);for(const t of Object.keys(db.sessions))if(db.sessions[t].uid===id)delete db.sessions[t];persist();return send(res,200,{ok:1})}
  send(res,404,{error:'Tidak ditemukan'})
 }catch(e){send(res,e.c||400,{error:e.message})}
}).listen(PORT,()=>console.log('Berjalan di http://localhost:'+PORT));
