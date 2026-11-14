// Pure generated values only; every caller capability is an explicit local fake.
const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
const caller=new AsyncFunction('tools','store','load','notify','text',candidate);
const K='controller-cache-continuation-v1-20261025-approval-writer';
const big='9007199254740993123';
const proof='{"bytes":1234,"metadata":[1,2,1000,1000,33152,1,1234,'+big+','+big+',8],"sha256":"'+'a'.repeat(64)+'"}';
const data={source_commit:'b'.repeat(40),program_sha256:'c'.repeat(64),summary_proof_json:proof};
const good='{"approval":'+proof+'}\n';
function assert(ok,message){if(!ok)throw Error(message);}
function bytes(s){let n=0;for(const c of s){const x=c.codePointAt(0);n+=x<128?1:x<2048?2:x<65536?3:4;}return n;}
function clone(x,memo=new Map()){
 if(x===null||typeof x!=='object')return x;if(memo.has(x))return memo.get(x);
 const y=Array.isArray(x)?[]:Object.create(Object.getPrototypeOf(x));
 Object.setPrototypeOf(y,Object.getPrototypeOf(x));memo.set(x,y);
 for(const k of Reflect.ownKeys(x)){
  const d=Object.getOwnPropertyDescriptor(x,k);if(Object.hasOwn(d,'value'))d.value=clone(d.value,memo);Object.defineProperty(y,k,d);
 }return y;
}
function bodyOf(s){
 const lines=s.split('\n');assert(lines[0]==='*** Begin Patch'&&lines[1]==='*** Add File: /home/postedism/Desktop/Warden/docs/evidence/task-6/controller-approval-writer-audit-20261025.json'&&lines.at(-1)==='*** End Patch','fixed patch framing');
 return lines.slice(2,-1).map(v=>{assert(v[0]==='+','patch line');return v.slice(1);}).join('\n')+'\n';
}
const abnormal=['negative-wall','negative-exit','negative-nested','array-accessor','array-hook','array-hole','array-extra','object-accessor','object-hook','undefined','bigint','nonfinite','cycle'];
const names=mode==='red'?['negative-wall','array-accessor','array-hook']:[
 'immediate','session','absent','initial-throw','poll-throw','nonzero','changed-session','invalid-session','terminal-session','truncation','unknown-json','bad-type','extra-output','32-running','large-proof',
 ...abnormal,'audit-65536','audit-65537','patch-null','patch-array','patch-nonempty','patch-foreign','patch-throw'];
const results=[];let nativeTotal=0,patchTotal=0;
for(const name of names){
 const memory=new Map(),snapshots=[],native=[],patches=[],outputs=[];
 memory.set(K+'-data',data);if(name!=='absent')memory.set(K+'-admitted',true);
 let hits=0,original,patchOriginal;
 function store(key,value){assert(key===K+'-attempt','local state only');memory.set(key,value);snapshots.push(clone(value));}
 function load(key){assert([K+'-attempt',K+'-admitted',K+'-data'].includes(key),'local key only');return memory.get(key);}
 function reply(output=good){return {output,wall_time_seconds:0,exit_code:0};}
 function malformed(){
  let r=reply();
  if(name==='negative-wall')r.wall_time_seconds=-0;
  if(name==='negative-exit')r.exit_code=-0;
  if(name==='negative-nested')r.extra={n:-0};
  if(name==='array-accessor'){r=[];Object.defineProperty(r,'0',{get(){hits++;return hits;},enumerable:true});}
  if(name==='array-hook'){r=['actual-invalid'];const p=Object.create(Array.prototype);Object.defineProperty(p,'toJSON',{value(){hits++;return {replaced:true};}});Object.setPrototypeOf(r,p);}
  if(name==='array-hole')r=new Array(1);
  if(name==='array-extra'){r=['actual'];r.extra='retained';}
  if(name==='object-accessor')Object.defineProperty(r,'output',{get(){hits++;return good;},enumerable:true});
  if(name==='object-hook')r.toJSON=function(){hits++;return {replaced:true};};
  if(name==='undefined')r=undefined;
  if(name==='bigint')r.extra=1n;
  if(name==='nonfinite')r.extra=Infinity;
  if(name==='cycle')r.extra=r;
  return r;
 }
 const fakeTools={
  exec_command:async request=>{
   const pending=memory.get(K+'-attempt').events.at(-1);
   assert(pending.request===request&&!Object.hasOwn(pending,'response'),'request before await');
   assert(request.workdir==='/home/postedism/Desktop/Warden'&&request.shell==='/bin/bash'&&request.login===false&&request.tty===false&&request.yield_time_ms===1000&&request.max_output_tokens===2000&&request.sandbox_permissions==='require_escalated'&&!Object.hasOwn(request,'prefix_rule'),'fixed request profile');
   assert(request.cmd.startsWith('exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 '+(mode==='red'?'-B':'-I -S -B')+" - '"+proof+"' <<'PY'\n"),'exact flags/data');
   native.push({tool:'exec_command',request});
   if(name==='initial-throw')throw Error('fixture throw');
   if(['session','poll-throw','changed-session','32-running'].includes(name))return original={output:'',wall_time_seconds:0,session_id:17};
   if(abnormal.includes(name))return original=malformed();
   let r=reply();
   if(name==='nonzero')r.exit_code=1;
   if(name==='invalid-session'){delete r.exit_code;r.session_id=0;}
   if(name==='terminal-session')r.session_id=17;
   if(name==='truncation')r.original_token_count=2001;
   if(name==='unknown-json')r.extra={retained:'é"\\\n'};
   if(name==='bad-type')r.output=17;
   if(name==='extra-output')r.output=good+'extra\n';
   if(name.startsWith('audit-')){
    r.extra='é"\\\n';const target=Number(name.slice(6));
    const audit={version:1,kind:'approval-writer-audit',authority:false,source_commit:data.source_commit,program_sha256:data.program_sha256,summary_proof_json:proof,approval_proof_json:null,state:'unknown-retain-no-pins',events:[{seq:0,tool:'exec_command',request,response:r}],Q_released:false};
    const pad=target-bytes(JSON.stringify(audit)+'\n');assert(pad>0,'positive boundary pad');r.extra+='x'.repeat(pad);
   }
   return original=r;
  },
  write_stdin:async request=>{
   const pending=memory.get(K+'-attempt').events.at(-1);
   assert(pending.request===request&&!Object.hasOwn(pending,'response'),'poll before await');
   assert(request.session_id===17&&request.chars===''&&request.yield_time_ms===45000&&request.max_output_tokens===2000,'fixed empty poll');native.push({tool:'write_stdin',request});
   if(name==='poll-throw')throw Error('fixture poll throw');
   if(name==='changed-session')return {output:'',wall_time_seconds:0,session_id:18};
   if(name==='32-running')return {output:'',wall_time_seconds:0,session_id:17};
   return reply();
  },
  apply_patch:async request=>{
   const pending=memory.get(K+'-attempt').audit_event;
   assert(pending.request===request&&!Object.hasOwn(pending,'response')&&patches.length===0,'one consumed patch before await');
   const body=bodyOf(request);patches.push({request,body});
   if(name==='patch-throw')throw Error('fixture patch throw');
   return patchOriginal=name==='patch-null'?null:name==='patch-array'?[]:name==='patch-nonempty'?{x:1}:name==='patch-foreign'?Object.create(null):{};
  }
 };
 let thrown=false;try{await caller(fakeTools,store,load,()=>{throw Error('unexpected notify');},v=>outputs.push(clone(v)));}catch(e){thrown=true;}
 const state=memory.get(K+'-attempt');
 if(name==='absent')assert(thrown&&!state&&native.length===0&&patches.length===0,'closed interlock');
 else{
  assert(!thrown&&state&&outputs.length===1&&outputs[0].authority===false&&outputs[0].Q_released===false,'nonauthority result');
  assert(native.length<=32&&patches.length<=1,'bounded calls');
  if(!name.includes('throw')||name==='patch-throw')assert(state.events[0].response===original,'original identity retained');
  for(const events of [state.events,state.audit_event?[state.audit_event]:[]])assert(events.every((e,i)=>Object.hasOwn(e,'response')||i===events.length-1),'pending last only');
  if(name==='initial-throw'||name==='poll-throw')assert(!Object.hasOwn(state.events.at(-1),'response'),'no fabricated response');
  if(name==='32-running')assert(native.length===32&&state.approval_proof_json===null,'no33rd call/approval');
  if(mode==='red'){
   assert(patches.length===1,'old serializes witness');const saved=JSON.parse(patches[0].body).events[0].response;
   if(name==='negative-wall')assert(Object.is(original.wall_time_seconds,-0)&&!Object.is(saved.wall_time_seconds,-0),'genuine negative-zero RED');
   if(name==='array-accessor')assert(hits>=2&&saved[0]===hits,'genuine accessor RED');
   if(name==='array-hook')assert(hits===1&&saved.replaced===true,'genuine inherited-hook RED');
  }else if(abnormal.includes(name)){
   assert(patches.length===0&&hits===0&&state.state==='unknown-outer-retention-only-no-pins'&&state.approval_proof_json===null,'unsupported outer-only, no hook/getter');
   const s=snapshots.at(-1).events[0].response;
   if(original&&typeof original==='object')assert(Object.getPrototypeOf(s)===Object.getPrototypeOf(original),'snapshot prototype');
   if(name==='negative-wall')assert(Object.is(s.wall_time_seconds,-0),'snapshot -0');
   if(name==='array-accessor')assert(Object.getOwnPropertyDescriptor(s,'0').get===Object.getOwnPropertyDescriptor(original,'0').get,'snapshot getter');
   if(name==='cycle')assert(s.extra===s,'snapshot cycle');
  }else if(name==='audit-65537')assert(patches.length===0&&state.state==='unknown-outer-retention-only-no-pins','over boundary outer-only');
  else{
   assert(patches.length===1,'one audit');const saved=JSON.parse(patches[0].body);
   assert(Object.keys(saved).sort().join(',')==='Q_released,approval_proof_json,authority,events,kind,program_sha256,source_commit,state,summary_proof_json,version','unchanged audit keys');
   assert(saved.summary_proof_json===proof&&patches[0].body.includes(big),'lossless large proof');
   if(name==='audit-65536')assert(bytes(patches[0].body)===65536,'exact allowed boundary');
   if(name==='unknown-json')assert(saved.events[0].response.extra.retained===original.extra.retained,'JSON unknown field retained');
   const normal=['immediate','session','large-proof'].includes(name);
   if(normal)assert(state.state==='normal0-audit-recorded'&&state.approval_proof_json===proof,'normal exact chain');
   else if(name.startsWith('patch-')){
    assert(state.state==='unknown-outer-retention-only-no-pins','patch failure no followup');
    if(name==='patch-throw')assert(!Object.hasOwn(state.audit_event,'response'),'patch pending');
    else assert(state.audit_event.response===patchOriginal,'actual patch return retained');
   }else assert(state.approval_proof_json===null&&state.state==='unknown-audit-recorded-no-pins','invalid response never approves');
  }
 }
 nativeTotal+=native.length;patchTotal+=patches.length;
 results.push({name,native_calls:native.length,patch_calls:patches.length,hook_calls:hits,state:state?state.state:'closed',audit_bytes:patches.length?bytes(patches[0].body):null,passed:mode!=='red',expected_regression_observed:mode==='red'});
}
return {tests_run:results.length,failures:mode==='red'?results.length:0,errors:0,skipped:0,cases:results,total_fake_native_calls:nativeTotal,total_fake_patch_calls:patchTotal,actual_nested_tools:0,actual_interlocks:false,limits:'finite pure JS only; native CPU/AS/45s not measured'};
