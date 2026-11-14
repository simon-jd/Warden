// Exactly four local-fake new metadata events; no original JSON/caller campaign.
const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
const factory=new AsyncFunction('tools','store','load','notify','text',common+'\nreturn {finalizeMetadata,operation,first};');
const K='controller-cache-continuation-v1-20261025-capture-preprobe-';
const proof='{"bytes":1234,"metadata":[1,2,1000,1000,33152,1,1234,9007199254740993123,9007199254740993123,8],"sha256":"'+'a'.repeat(64)+'"}';
const collector='{"admission":'+proof+',"invoker":'+proof+',"envelope":'+proof+',"claim":'+proof+',"supervisor":'+proof+',"source_commit":"'+'b'.repeat(40)+'","source_manifest_sha256":"'+'c'.repeat(64)+'","clock_identity":{"machine_id":"'+'d'.repeat(32)+'","boot_id":"22222222-2222-2222-2222-222222222222"}}\n';
const raw='{"fixture":"same stored raw apostrophe \' text","envelope":'+proof+'}\n';
function need(value,message){if(!value)throw Error(message);}
function reply(output='',code=0){return {output,wall_time_seconds:0,exit_code:code};}
for(const mode of ['normal','nonzero','throw','session']){
 const memory=new Map([[K+'reader',{state:'terminal',events:[{response:reply(collector)}]}],[K+'raw-body',raw],[K+'patch-root-tool.json',{}]]);
 const row={mode,calls:[],outputs:[],stored:{}};observation.cases.push(row);
 const thrownOriginal="fixture-only native rejection 'quoted'\nsecond line";let actual,request;
 const load=key=>{need(key.startsWith(K),'fixed mode store key');return memory.get(key);};
 const store=(key,value)=>{need(key===K+'metadata'||key===K+'reconcile','only affected keys');memory.set(key,value);row.stored[key]=value;};
 const fake={
  exec_command:async q=>{
   const phase=q.cmd.includes('python3 -I -S -B - ')?'metadata':'reconcile';row.calls.push(phase);
   if(phase==='reconcile'){
    need(q.cmd==='exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B scripts/identity_cache_control.py reconcile capture-preprobe','unchanged reconcile command');return reply('fixture-only reconcile');
   }
   request=q;const state=memory.get(K+'metadata'),event=state.events[0];
   need(state.request===q&&event.request===q&&event.tool==='exec_command'&&state.state==='awaiting'&&!Object.hasOwn(event,'response'),'original pending request before await');
   need(q.yield_time_ms===10000&&q.max_output_tokens===2000&&q.workdir==='/home/postedism/Desktop/Warden'&&q.shell==='/bin/bash'&&q.login===false&&q.tty===false&&q.sandbox_permissions==='require_escalated','fixed metadata request profile');
   const start='exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -I -S -B - ';
   need(q.cmd.startsWith(start),'isolated fixed native command');const split=q.cmd.indexOf(" <<'PY'\n",start.length),quoted=q.cmd.slice(start.length,split);
   need(quoted[0]==="'"&&quoted.at(-1)==="'"&&quoted.includes("'\\''"),'safe apostrophe quoting');
   const data=JSON.parse(quoted.slice(1,-1).replaceAll("'\\''","'"));
   need(Object.keys(data).sort().join(',')==='collector,raw'&&data.collector===collector&&data.raw===raw&&data.collector.includes('9007199254740993123'),'original exact strings/large integer fidelity');
   need(q.cmd.includes("M='capture-preprobe'")&&!q.cmd.includes('${MODE}'),'frozen helper mode');
   if(mode==='throw')throw thrownOriginal;
   actual=mode==='session'?{output:'',wall_time_seconds:0,session_id:17}:reply(mode==='normal'?'{"state":"six-mode-metadata-finalized","authority":false}\n':'fixture refusal',mode==='normal'?0:1);
   return actual;
  },
  write_stdin:async()=>{throw Error('no metadata poll');},
  apply_patch:async()=>{throw Error('metadata creates no record');}
 };
 const api=await factory(fake,store,load,()=>{throw Error('unexpected notify');},value=>row.outputs.push(value));
 let refused=false;
 try{await api.finalizeMetadata();}
 catch(error){refused=true;if(mode==='throw')need(error===thrownOriginal,'caller rethrows exact native original');}
 const state=memory.get(K+'metadata'),event=state.events[0];
 need(state.events.length===1&&event.request===request,'one original metadata request');
 if(mode==='throw')need(!Object.hasOwn(event,'response')&&event.thrown===thrownOriginal,'original thrown/pending retained');
 else need(event.response===actual,'exact original response identity');
 if(mode==='normal'){
  need(!refused&&state.state==='terminal','known normal metadata terminal');
  await api.first('reconcile',api.operation('reconcile'));
  need(row.calls.join(',')==='metadata,reconcile'&&row.outputs.length===1&&row.outputs[0].authority===false&&row.outputs[0].Q_released===false,'ordered nonauthority normal chain');
 }else{
  need(refused&&state.state==='unknown','unknown retained');let blocked=false;
  try{api.operation('reconcile');}catch(error){blocked=true;}
  need(blocked&&row.calls.join(',')==='metadata'&&!memory.has(K+'reconcile')&&row.outputs.length===0,'no reconcile/poll/authority on unknown');
  if(mode==='session')need(event.response.session_id===17,'owned session retained without terminal inference');
 }
 row.passed=true;row.metadata_state=state.state;row.metadata_response_present=Object.hasOwn(event,'response');
}
return {tests_run:4,failures:0,errors:0,actual_nested_tools:0,actual_interlocks:false,limits:'four finite fake cases; native caps do not contain or measure this JS isolate'};
