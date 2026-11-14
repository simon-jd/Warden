// Only four new metadata-event scenarios; no old caller/JSON campaign.
const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
const caller=new AsyncFunction('tools','store','load','notify','text',candidate);
const P='controller-cache-continuation-v1-20261025-coord-metadata-r1-material-';
const oldP='controller-cache-continuation-v1-20261025-material-';
const proof='{"bytes":1234,"metadata":[1,2,1000,1000,33152,1,1234,9007199254740993123,9007199254740993123,8],"sha256":"'+'a'.repeat(64)+'"}';
const t='{"admission":'+proof+',"invoker":'+proof+',"receipt":'+proof+',"source_commit":"'+'b'.repeat(40)+'","source_manifest_sha256":"'+'c'.repeat(64)+'","clock_identity":{"machine_id":"'+'d'.repeat(32)+'","boot_id":"22222222-2222-2222-2222-222222222222"}}\n';
const marker='{"marker":'+proof+',"state":"reconcile-terminal-pending"}\n';
function need(x,message){if(!x)throw Error(message);}
function bodyOf(request){const lines=request.split('\n');need(lines[0]==='*** Begin Patch'&&lines.at(-1)==='*** End Patch','patch frame');return lines.slice(2,-1).map(v=>{need(v[0]==='+','patch line');return v.slice(1);}).join('\n')+'\n';}
const rows=observation.cases;
for(const mode of ['normal','nonzero','throw','session']){
 const memory=new Map([[P+'one-shot-admitted',true]]),calls=[],patches=[],outputs=[];let original,request;
 const row={mode,native_calls:calls,patch_events:patches,outputs,outer_state:null};rows.push(row);
 const thrownOriginal="fixture metadata rejection: exact 'quoted' value\ncontinued";
 const store=(key,value)=>{need(key===P+'one-shot','new state key');memory.set(key,value);row.outer_state=value;};
 const load=key=>{need(key.startsWith(P)&&!key.startsWith(oldP),'new load key');return memory.get(key);};
 function reply(output='',code=0){return {output,wall_time_seconds:0,exit_code:code};}
 const fake={
  exec_command:async q=>{
   need(!q.cmd.includes(oldP),'no consumed namespace');
   const phase=q.cmd.endsWith(' material-four-get')?'get':q.cmd.endsWith(' material-reconcile')?'reconcile':q.cmd.includes('python3 -I -S -B - ')?'metadata':'reader';
   const state=memory.get(P+'one-shot'),event=state.chains[phase].at(-1);
   need(event.request===q&&!Object.hasOwn(event,'response'),'request before await');calls.push(phase);
   if(phase==='get')return reply("fixture's generated get output");
   if(phase==='reader')return reply(t);
   if(phase==='reconcile')return reply(marker);
   request=q;
   need(q.yield_time_ms===10000&&q.max_output_tokens===2000&&q.workdir==='/home/postedism/Desktop/Warden'&&q.shell==='/bin/bash'&&q.login===false&&q.tty===false&&q.sandbox_permissions==='require_escalated','metadata request profile');
   const start="exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -I -S -B - ";
   need(q.cmd.startsWith(start),'isolated metadata command');
   const split=q.cmd.indexOf(" <<'PY'\n",start.length),quoted=q.cmd.slice(start.length,split);
   need(quoted[0]==="'"&&quoted.at(-1)==="'"&&quoted.includes("'\\''"),'data quoting including apostrophe');
   const input=JSON.parse(quoted.slice(1,-1).replaceAll("'\\''","'"));
   need(Object.keys(input).sort().join(',')==='collector,raw,reader'&&input.collector===t,'original collector text');
   need(input.reader===patches[0].body&&input.raw===patches[1].body&&input.raw.includes('9007199254740993123'),'same intended bytes/large integer text');
   need(patches.length===2,'finalize after both patches');
   if(mode==='throw')throw thrownOriginal;
   original=mode==='session'?{output:'',wall_time_seconds:0,session_id:17}:reply(mode==='normal'?'{"state":"material-metadata-finalized","authority":false}\n':'fixture refusal',mode==='normal'?0:1);
   return original;
  },
  write_stdin:async()=>{throw Error('no metadata poll permitted');},
  apply_patch:async q=>{
   need(q.split('\n')[1].startsWith('*** Add File: /home/postedism/Desktop/Warden/docs/evidence/task-6/'+P)&&!q.includes(oldP),'new patch path only');
   const event=memory.get(P+'one-shot').patch_events.at(-1);need(event.request===q&&!Object.hasOwn(event,'response'),'patch request retained');
   patches.push({request:q,body:bodyOf(q)});return {};
  }
 };
 await caller(fake,store,load,()=>{},value=>outputs.push(value));
 const state=memory.get(P+'one-shot'),events=state.chains.metadata;
 need(events.length===1&&events[0].tool==='exec_command'&&events[0].request===request,'one exact native metadata event');
 if(mode==='throw')need(!Object.hasOwn(events[0],'response')&&events[0].thrown===thrownOriginal,'original rejection retained; no manufactured response');
 else need(events[0].response===original,'actual metadata return identity');
 if(mode==='normal')need(calls.join(',')==='get,reader,metadata,reconcile'&&state.state==='normal-chain-recorded'&&patches.length===3,'normal ordering');
 else{
  need(calls.join(',')==='get,reader,metadata'&&state.chains.reconcile===null&&state.state==='stopped-unknown'&&patches.length===3,'unknown stops before reconcile/one failure save');
  const saved=JSON.parse(patches[2].body);need(saved.authority===false&&saved.chains.metadata.length===1&&saved.chains.metadata[0].tool==='exec_command','metadata chain in failure envelope');
  if(mode==='throw')need(!Object.hasOwn(saved.chains.metadata[0],'response')&&saved.chains.metadata[0].thrown===thrownOriginal,'pending/rejection disk retention');
  else need(JSON.stringify(saved.chains.metadata[0].response)===JSON.stringify(original),'actual event disk retention');
  if(mode==='session')need(saved.chains.metadata[0].response.session_id===17,'owned session retained, no terminal inferred');
 }
 need(outputs.length===1&&outputs[0].authority===false&&outputs[0].Q_released===false,'nonauthority only');
 Object.assign(row,{passed:true,metadata_events:events.length,metadata_request:request,...(mode==='throw'?{metadata_thrown:events[0].thrown}:{metadata_response:original}),metadata_response_present:mode!=='throw',patches:patches.length,state:state.state});
}
return {cases:rows,tests_run:4,failures:0,errors:0,actual_nested_tools:0,actual_interlocks:false,limits:'four finite fake scenarios only; native resource/deadline limits do not measure this JS isolate'};
