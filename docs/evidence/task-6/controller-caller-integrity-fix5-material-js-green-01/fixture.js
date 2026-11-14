// Isolated finite simulation. The caller's tools/store/load/notify/text are all
// parameters bound below; no real tool, filesystem, network, clock or interlock.
const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
const caller=new AsyncFunction('tools','store','load','notify','text',candidate);
const P='controller-cache-continuation-v1-20261025-material-';
const big='9007199254740993123';
const proof='{"bytes":1234,"metadata":[1,2,1000,1000,33152,1,1234,'+big+','+big+',8],"sha256":"'+'a'.repeat(64)+'"}';
const collected='{"admission":'+proof+',"invoker":'+proof+',"receipt":'+proof+
  ',"source_commit":"'+'b'.repeat(40)+'","source_manifest_sha256":"'+'c'.repeat(64)+
  '","clock_identity":{"machine_id":"'+'d'.repeat(32)+'","boot_id":"22222222-2222-2222-2222-222222222222"}}\n';
const marker='{"marker":'+proof+',"state":"reconcile-terminal-pending"}\n';
function assert(value,why){if(!value)throw Error(why);}
function clone(x,memo=new Map()){
 if(x===null||typeof x!=='object')return x;
 if(memo.has(x))return memo.get(x);
 const y=Array.isArray(x)?[]:Object.create(Object.getPrototypeOf(x));
 Object.setPrototypeOf(y,Object.getPrototypeOf(x));memo.set(x,y);
 for(const k of Reflect.ownKeys(x)){
  const d=Object.getOwnPropertyDescriptor(x,k);
  if(Object.hasOwn(d,'value'))d.value=clone(d.value,memo);
  Object.defineProperty(y,k,d);
 }
 return y;
}
function bodyOf(request){
  const lines=request.split('\n');
  assert(lines[0]==='*** Begin Patch'&&lines[1].startsWith('*** Add File: '),'patch framing');
  return lines.slice(2,-1).map(line=>{assert(line.startsWith('+'),'patch body');return line.slice(1);}).join('\n')+'\n';
}
const cases=[
  {name:'inherited-hook',malformed:'hook'},
  ...(mode==='red'?[]:[{name:'negative-zero',malformed:'negative-zero'},
  {name:'index-accessor',malformed:'accessor'},{name:'object-hook',malformed:'object-hook'},
  {name:'normal-immediate'}, {name:'normal-session',session:true},
  {name:'interlock-absent',admitted:false},
  {name:'initial-rejected',reject:'get'}, {name:'poll-rejected',session:true,reject:'poll'},
  {name:'reader-rejected',reject:'reader'}, {name:'reconcile-rejected',reject:'reconcile'},
  {name:'first-patch-rejected',patchReject:1}, {name:'last-normal-patch-rejected',patchReject:3},
  {name:'failed-save-not-retried',patchReject:1,rejectSave:true},
  {name:'patch-nonempty',patchShape:'nonempty'}, {name:'patch-null',patchShape:'null'},
  {name:'patch-foreign-prototype',patchShape:'foreign'},
  {name:'missing-actual-return',missing:true}, {name:'normal-nonzero',nonzero:true},
  {name:'complete-oversize-to-diagnostic',oversize:true},
  {name:'noncanonical-marker-refused',badMarker:true},
  {name:'array-properties-retained-externally',arrayExtra:true}])
];
const results=[];
let totalNative=0,totalPatches=0;
for(const scenario of cases){
  let hits=0,original;
  const memory=new Map(),snapshots=[],native=[],patches=[],notices=[],outputs=[];
  if(scenario.admitted!==false)memory.set(P+'one-shot-admitted',true);
  function fakeStore(key,value){assert(key===P+'one-shot','only local one-shot state');memory.set(key,value);snapshots.push(clone(value));}
  function fakeLoad(key){assert(key===P+'one-shot'||key===P+'one-shot-admitted','local store keys');return memory.get(key);}
  function reply(output='',exit=0){return {output,wall_time_seconds:0,exit_code:exit,chunk_id:'generated',original_token_count:0};}
  const fakeTools={
    exec_command:async request=>{
      const phase=request.cmd.endsWith(' material-four-get')?'get':request.cmd.endsWith(' material-reconcile')?'reconcile':'reader';
      assert(request.workdir==='/home/postedism/Desktop/Warden'&&request.sandbox_permissions==='require_escalated'&&
        request.login===false&&request.tty===false&&request.shell==='/bin/bash'&&request.yield_time_ms===1000&&
        request.max_output_tokens===(phase==='reader'?4000:2000)&&!('prefix_rule'in request),'fixed native request');
      assert(request.cmd.startsWith('exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -B '),'fixed command');
      const pending=memory.get(P+'one-shot').chains[phase].at(-1);
      assert(pending.tool==='exec_command'&&!Object.hasOwn(pending,'response'),'request saved before initial await');
      native.push({phase,request:clone(request)});
      if(scenario.reject===phase)throw Error('generated rejected promise');
      if(phase==='get'){
        if(scenario.malformed){
          if(scenario.malformed==='negative-zero')original=reply('',-0);
          if(scenario.malformed==='hook'){
            original=['actual-invalid-response'];const p=Object.create(Array.prototype);
            Object.defineProperty(p,'toJSON',{value(){hits++;return {exit_code:0};}});Object.setPrototypeOf(original,p);
          }
          if(scenario.malformed==='accessor'){
            original=[];Object.defineProperty(original,'0',{get(){hits++;return hits;},enumerable:true});
          }
          if(scenario.malformed==='object-hook')original={toJSON(){hits++;return {exit_code:0};}};
          return original;
        }
        if(scenario.missing)return undefined;
        if(scenario.arrayExtra){const value=['invalid'];value.extra='must-not-disappear';return value;}
        if(scenario.oversize)return reply('x'.repeat(65537));
        if(scenario.session)return {output:'',wall_time_seconds:0,session_id:17};
        return reply('',scenario.nonzero?1:0);
      }
      if(phase==='reader')return reply(collected);
      return reply(scenario.badMarker?marker.replace(',1000,1000,',',01000,1000,'):marker);
    },
    write_stdin:async request=>{
      assert(request.session_id===17&&request.chars===''&&request.yield_time_ms===45000&&request.max_output_tokens===2000,'fixed empty poll');
      const pending=memory.get(P+'one-shot').chains.get.at(-1);
      assert(pending.tool==='write_stdin'&&!Object.hasOwn(pending,'response'),'poll saved before await');
      native.push({phase:'poll',request:clone(request)});
      if(scenario.reject==='poll')throw Error('generated rejected poll');
      return reply();
    },
    apply_patch:async request=>{
      const state=memory.get(P+'one-shot'),pending=state.patch_events.at(-1);
      assert(pending.request===request&&!Object.hasOwn(pending,'response'),'patch saved before await');
      const destination=request.split('\n')[1];
      assert(!patches.some(p=>p.destination===destination),'consumed destination never reused');
      const body=bodyOf(request);
      patches.push({destination,body});
      assert(patches.length<=4,'four patch bound');
      if(patches.length===scenario.patchReject||scenario.rejectSave&&patches.length===2)
        throw Error('generated rejected patch');
      if(patches.length===1){
        if(scenario.patchShape==='nonempty')return {unexpected:'full actual value'};
        if(scenario.patchShape==='null')return null;
        if(scenario.patchShape==='foreign')return Object.create(null);
      }
      return {};
    }
  };
  let thrown=false;
  try{await caller(fakeTools,fakeStore,fakeLoad,value=>notices.push(clone(value)),value=>outputs.push(clone(value)));}
  catch(error){thrown=true;}
  const state=memory.get(P+'one-shot');
  if(scenario.admitted===false){
    assert(thrown&&state===undefined&&native.length===0&&patches.length===0,'unadmitted caller must do nothing');
  }else{
    assert(!thrown&&state&&outputs.length===1&&outputs[0].authority===false&&outputs[0].Q_released===false,'only nonauthority result');
    assert(native.length<=4&&patches.length<=4,'finite fake calls');
    const normal=scenario.name.startsWith('normal-')&&!scenario.nonzero;
    if(normal){
      assert(state.state==='normal-chain-recorded'&&patches.length===3,'normal three patches');
      assert(native.filter(n=>n.phase==='get').length===1&&native.filter(n=>n.phase==='reader').length===1&&
        native.filter(n=>n.phase==='reconcile').length===1,'exact native sequence no successor');
      assert(patches[1].body.includes(big)&&patches[1].body.includes('"receipt":'+proof),'lossless large metadata');
      assert(JSON.parse(patches[2].body).marker_proof_json===proof,'lossless marker proof string');
      assert(state.patch_events.every(e=>Object.hasOwn(e,'response')&&Reflect.ownKeys(e.response).length===0),'actual empty patch profile');
    }else{
      assert(state.state.startsWith('stopped-unknown'),'failure never normal');
      if(scenario.reject){
        const phase=scenario.reject==='poll'?'get':scenario.reject;
        const es=state.chains[phase];
        assert(es.length>0&&!Object.hasOwn(es.at(-1),'response'),'rejected request remains pending without synthetic response');
      }
      if(scenario.patchReject){
        assert(!Object.hasOwn(state.patch_events[scenario.patchReject-1],'response'),'rejected patch remains pending');
        const expected=scenario.patchReject+1;
        assert(patches.length===expected,'exactly one failure save after normal patch rejection');
        if(scenario.rejectSave)assert(state.state==='stopped-unknown-outer-retention-only','no second fallback');
      }
      if(scenario.patchShape==='nonempty')assert(state.patch_events[0].response.unexpected==='full actual value','nonempty return preserved');
      if(scenario.patchShape==='null')assert(state.patch_events[0].response===null,'null return preserved');
      if(scenario.patchShape==='foreign')assert(patches.length===1&&state.state==='stopped-unknown-outer-retention-only','foreign prototype never repaired');
      if(scenario.missing)assert(state.state==='stopped-unknown-outer-retention-only'&&native.length===1,'undefined return cannot form normal chain');
      if(scenario.malformed){
        assert(state.chains.get[0].response===original,'original external identity');
        const snapshot=snapshots.at(-1).chains.get[0].response;
        assert(Object.getPrototypeOf(snapshot)===Object.getPrototypeOf(original),'prototype retained');
        if(scenario.malformed==='negative-zero')assert(Object.is(snapshot.exit_code,-0),'negative zero retained');
        if(scenario.malformed==='accessor')assert(Object.getOwnPropertyDescriptor(snapshot,'0').get===Object.getOwnPropertyDescriptor(original,'0').get,'getter retained');
        if(mode==='red'){
          assert(hits>0&&patches.length===1&&JSON.parse(patches[0].body).chains.get[0].response.exit_code===0,'old candidate genuine transformed-response RED');
        }else assert(hits===0&&patches.length===0&&state.state==='stopped-unknown-outer-retention-only','unsupported response outer-only without hooks');
      }
      if(scenario.arrayExtra)assert(state.chains.get[0].response.extra==='must-not-disappear'&&patches.length===0,'array extra must not be silently dropped');
      if(scenario.oversize){
        assert(patches.length===1&&patches[0].destination.endsWith('diagnostic-tool.json'),'oversize uses diagnostic only');
        assert(JSON.parse(patches[0].body).chains.get[0].response.output==='x'.repeat(65537),'complete oversized actual output retained');
      }
      if(scenario.badMarker)assert(!patches.some(p=>p.destination.endsWith('root-reconcile-tool.json')),'invalid marker never normal transcript');
      for(const patch of patches){
        const v=JSON.parse(patch.body);
        if(v.authority===false){
          assert(v.version===1&&v.mode==='material-four-get'&&v.state==='unknown-no-authority'&&v.Q_released===false,'strict diagnostic identity');
          assert(Object.keys(v).sort().join(',')==='Q_released,authority,chains,mode,patch_events,reason,state,version','strict diagnostic keys');
          assert(Array.isArray(v.patch_events)&&v.patch_events.length<=4,'diagnostic patch history');
          for(const es of [...Object.values(v.chains),v.patch_events])if(es!==null)
            assert(es.every((e,i)=>Object.hasOwn(e,'response')||i===es.length-1),'pending only last in saved envelope');
        }
      }
    }
    assert(memory.get(P+'one-shot-admitted')===true,'only local admission stays local');
  }
  totalNative+=native.length;totalPatches+=patches.length;
  results.push({name:scenario.name,state:state?state.state:'interlock-refused',native_calls:native.length,
                patch_calls:patches.length,saved_snapshots:snapshots.length,passed:mode!=='red',expected_regression_observed:mode==='red',hook_calls:hits});
}
return {tests_run:results.length,failures:mode==='red'?1:0,errors:0,skipped:0,cases:results,total_fake_native_calls:totalNative,
        total_fake_patch_calls:totalPatches,actual_nested_tools:0,actual_store_interlock_set:false,
        generated_payload_max_output_bytes:65537,limits:'Pure functions isolate; native CPU/AS/45s limits do not measure this JS simulation.'};
