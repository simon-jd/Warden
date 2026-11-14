// ONE finite affected execution; production cells receive only local fakes here.
const request={cmd:'exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C python3 -I -S -B docs/evidence/task-6/controller-six-mode-metadata-verification.py',workdir:'/home/postedism/Desktop/Warden',shell:'/bin/bash',login:false,tty:false,yield_time_ms:30000,max_output_tokens:30000};
const record={native_events:[],js:{state:'not-started',cases:[]}};
store('six-mode-metadata-affected-verification',record);
async function call(tool,request){
 const event={tool,request};record.native_events.push(event);
 try{event.response=await tools[tool](request);return event.response;}
 catch(error){event.thrown=error;throw error;}
}
try{
 let result=await call('exec_command',request);
 if(Object.hasOwn(result,'session_id'))result=await call('write_stdin',{session_id:result.session_id,chars:'',yield_time_ms:15000,max_output_tokens:30000});
 if(result.exit_code!==0||Object.hasOwn(result,'session_id'))throw Error('native verification failed/unknown; stop');
 const payload=JSON.parse(record.native_events.map(e=>e.response.output).join(''));
 if(payload.native.errors!==0||payload.native.failures!==0||payload.native.cases_passed!==4||payload.native.static_mappings_passed!==6||payload.native.missing.length!==0)throw Error('native verification incomplete; stop');
 record.js.state='started';
 const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
 record.js.result=await new AsyncFunction('common','observation',payload.events_fixture)(payload.common,record.js);
 record.js.state='passed';
 text({native_cases:4,static_mappings:6,js_cases:record.js.result.tests_run,failures:0,actual_runtime_interlocks:false});
}catch(error){
 record.failure=String(error);record.failure_stack=error&&error.stack;
 if(record.js.state==='started')record.js.state='failed';
 text({state:'STOP',reason:record.failure,js_state:record.js.state});
}
store('six-mode-metadata-affected-verification',record);
