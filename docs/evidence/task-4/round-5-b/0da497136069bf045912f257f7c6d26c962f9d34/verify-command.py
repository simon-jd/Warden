"""Read only the B delta and its own fixed test/accounting evidence; no test run."""
import ast,hashlib,json,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[5]
OUT=Path(__file__).resolve().parent
SOURCE='0da497136069bf045912f257f7c6d26c962f9d34'
BASE='f40934a5a3e6bc5f2d741120bcc5448ba996cd12'
FILES=['runtimes/firecracker/diagnostic.go','runtimes/firecracker/diagnostic_test.go',
       'runtimes/firecracker/lab_test.go','runtimes/firecracker/process.go','runtimes/firecracker/vm.go',
       'scripts/firecracker_code.py']
BINDINGS=['runtimes/firecracker/driver.go','runtimes/firecracker/scope.go','runtimes/firecracker/api.go',
          'runtimes/firecracker/protocol.go','runtimes/firecracker/supervisor.go','runtimes/firecracker/device_gate.go',
          'runtimes/firecracker/device_policy.go','runtimes/firecracker/session_mount.go',
          'runtimes/firecracker/firecracker.go','runtimes/gate/gate.go',
          'scripts/firecracker_lab.py','scripts/firecracker_device_receipt.py','scripts/azure_guard.py']
def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT)
def source(path,commit=SOURCE):return git('show',commit+':'+path).decode()
def stamp(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def between(s,start,end):return s[s.index(start):s.index(end,s.index(start))]
assert git('rev-parse',SOURCE+'^').decode().strip()==BASE
assert sorted(git('diff','--name-only',BASE,SOURCE).decode().splitlines())==FILES
files={}
for name in FILES:
    raw=(ROOT/name).read_bytes();assert raw==source(name).encode()
    assert (ROOT/name).stat().st_mode&0o7777==0o644
    files[name]=stamp(raw)
old=source('runtimes/firecracker/vm.go',BASE);new=source('runtimes/firecracker/vm.go')
assert between(old,'type boundedLog struct','func (d *Driver) start(')==between(new,'type boundedLog struct','func (d *Driver) start(')
assert old[old.index('func (h *vm) Wait('):]==new[new.index('func (h *vm) Wait('):]
retire=between(new,'func (h *vm) retire(', 'func (h *vm) Wait(')
retire=retire.replace('func (h *vm) retire() (retireErr error)', 'func (h *vm) retire() error')
retire=retire.replace('\tdefer func() {\n\t\tif retireErr != nil {\n\t\t\tretireErr = h.failure("retire", nil, retireErr)\n\t\t}\n\t}()\n','',1)
retire=retire.replace('\tif h.process != nil {\n\t\th.process.noteCleanup()\n\t}\n','',1)
assert retire==between(old,'func (h *vm) retire(', 'func (h *vm) Wait(')
oldp=source('runtimes/firecracker/process.go',BASE);newp=source('runtimes/firecracker/process.go')
assert between(oldp,'func startOwned(', '// Stop proves')==between(newp,'func startOwned(', '// Stop proves')
stop=between(newp,'func (p *ownedProcess) Stop()', '// Mark before')
newsignal='''\tp.noteCleanupLocked()
\te := unix.PidfdSendSignal(p.pidfd, unix.SIGKILL, nil, 0)
\tp.killSignalResult = "sent"
\tif errors.Is(e, unix.ESRCH) {
\t\tp.killSignalResult = "already_absent"
\t} else if e != nil {
\t\tp.killSignalResult = "error"
'''
oldsignal='\tif e := unix.PidfdSendSignal(p.pidfd, unix.SIGKILL, nil, 0); e != nil && !errors.Is(e, unix.ESRCH) {\n'
assert newsignal in stop
stop=stop.replace(newsignal,oldsignal,1)
assert stop.rstrip()==oldp[oldp.index('func (p *ownedProcess) Stop()'):].rstrip()
oldlab=source('runtimes/firecracker/lab_test.go',BASE);newlab=source('runtimes/firecracker/lab_test.go')
assert newlab.replace('\t\tt.Fatal(bootFailure(h.(*vm), out, len(raw), e, re))',
                      '\t\tt.Fatalf("actual boot %+v %q %v %v", out, raw, e, re)')==oldlab
oldpy=source('scripts/firecracker_code.py',BASE);newpy=source('scripts/firecracker_code.py')
normalized=newpy.replace("('code','build','tools','rootfs','diagnostics')","('code','build','tools','rootfs')",1)
normalized=normalized.replace("'--service-memory-bytes','3000000000'","'--service-memory-bytes','2000000000'",1)
selector='if mode==\'diagnostics\':command="umask 0077; exec "+go+" test -p 1 -count=1 -v -run \'^TestVMMDiagnostic\' ./runtimes/firecracker"\n'
assert selector in normalized;normalized=normalized.replace(selector,'',1)
assert ast.dump(ast.parse(normalized))==ast.dump(ast.parse(oldpy))
bindings={}
for name in BINDINGS:
    raw=source(name).encode();assert raw==source(name,BASE).encode()==(ROOT/name).read_bytes()
    bindings[name]=stamp(raw)
passes={}
for name in ('red','red-behavior','green','cover'):
    raw=(OUT/(name+'.log')).read_text();receipt=json.loads((OUT/(name+'.json')).read_text())
    events=[json.loads(line) for line in raw.splitlines() if line.startswith('{')]
    pre=[e for e in events if e.get('event')=='local-preflight'];assert len(pre)==1
    assert int(pre[0]['additional_bytes'])==5512000000 and int(pre[0]['service_memory_bytes'])==3000000000
    assert pre[0]['project_allocated_bytes']+5512000000<=12000000000
    create=[e for e in events if 'container_id' in e];removed=[e['removed_container'] for e in events if 'removed_container' in e]
    assert len(create)==1 and removed==[create[0]['container_id']]
    configs=[e['inspected_host_config'] for e in events if 'inspected_host_config' in e];assert len(configs)==1
    h=configs[0]
    assert h['Memory']==h['MemorySwap']==h['NanoCpus']==2000000000 and h['PidsLimit']==256
    assert h['CapDrop']==['ALL'] and not h['CapAdd'] and h['NetworkMode']=='none' and h['ReadonlyRootfs']
    assert not h['Privileged'] and not h['Devices'] and not h['DeviceCgroupRules'] and not h['DeviceRequests']
    assert h['IpcMode']==h['CgroupnsMode']=='private' and not h['PidMode'] and h['SecurityOpt']==['no-new-privileges']
    assert h['Mounts']==[{'Type':'bind','Source':str(ROOT),'Target':'/workspace','ReadOnly':True},
                         {'Type':'bind','Source':str(ROOT/'.cache/firecracker-code'),'Target':'/workspace/.cache/firecracker-code'}]
    assert receipt['before']['containers']==receipt['after']['containers']==[]
    assert receipt['before']['images']==receipt['after']['images']==[]
    assert receipt['before']['outstanding']==receipt['after']['outstanding']==5000000000
    assert receipt['sysctls_before']==receipt['sysctls_after']
    post=receipt['ordinary_postflight'];assert int(post['additional_bytes'])==5000000000
    assert post['project_allocated_bytes']+5000000000<=12000000000
    assert int(post['service_memory_bytes'])==1000000000
    result={'top_pass':len(re.findall(r'^--- PASS:',raw,re.M)), 'top_fail':len(re.findall(r'^--- FAIL:',raw,re.M)),
            'top_skip':len(re.findall(r'^--- SKIP:',raw,re.M)), 'exit_code':receipt['exit_code'],
            'container':create[0]['container_id'],'preflight':pre[0],'postflight':post,'sysctls_unchanged':True}
    passes[name]=result
assert passes['red']['exit_code']==1 and passes['red']['top_pass']==passes['red']['top_fail']==0
assert (passes['red-behavior']['top_pass'],passes['red-behavior']['top_fail'])==(1,2)
assert passes['green']['top_pass']==7 and passes['green']['top_fail']==passes['green']['top_skip']==0
assert passes['cover']['top_pass']==59 and passes['cover']['top_skip']==4 and passes['cover']['top_fail']==0
assert passes['green']['exit_code']==passes['cover']['exit_code']==0
assert json.loads((OUT/'cover.json').read_text())['source_head']==SOURCE
result={'source':SOURCE,'base':BASE,'files':files,'unchanged_bindings':bindings,
        'tenant_prefix_exact_unchanged':True,'startOwned_exact_unchanged':True,
        'Stop_original_signal_error_reap_poll_close_checks_preserved':True,
        'retire_original_checks_preserved_only_diagnostic_defer_and_cleanup_note_added':True,
        'Wait_Kill_Timings_unchanged':True,'boot_failure_assertion_only_one_line_changed':True,
        'code_profile_only_selector_and_host_allowance_changed':True,
        'test_passes':passes,'old_recovery_or_evidence_indices_read':False,
        'actual_VM_device_guest_modes_run':False,'original_Q_released':False}
(OUT/'source-verification.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print('PASS: six source files; original tenant prefix, startOwned and retirement checks preserved.')
print('PASS: fixed selector/1GB host allowance only; 13 runtime/Gate/device/guard bindings unchanged.')
print('PASS: real RED2fail, focused GREEN7pass; one committed covering59pass/4explicit-live-skips.')
print('PASS: all four code containers exactly removed; full pre/post guards include retained Q5GB; six sysctls unchanged.')
print('No old recovery/index crawl or actual VM/device mode.')
