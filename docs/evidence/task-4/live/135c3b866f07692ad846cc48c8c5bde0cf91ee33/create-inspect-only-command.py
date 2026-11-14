from pathlib import Path
import datetime,json,os,sys
root=Path('/home/postedism/Desktop/Warden');sys.path.insert(0,str(root/'scripts'))
import firecracker_lab as lab
os.umask(0o077);source='135c3b866f07692ad846cc48c8c5bde0cf91ee33';folder=root/'docs/evidence/task-4/live'/source
with lab.locked():
    assert lab.source_sha()==source
    lab.guard(lab.RESERVE,5000000000)
    package=json.loads(lab.bounded_input(lab.CACHE/'package.json',65536));raw=lab.bounded_input(lab.CACHE/'package.tar',512000000);assert package['source']==source and lab.sha(raw)==package['tar_sha256'];del raw
    output,labels=lab.fresh_session();lab.record_charge(output,reserve=lab.RESERVE);livefd=None;observed=False
    try:
        command=['image','import','--change','ENTRYPOINT ["/opt/warden/input/lab"]']
        for k,v in labels.items():command+=['--change','LABEL '+k+'='+v]
        image=lab.docker(command+[str(lab.CACHE/'package.tar')],timeout=120).strip();data=lab.owned_inspect('image',image,labels,lab.docker);assert data['Size']<=512000000
        lab.store(output/'identity.json',lab.encode({'source':source,'image':image,'labels':labels,'mode':'create-inspect-only','never_start_authorized':True}))
        lab.guard(0,5000000000)
        live=output/'live';live.mkdir(mode=0o700);livefd=lab.trusted_directory(str(live),1000);bind=f'/proc/{os.getpid()}/fd/{livefd}'
        cid=lab.docker(lab.live_args('boot',image,bind,labels,os.readlink('/proc/self/ns/cgroup'))).strip();container=lab.owned_inspect('container',cid,labels,lab.docker)
        assert container['State']['Status']=='created' and container['State']['Running']==False and container['State']['Pid']==0
        result={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':source,'session':str(output.relative_to(root)),'labels':labels,'image':image,'cid':cid,'state':container['State'],'host_config':container['HostConfig'],'mounts':container['Mounts'],'scope':'One exact reviewed-profile create/inspect diagnostic only. No Docker start, KVM open, VM, tenant or capability/device expansion.'}
        with (folder/'create-inspect-only.json').open('x') as out:json.dump(result,out,indent=2);out.write('\n')
        observed=True;print(json.dumps({'CapAdd':container['HostConfig']['CapAdd'],'CapDrop':container['HostConfig']['CapDrop'],'Mounts':container['HostConfig']['Mounts'],'SecurityOpt':container['HostConfig']['SecurityOpt'],'state':container['State']['Status'],'never_started':True}))
    finally:
        if livefd is not None:os.close(livefd)
        lab.remove_objects(labels)
        if observed:lab.record_charge(output,released=True,reserve=lab.RESERVE)
    lab.guard(0,1000000000)
