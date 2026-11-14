import sys,json,tarfile,hashlib
sys.path.insert(0,'/home/postedism/Desktop/Warden/scripts')
import firecracker_lab as lab
output=lab.BASE/'docker-firecracker-e8256cfac7abc6d246ccba7638dacbff'
with lab.locked():
    with tarfile.open(output/'probe.tar') as tar:
        m=json.load(tar.extractfile('manifest.json'))
        raw=tar.extractfile(m[0]['Config']).read()
        original=json.loads(raw);labels=original['config']['Labels']
    lab.guard(0,2000000000)
    try:
        loaded=lab.docker(['image','load','--input',str(output/'probe.tar')],timeout=120)
        ids=list(set(lab.scoped_ids('image',labels,lab.docker)))
        if len(ids)!=1:raise RuntimeError('unique own loaded image required')
        inspected=lab.owned_inspect('image',ids[0],labels,lab.docker)
        lab.guard(0,2000000000)
        lab.docker(['image','save','--output',str(output/'roundtrip.tar'),ids[0]],timeout=120)
        if (output/'roundtrip.tar').stat().st_size>64<<20:raise RuntimeError('oversized own roundtrip')
        with tarfile.open(output/'roundtrip.tar') as tar:
            saved=json.load(tar.extractfile('manifest.json'))
            config=tar.extractfile(saved[0]['Config']).read(65537)
        report={'source':'5d780d23ed8d762c547ecf7dd4765a25b6c968b9','load_response':loaded,'original_config_sha256':lab.sha(raw),'saved_config_sha256':lab.sha(config),'config_bytes_identical':config==raw,'image_inspect':inspected,'saved_manifest':saved,'executed_payload':False}
        lab.store(output/'image-binding-observation.json',lab.encode(report));print(json.dumps(report,indent=2))
    finally:
        lab.remove_objects(labels)
    if lab.scoped_ids('container',labels,lab.docker) or lab.scoped_ids('image',labels,lab.docker):raise RuntimeError('own objects remain')
    lab.record_charge(output,released=True,reserve=lab.RESERVE)
    lab.guard(0,0)
