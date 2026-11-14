# Task 15 首材料 caller（inert；待 root 裁定）

**命令未执行**；仅写此 ignored 文件，未写产品/Git/index。原 8189B 提案不改。

**原案勘误。** 完整流程应计 R≈4.7GB+Q5GB+6.46GB≈16.16GB >12GB；R 仅旧观测，完整流程关闭。漏洞 attestation 必须包含**未过滤完整扫描**，另从中判定有修复的 critical；`--only-fixed` 结果会漏掉不可修复 KEV。“Skip 计 passed”的固定源码是 [v1.19.2 `command.go` 181–195 行](https://github.com/kyverno/kyverno/blob/v1.19.2/cmd/cli/kubectl-kyverno/commands/test/command.go#L181-L195)：summary 使用 `rc.Pass+rc.Skip`，只在 `rc.Fail>0` 报错；`test.go` 不是计数位置。零退出/Skip 不证明验签。

首 caller 仅取固定 CLI archive、checksums、bundle 和官方 API，核 SHA/尺寸、有界解包；**不运行任何解包文件或 `--version`**。新私有 N=`.superpowers/sdd/2-warden-security-plan/.task15-cli-v1.19.2-material-20261025`，0700 且已存在即失败。root 须先全文/fresh 准入。命令从 workspace cwd 运行，89+1 秒涵盖全程；无 HOME/proxy/auth/凭据。`download0`：目前零 archive 下载，guard 前不下载。

```bash
/usr/bin/timeout --signal=TERM --kill-after=1s 89s /usr/bin/python3 -I -B - <<'PY'
import hashlib,json,os,pathlib,shutil,signal,ssl,tarfile
import urllib.parse,urllib.request
os.umask(0o077)
signal.signal(signal.SIGTERM,lambda *_: (_ for _ in ()).throw(TimeoutError('whole90')))
root=pathlib.Path('/home/postedism/Desktop/Warden/.superpowers/sdd/2-warden-security-plan')
N=root/'.task15-cli-v1.19.2-material-20261025'
Q_PLUS_N=5_419_430_400    # Q=5GB decimal + NEW N=400MiB
NEW_N=419_430_400
NEW_MEM=1_073_741_824
assert 9_000_000_000+NEW_MEM==10_073_741_824<16_000_000_000
assert shutil.disk_usage(root).free>=Q_PLUS_N,'fresh disk'
with open('/proc/meminfo',encoding='ascii') as f:
    mem={x[0].rstrip(':'):int(x[1])*1024 for x in (l.split() for l in f)}
assert mem['MemAvailable']>=NEW_MEM,'fresh memory'
os.mkdir(N,0o700)       # exclusive; no reuse or old-state cleanup
ok=False
try:
    tag='v1.19.2'
    api_url='https://api.github.com/repos/kyverno/kyverno/releases/tags/'+tag
    base='https://github.com/kyverno/kyverno/releases/download/'+tag+'/'
    sizes={
      'checksums.txt':(830,'f06301cec9bd1ed8e22fb94572fabd98726facd45de01b274db8ed283f36a822'),
      'checksums.txt.sigstore.json':(10079,'c6299581ae93e69b60e56fa86d89b4a2f66d7eebfba0be45cebc6b792de00e64'),
      'kyverno-cli_v1.19.2_linux_x86_64.tar.gz':(53485462,'357eaf1df8bc24ddd5a73979fadeaae6a032e8710f11af264229756e4956bf4a')}
    hosts={'api.github.com','github.com','release-assets.githubusercontent.com'}
    class Redirect(urllib.request.HTTPRedirectHandler):
        def __init__(self): self.n=0
        def redirect_request(self,req,fp,code,msg,headers,url):
            self.n+=1; p=urllib.parse.urlsplit(url)
            if self.n>2 or p.scheme!='https' or p.hostname not in hosts or p.username or p.password:
                raise ValueError('redirect denied')
            return super().redirect_request(req,fp,code,msg,headers,url)
    def get(url,limit,accept):
        p=urllib.parse.urlsplit(url)
        assert p.scheme=='https' and p.hostname in hosts and not p.username and not p.password
        op=urllib.request.build_opener(urllib.request.ProxyHandler({}),
             urllib.request.HTTPSHandler(context=ssl.create_default_context()),Redirect())
        req=urllib.request.Request(url,headers={'User-Agent':'warden-task15-material-v1','Accept':accept})
        with op.open(req,timeout=15) as r:
            q=urllib.parse.urlsplit(r.geturl())
            assert r.status==200 and q.scheme=='https' and q.hostname in hosts
            length=r.headers.get('Content-Length')
            if length is not None: assert int(length)<=limit
            data=r.read(limit+1)
        assert len(data)<=limit,'oversized response'
        return data
    api=json.loads(get(api_url,131072,'application/vnd.github+json'))
    assert api['tag_name']==tag and not api['draft'] and not api['prerelease']
    assets={a['name']:a for a in api['assets'] if a['name'] in sizes}
    assert set(assets)==set(sizes)
    for name,(size,digest) in sizes.items():
        a=assets[name]
        assert (a['size'],a['digest'],a['browser_download_url'])==(
                size,'sha256:'+digest,base+name)
    for name,(size,digest) in sizes.items():
        data=get(base+name,size,'application/octet-stream')
        assert len(data)==size and hashlib.sha256(data).hexdigest()==digest
        with open(N/name,'xb') as f: f.write(data)
        del data
    archive_name='kyverno-cli_v1.19.2_linux_x86_64.tar.gz'
    assert sizes[archive_name][1]+'  '+archive_name in (N/'checksums.txt').read_text().splitlines()
    archive=N/archive_name; cap=256*1024*1024
    entries=[]; kinds={}; needed=set(); expanded=0
    with tarfile.open(archive,'r:gz',errorlevel=2) as t:
        for m in t:
            name=m.name.rstrip('/'); parts=name.split('/')
            assert name and len(name.encode())<=1024 and len(entries)<512
            assert all(x not in ('','.','..') for x in parts) and '\\' not in name
            assert not name.startswith('/') and name not in kinds and not m.pax_headers
            assert m.isfile() or m.isdir()
            assert m.size>=0 and (m.isfile() or m.size==0)
            parents={'/'.join(parts[:i]) for i in range(1,len(parts))}
            assert name not in needed or m.isdir()
            assert all(kinds.get(x,'dir')=='dir' for x in parents)
            needed|=parents; kinds[name]='dir' if m.isdir() else 'file'
            expanded+=m.size; assert expanded<=cap,'expanded cap'
            entries.append((name,kinds[name],m.size))
    assert entries
    dest=N/'extract'; dest.mkdir(mode=0o700)
    files=[]
    with tarfile.open(archive,'r:gz',errorlevel=2) as t:
        for i,m in enumerate(t):
            assert i<len(entries) and (m.name.rstrip('/'),
                   'dir' if m.isdir() else 'file',m.size)==entries[i]
            name,kind,size=entries[i]; out=dest.joinpath(*name.split('/'))
            if kind=='dir': out.mkdir(mode=0o700,parents=True,exist_ok=True); continue
            out.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            h=hashlib.sha256(); left=size
            with t.extractfile(m) as src,open(out,'xb') as dst:
                while left:
                    b=src.read(min(left,1024*1024)); assert b,'truncated member'
                    dst.write(b);h.update(b);left-=len(b)
            files.append({'path':name,'bytes':size,'sha256':h.hexdigest()})
        assert i+1==len(entries)
    report={'source':api_url,'trust':'TLS GitHub API digests; bundle hash only, no publisher proof',
            'archive_bytes':sizes[archive_name][0],'expanded_bytes':expanded,
            'expanded_cap':cap,'files':files,'download0_before_guard':True}
    raw=json.dumps(report,sort_keys=True).encode()
    assert len(raw)<=32*1024*1024
    assert expanded+sum(s for s,_ in sizes.values())+len(raw)+131072<=NEW_N
    with open(N/'material-report.json','xb') as f:f.write(raw)
    ok=True
finally:
    if not ok: shutil.rmtree(N)  # only this call's new private N
PY
```

固定字节/SHA 见 [官方 API](https://api.github.com/repos/kyverno/kyverno/releases/tags/v1.19.2) 和 [root 元数据](official-static-metadata-20261025.json)。TLS host 白名单及最多两次重定向写在 caller 中。bundle 10079B/SHA `c6299581…` 仅按 hash 保存；无 Sigstore verifier/信任根闭包，**不声称发布者密码验证**。边界是 TLS 根与官方 API digest；独立验发布者须另裁定有界 bootstrap。256MiB 是展开上限，非实测。

完整新增 N ≤400MiB（原材料 368MiB+证据/元数据 32MiB），fresh `additional=5419430400` B 另含不可释放 Q5GB；`service-memory=10073741824` B 含旧 UNKNOWN9GB+新1GiB，服务总须 <16GB。R≈4.7GB 非 fresh 余量；不扫旧进程、不清全局。超时可能留下**仅此 N**，由 root 核精确路径。材料成功也不准运行 CLI、下载 DB、签名/发布或 registry/集群验收；Task15/Goal OPEN。
