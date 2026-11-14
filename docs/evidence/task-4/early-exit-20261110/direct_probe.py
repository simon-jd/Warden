"""Direct (no jailer/Docker) Firecracker diagnosis harness: boot, HELLO, optional BIND/EXEC."""
import base64, json, os, secrets, socket, struct, subprocess, sys, time
work, rootfs, mode, tag = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
os.chdir(work)
cfg = {"boot-source": {"kernel_image_path": "kernel", "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro init=/agent WARDEN_FC_GUEST=1"},
       "drives": [{"drive_id": "rootfs", "path_on_host": rootfs, "is_root_device": True, "is_read_only": True},
                  {"drive_id": "payload", "path_on_host": "payload.ext4", "is_root_device": False, "is_read_only": True}],
       "machine-config": {"vcpu_count": 1, "mem_size_mib": 640, "smt": False},
       "vsock": {"guest_cid": 3, "uds_path": "control-%s.sock" % tag}}
open("vm-%s.json" % tag, "w").write(json.dumps(cfg))
try: os.unlink(cfg["vsock"]["uds_path"])
except FileNotFoundError: pass
log = open("serial-%s.log" % tag, "wb")
t0 = time.monotonic()
p = subprocess.Popen(["./firecracker", "--no-api", "--config-file", "vm-%s.json" % tag, "--id", "diag-" + tag], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
def frame(sock, obj):
    b = json.dumps(obj).encode(); sock.sendall(struct.pack(">I", len(b)) + b)
def read_exact(f, n):
    b = f.read(n)
    if len(b) != n: raise EOFError("short read %d/%d" % (len(b), n))
    return b
def read_frame(f):
    n = struct.unpack(">I", read_exact(f, 4))[0]; return json.loads(read_exact(f, n))
result = {"tag": tag}
try:
    deadline = time.monotonic() + 15
    while True:
        if p.poll() is not None: raise RuntimeError("VMM exited rc=%s before HELLO" % p.returncode)
        if time.monotonic() > deadline: raise RuntimeError("no HELLO in 15 s")
        try:
            s = socket.socket(socket.AF_UNIX); s.settimeout(1); s.connect(cfg["vsock"]["uds_path"])
            s.sendall(b"CONNECT 52\n"); f = s.makefile("rb")
            line = f.readline()
            if not line.startswith(b"OK "): raise OSError("not OK: %r" % line)
            hello = read_frame(f); break
        except (OSError, EOFError, socket.timeout):
            s.close(); time.sleep(0.005)
    result["hello_ms"] = round((time.monotonic() - t0) * 1000, 1); result["hello"] = hello
    if mode != "hello":
        s.settimeout(30)
        run = base64.b32encode(secrets.token_bytes(16)).decode().rstrip("=")
        nonce = secrets.token_hex(32)
        limits = {"CPU": 1, "MemoryMiB": int(os.environ.get("MEM", "128")), "Pids": 32, "TimeoutS": int(os.environ.get("TMO", "10"))}
        spec = {"RunID": run, "ImageDigest": "sha256:" + "0" * 64, "Cmd": ["/warden-probe", mode], "Limits": limits, "Network": "none", "AllowDomains": None, "EgressSource": ""}
        frame(s, {"version": 1, "kind": "bind", "nonce": nonce, "run_id": run, "profile": {"Spec": spec, "VMMemoryMiB": limits["MemoryMiB"] + 128, "HostMemoryMiB": limits["MemoryMiB"] + 256, "AgentMemoryMiB": 64}})
        frame(s, {"version": 1, "kind": "exec", "nonce": nonce, "run_id": run})
        frames = []
        while True:
            fr = read_frame(f)
            if "data" in fr: fr["data"] = base64.b64decode(fr["data"]).decode(errors="replace")
            frames.append(fr)
            if fr["kind"] == "exit": break
        result["frames"] = frames
        result["exec_ms"] = round((time.monotonic() - t0) * 1000, 1)
except Exception as e:
    result["error"] = repr(e)
finally:
    time.sleep(0.3)
    if p.poll() is None: p.kill()
    p.wait(); result["vmm_rc"] = p.returncode
    try: os.unlink(cfg["vsock"]["uds_path"])
    except FileNotFoundError: pass
    print(json.dumps(result))
