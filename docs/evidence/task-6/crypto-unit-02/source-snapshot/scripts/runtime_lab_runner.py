#!/usr/bin/env python3
"""One independent containerd daemon; no shared daemon, service or root controller changes."""
import os
from pathlib import Path
import stat
import signal
import socket
import subprocess
import sys
import time
from runtime_lab_paths import NOFOLLOW_DIR, prepare_session

CGROUP = '/sys/fs/cgroup'


def write_control(fd, name, value):
    target = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    try:
        os.write(target, value.encode())
    finally:
        os.close(target)


def populated(fd):
    target = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    with os.fdopen(target) as source:
        lines = source.read(4096).splitlines()
    if 'populated 0' in lines:
        return False
    if 'populated 1' in lines:
        return True
    raise ValueError('missing populated event; refusing cleanup')


def remove_cgroups(parent, name):
    fd = os.open(name, NOFOLLOW_DIR, dir_fd=parent)
    try:
        for child in os.listdir(fd):
            info = os.stat(child, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                remove_cgroups(fd, child)
        if populated(fd):
            raise RuntimeError('CLEANUP FAILED: owned cgroup subtree still populated')
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent)


def system_binary(name):
    path = '/usr/bin/' + name
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('trusted root-owned system binary required: ' + path)
    return path


class CleanupError(RuntimeError):
    def __init__(self, failures):
        self.failures = tuple(failures)
        super().__init__('; '.join(f'{phase}: {error!r}' for phase, error in self.failures))


def cleanup_owned(daemon, cg_fd, cg_parent, created_cgroup, session, release_evidence=False):
    """Each independent cleanup action runs even if a previous action fails.

    Only the Popen object returned by this runner may be signalled/waited. Disk
    state is deleted only after both daemon reap and subtree-empty verification.
    """
    failures = []

    def attempt(phase, action):
        try:
            return True, action()
        except BaseException as error:
            failures.append((phase, error))
            return False, None

    if cg_fd is not None:
        attempt('kill cgroup', lambda: write_control(cg_fd, 'cgroup.kill', '1'))

    daemon_reaped = daemon is None
    if daemon is not None:
        inspected, status = attempt('inspect owned daemon', daemon.poll)
        if not inspected or status is None:
            attempt('terminate owned daemon', daemon.terminate)
        # A kill-control/terminate/poll error cannot skip wait or force-kill.
        try:
            daemon.wait(timeout=5)
            daemon_reaped = True
        except subprocess.TimeoutExpired:
            attempt('kill owned daemon', daemon.kill)
            daemon_reaped, _ = attempt('reap owned daemon', lambda: daemon.wait(timeout=5))
        except BaseException as error:
            failures.append(('wait owned daemon', error))
            attempt('kill owned daemon', daemon.kill)
            daemon_reaped, _ = attempt('reap owned daemon', lambda: daemon.wait(timeout=5))

    verified_empty = not created_cgroup and cg_fd is None
    if cg_fd is not None:
        def verify_empty():
            for _ in range(100):
                if not populated(cg_fd):
                    return
                time.sleep(.05)
            raise RuntimeError('dedicated subtree still populated; session preserved')
        verified_empty, _ = attempt('verify subtree empty', verify_empty)
    elif created_cgroup:
        failures.append(('verify subtree empty', RuntimeError('owned cgroup descriptor unavailable; session preserved')))

    if daemon_reaped and verified_empty:
        removed = True
        if created_cgroup:
            removed, _ = attempt('remove owned cgroups', lambda: remove_cgroups(cg_parent, 'warden-lab'))
        if removed:
            data_removed, _ = attempt('remove owned daemon data', session.cleanup_data)
            if data_removed and not failures and release_evidence:
                attempt('return owned evidence', session.release_evidence)
    if failures:
        raise CleanupError(failures)


def retirement_cleanup(daemon, cg_fd, session):
    """Only the original owner reaps its Popen; never acknowledge failed cleanup."""
    daemon.wait(timeout=5)
    if populated(cg_fd):
        raise RuntimeError('retirement node still populated; data preserved')
    session.cleanup_data()


def run_api_test(test_fd, environment, daemon, cg_fd, session):
    # Fixed binary and fixed one-message protocol. The response only wakes the
    # Go verifier, which checks pidfd HUP and original unlinked data-directory FDs.
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    process = None
    try:
        parent.settimeout(180)
        environment = {**environment, 'WARDEN_API_SUPERVISOR_FD': str(child.fileno())}
        process = subprocess.Popen([f'/proc/self/fd/{test_fd}', '-test.run', '^TestHTTPPostgresRuntime$', '-test.v', '-test.count=1'], pass_fds=(test_fd, child.fileno()), env=environment)
        child.close()
        if parent.recv(64) != b'RETIRE':
            raise RuntimeError('fixed retirement cleanup request missing')
        retirement_cleanup(daemon, cg_fd, session)
        parent.sendall(b'CLEANED')
        if process.wait(timeout=60) != 0:
            raise RuntimeError('API/runtime fixture failed')
    finally:
        child.close()
        parent.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)


def run_lab(artifact_base=None, release_evidence=False, profile="run"):
    if profile not in ("run", "api"):
        raise ValueError("fixed runtime profile required")
    if os.environ.get('WARDEN_LAB_ACK') != 'dedicated-warden-lab':
        raise ValueError('Dedicated warden-lab acknowledgement required')
    if os.geteuid() != 0:
        raise ValueError('Root access to dedicated cgroup required; do not change shared daemon or sudo')
    if os.uname().machine != 'x86_64':
        raise ValueError('amd64 guest required')
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    uid = int(os.environ.get('WARDEN_LAB_OWNER_UID', os.environ.get('SUDO_UID', '0')))
    # No privileged write precedes full no-follow ownership validation.
    session = prepare_session(root + '/.cache/warden-lab', uid)
    daemon = None
    cg_parent = cg_fd = None
    created_cgroup = False
    artifacts = []
    success = False
    try:
        for name in (('api.test' if profile == 'api' else 'runc.test'), 'probe.oci.tar', 'image-digest', 'image-name'):
            artifacts.append(session.artifact(name, artifact_base))
        test_fd, archive_fd, digest_fd, image_fd = artifacts
        digest, image = os.read(digest_fd, 256).decode().strip(), os.read(image_fd, 256).decode().strip()
        containerd, ctr = system_binary('containerd'), system_binary('ctr')
        system_binary('runc')
        cg_parent = os.open(CGROUP, NOFOLLOW_DIR)
        control = os.open('cgroup.subtree_control', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=cg_parent)
        with os.fdopen(control) as source:
            available = source.read().split()
        if not all(controller in available for controller in ('cpu', 'memory', 'pids')):
            raise ValueError('Parent controllers unavailable; refusing host controller changes')
        # mkdir is exclusive, including dangling/preexisting aliases.
        os.mkdir('warden-lab', 0o700, dir_fd=cg_parent)
        created_cgroup = True
        cg_fd = os.open('warden-lab', NOFOLLOW_DIR, dir_fd=cg_parent)
        write_control(cg_fd, 'memory.max', '16000000000')
        write_control(cg_fd, 'cgroup.subtree_control', '+cpu +memory +pids')
        os.mkdir('service', 0o700, dir_fd=cg_fd)
        service = os.open('service', NOFOLLOW_DIR, dir_fd=cg_fd)
        try:
            write_control(service, 'memory.max', '1073741824')
            log_fd = os.open('containerd.log', os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=session.fd)
            try:
                # Every write path is anchored to the private directory FD. A
                # renamed/symlinked .cache/session pathname cannot redirect it.
                daemon = subprocess.Popen([containerd, '--config', session.anchored('containerd.toml'), '--root', session.anchored('root'), '--state', session.anchored('state'), '--address', session.anchored('containerd.sock'), '--log-level', 'debug'], stdout=log_fd, stderr=subprocess.STDOUT, env={**os.environ, 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
            finally:
                os.close(log_fd)
            write_control(service, 'cgroup.procs', str(daemon.pid))
        finally:
            os.close(service)
        address = session.anchored('containerd.sock')
        for _ in range(100):
            if daemon.poll() is not None:
                raise RuntimeError('Dedicated daemon exited; inspect ' + str(session.run / 'containerd.log'))
            try:
                probe = subprocess.run([ctr, '--address', address, 'version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1)
                if probe.returncode == 0:
                    break
            except subprocess.TimeoutExpired:
                pass
            time.sleep(.1)
        else:
            raise TimeoutError('Dedicated daemon did not become ready')
        os.chmod('containerd.sock', 0o600, dir_fd=session.fd, follow_symlinks=False)
        subprocess.run([ctr, '--address', address, 'namespaces', 'create', 'warden-lab'], check=True, timeout=5)
        subprocess.run([ctr, '--address', address, '--namespace', 'warden-lab', 'images', 'import', f'/proc/{os.getpid()}/fd/{archive_fd}'], check=True, timeout=60)
        environment = {**os.environ, 'WARDEN_LAB_SOCKET': str(session.run / 'containerd.sock'), 'WARDEN_LAB_DAEMON_PID': str(daemon.pid), 'WARDEN_LAB_OWNER_UID': str(uid), 'WARDEN_LAB_IMAGE_DIGEST': digest, 'WARDEN_LAB_IMAGE_NAME': image}
        if profile == 'api':
            environment['WARDEN_API_GATE_DIR'] = str(session.run / 'gate')
        if profile == 'api':
            run_api_test(test_fd, environment, daemon, cg_fd, session)
        else:
            subprocess.run([f'/proc/self/fd/{test_fd}', '-test.run', '^TestConformance$', '-test.v', '-test.count=1'], pass_fds=(test_fd,), env=environment, check=True, timeout=240)
        success = True
    finally:
        failures = []
        try:
            cleanup_owned(daemon, cg_fd, cg_parent, created_cgroup, session, release_evidence)
        except CleanupError as error:
            failures.extend(error.failures)
        except BaseException as error:
            failures.append(('cleanup owned resources', error))
        finally:
            # Descriptor release is also best effort: one close error must not
            # hide earlier failures or skip unrelated owned descriptors.
            for fd in [cg_fd, cg_parent, *artifacts]:
                if fd is not None:
                    try:
                        os.close(fd)
                    except BaseException as error:
                        failures.append(('close owned descriptor', error))
            try:
                session.close()
            except BaseException as error:
                failures.append(('close owned session', error))
        print('Dedicated session logs/config retained:', session.run)
        if failures:
            error = CleanupError(failures)
            print('CLEANUP FAILED; unverified state preserved:', session.run, error, file=sys.stderr)
            raise error
    return 0 if success else 1


def interrupted(signum, frame):
    raise KeyboardInterrupt(f'lab runner interrupted by signal {signum}')


def main():
    if sys.argv[1:] == ['--help']:
        print('Build: scripts/build-runtime-lab.sh')
        print('Secure project/cache ownership and modes; root-only dedicated lab: sudo env WARDEN_LAB_ACK=dedicated-warden-lab scripts/run-runtime-lab.sh')
        return 0
    if sys.argv[1:]:
        raise ValueError('unexpected runner arguments')
    signal.signal(signal.SIGTERM, interrupted)
    return run_lab()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print(error, file=sys.stderr)
        sys.exit(2)
