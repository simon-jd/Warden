#!/usr/bin/env python3
"""The detector's smoke test: benign actions in Warden containers and in
non-Warden ones, on runc and on gVisor, through the whole chain, with the
host instance (the default detector).

    smoke.py all --out DIR    up, runc, gvisor, down, report (make detect-smoke)
    smoke.py runc --out DIR       (the detector must be up)
    smoke.py gvisor --out DIR     (the detector must be up; brings the k3s lab
                                   up --without-corpus and down again)
    smoke.py report --out DIR     bindings, alert_import, detection_metrics,
                                  recorder, observation, review groups, checks

runc, each action in its own Warden container (one run each):
* shell: an interactive shell (`docker exec -it`), which the stock rule
  "Terminal shell in container" describes;
* read: the container's own shell runs /bin/cat on a dummy /etc/shadow (no
  real hash), which "Read sensitive file untrusted" describes.
gVisor, host level, each in its own Warden pod (warden-lab, warden.dev/run):
* sandbox: a sandbox starts. This is not an action of the run and is not
  scored: the host sees runsc's sentry attach to its stubs with ptrace
  ("PTRACE attached to process"), which every sandbox does; the collector
  keeps it as platform start-up (platform-alerts.jsonl), and the smoke checks
  that it is there and that none of it is among the scored alerts;
* guest-read: the same read inside the sandbox; the host instance cannot see
  a sandbox's own system calls, so this one is expected not detected.
The controls (a container without project=warden; a pod in namespace
default) do the same, and nothing of them may be kept.

The image is warden-lab/detect-smoke:1, built FROM scratch out of the host's
statically linked /usr/bin/busybox (Ubuntu's busybox-static package; no
download). Everything the smoke creates carries owner=warden-lab and is
removed by exact name at the end.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bindings  # noqa: E402  (this directory: the smoke runs as python3 -I)
import detector  # noqa: E402
import recorder  # noqa: E402
import review  # noqa: E402

ROOT = detector.ROOT
CPUSET = detector.CPUSET
IMAGE = 'warden-lab/detect-smoke:1'
NODE = 'warden-k3s-gvisor'
ROLE = 'warden.detect/role'
BUSYBOX = Path('/usr/bin/busybox')
SHADOW = 'root:*:20000:0:99999:7:::\nnobody:*:20000:0:99999:7:::\n'
# The container's exit status is cat's, so a failed read is a failed execution.
READ = '/bin/sleep 1; /bin/cat /etc/shadow >/dev/null; s=$?; /bin/sleep 2; exit $s'
READ_THEN_SLEEP = '/bin/sleep 1; /bin/cat /etc/shadow >/dev/null; exec /bin/sleep 120'
# execution -> (ATT&CK tag of the stock rule, the rule the action should raise)
EXPECTED = {'smoke-runc-shell': ('T1059', 'Terminal shell in container'),
            'smoke-runc-read': ('T1555', 'Read sensitive file untrusted'),
            'smoke-gvisor-guest-read': ('T1555', 'Read sensitive file untrusted')}


def now():
    t = datetime.now(timezone.utc)
    return t.strftime('%Y-%m-%dT%H:%M:%S.') + '%06d000Z' % t.microsecond


def sh(argv, check=True, timeout=300, stdin=None, env=None):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, input=stdin, cwd=ROOT,
                            env=env or {'PATH': '/usr/bin:/bin', 'HOME': os.environ.get('HOME', ''), 'LC_ALL': 'C'})
    if check and result.returncode != 0:
        raise RuntimeError('%s failed (%d): %s' % (' '.join(argv[:6]), result.returncode, (result.stdout + result.stderr)[-2000:]))
    return result


def docker(*args, **kw):
    return sh(['/usr/bin/docker', '--host=unix:///var/run/docker.sock', *args], **kw)


def interactive(command):
    """Run command on a fresh pseudo-terminal (script(1)), typing `exit`."""
    return sh(['/usr/bin/script', '-q', '-e', '-c', command, '/dev/null'], check=False, stdin='exit\n', timeout=120)


def build_image(out):
    ctx = detector.DETECT / 'smoke-image'
    if ctx.exists():
        shutil.rmtree(ctx)
    (ctx / 'bin').mkdir(parents=True)
    (ctx / 'etc').mkdir()
    shutil.copyfile(BUSYBOX, ctx / 'bin/busybox')
    os.chmod(ctx / 'bin/busybox', 0o755)
    for applet in ('sh', 'sleep', 'cat'):
        os.symlink('busybox', ctx / 'bin' / applet)
    (ctx / 'etc/shadow').write_text(SHADOW)
    (ctx / 'etc/passwd').write_text('root:x:0:0:root:/:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/sh\n')
    # The modes go into the image as they are here (COPY --chmod would also
    # give the /etc it creates that mode, and a root without capabilities
    # could not enter it).
    for path, mode in (('bin', 0o755), ('etc', 0o755), ('etc/passwd', 0o644), ('etc/shadow', 0o600)):
        os.chmod(ctx / path, mode)
    (ctx / 'Dockerfile').write_text('FROM scratch\nCOPY bin/ /bin/\nCOPY etc/ /etc/\nENTRYPOINT ["/bin/sleep"]\nCMD ["120"]\n')
    docker('build', '-q', '--label', 'owner=warden-lab', '--label', ROLE + '=smoke', '-t', IMAGE, str(ctx))
    package = sh(['/usr/bin/dpkg', '-S', str(BUSYBOX)], check=False).stdout.strip()
    version = sh(['/usr/bin/dpkg-query', '-W', '-f', '${Package} ${Version}', package.split(':')[0]], check=False).stdout.strip() if package else ''
    image_id = docker('image', 'inspect', '--format', '{{.Id}}', IMAGE).stdout.strip()
    record = {'image': IMAGE, 'image_id': image_id, 'busybox_sha256': hashlib.sha256(BUSYBOX.read_bytes()).hexdigest(),
              'busybox_package': version, 'shadow_is_dummy': SHADOW}
    shutil.rmtree(ctx)
    return record


def container(name, labels, command, entrypoint=None):
    args = ['create', '--name', name, '--runtime', 'runc'] + (['--entrypoint', entrypoint] if entrypoint else []) + [ '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--cpuset-cpus', CPUSET, '--memory', '64m', '--memory-swap', '64m',
            '--pids-limit', '32', '--log-driver', 'json-file', '--log-opt', 'max-size=1m', '--label', 'owner=warden-lab',
            '--label', ROLE + '=smoke']
    for key, value in labels.items():
        args += ['--label', '%s=%s' % (key, value)]
    return docker(*args, IMAGE, *command).stdout.strip()


def runc(out, token):
    """Two Warden containers (one per action) and one control container."""
    record = {'runtime': 'runc', 'token': token, 'executions': [], 'containers': {}}
    warden_shell, warden_read, control = 'warden-detect-smoke-runc-shell', 'warden-detect-smoke-runc-read', 'warden-detect-control-runc'
    names = [warden_shell, warden_read, control]
    try:
        runs = {'shell': 'smoke-runc-shell-' + token, 'read': 'smoke-runc-read-' + token}
        ids = {
            warden_shell: container(warden_shell, {'project': 'warden', 'warden.dev/run': runs['shell']}, ['120']),
            warden_read: container(warden_read, {'project': 'warden', 'warden.dev/run': runs['read']}, ['-c', READ], '/bin/sh'),
            control: container(control, {'warden.detect/control': 'not-warden'}, ['-c', READ_THEN_SLEEP], '/bin/sh'),
        }
        for name, cid in ids.items():
            record['containers'][name] = cid
        executed = now()
        docker('start', warden_shell, control)
        read_at = now()
        docker('start', warden_read)
        time.sleep(2)
        shell = interactive('/usr/bin/docker exec -it %s /bin/sh' % warden_shell)
        control_shell = interactive('/usr/bin/docker exec -it %s /bin/sh' % control)
        record['executions'] = [
            {'execution_id': 'smoke-runc-shell', 'run_id': runs['shell'], 'technique_id': EXPECTED['smoke-runc-shell'][0],
             'executed_at': executed, 'outcome': 'succeeded' if shell.returncode == 0 else 'failed'},
            {'execution_id': 'smoke-runc-read', 'run_id': runs['read'], 'technique_id': EXPECTED['smoke-runc-read'][0],
             'executed_at': read_at, 'outcome': 'pending'}]
        record['control_shell_exit'] = control_shell.returncode
        exit_code = docker('wait', warden_read, timeout=60).stdout.strip()
        record['executions'][1]['outcome'] = 'succeeded' if exit_code == '0' else 'failed'
        time.sleep(3)
    finally:
        for name in names:
            if docker('container', 'inspect', name, check=False).returncode == 0:
                labels = json.loads(docker('container', 'inspect', name).stdout)[0]['Config']['Labels']
                if labels.get('owner') == 'warden-lab' and labels.get(ROLE) == 'smoke':
                    docker('rm', '-f', name)
    (out / 'smoke-runc.json').write_text(json.dumps(record, indent=1, sort_keys=True) + '\n')
    return record


def kubectl(*args, stdin=None, check=True, timeout=180):
    return docker('exec', '-i', NODE, 'kubectl', *args, stdin=stdin, check=check, timeout=timeout)


def pod(name, namespace, labels, command):
    return {'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'name': name, 'namespace': namespace, 'labels': {'owner': 'warden-lab', **labels}},
            'spec': {'runtimeClassName': 'gvisor', 'restartPolicy': 'Never', 'automountServiceAccountToken': False,
                     'enableServiceLinks': False, 'terminationGracePeriodSeconds': 1,
                     'containers': [{'name': 'smoke', 'image': 'docker.io/' + IMAGE, 'imagePullPolicy': 'Never',
                                     'command': command,
                                     'resources': {'limits': {'cpu': '500m', 'memory': '256Mi'}, 'requests': {'cpu': '500m', 'memory': '256Mi'}},
                                     'securityContext': {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False,
                                                         'capabilities': {'drop': ['ALL']}, 'seccompProfile': {'type': 'RuntimeDefault'}}}]}}


def sandbox_of(name):
    """The newest pod sandbox ID of a pod, from the node's CRI."""
    ids = docker('exec', NODE, 'crictl', 'pods', '--name', name, '-q', check=False).stdout.split()
    return ids[0] if ids else None


def gvisor_inner(out, token):
    """Inside `k3s_gvisor_lab.sh run --without-corpus`."""
    record = {'runtime': 'gvisor', 'token': token, 'executions': [], 'pods': {}}
    saved = subprocess.run(['/usr/bin/docker', '--host=unix:///var/run/docker.sock', 'save', IMAGE], capture_output=True, timeout=120, check=True,
                           env={'PATH': '/usr/bin:/bin'}).stdout
    imported = subprocess.run(['/usr/bin/docker', '--host=unix:///var/run/docker.sock', 'exec', '-i', NODE, 'ctr', '-n', 'k8s.io',
                               'images', 'import', '-'], input=saved, capture_output=True, timeout=120, env={'PATH': '/usr/bin:/bin'})
    if imported.returncode != 0:
        raise RuntimeError('ctr import failed: %s' % imported.stderr.decode()[-500:])
    runs = {'sandbox': 'smoke-gvisor-sandbox-' + token, 'guest-read': 'smoke-gvisor-guest-read-' + token}
    names = {'sandbox': ('warden-lab', 'warden-detect-smoke-sandbox'), 'guest-read': ('warden-lab', 'warden-detect-smoke-read'),
             'control': ('default', 'warden-detect-control')}
    pods = {'sandbox': pod(names['sandbox'][1], 'warden-lab', {'warden.dev/run': runs['sandbox']}, ['/bin/sleep', '15']),
            'guest-read': pod(names['guest-read'][1], 'warden-lab', {'warden.dev/run': runs['guest-read']}, ['/bin/sh', '-c', READ]),
            'control': pod(names['control'][1], 'default', {'warden.detect/control': 'not-warden'}, ['/bin/sh', '-c', READ_THEN_SLEEP])}
    # A namespace the lab has just made gets its default service account a
    # moment later; pods cannot be admitted before it exists.
    for _ in range(60):
        if kubectl('-n', 'warden-lab', 'get', 'serviceaccount', 'default', check=False).returncode == 0 and \
                kubectl('-n', 'default', 'get', 'serviceaccount', 'default', check=False).returncode == 0:
            break
        time.sleep(1)
    try:
        times = {}
        for key in ('sandbox', 'guest-read', 'control'):
            times[key] = now()
            kubectl('apply', '-f', '-', stdin=json.dumps(pods[key]))
            time.sleep(1)
        for key in ('sandbox', 'control'):
            namespace, name = names[key]
            kubectl('-n', namespace, 'wait', '--for=condition=Ready', 'pod/' + name, '--timeout=120s', check=False)
        kubectl('-n', 'warden-lab', 'wait', '--for=jsonpath={.status.phase}=Succeeded', 'pod/' + names['guest-read'][1],
                '--timeout=120s', check=False)
        time.sleep(3)
        for key, (namespace, name) in names.items():
            got = kubectl('-n', namespace, 'get', 'pod', name, '-o', 'json', check=False)
            if got.returncode == 0:
                data = json.loads(got.stdout)
                record['pods'][name] = {'namespace': namespace, 'phase': data['status'].get('phase'), 'sandbox': sandbox_of(name),
                                        'containers': [c.get('containerID') for c in data['status'].get('containerStatuses') or []]}
        phase = {key: record['pods'].get(names[key][1], {}).get('phase') for key in names}
        record['sandbox_started'] = phase['sandbox'] == 'Running'
        record['executions'] = [
            {'execution_id': 'smoke-gvisor-guest-read', 'run_id': runs['guest-read'],
             'technique_id': EXPECTED['smoke-gvisor-guest-read'][0], 'executed_at': times['guest-read'],
             'outcome': 'succeeded' if phase['guest-read'] == 'Succeeded' else 'failed'}]
    finally:
        kubectl('-n', 'warden-lab', 'delete', 'pod', names['sandbox'][1], names['guest-read'][1], '--grace-period=1',
                '--ignore-not-found', '--wait=true', check=False)
        kubectl('-n', 'default', 'delete', 'pod', names['control'][1], '--grace-period=1', '--ignore-not-found', '--wait=true',
                check=False)
        time.sleep(4)  # the host collector sees the pods go before the lab does
    (out / 'smoke-gvisor.json').write_text(json.dumps(record, indent=1, sort_keys=True) + '\n')
    return record


def gvisor(out, token):
    lab = sh([str(ROOT / 'scripts/k3s_gvisor_lab.sh'), 'run', '--without-corpus', '/usr/bin/taskset', '-c', CPUSET,
              '/usr/bin/python3', '-I', '-B', str(Path(__file__).resolve()), 'gvisor-inner', '--out', str(out), '--token', token],
             check=False, timeout=1800, env={'PATH': '/usr/bin:/bin', 'HOME': os.environ.get('HOME', ''), 'LC_ALL': 'C',
                                            'WARDEN_LAB_CPUSET': CPUSET})
    (out / 'gvisor-lab.log').write_text(lab.stdout + lab.stderr)
    if lab.returncode != 0:
        raise RuntimeError('gVisor smoke failed (%d); see %s' % (lab.returncode, out / 'gvisor-lab.log'))


def jsonl(rows):
    return ''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows)


def report(out, session=None):
    state = detector.load_state()
    session = session or state['session']
    data = detector.DATA / session
    host = data / 'host'
    runs = [json.loads((out / ('smoke-%s.json' % r)).read_text()) for r in ('runc', 'gvisor') if (out / ('smoke-%s.json' % r)).exists()]
    executions = [e for r in runs for e in r['executions']]
    registry = [json.loads(line) for line in (host / 'registry.jsonl').read_text().splitlines() if line.strip()] \
        if (host / 'registry.jsonl').exists() else []
    bound, errors = [], {}
    for e in executions:
        try:
            bound.append(bindings.binding(registry, run_id=e['run_id'], execution_id=e['execution_id']))
        except ValueError as error:
            errors[e['execution_id']] = str(error)
    (out / 'executions.jsonl').write_text(jsonl(executions))
    (out / 'bindings.jsonl').write_text(jsonl(bound))
    (out / 'expected-rules.jsonl').write_text(jsonl({'execution_id': e['execution_id'], 'rule_id': EXPECTED[e['execution_id']][1]}
                                                    for e in executions))
    kept = (host / 'alerts.jsonl').read_bytes() if (host / 'alerts.jsonl').exists() else b''
    (out / 'falco-warden-alerts.jsonl').write_bytes(kept)
    for name in ('alerts.jsonl', 'alert-provenance.jsonl', 'review-groups.jsonl', 'review-map-template.jsonl', 'coverage.jsonl',
                 'explain.jsonl'):
        if (out / name).exists():
            (out / name).unlink()
    py = ['/usr/bin/python3', '-E', '-s', '-B', '-m']
    imported = sh(py + ['detect.report.alert_import', '--falco', str(out / 'falco-warden-alerts.jsonl'), '--bindings', str(out / 'bindings.jsonl'),
                        '--expected-rules', str(out / 'expected-rules.jsonl'), '--out', str(out / 'alerts.jsonl'),
                        '--provenance', str(out / 'alert-provenance.jsonl')], check=False)
    observed = now()
    metrics = sh(py + ['detect.report.detection_metrics', '--executions', str(out / 'executions.jsonl'),
                       '--alerts', str(out / 'alerts.jsonl'), '--observed-until', observed], check=False)
    (out / 'alert-import.out').write_text(imported.stdout + imported.stderr)
    (out / 'metrics.json').write_text(metrics.stdout + metrics.stderr)
    checks = {'bindings_for_every_execution': not errors, 'alert_import_exit_0': imported.returncode == 0,
              'detection_metrics_exit_0': metrics.returncode == 0}
    status = {}
    if metrics.returncode == 0:
        status = {row['execution_id']: row['status'] for row in json.loads(metrics.stdout)['executions']}
    checks['runc_shell_detected'] = status.get('smoke-runc-shell') == 'detected'
    checks['runc_read_detected'] = status.get('smoke-runc-read') == 'detected'
    # A sandbox start is platform start-up: seen, kept as platform, never scored.
    platform_lines = (host / 'platform-alerts.jsonl').read_bytes() if (host / 'platform-alerts.jsonl').exists() else b''
    warden_sandbox = next((r.get('pods', {}).get('warden-detect-smoke-sandbox', {}).get('sandbox') for r in runs
                           if r.get('runtime') == 'gvisor'), None)
    checks['gvisor_sandbox_start_seen_as_platform'] = bool(warden_sandbox) and warden_sandbox[:12].encode() in platform_lines
    checks['gvisor_sandbox_start_not_scored'] = bool(warden_sandbox) and warden_sandbox[:12].encode() not in kept
    checks['no_platform_alert_imported'] = not any(json.loads(l)['rule_id'] == 'PTRACE attached to process'
                                                   for l in (out / 'alerts.jsonl').read_text().splitlines()) \
        if (out / 'alerts.jsonl').exists() else True
    checks['gvisor_guest_read_not_seen_as_expected'] = status.get('smoke-gvisor-guest-read') == 'not_detected_by_cutoff'
    controls = []
    for r in runs:
        for name, cid in (r.get('containers') or {}).items():
            if 'control' in name:
                controls.append(cid)
        for name, info in (r.get('pods') or {}).items():
            if 'control' in name:
                controls += [c.split('://', 1)[1] for c in info['containers'] if c] + ([info['sandbox']] if info.get('sandbox') else [])
    everything = b''.join(p.read_bytes() for p in data.rglob('*') if p.is_file())
    checks['control_ids_known'] = len(controls) >= 3
    checks['control_never_kept'] = all(c[:12].encode() not in everything for c in controls)
    counts = json.loads((host / 'heartbeats.jsonl').read_text().splitlines()[-1])['counts']
    checks['runc_control_only_counted'] = counts['dropped_other_lab_owned'] > 0
    checks['gvisor_control_pod_only_counted'] = counts['dropped_other_lab_pod'] > 0
    scopes = [json.loads(line) for line in (host / 'scoping.jsonl').read_text().splitlines()] if (host / 'scoping.jsonl').exists() else []
    (out / 'falco-platform-alerts.jsonl').write_bytes(platform_lines)
    alerts = [json.loads(line) for line in (kept + platform_lines).decode().splitlines() if line.strip()]
    found = review.groups(alerts, scopes)
    (out / 'review-groups.jsonl').write_text(jsonl(found))
    (out / 'review-map-template.jsonl').write_text(jsonl(review.template(found)))
    # The smoke window through recorder.py and observation.py: accepted, and
    # (no benign workload, minutes not days) not an eligible window.
    window = json.loads((out / 'window.json').read_text()) if (out / 'window.json').exists() else None
    if window:
        explain = []
        rows = recorder.intervals([(l.encode(), json.loads(l)) for l in (host / 'heartbeats.jsonl').read_text().splitlines()],
                                  [(l.encode(), json.loads(l)) for l in (host / 'health.jsonl').read_text().splitlines()], [],
                                  source_id='falco-host', runtimes=('runc', 'gvisor'), start=window['start'], end=window['end'],
                                  period=3600, max_gap=90, snapshot_gap=150, explain=explain)
        (out / 'coverage.jsonl').write_text(jsonl(rows))
        (out / 'explain.jsonl').write_text(jsonl(explain))
        (out / 'normal-alerts-none.jsonl').write_text('')
        obs = sh(py + ['detect.report.observation', '--coverage', str(out / 'coverage.jsonl'),
                       '--normal-alerts', str(out / 'normal-alerts-none.jsonl'), '--source', 'falco-host',
                       '--start', window['start'], '--end', window['end'], '--observed-until', window['end']], check=False)
        (out / 'observation.json').write_text(obs.stdout + obs.stderr)
        checks['observation_exit_0'] = obs.returncode == 0
        checks['smoke_window_contiguous'] = bool(rows) and rows[0]['start'] == window['start'] and rows[-1]['end'] == window['end']
    result = {'session': session, 'observed_until': observed, 'checks': checks, 'execution_status': status,
              'binding_errors': errors, 'collector_counts': counts, 'review_groups': len(found)}
    (out / 'checks.json').write_text(json.dumps(result, indent=1, sort_keys=True) + '\n')
    print(json.dumps(result, indent=1, sort_keys=True))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('all', 'image', 'runc', 'gvisor', 'gvisor-inner', 'report'))
    parser.add_argument('--out', required=True)
    parser.add_argument('--token', default=secrets.token_hex(4))
    parser.add_argument('--session')
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    host = detector.Host()
    if args.command == 'gvisor-inner':
        gvisor_inner(out, args.token)
        return 0
    if args.command == 'report':
        report(out, args.session)
        return 0
    if args.command == 'all':
        state = detector.up(host)
        # The window starts where the records can: the first heartbeat after
        # Falco's first counting snapshot.
        started = detector.first_healthy_point(host, state['session'])
        try:
            image = build_image(out)
            (out / 'smoke-image.json').write_text(json.dumps(image, indent=1, sort_keys=True) + '\n')
            runc(out, args.token)
            try:
                gvisor(out, args.token)
            except RuntimeError as error:
                # Recorded, and the report still runs: the runc half stands on its own.
                (out / 'gvisor-error.txt').write_text(str(error) + '\n')
        finally:
            docker('image', 'rm', IMAGE, check=False)
            time.sleep(5)
            # The window ends at a flushed heartbeat before down, so a later
            # heartbeat brackets it and the last record ends exactly there.
            ended = now()
            detector.flush(host, state['session'])
            detector.down(host)
        (out / 'window.json').write_text(json.dumps({'start': started, 'end': ended}) + '\n')
        report(out)
        return 0
    if args.command == 'image':
        (out / 'smoke-image.json').write_text(json.dumps(build_image(out), indent=1, sort_keys=True) + '\n')
    elif args.command == 'runc':
        runc(out, args.token)
    elif args.command == 'gvisor':
        gvisor(out, args.token)
    return 0


if __name__ == '__main__':
    sys.exit(main())
