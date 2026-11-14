#!/usr/bin/env python3
"""Task 7's live AKS drill: one free-tier AKS cluster with one node, Azure CNI
powered by Cilium, workload identity, and the managed identity the control
plane's service account federates with (docs/aks-drill.md).

  aks_drill.py prices           refresh the Retail Prices API snapshots
  aks_drill.py plan             print the reservation plan and its estimate
  aks_drill.py up               arm the hard stop, reserve, then create
  aks_drill.py env -- CMD...    run CMD with the live tests' environment
  aks_drill.py status           time left before the hard stop, estimate so far
  aks_drill.py down [--reason]  delete both groups, then the teardown check

Every Azure call goes through scripts/azure_guard.py (pinned subscription,
exact error codes). The guard decides what may be reserved; this script only
creates what it reserved, from the same AKS_PROFILE.

The hard stop: before anything is reserved or created, `up` arms three
systemd user timers on this host (the user has lingering on, so they outlive
the login session): at start + 4 h, and 20 and 40 minutes after that, each
runs `down`. A run that fails part-way also runs `down` at once. The reaper
(scripts/azure_reaper.sh) deletes the cluster once its ttl tag (start +
5 h 15 min, which the reservation covers) has passed. Every one of these
needs the Azure CLI login to still work; a reboot drops the timers. The
person running the drill watches it and runs `down` by hand
(docs/aks-drill.md).
"""
import argparse
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_CEILING
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.request
from urllib.parse import quote_plus, urlencode

if __package__:
    from . import azure_guard as g
else:
    import azure_guard as g

ROOT = Path(__file__).resolve().parents[1]
PRICES = ROOT / 'docs/evidence/azure/prices/aks-drill-20261113-swedencentral'
# The run's state (no IDs; untracked). Its private files (kubeconfig, raw
# Azure answers with IDs, the drill's principals) are in g.AKS_PRIVATE,
# outside the repository.
STATE = ROOT / '.cache/aks-drill'
KUBECTL = ROOT / '.tools/kubectl/kubectl'
PROBE = STATE / 'warden-probe'
# The pods' image: busybox 1.36.1-azl3.0.20261022-amd64 from MCR, by digest
# (it has sh, cat, chmod, sleep and httpd; the probe binary is copied in).
CARRIER_IMAGE = 'mcr.microsoft.com/azurelinux/busybox@sha256:0c30d83ac4d5b06d6124a7b69618887dcb72424e82ec1d50010943e9e1b276bd'

REGION = g.AKS_REGION
SANDBOX_NAMESPACE = 'warden-lab'
FIC = 'warden-controlplane'
CONTROL_PLANE_SUBJECT = 'system:serviceaccount:warden-system:warden-controlplane'
AUDIENCE = 'api://AzureADTokenExchange'
PLANNED = Decimal(3)                 # hours the drill should take
HARD_STOP = timedelta(hours=4)       # teardown starts here, whatever state the drill is in
RETRIES = (0, 20, 40)                # minutes after the hard stop: one teardown timer each
LAST_RETRY = HARD_STOP + timedelta(minutes=RETRIES[-1])
RESERVED = Decimal('5.25')           # hours reserved (and the ttl): the last retry plus 35 minutes to delete
LOGIN_MARGIN = timedelta(minutes=5)  # a token az hands out must have at least this long left
LB_DATA_GB = Decimal(4)              # through the outbound rule, both ways (image pulls)
EGRESS_GB = Decimal(1)               # to the internet

PRICE_QUERIES = {
    'aks': f"armRegionName eq '{g.AKS_REGION}' and serviceName eq 'Azure Kubernetes Service' and priceType eq 'Consumption'",
    'vm': f"armRegionName eq '{g.AKS_REGION}' and serviceName eq 'Virtual Machines' and armSkuName eq 'Standard_B2as_v2' "
          "and priceType eq 'Consumption'",
    'disk': f"armRegionName eq '{g.AKS_REGION}' and serviceName eq 'Storage' and productName eq 'Premium SSD Managed Disks' "
            "and skuName eq 'P4 LRS' and priceType eq 'Consumption'",
    'load-balancer': "armRegionName eq 'Global' and serviceName eq 'Load Balancer' and priceType eq 'Consumption'",
    'public-ip': f"armRegionName eq '{g.AKS_REGION}' and serviceName eq 'Virtual Network' and productName eq 'IP Addresses' "
                 "and priceType eq 'Consumption'",
    'bandwidth': f"armRegionName eq '{g.AKS_REGION}' and serviceName eq 'Bandwidth' and productName eq 'Rtn Preference: MGN' "
                 "and priceType eq 'Consumption'",
    'managed-identity': g.NO_METER_FILTERS['identity'],
}
SNAPSHOT = {'aks_control_plane': 'aks', 'vm': 'vm', 'os_disk': 'disk', 'load_balancer': 'load-balancer',
            'load_balancer_data': 'load-balancer', 'public_ip': 'public-ip', 'network': 'bandwidth'}
GUID = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')


class DrillError(Exception):
    pass


def utc_now():
    return datetime.now(timezone.utc)


def stamp(t):
    return t.strftime('%Y-%m-%dT%H:%M:%SZ')


def log(event, **fields):
    print(json.dumps({'at': stamp(utc_now()), 'event': event, **fields}, sort_keys=True, default=str), flush=True)


def redact(value):
    """value without IDs: every GUID, and the subscription wherever it is."""
    text = json.dumps(value, sort_keys=True)
    return json.loads(GUID.sub('<id>', text))


def private():
    return g.AKS_PRIVATE


def private_write(name, value):
    private().mkdir(parents=True, exist_ok=True)
    private().chmod(0o700)
    path = private() / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, indent=2, sort_keys=True)
    return path


# --- prices ------------------------------------------------------------------

def price_url(flt):
    return 'https://prices.azure.com/api/retail/prices?' + urlencode({'$filter': flt, 'currencyCode': 'USD'},
                                                                      quote_via=quote_plus)


def fetch_prices(out=PRICES):
    out.mkdir(parents=True, exist_ok=True)
    for name, flt in PRICE_QUERIES.items():
        url = price_url(flt)
        with urllib.request.urlopen(url, timeout=60) as r:
            body = json.load(r)
        if body.get('NextPageLink'):
            raise DrillError(f'{name}: the answer has more than one page; narrow the filter')
        snap = {'url': url, 'retrieved_at': utc_now().isoformat(), 'response': body}
        (out / f'{name}.json').write_text(json.dumps(snap, indent=2) + '\n')
        log('price-snapshot', name=name, items=len(body['Items']))


# --- plan --------------------------------------------------------------------

def meter_item(category):
    service, product, sku, arm, meter, unit, region, tier = g.AKS_METERS[category]
    path = PRICES / (SNAPSHOT[category] + '.json')
    items = json.loads(path.read_text())['response']['Items']
    want = (service, product, sku, arm, meter, unit, region)
    found = [i for i in items if (i['serviceName'], i['productName'], i['skuName'], i['armSkuName'], i['meterName'],
                                  i['unitOfMeasure'], i['armRegionName']) == want
             and i['type'] == 'Consumption' and i['currencyCode'] == 'USD' and i['tierMinimumUnits'] == tier]
    if len(found) != 1:
        raise DrillError(f'{category}: {len(found)} meters in {path.name} match {want}')
    return path, found[0], tier


def quantities(hours):
    months = (hours / g.HOURS_PER_MONTH).quantize(Decimal('0.0001'), rounding=ROUND_CEILING)
    nodes = g.AKS_PROFILE['node_count']
    return {'aks_control_plane': hours, 'vm': hours * nodes, 'os_disk': months, 'load_balancer': hours,
            'load_balancer_data': LB_DATA_GB, 'public_ip': hours, 'network': EGRESS_GB}


def estimate(hours):
    """{category: (price, quantity, cost)} and the total for a run of hours."""
    rows, total = {}, Decimal(0)
    for category, q in quantities(hours).items():
        _, item, _ = meter_item(category)
        price = Decimal(str(item['retailPrice']))
        rows[category] = (price, q, price * q)
        total += price * q
    return rows, total


def build_plan(start, session):
    end = start + timedelta(hours=float(RESERVED))
    components = []
    for category, q in quantities(RESERVED).items():
        path, item, tier = meter_item(category)
        c = {'category': category, 'quote': str(path), 'quantity': str(q),
             'selector': {k: item[k] for k in sorted(g.SELECTORS)}}
        if tier:
            c['tier_minimum_units'] = str(tier)
        components.append(c)
    times = {'region': REGION, 'start': stamp(start), 'end': stamp(end)}
    return {'session': session, 'resources': [
        {'id': g.aks_id(), 'kind': 'aks', 'sku': 'free', 'product': 'Azure Kubernetes Service', **times,
         'configuration': g.AKS_PROFILE, 'components': components},
        {'id': g.identity_id(), 'kind': 'identity', 'sku': 'UserAssigned', 'product': 'Managed Identity', **times,
         'no_meter_quote': str(PRICES / 'managed-identity.json'), 'components': []}]}


def print_estimates():
    for label, hours in [('planned run', PLANNED), ('hard stop', Decimal(HARD_STOP.total_seconds()) / 3600),
                         ('last retry', (Decimal(LAST_RETRY.total_seconds()) / 3600).quantize(Decimal('0.0001'))),
                         ('reserved', RESERVED)]:
        rows, total = estimate(hours)
        print(f'{label} ({hours} h): ${total.quantize(Decimal("0.0001"))}')
        for category, (price, q, cost) in rows.items():
            print(f'  {category:20} {price} × {q} = {cost.quantize(Decimal("0.0001"))}')


# --- az ------------------------------------------------------------------------

def tag_args(tags):
    return [f'{k}={tags[k]}' for k in sorted(tags)]


def four(tags):
    return {k: tags[k] for k in ('project', 'owner', 'ttl', 'est_usd_per_hour')}


def create_command(tags):
    """`az aks create` for AKS_PROFILE, nothing else switched on."""
    p = g.AKS_PROFILE
    if (p['addons'] or p['acns'] or p['log_analytics'] or p['diagnostic_settings'] or p['csi_drivers'] or p['ssh']
            or not p['oidc_issuer'] or not p['workload_identity'] or not p['local_accounts']):
        raise DrillError('AKS_PROFILE asks for something this script does not create')
    return ['aks', 'create', '--resource-group', g.GROUP, '--name', g.AKS_CLUSTER, '--location', REGION,
            '--dns-name-prefix', p['dns_prefix'], '--tier', p['tier'], '--kubernetes-version', p['kubernetes_version'],
            '--nodepool-name', 'system', '--node-count', str(p['node_count']), '--node-vm-size', p['node_vm_size'],
            '--max-pods', str(p['max_pods']), '--node-osdisk-type', p['os_disk_type'],
            '--node-osdisk-size', str(p['os_disk_gb']), '--node-resource-group', p['node_resource_group'],
            '--network-plugin', p['network_plugin'], '--network-plugin-mode', p['network_plugin_mode'],
            '--network-dataplane', p['network_dataplane'], '--outbound-type', p['outbound_type'],
            '--load-balancer-sku', p['load_balancer_sku'],
            '--load-balancer-managed-outbound-ip-count', str(p['outbound_ips']),
            '--enable-managed-identity', '--enable-oidc-issuer', '--enable-workload-identity',
            '--disable-disk-driver', '--disable-file-driver', '--disable-snapshot-controller',
            '--no-ssh-key', '--ssh-access', 'disabled',
            '--auto-upgrade-channel', p['auto_upgrade'], '--node-os-upgrade-channel', p['node_os_upgrade'],
            '--tags', *tag_args(tags), '--nodepool-tags', *tag_args(tags)]


def cluster_mismatches(c):
    """How the cluster Azure created differs from AKS_PROFILE (empty: it does not)."""
    p = g.AKS_PROFILE
    pools = c.get('agentPoolProfiles') or []
    pool = pools[0] if len(pools) == 1 else {}
    net = c.get('networkProfile') or {}
    want = {
        'sku.tier': ((c.get('sku') or {}).get('tier'), 'Free'),
        'kubernetesVersion': (c.get('currentKubernetesVersion') or c.get('kubernetesVersion'), p['kubernetes_version']),
        'dnsPrefix': (c.get('dnsPrefix'), p['dns_prefix']),
        'nodeResourceGroup': (c.get('nodeResourceGroup'), p['node_resource_group']),
        'location': (c.get('location'), REGION),
        'agentPools': (len(pools), 1),
        'pool.count': (pool.get('count'), p['node_count']),
        'pool.vmSize': (pool.get('vmSize'), p['node_vm_size']),
        'pool.osDiskType': (pool.get('osDiskType'), p['os_disk_type']),
        'pool.osDiskSizeGb': (pool.get('osDiskSizeGb'), p['os_disk_gb']),
        'pool.enableAutoScaling': (bool(pool.get('enableAutoScaling')), False),
        'pool.scaleSetPriority': (pool.get('scaleSetPriority') or 'Regular', 'Regular'),
        'network.plugin': (net.get('networkPlugin'), p['network_plugin']),
        'network.pluginMode': (net.get('networkPluginMode'), p['network_plugin_mode']),
        'network.dataplane': (net.get('networkDataplane'), p['network_dataplane']),
        'network.outboundType': (net.get('outboundType'), p['outbound_type']),
        'network.loadBalancerSku': ((net.get('loadBalancerSku') or '').lower(), p['load_balancer_sku']),
        'oidcIssuer': (bool((c.get('oidcIssuerProfile') or {}).get('enabled')), True),
        'workloadIdentity': (bool(((c.get('securityProfile') or {}).get('workloadIdentity') or {}).get('enabled')), True),
        'disableLocalAccounts': (bool(c.get('disableLocalAccounts')), False),
    }
    out = [f'{k}: {got!r}, want {exp!r}' for k, (got, exp) in want.items() if got != exp]
    for name, addon in (c.get('addonProfiles') or {}).items():
        if (addon or {}).get('enabled'):
            out.append(f'add-on {name} is enabled')
    monitor = c.get('azureMonitorProfile') or {}
    for part in ('metrics', 'containerInsights', 'appMonitoring'):
        if (monitor.get(part) or {}).get('enabled'):
            out.append(f'azureMonitorProfile.{part} is enabled')
    security = c.get('securityProfile') or {}
    if ((security.get('defender') or {}).get('securityMonitoring') or {}).get('enabled'):
        out.append('Defender security monitoring is enabled')
    if ((net.get('advancedNetworking') or {}).get('enabled')):
        out.append('advanced container networking (ACNS) is enabled')
    if (c.get('costAnalysis') or ((c.get('metricsProfile') or {}).get('costAnalysis') or {}).get('enabled')):
        out.append('cost analysis is enabled')
    return out


def kubectl(*args, stdin=None):
    env = {**os.environ, 'HOME': str(ROOT / '.cache/home'), 'KUBECONFIG': str(private() / 'kubeconfig')}
    return subprocess.run([str(KUBECTL), *args], input=stdin, capture_output=True, text=True, timeout=300, env=env,
                          check=True).stdout


# --- the hard stop -------------------------------------------------------------

def timer_units(session):
    return [f'warden-aks-hardstop-{session}-{minutes}m' for minutes in RETRIES]


def arm(session, hard_stop):
    for unit, minutes in zip(timer_units(session), RETRIES):
        at = hard_stop + timedelta(minutes=minutes)
        subprocess.run(['systemd-run', '--user', '--unit', unit, '--description', f'Warden AKS drill teardown ({unit})',
                        '--on-calendar', at.strftime('%Y-%m-%d %H:%M:%S UTC'), '--timer-property=AccuracySec=1s',
                        '--working-directory', str(ROOT), '--setenv', 'PATH=/usr/bin:/bin', '--setenv', f'HOME={Path.home()}',
                        sys.executable, '-B', str(Path(__file__).resolve()), 'down', '--reason', f'hard-stop+{minutes}m'],
                       check=True, capture_output=True, text=True, timeout=60)
        state = subprocess.run(['systemctl', '--user', 'is-active', unit + '.timer'], capture_output=True, text=True,
                               timeout=60).stdout.strip()
        if state != 'active':
            raise DrillError(f'timer {unit} is {state!r}, not active')
        log('hard-stop-armed', unit=unit, at=stamp(at))


def disarm(session):
    for unit in timer_units(session):
        subprocess.run(['systemctl', '--user', 'stop', unit + '.timer'], capture_output=True, text=True, timeout=60)
        log('hard-stop-disarmed', unit=unit)


# --- state ---------------------------------------------------------------------

def load_state():
    path = STATE / 'state.json'
    return json.loads(path.read_text()) if path.exists() else None


def save_state(state):
    STATE.mkdir(parents=True, exist_ok=True)
    tmp = STATE / 'state.json.tmp'
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + '\n')
    tmp.replace(STATE / 'state.json')


# --- up ------------------------------------------------------------------------

def up():
    if load_state() is not None:
        raise DrillError(f'{STATE / "state.json"} exists: a drill was started; run `down` and check it first')
    pending = [k for k, approved in g.AKS_APPROVALS.items() if not approved]
    if pending:
        raise DrillError("AKS needs the user's approval first: " + ', '.join(pending) + ' (docs/aks-drill.md)')
    for path in (KUBECTL, PROBE):
        if not os.access(path, os.X_OK):
            raise DrillError(f'{path} is missing: scripts/restore-tools.sh kubectl; make aks-probe')
    start = (utc_now() + timedelta(minutes=1)).replace(second=0, microsecond=0)
    hard_stop = start + HARD_STOP
    ttl = start + timedelta(hours=float(RESERVED))
    for what, at in [('hard stop', hard_stop), ('last retry', start + LAST_RETRY), ('ttl', ttl)]:
        if at.astimezone().date() != start.astimezone().date():
            raise DrillError(f'the {what} ({at.astimezone():%Y-%m-%d %H:%M %Z}) would be after midnight: nothing overnight')
    session = 'aks-' + start.strftime('%Y%m%dT%H%MZ')
    login = check_login(ttl)
    # Read-only: nothing of the drill exists yet.
    if g.account_and_group() is not None or g.node_group() is not None:
        raise DrillError(f'{g.GROUP} or {g.NODE_GROUP} already exists')
    if any(c.get('name') == g.AKS_CLUSTER for c in g.az('aks', 'list')):
        raise DrillError(f'a cluster named {g.AKS_CLUSTER} already exists')
    plan = build_plan(start, session)
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    state = {'session': session, 'start': stamp(start), 'hard_stop': stamp(hard_stop), 'ttl': stamp(ttl),
             'last_retry': stamp(start + LAST_RETRY), 'timers': timer_units(session), 'login': login, 'phase': 'arming'}
    save_state(state)
    try:
        arm(session, hard_stop)
    except Exception:
        disarm(session)
        (STATE / 'state.json').unlink()
        raise
    state['phase'] = 'armed'
    save_state(state)
    try:
        g.reserve(plan, g.DEFAULT_LEDGER, g.DEFAULT_MARKDOWN)
    except Exception:
        disarm(session)
        (STATE / 'state.json').unlink()
        raise
    rows = {r['kind']: r for r in g.read_ledger(g.DEFAULT_LEDGER)['reservations'] if r['session'] == session}
    state['phase'] = 'creating'
    save_state(state)
    try:
        create(rows['aks']['tags'], rows['identity']['tags'], state)
    except BaseException as exc:
        log('up-failed', error=f'{type(exc).__name__}: {exc}')
        try:
            teardown('up-failed')
        except Exception as down_exc:  # the timers stay armed and retry
            log('up-failed-teardown-failed', error=str(down_exc))
        raise
    state['phase'] = 'up'
    save_state(state)
    log('up', session=session, hard_stop=state['hard_stop'])


def check_login(until):
    """The Azure CLI login, which every teardown path needs. It refuses when
    no token can be had now for Resource Manager, or when a second resource
    (Microsoft Graph) cannot be had, which needs the refresh token. The CLI
    cannot say how long the refresh token itself lives or whether a
    Conditional Access sign-in frequency will end it inside the window: that
    stays a risk (docs/aks-drill.md). Only expiry times are read, never a
    token."""
    user = (g.az('account', 'show').get('user') or {}).get('type')
    if user not in ('user', 'servicePrincipal'):
        raise DrillError(f'the Azure CLI login is of an unknown kind ({user!r})')
    now = utc_now().timestamp()
    left = {}
    for name, args in [('arm', ['--resource', 'https://management.azure.com/']), ('graph', ['--resource-type', 'ms-graph'])]:
        try:
            expires = g.az('account', 'get-access-token', *args, '--query', 'expires_on')
        except g.GuardError as exc:
            raise DrillError(f'the Azure CLI login cannot get a {name} token now ({exc}): log in again first') from None
        if not isinstance(expires, int) or expires - now < LOGIN_MARGIN.total_seconds():
            raise DrillError(f'the Azure CLI login hands out a {name} token about to expire: log in again first')
        left[name + '_token_minutes_left'] = round((expires - now) / 60)
    return {'user_type': user, **left, 'window_ends': stamp(until),
            'not_checked': 'how long the refresh token lives; Conditional Access sign-in frequency'}


def principals(found):
    """Keeps the drill's principals (private: they are object IDs) for the
    teardown check, which looks for role assignments they still hold."""
    path = private() / 'principals.json'
    have = json.loads(path.read_text()) if path.exists() else {}
    private_write('principals.json', {**have, **{k: v for k, v in found.items() if v}})


def ensure_node_group(tags):
    """The node group as down and reap require it: exactly NODE_GROUP,
    managed by the cluster, with the four tags. Tags AKS did not set are set
    here; anything else is a reason to tear down at once."""
    group = g.az('group', 'show', '--name', g.NODE_GROUP)
    if (group.get('id') != g.node_group_id() or group.get('name') != g.NODE_GROUP
            or (group.get('managedBy') or '').lower() != g.aks_id().lower()):
        raise DrillError(f'the node resource group is not {g.NODE_GROUP} managed by {g.AKS_CLUSTER}')
    missing = {k: v for k, v in four(tags).items() if k not in (group.get('tags') or {})}
    if missing:
        g.az('group', 'update', '--name', g.NODE_GROUP, '--set', *[f'tags.{k}={v}' for k, v in sorted(missing.items())])
        log('node-group-tagged', tags=sorted(missing))
    g.node_group()  # raises unless the group now passes the guard's own check


def create(aks_tags, identity_tags, state):
    g.az('group', 'create', '--name', g.GROUP, '--location', REGION, '--tags', *tag_args(four(aks_tags)))
    log('created', what='resource group', name=g.GROUP)
    identity = g.az('identity', 'create', '--resource-group', g.GROUP, '--name', g.AKS_IDENTITY, '--location', REGION,
                    '--tags', *tag_args(identity_tags))
    private_write('identity.json', identity)
    principals({'managed identity': identity.get('principalId')})
    log('created', what='managed identity', name=g.AKS_IDENTITY)
    cluster = g.az(*create_command(aks_tags), timeout=3600)
    private_write('cluster.json', cluster)
    principals({'cluster': (cluster.get('identity') or {}).get('principalId'),
                'kubelet': ((cluster.get('identityProfile') or {}).get('kubeletidentity') or {}).get('objectId'),
                **{'add-on ' + name: ((a or {}).get('identity') or {}).get('objectId')
                   for name, a in (cluster.get('addonProfiles') or {}).items()}})
    log('created', what='AKS cluster', name=g.AKS_CLUSTER)
    wrong = cluster_mismatches(cluster)
    if wrong:
        raise DrillError('the cluster is not AKS_PROFILE: ' + '; '.join(wrong))
    ensure_node_group(aks_tags)
    (STATE / 'cluster-summary.json').write_text(json.dumps(redact(summary(cluster)), indent=2, sort_keys=True) + '\n')
    issuer = cluster['oidcIssuerProfile']['issuerUrl']
    fic = g.az('identity', 'federated-credential', 'create', '--name', FIC, '--identity-name', g.AKS_IDENTITY,
               '--resource-group', g.GROUP, '--issuer', issuer, '--subject', CONTROL_PLANE_SUBJECT,
               '--audiences', AUDIENCE)
    private_write('federated-credential.json', fic)
    log('created', what='federated credential', name=FIC, subject=CONTROL_PLANE_SUBJECT)
    private().mkdir(parents=True, exist_ok=True)
    kubeconfig = private() / 'kubeconfig'
    g.az('aks', 'get-credentials', '--resource-group', g.GROUP, '--name', g.AKS_CLUSTER, '--admin',
         '--file', str(kubeconfig), '--overwrite-existing', empty_ok=True)
    kubeconfig.chmod(0o600)
    kubectl('create', 'namespace', SANDBOX_NAMESPACE)
    log('created', what='namespace', name=SANDBOX_NAMESPACE)
    state['tags'] = tag_audit(aks_tags)
    save_state(state)


def summary(cluster):
    keys = ['kubernetesVersion', 'currentKubernetesVersion', 'dnsPrefix', 'location', 'nodeResourceGroup', 'sku', 'networkProfile',
            'addonProfiles', 'azureMonitorProfile', 'oidcIssuerProfile', 'securityProfile', 'disableLocalAccounts',
            'autoUpgradeProfile', 'tags']
    out = {k: cluster.get(k) for k in keys}
    out['agentPoolProfiles'] = [{k: p.get(k) for k in ['name', 'mode', 'count', 'vmSize', 'osDiskType', 'osDiskSizeGb',
                                                         'osSku', 'maxPods', 'nodeImageVersion', 'orchestratorVersion',
                                                         'enableAutoScaling', 'scaleSetPriority', 'tags']}
                                for p in cluster.get('agentPoolProfiles') or []]
    if out.get('oidcIssuerProfile'):
        out['oidcIssuerProfile'] = {'enabled': out['oidcIssuerProfile'].get('enabled')}
    return out


def tag_audit(tags):
    """Every resource in both groups ends up with the four tags. AKS copies
    the cluster's tags to most of what it creates; a resource missing any of
    the four gets the cluster's value for it. Tags already there are kept."""
    want = four(tags)
    added = []
    for group in (g.GROUP, g.NODE_GROUP):
        for r in g.az('resource', 'list', '--resource-group', group):
            missing = {k: v for k, v in want.items() if k not in (r.get('tags') or {})}
            if missing:
                g.az('resource', 'tag', '--ids', r['id'], '--is-incremental', '--tags', *tag_args(missing))
                added.append({'type': r.get('type'), 'name': r.get('name'), 'tags': sorted(missing)})
    log('tag-audit', added=added)
    left = []
    for group in (g.GROUP, g.NODE_GROUP):
        for r in g.az('resource', 'list', '--resource-group', group):
            try:
                g.tags_valid(r.get('tags'))
            except g.GuardError:
                left.append(f"{r.get('type')}/{r.get('name')}")
    if left:
        raise DrillError('resources without the four tags: ' + ', '.join(left))
    return {'tagged_by_drill': added}


# --- down ----------------------------------------------------------------------

def teardown(reason):
    log('teardown', reason=reason)
    failed = None
    try:
        g.down(False, g.DEFAULT_LEDGER, g.DEFAULT_MARKDOWN)
    except Exception as exc:  # the check below still runs and says what is left
        failed = f'down: {type(exc).__name__}: {exc}'
        log('down-failed', error=failed)
    try:
        g.teardown_check(g.DEFAULT_LEDGER)
    except Exception as exc:
        failed = failed or f'teardown check: {exc}'
        log('teardown-check-failed', error=str(exc))
    if failed:
        raise DrillError(failed)
    state = load_state()
    if state:
        disarm(state['session'])
        state['phase'] = 'down'
        state['down'] = {'reason': reason, 'at': stamp(utc_now())}
        save_state(state)
    kubeconfig = private() / 'kubeconfig'
    if kubeconfig.exists():
        kubeconfig.unlink()
    log('down', reason=reason)


# --- env, status -----------------------------------------------------------------

def live_env():
    state = load_state()
    if not state or state.get('phase') != 'up':
        raise DrillError('no drill is up')
    cluster = g.az('aks', 'show', '--resource-group', g.GROUP, '--name', g.AKS_CLUSTER)
    identity = g.az('identity', 'show', '--resource-group', g.GROUP, '--name', g.AKS_IDENTITY)
    account = g.az('account', 'show')
    return {'WARDEN_LIVE_AKS': '1', 'WARDEN_LIVE_IDENTITY': '1', 'WARDEN_IDENTITY_TARGET': 'aks',
            'WARDEN_AKS_KUBECONFIG': str(private() / 'kubeconfig'), 'WARDEN_AKS_API_HOST': cluster['fqdn'],
            'WARDEN_KUBECTL': str(KUBECTL), 'WARDEN_AKS_CARRIER_IMAGE': CARRIER_IMAGE, 'WARDEN_AKS_PROBE': str(PROBE),
            'WARDEN_AKS_CLIENT_ID': identity['clientId'], 'WARDEN_AKS_PRINCIPAL_ID': identity['principalId'],
            'WARDEN_AKS_TENANT_ID': account['tenantId'], 'WARDEN_AKS_ISSUER': cluster['oidcIssuerProfile']['issuerUrl'],
            'WARDEN_AKS_HARD_STOP': state['hard_stop'], 'WARDEN_AZ': shutil.which('az') or 'az',
            'WARDEN_AZ_SUBSCRIPTION': g.subscription(), 'WARDEN_PRIVATE_OUT': str(private())}


def status():
    state = load_state()
    if not state:
        print('no drill state')
        return
    now = utc_now()
    start = datetime.fromisoformat(state['start'].replace('Z', '+00:00'))
    hard = datetime.fromisoformat(state['hard_stop'].replace('Z', '+00:00'))
    hours = Decimal(max(0, int((now - start).total_seconds()))) / 3600
    _, so_far = estimate(hours)
    print(json.dumps({'session': state['session'], 'phase': state['phase'], 'now': stamp(now),
                      'hard_stop': state['hard_stop'], 'minutes_left': round((hard - now).total_seconds() / 60, 1),
                      'estimate_so_far_usd': str(so_far.quantize(Decimal('0.0001')))}, indent=2))
    out = subprocess.run(['systemctl', '--user', 'list-timers', '--all', '--no-pager', 'warden-aks-hardstop-*'],
                         capture_output=True, text=True, timeout=60)
    print(out.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('prices')
    p = sub.add_parser('plan')
    p.add_argument('--start', help='UTC start, default the next minute')
    sub.add_parser('up')
    p = sub.add_parser('env')
    p.add_argument('cmd', nargs=argparse.REMAINDER)
    sub.add_parser('status')
    p = sub.add_parser('down')
    p.add_argument('--reason', default='manual')
    args = parser.parse_args()
    try:
        if args.command == 'prices':
            fetch_prices()
        elif args.command == 'plan':
            start = g.utc(args.start) if args.start else (utc_now() + timedelta(minutes=1)).replace(second=0, microsecond=0)
            print(json.dumps(redact(build_plan(start, 'aks-plan')), indent=2))
            print_estimates()
        elif args.command == 'up':
            up()
        elif args.command == 'env':
            cmd = args.cmd[1:] if args.cmd[:1] == ['--'] else args.cmd
            if not cmd:
                raise DrillError('usage: aks_drill.py env -- CMD...')
            env = {**os.environ, **live_env()}
            os.execvpe(cmd[0], cmd, env)
        elif args.command == 'status':
            status()
        else:
            teardown(args.reason)
    except (DrillError, g.GuardError, KeyError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print('aks drill refused: ' + str(exc), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
