"""Offline tests of scripts/aks_drill.py. Azure, systemd and kubectl are fakes;
the committed Retail Prices snapshots and the real guard are not."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SUB = '11111111-2222-4333-8444-555555555555'
PREFIX = f'/subscriptions/{SUB}/resourceGroups/rg-warden-lab'
AKS_ID = PREFIX + '/providers/Microsoft.ContainerService/managedClusters/warden-lab-aks'
NODES = f'/subscriptions/{SUB}/resourceGroups/rg-warden-lab-aks-nodes'

FAKE_AZ = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
F = os.environ['FAKE_STATE']
d = json.load(open(F))
d['calls'].append(a)
def save(): json.dump(d, open(F, 'w'))
def arg(k): return a[a.index(k) + 1] if k in a else None
def out(v):
    save(); print(json.dumps(v)); sys.exit(0)
def fail(code):
    save(); print('ERROR: (' + code + ') fake', file=sys.stderr); sys.exit(3)
if arg('--subscription') != os.environ['FAKE_SUB']: fail('WrongSubscription')
for prefix in d.get('fail', []):
    if a[:len(prefix)] == prefix: fail('FakeFailure')
tags = lambda: dict(t.split('=', 1) for t in a[a.index('--tags') + 1:] if '=' in t and not t.startswith('--')) if '--tags' in a else {}
head = a[:2]
if head == ['account', 'show']:
    out({'id': os.environ['FAKE_SUB'], 'name': 'Azure for Students', 'state': 'Enabled', 'tenantId': 'tenant',
         'user': {'type': 'user', 'name': 'someone'}})
if head == ['account', 'get-access-token']:
    if a[a.index('--query') + 1] != 'expires_on': fail('WouldPrintTheToken')
    if '--resource-type' in a and d.get('graph_fails'): fail('InteractionRequired')
    out(int(os.environ['FAKE_NOW']) + d.get('token_seconds', 3600))
if a[:3] == ['policy', 'assignment', 'list']:
    out([{'name': 'sys.regionrestriction', 'enforcementMode': 'Default',
          'policyDefinitionId': '/providers/Microsoft.Authorization/policyDefinitions/b86dabb9-b578-4d7b-b842-3b45e95769a1',
          'parameters': {'listOfAllowedLocations': {'value': ['norwayeast', 'francecentral', 'denmarkeast', 'swedencentral', 'westus']}}}])
if a[:3] == ['role', 'assignment', 'list']: out([])
if head == ['group', 'update']:
    g = d['groups'][arg('--name')]
    for kv in a[a.index('--set') + 1:]:
        if kv.startswith('tags.'):
            k, v = kv[5:].split('=', 1); g['tags'] = {**(g.get('tags') or {}), k: v}
    out(g)
if head == ['group', 'show']:
    g = d['groups'].get(arg('--name'))
    out(g) if g else fail('ResourceGroupNotFound')
if head == ['group', 'create']:
    name = arg('--name')
    d['groups'][name] = {'id': os.environ['FAKE_PREFIX'], 'name': name, 'managedBy': None, 'tags': tags()}
    d['resources'][name] = []
    out(d['groups'][name])
if head == ['group', 'delete']:
    d['groups'].pop(arg('--name'), None); d['resources'].pop(arg('--name'), None)
    save(); sys.exit(0)
if head == ['group', 'list']: out(list(d['groups'].values()))
if head == ['identity', 'create']:
    i = {'id': os.environ['FAKE_PREFIX'] + '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/' + arg('--name'),
         'name': arg('--name'), 'type': 'Microsoft.ManagedIdentity/userAssignedIdentities', 'clientId': 'c', 'principalId': 'p-uami',
         'resourceGroup': 'rg-warden-lab', 'tags': tags()}
    d['resources']['rg-warden-lab'].append(i); out(i)
if head == ['identity', 'list']:
    out([r for rs in d['resources'].values() for r in rs if r['type'].endswith('userAssignedIdentities')])
if a[:3] == ['identity', 'federated-credential', 'create']: out({'name': arg('--name'), 'subject': arg('--subject')})
if head == ['aks', 'list']: out([d['aks']] if d.get('aks') else [])
if head == ['aks', 'show']: out(d['aks']) if d.get('aks') else fail('ResourceNotFound')
if head == ['aks', 'create']:
    c = json.loads(os.environ['FAKE_CLUSTER']); c['tags'] = tags()
    d['aks'] = c
    d['resources']['rg-warden-lab'].append({'id': c['id'], 'name': c['name'], 'type': 'Microsoft.ContainerService/managedClusters', 'tags': tags()})
    d['groups']['rg-warden-lab-aks-nodes'] = {'id': os.environ['FAKE_NODES'], 'name': 'rg-warden-lab-aks-nodes',
                                              'managedBy': d.get('node_group_managed_by', c['id']),
                                              'tags': None if d.get('node_group_untagged') else
                                              {k: tags()[k] for k in ['project', 'owner', 'ttl', 'est_usd_per_hour']}}
    d['resources']['rg-warden-lab-aks-nodes'] = [
        {'id': os.environ['FAKE_NODES'] + '/providers/Microsoft.Network/loadBalancers/kubernetes', 'name': 'kubernetes',
         'type': 'Microsoft.Network/loadBalancers', 'tags': tags()},
        {'id': os.environ['FAKE_NODES'] + '/providers/Microsoft.Compute/disks/osdisk', 'name': 'osdisk',
         'type': 'Microsoft.Compute/disks', 'tags': None}]
    out(c)
if head == ['aks', 'delete']:
    d.pop('aks', None); d['groups'].pop('rg-warden-lab-aks-nodes', None); d['resources'].pop('rg-warden-lab-aks-nodes', None)
    d['resources']['rg-warden-lab'] = [r for r in d['resources'].get('rg-warden-lab', []) if 'managedClusters' not in r['type']]
    save(); sys.exit(0)
if head == ['aks', 'get-credentials']:
    open(arg('--file'), 'w').write('apiVersion: v1\n'); save(); sys.exit(0)
if head == ['resource', 'list'] and '--tag' in a:
    out([r for rs in d['resources'].values() for r in rs])
if head == ['resource', 'list']: out(d['resources'].get(arg('--resource-group'), []))
if head == ['resource', 'tag']:
    for rs in d['resources'].values():
        for r in rs:
            if r['id'] == arg('--ids'): r['tags'] = {**(r['tags'] or {}), **tags()}
    out({})
if a[:3] == ['security', 'pricing', 'show']: out({'name': arg('--name'), 'pricingTier': 'Free'})
if a[:3] == ['network', 'watcher', 'list']:
    out([{'id': '/subscriptions/' + os.environ['FAKE_SUB'] + '/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_swedencentral',
          'name': 'NetworkWatcher_swedencentral', 'location': 'swedencentral', 'resourceGroup': 'NetworkWatcherRG', 'tags': None,
          'provisioningState': 'Succeeded', 'etag': 'W/"e"'}])
if head == ['vm', 'list-usage']:
    out([{'name': {'value': 'cores'}, 'currentValue': 0, 'limit': 6}, {'name': {'value': 'standardBasv2Family'}, 'currentValue': 0, 'limit': 10}])
fail('UnexpectedCommand')
'''

GIT = r'''#!/usr/bin/env python3
import sys
a = sys.argv[1:]
if a[:1] != ['-C'] or a[2:] != ['worktree', 'list', '--porcelain']: sys.exit(2)
print('worktree ' + a[1] + '\nHEAD 0\nbranch refs/heads/x\n')
'''

LOGGER = r'''#!/usr/bin/env python3
import json, os, sys
d = json.load(open(os.environ['FAKE_STATE']))
d['calls'].append([os.path.basename(sys.argv[0])] + sys.argv[1:])
json.dump(d, open(os.environ['FAKE_STATE'], 'w'))
if os.path.basename(sys.argv[0]) == 'systemctl' and 'is-active' in sys.argv:
    print(os.environ.get('FAKE_TIMER_STATE', 'active'))
'''

CLUSTER = {
    'id': AKS_ID, 'name': 'warden-lab-aks', 'location': 'swedencentral', 'kubernetesVersion': '1.36.5', 'dnsPrefix': 'warden-lab-aks',
    'currentKubernetesVersion': '1.36.5', 'nodeResourceGroup': 'rg-warden-lab-aks-nodes',
    'sku': {'name': 'Base', 'tier': 'Free'}, 'fqdn': 'warden-lab-aks-x.hcp.swedencentral.azmk8s.io',
    'identity': {'type': 'SystemAssigned', 'principalId': 'p-cluster'},
    'identityProfile': {'kubeletidentity': {'objectId': 'p-kubelet', 'clientId': 'k'}},
    'agentPoolProfiles': [{'name': 'system', 'mode': 'System', 'count': 1, 'vmSize': 'Standard_B2as_v2',
                           'osDiskType': 'Managed', 'osDiskSizeGb': 30, 'enableAutoScaling': False,
                           'scaleSetPriority': None}],
    'networkProfile': {'networkPlugin': 'azure', 'networkPluginMode': 'overlay', 'networkDataplane': 'cilium',
                       'networkPolicy': 'cilium', 'outboundType': 'loadBalancer', 'loadBalancerSku': 'standard'},
    'oidcIssuerProfile': {'enabled': True,
                          'issuerUrl': 'https://swedencentral.oic.prod-aks.azure.com/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/ffffffff-0000-4111-8222-333333333333/'},
    'securityProfile': {'workloadIdentity': {'enabled': True}}, 'addonProfiles': None, 'azureMonitorProfile': None,
    'disableLocalAccounts': False}


class AKSDrillTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.d = Path(self.temp.name)
        (self.d / 'bin').mkdir()
        (self.d / 'bin/az').write_text(FAKE_AZ)
        (self.d / 'bin/git').write_text(GIT)
        for name in ['systemd-run', 'systemctl', 'kubectl']:
            (self.d / 'bin' / name).write_text(LOGGER)
        for f in (self.d / 'bin').iterdir():
            f.chmod(0o755)
        (self.d / 'probe').write_text('#!/bin/sh\n')
        (self.d / 'probe').chmod(0o755)
        self.scope = self.d / 'azure-subscription'
        self.scope.write_text(SUB + '\n')
        self.scope.chmod(0o600)
        self.fake = self.d / 'fake.json'
        self.fake.write_text(json.dumps({'calls': [], 'groups': {}, 'resources': {}}))
        self.ledger = self.d / 'azure-spend.json'
        import hashlib
        self.ledger.write_text(json.dumps({'version': 2, 'subscription_sha256': hashlib.sha256(SUB.encode()).hexdigest(),
                                           'group': 'rg-warden-lab', 'reservations': []}))
        self.env = dict(os.environ, PATH=f'{self.d / "bin"}:{os.environ["PATH"]}', FAKE_STATE=str(self.fake),
                        FAKE_SUB=SUB, FAKE_PREFIX=PREFIX, FAKE_NODES=NODES, FAKE_CLUSTER=json.dumps(CLUSTER))
        self.now = '2026-11-14T17:00:20+00:00'  # 09:00 in Los Angeles, after the price snapshots

    def drill(self, *args, approve=True, extra=''):
        d = self.d
        # Local time is Los Angeles' for every run: "nothing overnight" is about its midnight.
        code = ("import os, time; os.environ['TZ']='America/Los_Angeles'; time.tzset(); "
                'from scripts import aks_drill as d; from scripts import azure_guard as g; from datetime import datetime; '
                'from pathlib import Path; '
                f'g.SCOPE_FILE=Path({str(self.scope)!r}); g.DEFAULT_LEDGER=Path({str(self.ledger)!r}); '
                f'g.DEFAULT_MARKDOWN=Path({str(d / "azure-spend.md")!r}); g.NODE_GROUP_WAIT=(1, 0); '
                f'd.STATE=Path({str(d / "state")!r}); g.AKS_PRIVATE=Path({str(d / "private")!r}); '
                f'd.KUBECTL=Path({str(d / "bin/kubectl")!r}); d.PROBE=Path({str(d / "probe")!r}); '
                f'd.utc_now=lambda: datetime.fromisoformat({self.now!r}); '
                + ("" if approve else "g.AKS_APPROVALS['premium_os_disk']=False; ")
                + extra + f'import sys; sys.argv=["aks_drill.py", *{list(args)!r}]; d.main()')
        from datetime import datetime
        self.env['FAKE_NOW'] = str(int(datetime.fromisoformat(self.now).timestamp()))
        return subprocess.run([sys.executable, '-B', '-c', code], env=self.env, cwd=ROOT, text=True, capture_output=True)

    def state(self):
        return json.loads(self.fake.read_text())

    def calls(self):
        return self.state()['calls']

    def index(self, pred):
        return next((i for i, c in enumerate(self.calls()) if pred(c)), None)

    def test_committed_snapshots_price_a_plan_the_guard_accepts(self):
        code = ('from scripts import aks_drill as d; from scripts import azure_guard as g; import json; '
                'from pathlib import Path; from decimal import Decimal; '
                f'g.SCOPE_FILE=Path({str(self.scope)!r}); '
                "plan=d.build_plan(g.utc('2026-11-14T17:00:00Z'), 'aks-test'); "
                f"g.reserve(plan, Path({str(self.ledger)!r}), Path({str(self.d / 'spend.md')!r})); "
                "print(json.dumps({k: str(d.estimate(Decimal(h))[1]) for k, h in [('planned', 3), ('hard_stop', 4), ('reserved', '5.25')]}))")
        p = subprocess.run([sys.executable, '-B', '-c', code], env=self.env, cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        rows = json.loads(self.ledger.read_text())['reservations']
        # swedencentral, 5.25 h: 0.05·5.25 + 0.0778·5.25 + 5.8072·0.0072 + 0.025·5.25 + 0.005·4 + 0.005·5.25 + 0.087·1
        self.assertEqual([(r['kind'], r['estimate_usd']) for r in rows], [('aks', '0.97726184'), ('identity', '0')])
        self.assertEqual(rows[0]['end'], '2026-11-14T22:15:00Z')
        self.assertEqual(rows[0]['region'], 'swedencentral')
        est = json.loads(p.stdout.splitlines()[-1])
        self.assertLess(float(est['planned']), 1.0)
        self.assertLess(float(est['hard_stop']), 1.0)
        self.assertEqual(est['reserved'], '0.97726184')

    def test_create_command_switches_on_only_the_profile(self):
        code = ('from scripts import aks_drill as d; import json; '
                "print(json.dumps(d.create_command({'project': 'warden', 'owner': 'warden-lab', 'ttl': 't', 'est_usd_per_hour': '1'})))")
        p = subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        cmd = json.loads(p.stdout)
        pairs = {cmd[i]: cmd[i + 1] for i in range(len(cmd) - 1) if cmd[i].startswith('--')}
        for flag, value in [('--tier', 'free'), ('--node-count', '1'), ('--node-vm-size', 'Standard_B2as_v2'),
                            ('--node-resource-group', 'rg-warden-lab-aks-nodes'), ('--network-plugin', 'azure'),
                            ('--network-plugin-mode', 'overlay'), ('--network-dataplane', 'cilium'),
                            ('--node-osdisk-type', 'Managed'), ('--node-osdisk-size', '30'),
                            ('--outbound-type', 'loadBalancer'), ('--load-balancer-managed-outbound-ip-count', '1'),
                            ('--kubernetes-version', '1.36.5'), ('--location', 'swedencentral'), ('--ssh-access', 'disabled'),
                            ('--dns-name-prefix', 'warden-lab-aks')]:
            self.assertEqual(pairs.get(flag), value, flag)
        for flag in ['--enable-oidc-issuer', '--enable-workload-identity', '--no-ssh-key', '--disable-disk-driver']:
            self.assertIn(flag, cmd)
        for word in ['--enable-addons', '--enable-azure-monitor-metrics', '--enable-acns', '--generate-ssh-keys',
                     '--enable-cost-analysis', '--workspace-resource-id', '--enable-defender', '--uptime-sla',
                     '--enable-cluster-autoscaler', '--zones', '--priority']:
            self.assertNotIn(word, cmd)
        self.assertEqual(cmd[cmd.index('--tags') + 1:cmd.index('--nodepool-tags')],
                         ['est_usd_per_hour=1', 'owner=warden-lab', 'project=warden', 'ttl=t'])

    def test_cluster_mismatches_name_every_difference_from_the_profile(self):
        cases = [(['sku', 'tier'], 'Standard'), (['nodeResourceGroup'], 'MC_rg-warden-lab_warden-lab-aks_westus2'),
                 (['agentPoolProfiles', 0, 'count'], 2), (['agentPoolProfiles', 0, 'vmSize'], 'Standard_B2s_v2'),
                 (['agentPoolProfiles', 0, 'osDiskType'], 'Ephemeral'), (['agentPoolProfiles', 0, 'scaleSetPriority'], 'Spot'),
                 (['networkProfile', 'networkDataplane'], 'azure'), (['networkProfile', 'outboundType'], 'managedNATGateway'),
                 (['addonProfiles'], {'omsagent': {'enabled': True}}),
                 (['azureMonitorProfile'], {'metrics': {'enabled': True}}),
                 (['securityProfile', 'workloadIdentity', 'enabled'], False), (['location'], 'westus'),
                 (['dnsPrefix'], 'warden-lab-aks-1234abcd')]
        code = ('from scripts import aks_drill as d; import json, sys; '
                'print(json.dumps(d.cluster_mismatches(json.loads(sys.stdin.read()))))')
        run = lambda c: json.loads(subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT, text=True, input=json.dumps(c),
                                                  capture_output=True, check=True).stdout)
        self.assertEqual(run(CLUSTER), [])
        for path, value in cases:
            with self.subTest(path=path):
                c = json.loads(json.dumps(CLUSTER))
                node = c
                for k in path[:-1]:
                    node = node[k]
                node[path[-1]] = value
                self.assertEqual(len(run(c)), 1, path)

    def test_up_arms_the_hard_stop_before_anything_is_reserved_or_created(self):
        p = self.drill('up')
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        calls = self.calls()
        armed = [c for c in calls if c[0] == 'systemd-run']
        self.assertEqual([c[c.index('--on-calendar') + 1] for c in armed],
                         ['2026-11-14 21:01:00 UTC', '2026-11-14 21:21:00 UTC', '2026-11-14 21:41:00 UTC'])
        self.assertTrue(all(c[-3:-1] == ['down', '--reason'] for c in armed))
        first_create = self.index(lambda c: c[0] != 'systemd-run' and 'create' in c[:3])
        self.assertLess(self.index(lambda c: c[0] == 'systemd-run'), first_create)
        self.assertLess(max(i for i, c in enumerate(calls) if c[0] == 'systemctl'), first_create)
        rows = json.loads(self.ledger.read_text())['reservations']
        self.assertEqual([r['kind'] for r in rows], ['aks', 'identity'])
        aks = next(c for c in calls if c[:2] == ['aks', 'create'])
        tags = aks[aks.index('--tags') + 1:aks.index('--nodepool-tags')]
        self.assertIn('ttl=2026-11-14T22:16:00Z', tags)
        self.assertIn(f"warden_reservation={rows[0]['reservation']}", tags)
        fic = next(c for c in calls if c[:3] == ['identity', 'federated-credential', 'create'])
        self.assertEqual(fic[fic.index('--subject') + 1], 'system:serviceaccount:warden-system:warden-controlplane')
        self.assertEqual(fic[fic.index('--issuer') + 1], CLUSTER['oidcIssuerProfile']['issuerUrl'])
        self.assertIn(['kubectl', 'create', 'namespace', 'warden-lab'], calls)
        tagged = [c for c in calls if c[:2] == ['resource', 'tag']]
        self.assertEqual(len(tagged), 1, 'the untagged OS disk')
        self.assertIn('/disks/osdisk', tagged[0][tagged[0].index('--ids') + 1])
        state = json.loads((self.d / 'state/state.json').read_text())
        self.assertEqual((state['phase'], state['hard_stop'], state['last_retry'], state['ttl']),
                         ('up', '2026-11-14T21:01:00Z', '2026-11-14T21:41:00Z', '2026-11-14T22:16:00Z'))
        summary = (self.d / 'state/cluster-summary.json').read_text()
        self.assertNotIn('aaaaaaaa-bbbb', summary)
        self.assertNotIn(SUB, summary)
        self.assertEqual(oct((self.d / 'private/kubeconfig').stat().st_mode & 0o777), '0o600')
        principals = json.loads((self.d / 'private/principals.json').read_text())
        self.assertEqual(principals, {'managed identity': 'p-uami', 'cluster': 'p-cluster', 'kubelet': 'p-kubelet'})
        login = state['login']
        self.assertEqual((login['user_type'], login['arm_token_minutes_left'] >= 5), ('user', True))
        self.assertNotIn('fqdn', summary)
        self.assertNotIn('azmk8s', summary)
        # The node group was checked like down and reap check it.
        self.assertIn(['group', 'show'], [c[:2] for c in calls[calls.index(aks):]])

    def test_up_tags_the_node_group_when_aks_did_not(self):
        f = json.loads(self.fake.read_text())
        f['node_group_untagged'] = True
        self.fake.write_text(json.dumps(f))
        p = self.drill('up')
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        update = next(c for c in self.calls() if c[:2] == ['group', 'update'])
        self.assertEqual(update[update.index('--name') + 1], 'rg-warden-lab-aks-nodes')
        self.assertEqual(self.state()['groups']['rg-warden-lab-aks-nodes']['tags']['owner'], 'warden-lab')

    def test_up_tears_down_when_the_node_group_is_not_the_clusters(self):
        f = json.loads(self.fake.read_text())
        f['node_group_managed_by'] = AKS_ID.replace('warden-lab-aks', 'other')
        self.fake.write_text(json.dumps(f))
        p = self.drill('up')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('node resource group', p.stdout + p.stderr)
        self.assertNotIn(['group', 'update'], [c[:2] for c in self.calls()])

    def test_up_refuses_a_login_that_cannot_be_refreshed_before_anything(self):
        for change in [{'graph_fails': True}, {'token_seconds': 60}]:
            with self.subTest(change=change):
                self.setUp()
                f = json.loads(self.fake.read_text())
                f.update(change)
                self.fake.write_text(json.dumps(f))
                p = self.drill('up')
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('login', p.stderr)
                self.assertEqual([c for c in self.calls() if c[0] in ('systemd-run',) or 'create' in c[:3]], [])
                self.assertEqual(json.loads(self.ledger.read_text())['reservations'], [])

    def test_up_creates_nothing_when_the_hard_stop_cannot_be_armed(self):
        self.env['FAKE_TIMER_STATE'] = 'failed'
        p = self.drill('up')
        self.assertNotEqual(p.returncode, 0)
        self.assertIsNone(self.index(lambda c: 'create' in c[:3] and c[0] != 'systemd-run'))
        self.assertEqual(json.loads(self.ledger.read_text())['reservations'], [])
        self.assertFalse((self.d / 'state/state.json').exists())
        self.assertTrue(any(c[:3] == ['systemctl', '--user', 'stop'] for c in self.calls()))

    def test_up_tears_everything_down_when_a_step_fails(self):
        for step in [['aks', 'create'], ['identity', 'federated-credential', 'create']]:
            with self.subTest(step=step):
                self.setUp()
                f = json.loads(self.fake.read_text())
                f['fail'] = [step]
                self.fake.write_text(json.dumps(f))
                p = self.drill('up')
                self.assertNotEqual(p.returncode, 0)
                calls = self.calls()
                self.assertIn(['group', 'delete'], [c[:2] for c in calls])
                self.assertEqual(self.state()['groups'], {})
                rows = json.loads(self.ledger.read_text())['reservations']
                self.assertTrue(rows and all(r['deleted_at'] for r in rows))
                self.assertIn('teardown-check', p.stdout)
                state = json.loads((self.d / 'state/state.json').read_text())
                self.assertEqual(state['phase'], 'down')

    def test_down_after_up_leaves_nothing_and_disarms_the_timers(self):
        self.assertEqual(self.drill('up').returncode, 0)
        p = self.drill('down', '--reason', 'manual')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.state()['groups'], {})
        self.assertEqual(sum(c[:3] == ['systemctl', '--user', 'stop'] for c in self.calls()), 3)
        self.assertFalse((self.d / 'private/kubeconfig').exists())
        check = [json.loads(line) for line in p.stdout.splitlines() if '"teardown-check"' in line]
        self.assertTrue(check and check[-1]['ok'])

    def test_up_refuses_an_overnight_run_or_a_pending_approval_before_any_call(self):
        # Starts in Los Angeles (start = the next minute): 20:01 puts the hard stop
        # (+4 h) past midnight; 19:30 the last retry (+4 h 40 min); 19:00 the ttl
        # (+5 h 15 min). 18:41 keeps everything on the same day (ttl 23:56).
        for now, what in [('2026-11-14T04:00:00+00:00', 'hard stop'), ('2026-11-14T03:29:00+00:00', 'last retry'),
                          ('2026-11-14T02:59:00+00:00', 'ttl')]:
            with self.subTest(what=what):
                self.now = now
                p = self.drill('up')
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('midnight', p.stderr)
                self.assertIn(what, p.stderr)
                self.assertEqual(self.calls(), [])
        self.now = '2026-11-14T02:40:00+00:00'
        p = self.drill('up')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.setUp()
        self.now = '2026-11-14T17:00:20+00:00'  # 09:00 in Los Angeles, after the price snapshots
        p = self.drill('up', approve=False)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('premium_os_disk', p.stderr)
        self.assertEqual(self.calls(), [])

    def test_redact_removes_every_id(self):
        code = ('from scripts import aks_drill as d; import json; '
                f"print(json.dumps(d.redact({{'a': {PREFIX!r}, 'b': [{CLUSTER['oidcIssuerProfile']['issuerUrl']!r}]}})))")
        out = subprocess.run([sys.executable, '-B', '-c', code], cwd=ROOT, text=True, capture_output=True, check=True).stdout
        self.assertNotRegex(out, r'[0-9a-f]{8}-[0-9a-f]{4}-')
        self.assertIn('<id>', out)


if __name__ == '__main__':
    unittest.main(verbosity=2)
