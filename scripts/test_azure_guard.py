"""Behavior tests; Azure subprocess is the only substituted external boundary."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
# A made-up subscription; the guard reads it from the scope file below.
SUB = '11111111-2222-4333-8444-555555555555'
PREFIX = f'/subscriptions/{SUB}/resourceGroups/rg-warden-lab'
NOW = '2026-10-24T04:00:00Z'


class AzureGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.d = Path(self.temp.name)
        self.calls = self.d / 'calls.jsonl'
        self.fixture = self.d / 'azure.json'
        self.state = self.d / 'ledger.json'
        self.md = self.d / 'spend.md'
        # The expected subscription comes only from this file (the real one is the
        # untracked .cache/azure-subscription).
        self.scope_file = self.d / 'azure-subscription'
        self.scope_file.write_text(SUB + '\n')
        self.scope_file.chmod(0o600)
        self.resource = {'id': PREFIX + '/providers/Microsoft.Storage/storageAccounts/warden1',
                         'name': 'warden1', 'type': 'Microsoft.Storage/storageAccounts',
                         'tags': {'project': 'warden', 'owner': 'warden-lab', 'ttl': NOW,
                                  'est_usd_per_hour': '0.01'}}
        self.data = {'account': {'id': SUB, 'name': 'Azure for Students', 'state': 'Enabled'},
                     'group': {'id': PREFIX, 'name': 'rg-warden-lab', 'tags': copy.deepcopy(self.resource['tags'])},
                     'resources': [self.resource]}
        fake = self.d / 'az'
        fake.write_text('''#!/usr/bin/env python3
import json, os, sys
a=sys.argv[1:]
with open(os.environ['FAKE_CALLS'],'a') as f: f.write(json.dumps(a)+'\\n')
d=json.load(open(os.environ['FAKE_FIXTURE']))
if '--subscription' not in a or a[a.index('--subscription')+1] != '@SUB@':
 print('ERROR: missing fixed subscription',file=sys.stderr); sys.exit(2)
def arg(k): return a[a.index(k)+1] if k in a else None
def save():
 json.dump(d,open(os.environ['FAKE_FIXTURE'],'w'))
def absent(code):
 print('ERROR: ('+code+') not found',file=sys.stderr); sys.exit(3)
if a[:2]==['account','show']: out=d['account']
elif a[:2]==['group','show'] and arg('--name')=='rg-warden-lab':
 if 'error' in d:
  print(d['error'],file=sys.stderr); sys.exit(3)
 out=d['group']
elif a[:2]==['group','show']:
 if arg('--name') not in d.get('groups_by_name',{}): absent('ResourceGroupNotFound')
 out=d['groups_by_name'][arg('--name')]
elif a[:2]==['group','list']: out=d.get('groups',[])
elif a[:2]==['resource','list'] and '--tag' in a: out=d.get('tagged',[])
elif a[:2]==['resource','list']: out=d['resources']
elif a[:2]==['resource','show']:
 if 'show_error' in d: print('ERROR: (AuthorizationFailed) forbidden',file=sys.stderr); sys.exit(3)
 out=d.get('show_resource',next(x for x in d['resources'] if x['id']==a[a.index('--ids')+1]))
elif a[:2]==['resource','delete']:
 d['watchers']=[w for w in d.get('watchers',[]) if w.get('id')!=arg('--ids')]
 save(); sys.exit(0)
elif a[:2]==['group','delete']:
 if arg('--name')=='rg-warden-lab':
  d['error']='ERROR: (ResourceGroupNotFound) gone'
 else:
  d.get('groups_by_name',{}).pop(arg('--name'),None)
 save(); sys.exit(0)
elif a[:2]==['aks','show']:
 if 'aks' not in d: absent('ResourceNotFound')
 out=d['aks']
elif a[:2]==['aks','delete']:
 d.pop('aks',None)
 if not d.get('node_group_sticky'): d.get('groups_by_name',{}).pop('rg-warden-lab-aks-nodes',None)
 save(); sys.exit(0)
elif a[:2]==['aks','list']: out=d.get('aks_list',[])
elif a[:2]==['identity','list']: out=d.get('identities',[])
elif a[:3]==['network','watcher','list']: out=d.get('watchers',[])
elif a[:3]==['policy','assignment','list']:
 if 'policy_error' in d: print('ERROR: (AuthorizationFailed) forbidden',file=sys.stderr); sys.exit(3)
 out=d.get('policies',[])
elif a[:3]==['role','assignment','list']: out=d.get('role_assignments',[])
elif a[:3]==['policy','definition','show']: out=d.get('policy_definitions',{}).get(arg('--name'),{'parameters':{}})
elif a[:3]==['security','pricing','show']: out=d.get('defender',{}).get(arg('--name'),{'name':arg('--name'),'pricingTier':'Free'})
elif a[:2]==['vm','list-usage']: out=d.get('usage',[])
else: print('ERROR: unexpected command',file=sys.stderr); sys.exit(2)
print(json.dumps(out))
'''.replace('@SUB@', SUB))
        fake.chmod(0o755)
        # git worktree list: only the project itself, unless a test lists others.
        self.worktrees = self.d / 'worktrees'
        git = self.d / 'git'
        git.write_text('''#!/usr/bin/env python3
import os, sys
a=sys.argv[1:]
if a[:1]!=['-C'] or a[2:]!=['worktree','list','--porcelain']:
 print('fatal: unexpected git call',file=sys.stderr); sys.exit(2)
extra=os.environ.get('FAKE_WORKTREES')
if extra=='fail': print('fatal: not a git repository',file=sys.stderr); sys.exit(128)
print('worktree '+a[1]+'\\nHEAD 0\\nbranch refs/heads/x\\n')
for w in (extra.split(':') if extra else []): print('worktree '+w+'\\nHEAD 0\\ndetached\\n')
''')
        git.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.d) + ':' + os.environ['PATH'],
                        FAKE_CALLS=str(self.calls), FAKE_FIXTURE=str(self.fixture))

    def run_guard(self, *args):
        if args[0] == 'down' and '--ledger' not in args:
            args = (*args, '--ledger', str(self.state), '--markdown', str(self.md))
        if args[0] == 'teardown-check' and '--ledger' not in args:
            args = (*args, '--ledger', str(self.state))
        self.fixture.write_text(json.dumps(self.data))
        # The local disk preflight measures g.ROOT; point it at a small fixed
        # project so results do not depend on the size of this checkout.
        project = self.d / 'project'
        project.mkdir(exist_ok=True)
        (project / 'go.mod').write_text('module warden\n')
        return subprocess.run([sys.executable, '-B', '-c',
                               'from scripts import azure_guard as g; from datetime import datetime; '
                               'g.utc_now=lambda: datetime.fromisoformat("2026-10-24T04:00:00+00:00"); '
                               f'g.ROOT=__import__("pathlib").Path({str(project)!r}); '
                               f'g.SCOPE_FILE=__import__("pathlib").Path({str(self.scope_file)!r}); '
                               f'g.AKS_PRIVATE=__import__("pathlib").Path({str(self.d / "private")!r}); '
                               + getattr(self, 'before_main', '') + 'g.main()', *args],
                              env=self.env, text=True, capture_output=True, cwd=ROOT)

    def mutations(self):
        calls = [json.loads(x) for x in self.calls.read_text().splitlines()] if self.calls.exists() else []
        return [x for x in calls if 'delete' in x]

    def reaper(self, *args):
        return self.run_guard('reap', '--ledger', str(self.state),
                              '--markdown', str(self.md), *args)

    def plan(self, price='0.01', quantity='1'):
        quote = {'retrieved_at': '2026-10-24T03:00:00Z',
                 'url': 'https://prices.azure.com/api/retail/prices?currencyCode=USD',
                 'response': {'NextPageLink': None, 'Items': []}}
        components = []
        for category in ['storage_capacity', 'storage_operations', 'logs']:
            meter = {'meterId': category, 'meterName': category, 'serviceName': 'Storage',
                     'productName': 'General Block Blob v2', 'skuName': 'Hot LRS',
                     'armSkuName': '', 'armRegionName': 'westus2', 'currencyCode': 'USD',
                     'type': 'Consumption', 'unitOfMeasure': '10K' if category == 'storage_operations' else '1 GB/Month',
                     'retailPrice': price, 'unitPrice': price, 'tierMinimumUnits': 0,
                     'effectiveStartDate': '2026-10-01T00:00:00Z'}
            meter['meterName'] = 'Hot Read Operations' if category == 'storage_operations' else 'Hot LRS Data Stored'
            quote['response']['Items'].append(meter)
            selector = {k: meter[k] for k in ['meterId', 'meterName', 'serviceName', 'productName',
                       'skuName', 'armSkuName', 'armRegionName', 'unitOfMeasure']}
            components.append({'category': category, 'quote': str(self.d / 'quote.json'),
                               'selector': selector, 'quantity': quantity})
        (self.d / 'quote.json').write_text(json.dumps(quote))
        return {'session': 'session-1', 'resources': [{'id': self.resource['id'], 'kind': 'storage',
                'sku': 'Hot LRS', 'product': 'General Block Blob v2', 'region': 'westus2', 'start': NOW,
                'end': '2026-10-24T05:00:00Z', 'components': components}]}

    def reserve(self, plan):
        p = self.d / 'plan.json'
        p.write_text(json.dumps(plan))
        return self.run_guard('reserve', str(p), '--ledger', str(self.state), '--markdown', str(self.md))

    def vm_plan(self):
        plan = self.plan()
        r = plan['resources'][0]
        r.update(id=PREFIX + '/providers/Microsoft.Compute/virtualMachines/vm1', kind='vm',
                 sku='Standard_B2s', os_disk_sku='Standard_LRS', os_disk_gb=30, image='Ubuntu2204',
                 billing='on_demand', product='Virtual Machines BS Series')
        q = json.loads((self.d / 'quote.json').read_text())
        q['response']['Items'] = []
        r['components'] = []
        for category, service, sku, unit in [
            ('vm', 'Virtual Machines', 'B2s', '1 Hour'),
            ('os_disk', 'Storage', 'S4 LRS', '1/Month'),
            ('public_ip', 'Virtual Network', 'Standard IPv4', '1 Hour'),
            ('network', 'Bandwidth', 'Data Transfer', '1 GB'),
            ('storage_operations', 'Storage', 'S4 LRS', '10K'),
            ('logs', 'Storage', 'Hot LRS', '1 GB/Month')]:
            item = {'meterId': category, 'meterName': category, 'serviceName': service,
                    'productName': service, 'skuName': sku, 'armSkuName': 'Standard_B2s' if category == 'vm' else '',
                    'armRegionName': 'westus2', 'currencyCode': 'USD', 'type': 'Consumption',
                    'unitOfMeasure': unit, 'retailPrice': '0.01', 'unitPrice': '0.01',
                    'tierMinimumUnits': 0, 'effectiveStartDate': '2026-10-01T00:00:00Z'}
            if category == 'vm':
                item.update(productName='Virtual Machines BS Series', meterName='B2s')
            elif category in {'os_disk', 'storage_operations'}:
                item.update(productName='Standard HDD Managed Disks',
                            meterName='S4 LRS Disk' if category == 'os_disk' else 'S4 LRS Disk Operations')
            elif category == 'logs':
                item.update(productName='General Block Blob v2', meterName='Hot LRS Data Stored')
            q['response']['Items'].append(item)
            r['components'].append({'category': category, 'quote': str(self.d / 'quote.json'),
                'quantity': '1', 'selector': {k: item[k] for k in ['meterId', 'meterName', 'serviceName',
                'productName', 'skuName', 'armSkuName', 'armRegionName', 'unitOfMeasure']}})
        (self.d / 'quote.json').write_text(json.dumps(q))
        self.data['usage'] = [{'name': {'value': 'cores', 'localizedValue': 'Total Regional vCPUs'},
                               'currentValue': 4, 'limit': 6, 'unit': 'Count'}]
        return plan

    # The drill's billing identities, written out independently of the guard's
    # AKS_METERS: category -> (serviceName, productName, skuName, armSkuName,
    # meterName, unitOfMeasure, armRegionName, tierMinimumUnits).
    AKS_METERS = {
        'aks_control_plane': ('Azure Kubernetes Service', 'Azure Kubernetes Service', 'FreeTierInfrastructureCost',
                              'FreeTierInfrastructureCost', 'FreeTierInfrastructureCost Uptime SLA', '1 Hour', 'swedencentral', 0),
        'vm': ('Virtual Machines', 'Virtual Machines Basv2 Series', 'B2as v2', 'Standard_B2as_v2', 'B2as v2', '1 Hour', 'swedencentral', 0),
        'os_disk': ('Storage', 'Premium SSD Managed Disks', 'P4 LRS', '', 'P4 LRS Disk', '1/Month', 'swedencentral', 0),
        'load_balancer': ('Load Balancer', 'Load Balancer', 'Standard', '', 'Standard Included LB Rules and Outbound Rules',
                          '1 Hour', 'Global', 0),
        'load_balancer_data': ('Load Balancer', 'Load Balancer', 'Standard', '', 'Standard Data Processed', '1 GB', 'Global', 0),
        'public_ip': ('Virtual Network', 'IP Addresses', 'Standard', '', 'Standard IPv4 Static Public IP', '1 Hour', 'swedencentral', 0),
        'network': ('Bandwidth', 'Rtn Preference: MGN', 'Standard', '', 'Standard Data Transfer Out', '1 GB', 'swedencentral', 100),
    }
    AKS_PROFILE = {'tier': 'free', 'kubernetes_version': '1.36.5', 'dns_prefix': 'warden-lab-aks', 'node_count': 1, 'node_vm_size': 'Standard_B2as_v2',
                   'node_vcpus': 2, 'quota_family': 'standardBasv2Family', 'max_pods': 30, 'os_disk_type': 'Managed',
                   'os_disk_gb': 30, 'os_disk_sku': 'Premium_LRS', 'node_resource_group': 'rg-warden-lab-aks-nodes',
                   'network_plugin': 'azure', 'network_plugin_mode': 'overlay', 'network_dataplane': 'cilium',
                   'outbound_type': 'loadBalancer', 'load_balancer_sku': 'standard', 'outbound_ips': 1,
                   'oidc_issuer': True, 'workload_identity': True, 'addons': [], 'acns': False,
                   'log_analytics': False, 'diagnostic_settings': False, 'csi_drivers': False, 'ssh': False,
                   'local_accounts': True, 'auto_upgrade': 'none', 'node_os_upgrade': 'None'}
    AKS_ID = PREFIX + '/providers/Microsoft.ContainerService/managedClusters/warden-lab-aks'
    IDENTITY_ID = PREFIX + '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/warden-lab-controlplane'
    APPROVE = ''  # the user approved both on 2026-11-13 (AKS_APPROVALS)
    WATCHER = {'id': f'/subscriptions/{SUB}/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_swedencentral',
               'name': 'NetworkWatcher_swedencentral', 'location': 'swedencentral', 'resourceGroup': 'NetworkWatcherRG',
               'tags': None, 'provisioningState': 'Succeeded', 'etag': 'W/"x"'}
    POLICY = {'name': 'sys.regionrestriction', 'displayName': 'Allowed resource deployment regions', 'enforcementMode': 'Default',
              'policyDefinitionId': '/providers/Microsoft.Authorization/policyDefinitions/b86dabb9-b578-4d7b-b842-3b45e95769a1',
              'parameters': {'listOfAllowedLocations': {'value': ['norwayeast', 'francecentral', 'denmarkeast', 'swedencentral', 'westus']}}}

    def aks_plan(self, price='0.01', hours=5.25):
        q = {'retrieved_at': '2026-10-24T03:00:00Z', 'url': 'https://prices.azure.com/api/retail/prices?currencyCode=USD',
             'response': {'NextPageLink': None, 'Items': []}}
        components = []
        quantity = {'vm': hours, 'aks_control_plane': hours, 'load_balancer': hours, 'public_ip': hours,
                    'os_disk': '0.0072' if hours == 5.25 else round(hours / 730 + 0.00005, 4), 'load_balancer_data': 4, 'network': 1}
        for category, (service, product, sku, arm, meter, unit, region, tier) in self.AKS_METERS.items():
            item = {'meterId': 'm-' + category, 'meterName': meter, 'serviceName': service, 'productName': product,
                    'skuName': sku, 'armSkuName': arm, 'armRegionName': region, 'currencyCode': 'USD',
                    'type': 'Consumption', 'unitOfMeasure': unit, 'retailPrice': price, 'unitPrice': price,
                    'tierMinimumUnits': tier, 'effectiveStartDate': '2026-10-01T00:00:00Z'}
            q['response']['Items'].append(item)
            c = {'category': category, 'quote': str(self.d / 'aks-quote.json'), 'quantity': str(quantity[category]),
                 'selector': {k: item[k] for k in ['meterId', 'meterName', 'serviceName', 'productName', 'skuName',
                                                   'armSkuName', 'armRegionName', 'unitOfMeasure']}}
            if tier:
                c['tier_minimum_units'] = str(tier)
            components.append(c)
        (self.d / 'aks-quote.json').write_text(json.dumps(q))
        none = {'retrieved_at': '2026-10-24T03:00:00Z',
                'url': "https://prices.azure.com/api/retail/prices?%24filter=serviceName+eq+%27Managed+Identity%27&currencyCode=USD",
                'response': {'BillingCurrency': 'USD', 'NextPageLink': None, 'Items': [], 'Count': 0}}
        (self.d / 'identity-quote.json').write_text(json.dumps(none))
        end = '2026-10-24T09:15:00Z' if hours == 5.25 else '2026-10-24T05:00:00Z'
        self.data['usage'] = [{'name': {'value': 'cores', 'localizedValue': 'Total Regional vCPUs'},
                               'currentValue': 0, 'limit': 6, 'unit': 'Count'},
                              {'name': {'value': 'standardBasv2Family', 'localizedValue': 'Standard Basv2 Family vCPUs'},
                               'currentValue': 0, 'limit': 10, 'unit': 'Count'}]
        self.data['watchers'] = [copy.deepcopy(self.WATCHER)]
        self.data['policies'] = [copy.deepcopy(self.POLICY)]
        self.data.pop('error', None)
        return {'session': 'aks-1', 'resources': [
            {'id': self.AKS_ID, 'kind': 'aks', 'sku': 'free', 'product': 'Azure Kubernetes Service', 'region': 'swedencentral',
             'start': NOW, 'end': end, 'configuration': copy.deepcopy(self.AKS_PROFILE), 'components': components},
            {'id': self.IDENTITY_ID, 'kind': 'identity', 'sku': 'UserAssigned', 'product': 'Managed Identity',
             'region': 'swedencentral', 'start': NOW, 'end': end, 'no_meter_quote': str(self.d / 'identity-quote.json'),
             'components': []}]}

    def aks_reserve(self, plan, approve=True):
        self.before_main = self.APPROVE if approve else ''
        try:
            return self.reserve(plan)
        finally:
            self.before_main = ''

    def test_aks_drill_reserves_the_approved_cluster_and_its_identity(self):
        p = self.aks_reserve(self.aks_plan())
        self.assertEqual(p.returncode, 0, p.stderr)
        rows = json.loads(self.state.read_text())['reservations']
        self.assertEqual([r['kind'] for r in rows], ['aks', 'identity'])
        aks, identity = rows
        # 0.01 × (5.25 h × 4 hourly meters + 0.0072 month + 4 GB + 1 GB)
        self.assertEqual(aks['estimate_usd'], '0.260072')
        self.assertEqual(aks['configuration'], self.AKS_PROFILE)
        self.assertEqual(identity['estimate_usd'], '0')
        self.assertEqual(identity['tags']['est_usd_per_hour'], '0')
        for r in rows:
            self.assertEqual({k: r['tags'][k] for k in ['project', 'owner', 'ttl']},
                             {'project': 'warden', 'owner': 'warden-lab', 'ttl': '2026-10-24T09:15:00Z'})
        calls = [json.loads(x) for x in self.calls.read_text().splitlines()]
        usage = [x for x in calls if x[:2] == ['vm', 'list-usage']]
        self.assertEqual(len(usage), 1)
        self.assertIn(['security', 'pricing', 'show'], [x[:3] for x in calls])
        self.assertIn(['network', 'watcher', 'list'], [x[:3] for x in calls])
        self.assertIn(['policy', 'assignment', 'list'], [x[:3] for x in calls])
        self.assertEqual(aks['id'], 'resourceGroups/rg-warden-lab/providers/Microsoft.ContainerService/managedClusters/warden-lab-aks')
        watcher = aks['preconditions']['network_watcher']
        self.assertEqual((watcher['existed'], watcher['name'], watcher['resourceGroup']),
                         (True, 'NetworkWatcher_swedencentral', 'NetworkWatcherRG'))
        self.assertEqual(aks['preconditions']['allowed_locations'], self.POLICY['parameters']['listOfAllowedLocations']['value'])

    def test_aks_is_refused_while_an_approval_is_pending(self):
        for pending in ['premium_os_disk', 'network_watcher_autocreate']:
            with self.subTest(pending=pending):
                plan = self.aks_plan()
                self.before_main = self.APPROVE + f"g.AKS_APPROVALS[{pending!r}]=False; "
                p = self.reserve(plan)
                self.before_main = ''
                self.assertNotEqual(p.returncode, 0)
                self.assertIn(pending.replace('_', ' '), p.stderr)
                self.assertFalse(self.state.exists())
                self.assertFalse(self.calls.exists())

    def test_aks_configuration_must_be_exactly_the_approved_profile(self):
        for field, value in [('node_resource_group', 'MC_rg-warden-lab_warden-lab-aks_swedencentral'), ('tier', 'standard'),
                             ('dns_prefix', None), ('dns_prefix', 'warden-lab-aks-1234abcd'),
                             ('node_count', 2), ('node_vm_size', 'Standard_B2s_v2'), ('log_analytics', True),
                             ('addons', ['monitoring']), ('acns', True), ('outbound_type', 'managedNATGateway'),
                             ('os_disk_sku', 'Standard_LRS'), ('network_dataplane', 'azure'), ('extra', 1)]:
            with self.subTest(field=field):
                plan = self.aks_plan()
                plan['resources'][0]['configuration'][field] = value
                self.assertNotEqual(self.aks_reserve(plan).returncode, 0)
                self.assertFalse(self.state.exists())
        for field, value in [('id', self.AKS_ID.replace('warden-lab-aks', 'other-aks')), ('region', 'westus'), ('region', 'westus2'),
                             ('id', self.AKS_ID.replace('rg-warden-lab', 'rg-warden-lab-aks-nodes'))]:
            with self.subTest(field=field, value=value):
                plan = self.aks_plan()
                plan['resources'][0][field] = value
                self.assertNotEqual(self.aks_reserve(plan).returncode, 0)
                self.assertFalse(self.state.exists())
        plan = self.aks_plan()
        plan['resources'] = plan['resources'][:1]
        self.assertNotEqual(self.aks_reserve(plan).returncode, 0, 'the cluster without its identity')

    def test_aks_meters_must_be_the_drill_billing_identities(self):
        plan = self.aks_plan()
        self.assertEqual(self.aks_reserve(plan).returncode, 0)
        for category, fields in [('vm', {'meterName': 'B2as v2 Spot', 'skuName': 'B2as v2 Spot'}),
                                 ('vm', {'armSkuName': 'Standard_B2s_v2'}),
                                 ('vm', {'productName': 'Basv2 Series Cloud Services'}),
                                 ('os_disk', {'skuName': 'P10 LRS', 'meterName': 'P10 LRS Disk'}),
                                 ('os_disk', {'productName': 'Standard HDD Managed Disks', 'skuName': 'S4 LRS'}),
                                 ('aks_control_plane', {'meterName': 'Standard Uptime SLA', 'skuName': 'Standard'}),
                                 ('load_balancer', {'meterName': 'Standard Included LB Rules and Outbound Rules - Free'}),
                                 ('public_ip', {'skuName': 'Basic', 'meterName': 'Basic IPv4 Static Public IP'}),
                                 ('network', {'productName': 'Bandwidth - Routing Preference: Internet'})]:
            with self.subTest(category=category, fields=fields):
                self.state = self.d / f'{category}-{len(fields)}-{sorted(fields)[0]}.json'
                plan = self.aks_plan()
                self.alter_quote(plan, category, **fields)
                self.assertNotEqual(self.aks_reserve(plan).returncode, 0)
                self.assertFalse(self.state.exists())

    def test_aks_egress_is_priced_at_the_first_paid_tier(self):
        # The 100 GB a month at $0 is shared with every project, so it is not counted.
        plan = self.aks_plan()
        c = next(c for c in plan['resources'][0]['components'] if c['category'] == 'network')
        del c['tier_minimum_units']
        self.assertNotEqual(self.aks_reserve(plan).returncode, 0)
        self.assertFalse(self.state.exists())

    def test_aks_quantities_cover_the_reserved_hours(self):
        for category, quantity in [('vm', '5.2'), ('aks_control_plane', '4.5'), ('load_balancer', '1'),
                                   ('public_ip', '5.24'), ('os_disk', '0.0071')]:
            with self.subTest(category=category):
                plan = self.aks_plan()
                c = next(c for c in plan['resources'][0]['components'] if c['category'] == category)
                c['quantity'] = quantity
                self.assertNotEqual(self.aks_reserve(plan).returncode, 0)
                self.assertFalse(self.state.exists())

    def test_aks_drill_cap_is_ninety_percent_of_two_dollars(self):
        # 0.0692 × (21 + 0.0072 + 5) = 1.79969...; 0.0693 × 26.0072 = 1.80229...
        p = self.aks_reserve(self.aks_plan('0.0692'))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.state = self.d / 'over.json'
        p = self.aks_reserve(self.aks_plan('0.0693'))
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('1.80', p.stderr)
        self.assertFalse(self.state.exists())

    def test_only_one_aks_cluster_is_ever_reserved(self):
        self.assertEqual(self.aks_reserve(self.aks_plan()).returncode, 0)
        plan = self.aks_plan()
        plan['session'] = 'aks-2'
        p = self.aks_reserve(plan)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('one AKS cluster', p.stderr)
        self.assertEqual(len(json.loads(self.state.read_text())['reservations']), 2)

    def test_aks_reservation_checks_regional_and_family_quota(self):
        for name, limit, used in [('cores', 6, 5), ('cores', 7, 0), ('standardBasv2Family', 10, 9),
                                  ('standardBasv2Family', 0, 0)]:
            with self.subTest(name=name, limit=limit, used=used):
                plan = self.aks_plan()
                next(u for u in self.data['usage'] if u['name']['value'] == name).update(limit=limit, currentValue=used)
                self.assertNotEqual(self.aks_reserve(plan).returncode, 0)
                self.assertFalse(self.state.exists())

    def test_aks_reservation_checks_defender_and_the_existing_groups(self):
        cases = [('defender', {'Containers': {'name': 'Containers', 'pricingTier': 'Standard'}}),
                 ('defender', {'KubernetesService': {'name': 'KubernetesService', 'pricingTier': 'Standard'}}),
                 ('groups_by_name', {'rg-warden-lab-aks-nodes': {'id': PREFIX + '-aks-nodes', 'name': 'rg-warden-lab-aks-nodes'}})]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                plan = self.aks_plan()
                self.data[key] = value
                self.assertNotEqual(self.aks_reserve(plan).returncode, 0)
                self.assertFalse(self.state.exists())
                del self.data[key]

    def test_identity_is_free_only_with_an_empty_retail_answer(self):
        for change in ['items', 'filter', 'page', 'components']:
            with self.subTest(change=change):
                plan = self.aks_plan()
                ident = plan['resources'][1]
                q = json.loads(Path(ident['no_meter_quote']).read_text())
                if change == 'items':
                    q['response']['Items'] = [{'meterName': 'x', 'retailPrice': 0.1}]
                elif change == 'filter':
                    q['url'] = q['url'].replace('Managed+Identity', 'Virtual+Network')
                elif change == 'page':
                    q['response']['NextPageLink'] = 'https://prices.azure.com/api/retail/prices?$skip=100'
                else:
                    ident['components'] = [plan['resources'][0]['components'][0]]
                Path(ident['no_meter_quote']).write_text(json.dumps(q))
                self.assertNotEqual(self.aks_reserve(plan).returncode, 0)
                self.assertFalse(self.state.exists())

    def node_group(self, **fields):
        g = {'id': f'/subscriptions/{SUB}/resourceGroups/rg-warden-lab-aks-nodes', 'name': 'rg-warden-lab-aks-nodes',
             'managedBy': self.AKS_ID, 'location': 'swedencentral', 'tags': copy.deepcopy(self.resource['tags'])}
        g.update(fields)
        return g

    def test_down_deletes_the_cluster_then_the_group_and_sees_both_gone(self):
        self.data['aks'] = {'id': self.AKS_ID, 'name': 'warden-lab-aks', 'nodeResourceGroup': 'rg-warden-lab-aks-nodes'}
        self.data['groups_by_name'] = {'rg-warden-lab-aks-nodes': self.node_group()}
        self.assertEqual(self.run_guard('down', '--dry-run').returncode, 0)
        self.assertEqual(self.mutations(), [])
        p = self.run_guard('down')
        self.assertEqual(p.returncode, 0, p.stderr)
        m = self.mutations()
        self.assertEqual([x[:2] for x in m], [['aks', 'delete'], ['group', 'delete']])
        self.assertEqual(m[0][m[0].index('--name') + 1], 'warden-lab-aks')
        self.assertEqual(m[1][m[1].index('--name') + 1], 'rg-warden-lab')
        self.assertIn('node-group-absent', p.stdout)

    def test_down_fails_when_the_node_group_outlives_the_cluster(self):
        self.data['aks'] = {'id': self.AKS_ID, 'name': 'warden-lab-aks', 'nodeResourceGroup': 'rg-warden-lab-aks-nodes'}
        self.data['groups_by_name'] = {'rg-warden-lab-aks-nodes': self.node_group()}
        self.data['node_group_sticky'] = True
        self.before_main = 'g.NODE_GROUP_WAIT=(0, 0); '
        p = self.run_guard('down')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('rg-warden-lab-aks-nodes', p.stderr)

    def test_only_the_named_node_group_managed_by_the_cluster_is_accepted(self):
        for fields in [{'managedBy': self.AKS_ID.replace('warden-lab-aks', 'other')}, {'managedBy': None},
                       {'id': f'/subscriptions/{SUB}/resourceGroups/rg-mlinfra-westus'}, {'tags': None},
                       {'tags': {'project': 'pathwatch', 'owner': 'pathwatch-lab', 'ttl': NOW, 'est_usd_per_hour': '0'}}]:
            for command in [('down',), ('down', '--dry-run'), ('reap',)]:
                with self.subTest(fields=fields, command=command):
                    self.data['groups_by_name'] = {'rg-warden-lab-aks-nodes': self.node_group(**fields)}
                    self.calls.unlink(missing_ok=True)
                    p = self.reaper() if command == ('reap',) else self.run_guard(*command)
                    self.assertNotEqual(p.returncode, 0)
                    self.assertEqual(self.mutations(), [])

    def test_down_refuses_a_node_group_without_its_cluster_group(self):
        self.data['error'] = 'ERROR: (ResourceGroupNotFound) absent'
        self.data['groups_by_name'] = {'rg-warden-lab-aks-nodes': self.node_group()}
        p = self.run_guard('down')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.mutations(), [])

    def teardown_fixture(self):
        self.data['error'] = 'ERROR: (ResourceGroupNotFound) gone'
        self.data['groups'] = [{'name': 'rg-mlinfra-westus', 'managedBy': None}, {'name': 'NetworkWatcherRG', 'managedBy': None}]
        self.data['watchers'] = [copy.deepcopy(self.WATCHER)]
        self.data['role_assignments'] = [{'scope': f'/subscriptions/{SUB}/resourceGroups/rg-mlinfra-westus', 'principalId': 'other'}]

    def test_teardown_check_passes_only_when_nothing_of_the_drill_is_left(self):
        self.teardown_fixture()
        p = self.run_guard('teardown-check')
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        result = json.loads(p.stdout.splitlines()[-1])
        self.assertTrue(result['ok'])
        self.assertEqual(self.mutations(), [])
        leftovers = [('error', None), ('groups_by_name', {'rg-warden-lab-aks-nodes': self.node_group()}),
                     ('aks_list', [{'name': 'warden-lab-aks', 'resourceGroup': 'rg-warden-lab'}]),
                     ('tagged', [{'id': '/subscriptions/x/resourceGroups/y/providers/Microsoft.Network/publicIPAddresses/ip',
                                  'tags': {'project': 'warden'}}]),
                     ('groups', [{'name': 'MC_rg-warden-lab_warden-lab-aks_swedencentral', 'managedBy': None}]),
                     ('role_assignments', [{'scope': f'/subscriptions/{SUB}/resourceGroups/rg-warden-lab-aks-nodes/providers/x/y/z',
                                            'principalId': 'p'}]),
                     ('role_assignments', [{'scope': f'/subscriptions/{SUB}/resourceGroups/RG-WARDEN-LAB', 'principalId': 'p'}]),
                     ('groups', [{'name': 'other', 'managedBy': self.AKS_ID}]),
                     ('identities', [{'name': 'warden-lab-controlplane', 'resourceGroup': 'rg-warden-lab'}])]
        for key, value in leftovers:
            with self.subTest(key=key):
                self.teardown_fixture()
                if value is None:
                    del self.data[key]
                else:
                    self.data[key] = value
                p = self.run_guard('teardown-check')
                self.assertNotEqual(p.returncode, 0)
                self.assertFalse(json.loads(p.stdout.splitlines()[-1])['ok'])
                self.assertEqual(self.mutations(), [])
                self.data.pop('groups_by_name', None)
                for k in ['aks_list', 'tagged', 'identities']:
                    self.data.pop(k, None)
                self.teardown_fixture()

    def test_ledger_keeps_no_subscription_id_or_local_path(self):
        # Tracked ledgers hold resource-group-relative IDs and repository-relative
        # quote paths; the subscription only as its digest.
        self.assertEqual(self.aks_reserve(self.aks_plan()).returncode, 0)
        plan = json.loads((ROOT / 'docs/azure-reservation.example.json').read_text().replace('<subscription-id>', SUB))
        self.assertEqual(self.reserve(plan).returncode, 0)
        for path in [self.state, self.md]:
            text = path.read_text()
            for leak in [SUB, '/subscriptions/', str(self.d), str(ROOT), '/home/']:
                self.assertNotIn(leak, text, f'{path.name} has {leak}')
        rows = json.loads(self.state.read_text())['reservations']
        self.assertTrue(all(r['id'].startswith('resourceGroups/rg-warden-lab/providers/') for r in rows))
        sources = {c['quote_source_path'] for r in rows for c in r['components']}
        self.assertIn('docs/evidence/azure/prices/blob-westus2.json', sources)
        self.assertIn('<outside the repository>', sources)
        # The relative IDs still bind the Azure resources: the reaper finds them.
        self.resource['id'] = PREFIX + '/providers/Microsoft.Storage/storageAccounts/wardenexample'
        self.resource['tags'] = dict(rows[-1]['tags'])
        self.data['resources'] = [self.resource]
        p = self.reaper('--end-session', plan['session'], '--dry-run')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('would-delete', p.stdout)

    def test_aks_refuses_a_region_the_location_policy_denies(self):
        cases = {'not allowed': [dict(self.POLICY, parameters={'listOfAllowedLocations': {'value': ['westus', 'norwayeast']}})],
                 'two policies': [self.POLICY, dict(self.POLICY, name='rg-locations', parameters={
                     'listOfAllowedLocations': {'value': ['francecentral']}})],
                 'no parameter': [dict(self.POLICY, parameters={})],
                 'only a default': [dict(self.POLICY, parameters={})],
                 'unreadable': None}
        for name, policies in cases.items():
            with self.subTest(name=name):
                plan = self.aks_plan()
                if policies is None:
                    self.data['policy_error'] = True
                else:
                    self.data['policies'] = policies
                # The built-in definition takes listOfAllowedLocations; one
                # assignment leaves it unset (no default), one to a default without the region.
                self.data['policy_definitions'] = {'b86dabb9-b578-4d7b-b842-3b45e95769a1': {'parameters': {
                    'listOfAllowedLocations': {'type': 'Array'} if name == 'no parameter' else
                    {'type': 'Array', 'defaultValue': ['westus']}}}}
                p = self.aks_reserve(plan)
                self.data.pop('policy_error', None)
                self.data.pop('policy_definitions', None)
                self.assertNotEqual(p.returncode, 0)
                self.assertFalse(self.state.exists())
        plan = self.aks_plan()
        self.data['policies'] = [dict(self.POLICY, enforcementMode='DoNotEnforce', parameters={
            'listOfAllowedLocations': {'value': ['westus']}}), self.POLICY,
            {'name': 'initiative', 'policyDefinitionId': '/providers/Microsoft.Authorization/policySetDefinitions/x', 'parameters': {}},
            {'name': 'other', 'policyDefinitionId': '/providers/Microsoft.Authorization/policyDefinitions/y', 'parameters': {}}]
        self.assertEqual(self.aks_reserve(plan).returncode, 0, 'a policy that is not enforced, or not about locations, does not deny')
        self.data['policy_definitions'] = {'y': {'parameters': {'listOfAllowedLocations': {'defaultValue': ['swedencentral']}}}}
        self.state = self.d / 'default.json'
        self.assertEqual(self.aks_reserve(self.aks_plan()).returncode, 0, 'a default that allows the region')

    def test_network_watcher_is_judged_against_its_state_before_the_drill(self):
        self.assertEqual(self.aks_reserve(self.aks_plan()).returncode, 0)
        self.teardown_fixture()
        p = self.run_guard('teardown-check')
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        self.assertEqual(json.loads(p.stdout.splitlines()[-1])['network_watcher'], 'unchanged')
        for change in [{'tags': {'x': 'y'}}, {'etag': 'W/"z"'}, None]:
            with self.subTest(change=change):
                self.teardown_fixture()
                self.data['watchers'] = [] if change is None else [dict(self.WATCHER, **change)]
                p = self.run_guard('teardown-check')
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('network_watcher', json.loads(p.stdout.splitlines()[-1])['found'])
        # It existed before: down never deletes it.
        self.teardown_fixture()
        self.data.pop('error')
        self.data['aks'] = {'id': self.AKS_ID, 'name': 'warden-lab-aks', 'nodeResourceGroup': 'rg-warden-lab-aks-nodes'}
        self.assertEqual(self.run_guard('down').returncode, 0)
        self.assertFalse(any('NetworkWatcher' in ' '.join(m) for m in self.mutations()))

    def test_a_network_watcher_the_drill_caused_is_deleted_by_down(self):
        plan = self.aks_plan()
        self.data['watchers'] = []
        self.assertEqual(self.aks_reserve(plan).returncode, 0)
        aks = json.loads(self.state.read_text())['reservations'][0]
        self.assertFalse(aks['preconditions']['network_watcher']['existed'])
        # Azure made NetworkWatcher_swedencentral with the cluster's VNet.
        self.data['watchers'] = [copy.deepcopy(self.WATCHER)]
        self.data['aks'] = {'id': self.AKS_ID, 'name': 'warden-lab-aks', 'nodeResourceGroup': 'rg-warden-lab-aks-nodes'}
        self.data['groups_by_name'] = {'rg-warden-lab-aks-nodes': self.node_group()}
        p = self.run_guard('down')
        self.assertEqual(p.returncode, 0, p.stderr)
        deleted = [m for m in self.mutations() if m[:2] == ['resource', 'delete']]
        self.assertEqual([m[m.index('--ids') + 1] for m in deleted], [self.WATCHER['id']])
        self.data = json.loads(self.fixture.read_text())
        self.data['groups'] = []
        p = self.run_guard('teardown-check')
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(json.loads(p.stdout.splitlines()[-1])['network_watcher'], 'absent, as before the drill')
        # Another watcher, or one in another group, is never touched.
        for other in [dict(self.WATCHER, name='NetworkWatcher_westus', location='westus',
                           id=self.WATCHER['id'].replace('swedencentral', 'westus')),
                      dict(self.WATCHER, resourceGroup='rg-other', id=self.WATCHER['id'].replace('NetworkWatcherRG', 'rg-other'))]:
            with self.subTest(other=other['id']):
                self.calls.unlink(missing_ok=True)
                self.data = json.loads(self.fixture.read_text())
                self.data.pop('error', None)
                self.data['watchers'] = [other]
                self.assertEqual(self.run_guard('down').returncode, 0)
                self.assertEqual([m for m in self.mutations() if m[:2] == ['resource', 'delete']], [])

    def test_teardown_check_finds_role_assignments_of_the_drill_principals(self):
        private = self.d / 'private'
        private.mkdir()
        (private / 'principals.json').write_text(json.dumps({'managed identity': 'p-uami', 'kubelet': 'p-kubelet'}))
        self.teardown_fixture()
        self.data['role_assignments'] = [{'scope': f'/subscriptions/{SUB}', 'principalId': 'p-kubelet'}]
        p = self.run_guard('teardown-check')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('role_assignments', json.loads(p.stdout.splitlines()[-1])['found'])
        self.teardown_fixture()
        p = self.run_guard('teardown-check')
        self.assertEqual(p.returncode, 0, p.stdout)

    def other_worktree(self, reservations, digest=None, version=2):
        w = self.d / f'wt{len(list(self.d.glob("wt*")))}'
        (w / 'docs').mkdir(parents=True)
        scope = {'subscription_sha256': digest or hashlib.sha256(SUB.encode()).hexdigest()} if version == 2 else \
            {'subscription': digest or SUB}
        (w / 'docs/azure-spend.json').write_text(json.dumps({
            'version': version, **scope, 'group': 'rg-warden-lab', 'reservations': reservations}))
        self.env['FAKE_WORKTREES'] = ':'.join(filter(None, [self.env.get('FAKE_WORKTREES'), str(w)]))
        return w

    def test_other_worktrees_ledgers_count_toward_the_caps(self):
        row = lambda kind, usd, rid: {'reservation': rid, 'session': 's', 'kind': kind, 'estimate_usd': usd, 'deleted_at': None,
                                      'id': 'resourceGroups/rg-warden-lab/providers/Microsoft.Storage/storageAccounts/' + rid}
        self.other_worktree([row('storage', '5.20', 'other1')])
        self.other_worktree([row('storage', '0.10', 'other2')], version=1)  # an older branch's ledger
        self.assertNotEqual(self.reserve(self.plan('0.2')).returncode, 0, '5.30 + 0.60 > 5.40')
        self.assertFalse(self.state.exists())
        self.assertEqual(self.reserve(self.plan('0.03')).returncode, 0, '5.30 + 0.09 <= 5.40')
        self.env.pop('FAKE_WORKTREES')
        self.state = self.d / 'aks.json'
        self.other_worktree([row('aks', '0.5', 'other-aks')])
        p = self.aks_reserve(self.aks_plan())
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('one AKS cluster', p.stderr)
        for case in ['fail', 'digest', 'version-1 subscription']:
            with self.subTest(case=case):
                self.env.pop('FAKE_WORKTREES')
                self.state = self.d / f'{case}.json'
                if case == 'fail':
                    self.env['FAKE_WORKTREES'] = 'fail'
                elif case == 'digest':
                    self.other_worktree([], digest='0' * 64)
                else:
                    self.other_worktree([], digest='99999999-2222-4333-8444-555555555555', version=1)
                self.assertNotEqual(self.reserve(self.plan()).returncode, 0)
                self.assertFalse(self.state.exists())

    def alter_quote(self, plan, category, **fields):
        c = next(c for c in plan['resources'][0]['components'] if c['category'] == category)
        q = json.loads(Path(c['quote']).read_text())
        item = next(x for x in q['response']['Items'] if all(x.get(k) == v for k, v in c['selector'].items()))
        item.update(fields)
        c['selector'].update(fields)
        Path(c['quote']).write_text(json.dumps(q))

    def test_real_archived_storage_quote_cannot_price_different_declared_profile(self):
        for field, value in [('sku', 'Cool GRS'), ('product', 'Files v2')]:
            with self.subTest(field=field):
                plan = json.loads((ROOT / 'docs/azure-reservation.example.json').read_text().replace('<subscription-id>', SUB))
                plan['resources'][0][field] = value
                p = self.reserve(plan)
                self.assertNotEqual(p.returncode, 0)
                self.assertFalse(self.state.exists())

    def test_storage_quote_sku_or_product_cannot_disagree_with_declared_profile(self):
        for category in ['storage_capacity', 'storage_operations', 'logs']:
            for field, value in [('skuName', 'Cool GRS'), ('productName', 'Files v2')]:
                with self.subTest(category=category, field=field):
                    plan = self.plan()
                    self.alter_quote(plan, category, **{field: value})
                    self.assertNotEqual(self.reserve(plan).returncode, 0)
                    self.assertFalse(self.state.exists())

    def test_thirty_to_thirty_two_gb_disk_cannot_use_s1_to_s3_or_other_product(self):
        for size in [30, 31, 32]:
            for sku in ['S1 LRS', 'S2 LRS', 'S3 LRS']:
                with self.subTest(size=size, sku=sku):
                    plan = self.vm_plan()
                    plan['resources'][0]['os_disk_gb'] = size
                    self.alter_quote(plan, 'os_disk', skuName=sku, meterName=sku + ' Disk')
                    self.assertNotEqual(self.reserve(plan).returncode, 0)
                    self.assertFalse(self.state.exists())
        plan = self.vm_plan()
        self.alter_quote(plan, 'os_disk', productName='Premium SSD Managed Disks')
        self.assertNotEqual(self.reserve(plan).returncode, 0)
        self.assertFalse(self.state.exists())

    def test_vm_compute_billing_and_linux_product_must_match(self):
        for billing in ['spot', 'reservation', None]:
            with self.subTest(billing=billing):
                plan = self.vm_plan()
                plan['resources'][0]['billing'] = billing
                self.assertNotEqual(self.reserve(plan).returncode, 0)
                self.assertFalse(self.state.exists())
        plan = self.vm_plan()
        plan['resources'][0]['product'] = 'Virtual Machines BS Series Windows'
        self.assertNotEqual(self.reserve(plan).returncode, 0)
        self.assertFalse(self.state.exists())
        for field, value in [('productName', 'Virtual Machines BS Series Windows'),
                             ('skuName', 'B2s Spot'), ('meterName', 'B2s Low Priority')]:
            with self.subTest(field=field):
                plan = self.vm_plan()
                self.alter_quote(plan, 'vm', **{field: value})
                self.assertNotEqual(self.reserve(plan).returncode, 0)
                self.assertFalse(self.state.exists())

    def test_keyvault_profile_requires_future_exact_priced_support(self):
        plan = self.plan()
        r = plan['resources'][0]
        r.update(id=PREFIX + '/providers/Microsoft.KeyVault/vaults/vault1', kind='keyvault', sku='Standard')
        r['components'] = [c for c in r['components'] if c['category'] != 'storage_capacity']
        r['components'][0]['category'] = 'keyvault_operations'
        self.alter_quote(plan, 'keyvault_operations', serviceName='Key Vault')
        self.assertNotEqual(self.reserve(plan).returncode, 0)
        self.assertFalse(self.state.exists())

    def test_known_high_cost_session_lost_binding_reports_incomplete_without_deleting(self):
        for field, value in [('warden_reservation', None), ('warden_reservation', 'changed'),
                             ('warden_session', 'changed'), ('est_usd_per_hour', '0'),
                             ('owner', 'other'), ('project', None)]:
            with self.subTest(field=field, value=value):
                # A separate ledger per case preserves the test's historical-ID contract.
                self.state = self.d / (field + str(value) + '.json')
                self.assertEqual(self.reserve(self.plan()).returncode, 0)
                row = json.loads(self.state.read_text())['reservations'][0]
                self.resource['tags'] = dict(row['tags'])
                if value is None:
                    del self.resource['tags'][field]
                else:
                    self.resource['tags'][field] = value
                self.assertEqual(self.reaper('--end-session', 'wrong-session').returncode, 0)
                p = self.reaper('--end-session', 'session-1')
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('unresolved', p.stdout)
                self.assertEqual(self.mutations(), [])
                self.assertIsNone(json.loads(self.state.read_text())['reservations'][0]['deleted_at'])

    def test_unresolved_cleanup_prevents_deletion_of_other_candidates_even_in_dry_run(self):
        self.assertEqual(self.reserve(self.plan()).returncode, 0)
        row = json.loads(self.state.read_text())['reservations'][0]
        self.resource['tags'] = dict(row['tags'])
        del self.resource['tags']['warden_reservation']
        expired = copy.deepcopy(self.resource)
        expired['id'] += 'expired'
        expired['tags']['ttl'] = NOW
        self.data['resources'].insert(0, expired)
        for args in [('--end-session', 'session-1'), ('--end-session', 'session-1', '--dry-run')]:
            p = self.reaper(*args)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(self.mutations(), [])

    def test_supported_s4_disk_prices_each_allowed_size(self):
        for size in [30, 31, 32]:
            with self.subTest(size=size):
                self.state = self.d / f'valid-disk-{size}.json'
                plan = self.vm_plan()
                plan['resources'][0]['os_disk_gb'] = size
                p = self.reserve(plan)
                self.assertEqual(p.returncode, 0, p.stderr)

    def test_default_expiry_still_deletes_owned_resource_with_lost_extra_binding(self):
        self.assertEqual(self.reserve(self.plan()).returncode, 0)
        row = json.loads(self.state.read_text())['reservations'][0]
        self.resource['tags'] = dict(row['tags'])
        del self.resource['tags']['warden_reservation']
        self.resource['tags']['ttl'] = NOW
        p = self.reaper()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(self.mutations()), 1)

    def test_vm_reservation_checks_six_core_region_quota(self):
        p = self.reserve(self.vm_plan())
        self.assertEqual(p.returncode, 0, p.stderr)
        calls = [json.loads(x) for x in self.calls.read_text().splitlines()]
        usage = [x for x in calls if x[:2] == ['vm', 'list-usage']]
        self.assertEqual(len(usage), 1)
        self.assertEqual(usage[0][usage[0].index('--location')+1], 'westus2')

    def test_vm_quota_missing_exhausted_or_not_six_is_refused(self):
        for limit, used in [(6, 5), (7, 0), (0, 0)]:
            plan = self.vm_plan()
            self.data['usage'][0].update(limit=limit, currentValue=used)
            self.assertNotEqual(self.reserve(plan).returncode, 0)
            self.assertFalse(self.state.exists())
        plan = self.vm_plan()
        self.data['usage'] = []
        self.assertNotEqual(self.reserve(plan).returncode, 0)

    def test_vm_batch_aggregates_quota_before_reservation(self):
        plan = self.vm_plan()
        second = copy.deepcopy(plan['resources'][0])
        second['id'] += 'second'
        plan['resources'].append(second)
        self.assertNotEqual(self.reserve(plan).returncode, 0)
        self.assertFalse(self.state.exists())

    def test_exact_expiry_deletes_only_full_scoped_id(self):
        future = copy.deepcopy(self.resource)
        future['id'] += 'future'
        future['tags']['ttl'] = '2026-10-24T04:00:01Z'
        self.data['resources'].append(future)
        p = self.reaper()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(self.mutations()), 1)
        self.assertIn(self.resource['id'], self.mutations()[0])

    def test_future_ttl_is_retained(self):
        self.resource['tags']['ttl'] = '2026-10-24T04:00:01Z'
        self.assertEqual(self.reaper().returncode, 0)
        self.assertEqual(self.mutations(), [])

    def test_dry_run_never_mutates(self):
        self.assertEqual(self.reaper('--dry-run').returncode, 0)
        self.assertEqual(self.mutations(), [])

    def test_ownership_or_scope_corruption_never_deletes(self):
        for change in ['other-group', 'other-subscription', 'encoded-id', 'missing-tag',
                       'wrong-owner', 'invalid-ttl', 'non-utc', 'nan-rate', 'missing-rate']:
            with self.subTest(change=change):
                self.data['resources'] = [copy.deepcopy(self.resource)]
                r = self.data['resources'][0]
                if change == 'other-group': r['id'] = r['id'].replace('rg-warden-lab', 'rg-mlinfra-westus')
                if change == 'other-subscription': r['id'] = r['id'].replace(SUB, '00000000-0000-0000-0000-000000000000')
                if change == 'encoded-id': r['id'] += '/%2fproviders/evil'
                if change == 'missing-tag': del r['tags']['project']
                if change == 'wrong-owner': r['tags']['owner'] = 'someone-else'
                if change == 'invalid-ttl': r['tags']['ttl'] = 'yesterday'
                if change == 'non-utc': r['tags']['ttl'] = '2026-10-24T04:00:00+01:00'
                if change == 'nan-rate': r['tags']['est_usd_per_hour'] = 'NaN'
                if change == 'missing-rate': del r['tags']['est_usd_per_hour']
                self.reaper()
                self.assertEqual(self.mutations(), [])

    def test_api_failure_is_not_absence(self):
        for error in ['ERROR: (AuthorizationFailed) forbidden', 'ERROR: (OtherError) ResourceGroupNotFound']:
            self.data['error'] = error
            p = self.reaper()
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(self.mutations(), [])

    def test_missing_group_is_safe_noop(self):
        self.data['error'] = "ERROR: (ResourceGroupNotFound) absent\nCode: ResourceGroupNotFound"
        p = self.reaper()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('absent', p.stdout)
        self.assertEqual(self.mutations(), [])

    def test_wrong_account_fails_closed(self):
        self.data['account']['id'] = 'other'
        self.assertNotEqual(self.reaper().returncode, 0)
        self.assertEqual(self.mutations(), [])

    def test_changed_resource_or_show_failure_aborts_before_delete(self):
        self.data['show_error'] = True
        self.assertNotEqual(self.reaper().returncode, 0)
        self.assertEqual(self.mutations(), [])
        del self.data['show_error']
        self.data['show_resource'] = copy.deepcopy(self.resource)
        self.data['show_resource']['tags']['owner'] = 'other'
        self.assertNotEqual(self.reaper().returncode, 0)
        self.assertEqual(self.mutations(), [])

    def test_duplicate_api_id_is_rejected_before_delete(self):
        self.data['resources'].append(copy.deepcopy(self.resource))
        self.assertNotEqual(self.reaper().returncode, 0)
        self.assertEqual(self.mutations(), [])

    def test_target_environment_cannot_redirect_pinned_scope(self):
        self.env['AZURE_SUBSCRIPTION_ID'] = 'other'
        self.env['AZURE_RESOURCE_GROUP'] = 'rg-mlinfra-westus'
        self.assertEqual(self.reaper('--dry-run').returncode, 0)
        calls = [json.loads(x) for x in self.calls.read_text().splitlines()]
        self.assertTrue(all(x[x.index('--subscription')+1] == SUB for x in calls))
        self.assertFalse(any('rg-mlinfra-westus' in x for x in calls))

    def test_down_checks_ownership_and_rejects_protected_target(self):
        self.data['group']['id'] = PREFIX.replace('rg-warden-lab', 'rg-mlinfra-westus')
        p = self.run_guard('down')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.mutations(), [])
        p = self.run_guard('down', '--resource-group', 'rg-mlinfra-westus')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.mutations(), [])

    def test_down_dry_run_and_real_fake_boundary(self):
        self.assertEqual(self.run_guard('down', '--dry-run').returncode, 0)
        self.assertEqual(self.mutations(), [])
        p = self.run_guard('down')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(self.mutations()), 1)
        self.assertIn('rg-warden-lab', self.mutations()[0])

    def test_reservation_exact_540_boundary_and_document(self):
        p = self.reserve(self.plan('1.80'))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(self.state.read_text())['reservations'][0]['estimate_usd'], '5.40')
        self.assertIn('$5.40', self.md.read_text())

    def test_real_archived_storage_quote_selects_base_tier(self):
        plan = json.loads((ROOT / 'docs/azure-reservation.example.json').read_text().replace('<subscription-id>', SUB))
        p = self.reserve(plan)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(self.state.read_text())['reservations'][0]['estimate_usd'], '0.1448')

    def test_over_budget_or_duplicate_does_not_write(self):
        self.assertNotEqual(self.reserve(self.plan('1.80000001')).returncode, 0)
        self.assertFalse(self.state.exists())
        plan = self.plan('0.01')
        self.assertEqual(self.reserve(plan).returncode, 0)
        before = self.state.read_bytes()
        self.assertNotEqual(self.reserve(plan).returncode, 0)
        self.assertEqual(self.state.read_bytes(), before)

    def test_invalid_quote_or_plan_fails_closed(self):
        for change in ['negative', 'nan', 'unit', 'region', 'backwards', 'missing', 'currency',
                       'type', 'ambiguous', 'future-quote', 'aks', 'scope', 'coverage']:
            with self.subTest(change=change):
                plan = self.plan()
                q = json.loads((self.d / 'quote.json').read_text())
                item = q['response']['Items'][0]
                if change == 'negative': item['retailPrice'] = '-1'
                if change == 'nan': item['retailPrice'] = 'NaN'
                if change == 'unit': item['unitOfMeasure'] = 'unknown'
                if change == 'region': item['armRegionName'] = ''
                if change == 'backwards': plan['resources'][0]['end'] = '2026-10-24T02:00:00Z'
                if change == 'missing': q['response']['Items'] = []
                if change == 'currency': item['currencyCode'] = 'EUR'
                if change == 'type': item['type'] = 'Reservation'
                if change == 'ambiguous': q['response']['Items'].append(copy.deepcopy(item))
                if change == 'future-quote': q['retrieved_at'] = '2026-10-25T00:00:00Z'
                if change == 'aks': plan['resources'][0]['kind'] = 'aks'
                if change == 'scope': plan['resources'][0]['id'] = '/subscriptions/other/resourceGroups/rg-warden-lab/providers/X/y/z'
                if change == 'coverage': plan['resources'][0]['components'].pop()
                (self.d / 'quote.json').write_text(json.dumps(q))
                self.assertNotEqual(self.reserve(plan).returncode, 0)
                self.assertFalse(self.state.exists())

    def test_operation_coverage_cannot_use_capacity_meter(self):
        plan = self.plan()
        q = json.loads((self.d / 'quote.json').read_text())
        q['response']['Items'][1]['unitOfMeasure'] = '1 GB/Month'
        plan['resources'][0]['components'][1]['selector']['unitOfMeasure'] = '1 GB/Month'
        (self.d / 'quote.json').write_text(json.dumps(q))
        p = self.reserve(plan)
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse(self.state.exists())

    def test_multiple_operation_meters_can_cover_reads_and_writes(self):
        plan = self.plan()
        q = json.loads((self.d / 'quote.json').read_text())
        meter = copy.deepcopy(q['response']['Items'][1])
        meter['meterId'] = 'write-ops'
        meter['meterName'] = 'Hot LRS Write Operations'
        q['response']['Items'].append(meter)
        c = copy.deepcopy(plan['resources'][0]['components'][1])
        c['selector']['meterId'] = 'write-ops'
        c['selector']['meterName'] = 'Hot LRS Write Operations'
        plan['resources'][0]['components'].append(c)
        (self.d / 'quote.json').write_text(json.dumps(q))
        p = self.reserve(plan)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(self.state.read_text())['reservations'][0]['estimate_usd'], '0.04')

    def test_wrong_service_cannot_be_labeled_storage_cost(self):
        plan = self.plan()
        q = json.loads((self.d / 'quote.json').read_text())
        q['response']['Items'][0]['serviceName'] = 'Virtual Machines'
        plan['resources'][0]['components'][0]['selector']['serviceName'] = 'Virtual Machines'
        (self.d / 'quote.json').write_text(json.dumps(q))
        self.assertNotEqual(self.reserve(plan).returncode, 0)
        self.assertFalse(self.state.exists())

    def test_down_records_deletion_without_refund(self):
        self.assertEqual(self.reserve(self.plan()).returncode, 0)
        p = self.run_guard('down', '--ledger', str(self.state), '--markdown', str(self.md))
        self.assertEqual(p.returncode, 0, p.stderr)
        row = json.loads(self.state.read_text())['reservations'][0]
        self.assertEqual(row['estimate_usd'], '0.03')
        self.assertEqual(row['deleted_at'], NOW)

    def test_fractional_hour_rate_rounding_can_be_read_back(self):
        plan = self.plan()
        plan['resources'][0]['end'] = '2026-10-24T07:00:01Z'
        self.assertEqual(self.reserve(plan).returncode, 0)
        p = self.run_guard('render', '--ledger', str(self.state), '--markdown', str(self.md))
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_concurrent_reservations_cannot_overbook(self):
        plan = self.plan('1')
        paths = []
        for n in range(2):
            p = copy.deepcopy(plan)
            p['resources'][0]['id'] += str(n)
            path = self.d / f'plan{n}.json'
            path.write_text(json.dumps(p))
            paths.append(path)
        procs = [subprocess.Popen([sys.executable, '-B', '-c', 'from scripts import azure_guard as g; '
                 f'g.SCOPE_FILE=__import__("pathlib").Path({str(self.scope_file)!r}); g.main()', 'reserve',
                 str(p), '--ledger', str(self.state), '--markdown', str(self.md)],
                 env=self.env, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for p in paths]
        results = [(p.communicate(), p.returncode)[1] for p in procs]
        self.assertEqual(sorted(results), [0, 1])
        self.assertEqual(len(json.loads(self.state.read_text())['reservations']), 1)

    def test_session_end_uses_reservation_binding_and_keeps_cost(self):
        plan = self.plan('0.01')
        plan['resources'][0]['end'] = '2026-10-24T05:00:00Z'
        p = self.reserve(plan)
        self.assertEqual(p.returncode, 0, p.stderr)
        record = json.loads(self.state.read_text())['reservations'][0]
        self.resource['tags'].update(record['tags'])
        self.assertEqual(self.reaper('--end-session', 'wrong-session').returncode, 0)
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.reaper('--end-session', 'session-1').returncode, 0)
        self.assertEqual(len(self.mutations()), 1)
        state = json.loads(self.state.read_text())
        self.assertEqual(state['reservations'][0]['estimate_usd'], '0.03')
        self.assertEqual(state['reservations'][0]['deleted_at'], NOW)

    def test_unbound_high_price_future_resource_is_retained(self):
        self.resource['tags'].update(ttl='2026-10-24T05:00:00Z', est_usd_per_hour='1',
                                     warden_session='session-1', warden_reservation='forged')
        self.assertEqual(self.reaper('--end-session', 'session-1').returncode, 0)
        self.assertEqual(self.mutations(), [])

    def test_nonpositive_quantities_and_invalid_ledger_never_reserve(self):
        for value in ['-1', '0', 'Infinity']:
            self.assertNotEqual(self.reserve(self.plan(quantity=value)).returncode, 0)
            self.assertFalse(self.state.exists())
        self.state.write_text('{"version": 1, "subscription": "other", "group": "rg-warden-lab", "reservations": []}')
        self.assertNotEqual(self.reserve(self.plan()).returncode, 0)

    def test_download_requires_fifty_gb_plus_size_only_above_five_gb(self):
        self.before_main = 'from types import SimpleNamespace; g.shutil.disk_usage=lambda _: SimpleNamespace(free=55000000000); '
        self.assertNotEqual(self.run_guard('preflight', '--download-bytes', '6000000000').returncode, 0)
        self.assertEqual(self.run_guard('preflight', '--download-bytes', '5000000000').returncode, 0)
        self.before_main = 'from types import SimpleNamespace; g.shutil.disk_usage=lambda _: SimpleNamespace(free=56000000000); '
        p = self.run_guard('preflight', '--download-bytes', '6000000000', '--service-memory-bytes', '16000000000')
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_unreadable_project_tree_is_not_zero_disk_usage(self):
        self.before_main = "g.os.walk=lambda *a,**k: k.get('onerror',lambda e: iter([]))(PermissionError('unreadable subtree')); "
        self.assertNotEqual(self.run_guard('preflight').returncode, 0)

    def test_local_preflight_rejects_resource_excess(self):
        for args in [('--additional-bytes', '24000000001'), ('--service-memory-bytes', '16000000001'),
                     ('--download-bytes', '9999999999999999'), ('--download-bytes', '-1')]:
            p = self.run_guard('preflight', *args)
            self.assertNotEqual(p.returncode, 0)
        p = self.run_guard('preflight')
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_guard_source_pins_no_subscription_id(self):
        # No real subscription or tenant ID in tracked files: the expected one
        # lives only in the untracked .cache/azure-subscription.
        source = (ROOT / 'scripts/azure_guard.py').read_text()
        guids = re.findall(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', source)
        self.assertTrue(guids == [], f'{len(guids)} GUID literal(s) in azure_guard.py')

    def test_missing_or_unsafe_scope_file_fails_closed(self):
        for case in ['missing', 'group-writable', 'not-a-guid', 'symlink', 'two-lines']:
            with self.subTest(case=case):
                (self.d / case).mkdir()
                scope = self.d / case / 'azure-subscription'
                if case == 'group-writable':
                    scope.write_text(SUB + '\n')
                    scope.chmod(0o620)
                if case == 'not-a-guid':
                    scope.write_text('Azure for Students\n')
                    scope.chmod(0o600)
                if case == 'symlink':
                    target = self.d / case / 'target'
                    target.write_text(SUB + '\n')
                    target.chmod(0o600)
                    scope.symlink_to(target)
                if case == 'two-lines':
                    scope.write_text(SUB + '\n' + SUB + '\n')
                    scope.chmod(0o600)
                self.scope_file = scope
                if self.calls.exists():
                    self.calls.unlink()
                p = self.reaper('--dry-run')
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('azure-subscription', p.stderr)
                self.assertFalse(self.calls.exists(), 'az ran without a usable expected subscription')

    def test_ledger_names_its_subscription_only_by_digest(self):
        # Reserved resource IDs still contain the subscription; the ledger's own
        # scope field does not.
        p = self.reserve(self.plan())
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(self.state.read_text())
        self.assertNotIn('subscription', data)
        self.assertEqual((data.get('version'), data.get('subscription_sha256')), (2, hashlib.sha256(SUB.encode()).hexdigest()))
        data['subscription_sha256'] = hashlib.sha256(b'another subscription').hexdigest()
        self.state.write_text(json.dumps(data))
        p = self.run_guard('render', '--ledger', str(self.state), '--markdown', str(self.md))
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('ledger scope', p.stderr)

    DIRECTORY_OBJECT = {'task': '14 run9', 'objects': 'warden-lab-x：应用1、服务主体1', 'created': '2026-11-11T00:00:00Z',
                        'deleted': '2026-11-11T00:10:00Z', 'estimate_usd': '0', 'price_source': 'Retail Prices API：没有对应的计量',
                        'price_checked': '2026-11-12T06:42:01Z', 'evidence': 'evidence/task-14/x.txt'}

    def render_directory_objects(self, *objects):
        self.state.write_text(json.dumps({'version': 2, 'subscription_sha256': hashlib.sha256(SUB.encode()).hexdigest(),
                                          'group': 'rg-warden-lab', 'reservations': [],
                                          'directory_objects': list(objects)}, ensure_ascii=False))
        return self.run_guard('render', '--ledger', str(self.state), '--markdown', str(self.md))

    def test_directory_objects_render_as_zero_cost_rows(self):
        p = self.render_directory_objects(self.DIRECTORY_OBJECT)
        self.assertEqual(p.returncode, 0, p.stderr)
        md = self.md.read_text()
        self.assertIn('| 14 run9 | warden-lab-x：应用1、服务主体1 | 2026-11-11T00:00:00Z | 2026-11-11T00:10:00Z | 0 | '
                      'Retail Prices API：没有对应的计量 | 2026-11-12T06:42:01Z | evidence/task-14/x.txt |\n', md)
        self.assertIn('本项目已承诺新增估算：**$0.00**', md)
        self.assertIn('流程偏差：取价晚于创建', md)

    def test_priced_or_malformed_directory_object_is_refused(self):
        cases = {'priced': {'estimate_usd': '0.01'}, 'missing-field': {'deleted': None}, 'extra-field': {'sku': 'x'},
                 'empty-field': {'evidence': ''}, 'price-date': {'price_checked': '2026-11-12'}}
        for case, change in cases.items():
            with self.subTest(case=case):
                entry = {k: v for k, v in dict(self.DIRECTORY_OBJECT, **change).items() if v is not None}
                p = self.render_directory_objects(entry)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn('directory object', p.stderr)

    def test_committed_ledger_renders_to_the_committed_markdown(self):
        # docs/azure-spend.md is generated: the committed JSON must reproduce it byte for byte.
        p = subprocess.run([sys.executable, '-B', '-c',
                            'import sys; from scripts import azure_guard as g; '
                            'data = g.parse_json(open("docs/azure-spend.json", "rb").read()); g.directory_objects(data); '
                            'sys.stdout.buffer.write(g.markdown(data).encode())'],
                           capture_output=True, cwd=ROOT)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.decode(), (ROOT / 'docs/azure-spend.md').read_text())

    def test_disk_share_is_24_gb(self):
        # AZURE-BUDGET.md 2.9 (2026-10-27): Warden's disk share is 24 GB.
        p = self.run_guard('preflight', '--additional-bytes', '20000000000')
        self.assertEqual(p.returncode, 0, p.stderr)
        p = self.run_guard('preflight', '--additional-bytes', '24000000000')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('exceed 24GB', p.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
