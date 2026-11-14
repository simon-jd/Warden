"""Behavior tests; Azure subprocess is the only substituted external boundary."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SUB = '<subscription-id>'
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
        self.resource = {'id': PREFIX + '/providers/Microsoft.Storage/storageAccounts/warden1',
                         'name': 'warden1', 'type': 'Microsoft.Storage/storageAccounts',
                         'tags': {'project': 'warden', 'owner': 'codex-warden', 'ttl': NOW,
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
if '--subscription' not in a or a[a.index('--subscription')+1] != '<subscription-id>':
 print('ERROR: missing fixed subscription',file=sys.stderr); sys.exit(2)
if a[:2]==['account','show']: out=d['account']
elif a[:2]==['group','show']:
 if 'error' in d:
  print(d['error'],file=sys.stderr); sys.exit(3)
 out=d['group']
elif a[:2]==['resource','list']: out=d['resources']
elif a[:2]==['resource','show']:
 if 'show_error' in d: print('ERROR: (AuthorizationFailed) forbidden',file=sys.stderr); sys.exit(3)
 out=d.get('show_resource',next(x for x in d['resources'] if x['id']==a[a.index('--ids')+1]))
elif a[:2] in (['resource','delete'],['group','delete']): sys.exit(0)
elif a[:2]==['vm','list-usage']: out=d.get('usage',[])
else: print('ERROR: unexpected command',file=sys.stderr); sys.exit(2)
print(json.dumps(out))
''')
        fake.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.d) + ':' + os.environ['PATH'],
                        FAKE_CALLS=str(self.calls), FAKE_FIXTURE=str(self.fixture))

    def run_guard(self, *args):
        if args[0] == 'down' and '--ledger' not in args:
            args = (*args, '--ledger', str(self.state), '--markdown', str(self.md))
        self.fixture.write_text(json.dumps(self.data))
        return subprocess.run([sys.executable, '-B', '-c',
                               'from scripts import azure_guard as g; from datetime import datetime; '
                               'g.utc_now=lambda: datetime.fromisoformat("2026-10-24T04:00:00+00:00"); '
                               + getattr(self, 'before_main', '') + 'g.main()', *args],
                              env=self.env, text=True, capture_output=True)

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
                plan = json.loads((ROOT / 'docs/azure-reservation.example.json').read_text())
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
        plan = json.loads((ROOT / 'docs/azure-reservation.example.json').read_text())
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
        procs = [subprocess.Popen([sys.executable, '-B', str(ROOT / 'scripts/azure_guard.py'), 'reserve',
                 str(p), '--ledger', str(self.state), '--markdown', str(self.md)],
                 env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for p in paths]
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
        for args in [('--additional-bytes', '12000000001'), ('--service-memory-bytes', '16000000001'),
                     ('--download-bytes', '9999999999999999'), ('--download-bytes', '-1')]:
            p = self.run_guard('preflight', *args)
            self.assertNotEqual(p.returncode, 0)
        p = self.run_guard('preflight')
        self.assertEqual(p.returncode, 0, p.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
