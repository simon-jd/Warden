#!/usr/bin/env python3
"""Warden-only safeguards. This tool reserves estimates; it never creates resources."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, localcontext, ROUND_CEILING
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
# Independently read from the authorized Azure for Students account, 2026-10-23.
# No CLI argument or environment variable may replace this scope.
SUBSCRIPTION = '<subscription-id>'
GROUP = 'rg-warden-lab'
GROUP_ID = f'/subscriptions/{SUBSCRIPTION}/resourceGroups/{GROUP}'
LIMIT = Decimal('5.40')
DEFAULT_LEDGER = ROOT / 'docs/azure-spend.json'
DEFAULT_MARKDOWN = ROOT / 'docs/azure-spend.md'
REQUIRED = {'storage': {'storage_capacity', 'storage_operations', 'logs'},
            'vm': {'vm', 'os_disk', 'public_ip', 'network', 'storage_operations', 'logs'}}
RESOURCE_TYPES = {'storage': 'Microsoft.Storage/storageAccounts',
                  'keyvault': 'Microsoft.KeyVault/vaults',
                  'vm': 'Microsoft.Compute/virtualMachines'}
SELECTORS = {'meterId', 'meterName', 'serviceName', 'productName', 'skuName',
             'armSkuName', 'armRegionName', 'unitOfMeasure'}
UNITS = {'1 Hour', '1 GB', '1 GB/Month', '1/Month', '100', '10K', '10K/Month', '1M', '1K'}
CATEGORY_UNITS = {
    'storage_capacity': {'1 GB/Month'},
    'storage_operations': {'100', '1K', '10K', '10K/Month', '1M'},
    'keyvault_operations': {'100', '1K', '10K', '1M'},
    'logs': {'1 GB', '1 GB/Month'},
    'vm': {'1 Hour'}, 'os_disk': {'1/Month', '1 GB/Month'},
    'public_ip': {'1 Hour'}, 'network': {'1 GB'},
}


class GuardError(ValueError):
    pass


def utc_now():
    return datetime.now(timezone.utc)


def stamp(value):
    return value.isoformat(timespec='seconds').replace('+00:00', 'Z')


def utc(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)', value):
        raise GuardError('UTC timestamp required')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise GuardError('invalid UTC timestamp') from exc


def number(value, positive=False):
    if isinstance(value, bool):
        raise GuardError('boolean is not an estimate')
    try:
        n = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise GuardError('invalid decimal') from None
    if not n.is_finite() or n < 0 or (positive and n == 0) or n.adjusted() > 20:
        raise GuardError('estimate must be finite and nonnegative (quantity positive)')
    return n


def priced_number(value, positive=False):
    n = number(value, positive)
    if len(n.as_tuple().digits) > 18 or n.as_tuple().exponent < -12:
        raise GuardError('price/quantity exceeds supported decimal precision')
    return n


def resource_id(value):
    # Azure resource IDs have alternating provider/type/name segments. No URL
    # encoding, query strings, nested scope, dot segments, or prefix matching.
    if not isinstance(value, str) or not value.startswith(GROUP_ID + '/providers/'):
        raise GuardError('resource outside the pinned Warden scope')
    parts = value[len(GROUP_ID + '/providers/'):].split('/')
    if len(parts) < 3 or len(parts) % 2 != 1:
        raise GuardError('invalid resource ID')
    if any(not re.fullmatch(r'[A-Za-z0-9_.()-]+', x) or x in {'.', '..'} for x in parts):
        raise GuardError('invalid resource ID segment')
    if any(x.lower() in {'providers', 'subscriptions', 'resourcegroups'} for x in parts):
        raise GuardError('nested scope forbidden')
    return value


def tags_valid(tags):
    if not isinstance(tags, dict) or tags.get('project') != 'warden' or tags.get('owner') != 'codex-warden':
        raise GuardError('missing or mismatched ownership tags')
    expiry = utc(tags.get('ttl'))
    rate = number(tags.get('est_usd_per_hour'))
    return expiry, rate


def az(*args, absent_ok=False):
    command = ['az', *args, '--subscription', SUBSCRIPTION, '--output', 'json', '--only-show-errors']
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode:
        # An exact Azure error code is required; arbitrary text mentioning 404
        # or ResourceGroupNotFound is not evidence of absence.
        code = re.search(r'^ERROR: \(([A-Za-z0-9]+)\)', result.stderr, re.MULTILINE)
        if absent_ok and code and code.group(1) == 'ResourceGroupNotFound':
            return None
        raise GuardError('Azure command failed: ' + (code.group(1) if code else 'unclassified error'))
    if args[:2] in (('resource', 'delete'), ('group', 'delete')) and not result.stdout.strip():
        return None  # Azure CLI delete commands legitimately have no JSON body.
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise GuardError('Azure returned invalid JSON') from None


def account_and_group():
    account = az('account', 'show')
    if account.get('id') != SUBSCRIPTION or account.get('name') != 'Azure for Students' or account.get('state') != 'Enabled':
        raise GuardError('pinned Azure for Students account mismatch')
    group = az('group', 'show', '--name', GROUP, absent_ok=True)
    if group is None:
        audit('group-absent', id=GROUP_ID)
        return None
    if group.get('id') != GROUP_ID or group.get('name') != GROUP:
        raise GuardError('resource group identity mismatch; rg-mlinfra-westus is always protected')
    tags_valid(group.get('tags'))
    return group


def audit(event, **fields):
    print(json.dumps({'at': stamp(utc_now()), 'event': event, **fields}, sort_keys=True), flush=True)


def read_json(path):
    return parse_json(Path(path).read_text())


def parse_json(raw):
    def pairs(items):
        obj = {}
        for k, v in items:
            if k in obj:
                raise GuardError('duplicate JSON key')
            obj[k] = v
        return obj
    return json.loads(raw, parse_float=Decimal, object_pairs_hook=pairs)


def initial_ledger():
    return {'version': 1, 'subscription': SUBSCRIPTION, 'group': GROUP, 'reservations': []}


def read_ledger(path):
    path = Path(path)
    if not path.exists():
        if path == DEFAULT_LEDGER:
            raise GuardError('authoritative project ledger is missing; reconcile before reserving')
        return initial_ledger()
    data = read_json(path)
    if (data.get('version'), data.get('subscription'), data.get('group')) != (1, SUBSCRIPTION, GROUP):
        raise GuardError('ledger scope or version mismatch')
    seen = set()
    for r in data['reservations']:
        rid = resource_id(r['id'])
        if rid.lower() in seen:
            raise GuardError('duplicate resource in ledger')
        seen.add(rid.lower())
        number(r['estimate_usd'])
        tags_valid(r['tags'])
    if sum((number(r['estimate_usd']) for r in data['reservations']), Decimal(0)) > LIMIT:
        raise GuardError('ledger exceeds hard gate')
    return data


@contextmanager
def ledger_lock(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(str(path) + '.lock', 'a') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


def atomic_write(path, content):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dirfd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def markdown(data):
    total = sum((number(r['estimate_usd']) for r in data['reservations']), Decimal(0))
    text = f'''# Warden Azure估算台账

约束：[AZURE-BUDGET.md](../AZURE-BUDGET.md)。总上限$6.00；开通硬门槛$5.40（90%）。
本项目已承诺新增估算：**${total:.2f}**；剩余估算额度：**${LIMIT-total:.2f}**。
这是累计承诺估算，不是实际账单。删除资源不会返还承诺；消费API金额为空，不能声明实际免费。
权威记录为同目录azure-spend.json；本表由工具在项目锁内生成，JSON先落盘。

| 资源/ID | SKU | 区域 | 单价/单位及Retail API原始路径 | 开始UTC | 计划结束UTC | 承诺估算USD | 实际删除UTC |
|---|---|---|---|---|---|---|---|
'''
    for r in data['reservations']:
        prices = '; '.join(f"{c['category']}: {c['price_usd']}/{c['unit']} × {c['quantity']} [{c['quote_sha256']}]" for c in r['components'])
        cells = [r['id'], r['sku'], r['region'], prices, r['start'], r['end'], r['estimate_usd'], r['deleted_at'] or '']
        text += '| ' + ' | '.join(str(c).replace('|', '\\|').replace('\n', ' ') for c in cells) + ' |\n'
    return text + '''
## 开通前规则与边界

- 精确Retail API meter/region/SKU/USD/Consumption/单位，原始报价快照与获取时间保留在JSON及其旁边的quotes目录；不默认免费层为0。
- 在任何创建前预留全部适用VM、OS HDD Standard_LRS 30–32GB、IP、网络、存储容量/操作、AKS基础计量与日志；锁内校验累计≤$5.40。
- 仅rg-warden-lab，所有资源（包括组）四标签齐全；rg-mlinfra-westus永远不可修改/删除；不设置订阅级提醒。
- >$0.02/h同会话销毁；结束时使用本会话reservation绑定清理。删除时间仅表示已收到Azure删除成功响应，费用不归零。
- 工具只做预留，不会创建资源；AKS node RG超出当前授权，AKS继续门禁。部署代码必须独立审查成本覆盖、使用量上限和配额后才可开通。
- 本周2026-10-23：未开通Azure资源。已观察rg-warden-lab不存在；实际调用证据见evidence/azure-budget。
'''


def save_ledger(path, md, data):
    atomic_write(path, json.dumps(data, indent=2, ensure_ascii=False) + '\n')
    atomic_write(md, markdown(data))


def quote_component(component, region, start, hours):
    raw = Path(component['quote']).read_bytes()
    quote = parse_json(raw)
    url = urlsplit(quote['url'])
    if url.scheme != 'https' or url.netloc != 'prices.azure.com' or url.path != '/api/retail/prices':
        raise GuardError('quote source must be Azure Retail Prices API')
    if utc(quote['retrieved_at']) > start:
        raise GuardError('quote acquired after planned start')
    selector = component['selector']
    if set(selector) != SELECTORS or selector['armRegionName'] != region or not region:
        raise GuardError('exact meter/region/SKU/unit selector required')
    if selector['unitOfMeasure'] not in UNITS:
        raise GuardError('unsupported billing unit')
    category = component['category']
    if selector['unitOfMeasure'] not in CATEGORY_UNITS[category]:
        raise GuardError('meter unit incompatible with cost category')
    if category.startswith('storage_') and selector['serviceName'] != 'Storage':
        raise GuardError('storage category requires Storage meter')
    if category == 'keyvault_operations' and selector['serviceName'] != 'Key Vault':
        raise GuardError('Key Vault category requires Key Vault meter')
    if category == 'logs' and selector['serviceName'] != 'Storage':
        raise GuardError('only storage-backed logs supported; Log Analytics needs daily-cap deployment review')
    if category == 'vm' and selector['serviceName'] != 'Virtual Machines':
        raise GuardError('VM category requires Virtual Machines meter')
    if category == 'os_disk' and (selector['serviceName'] != 'Storage' or
                                 not re.fullmatch(r'S[1-4] LRS', selector['skuName'])):
        raise GuardError('only Standard HDD S1–S4 LRS disk meters allowed')
    if category in {'public_ip', 'network'} and selector['serviceName'] not in {'Virtual Network', 'Bandwidth'}:
        raise GuardError('IP/network category requires Virtual Network or Bandwidth meter')
    response = quote['response']
    if response.get('NextPageLink'):
        raise GuardError('quote pagination incomplete')
    matches = [item for item in response['Items'] if all(item.get(k) == v for k, v in selector.items())
               and item.get('currencyCode') == 'USD' and item.get('type') == 'Consumption'
               and number(item.get('tierMinimumUnits')) == 0]
    if len(matches) != 1:
        raise GuardError('quote missing or ambiguous')
    item = matches[0]
    if item.get('currencyCode') != 'USD' or item.get('type') != 'Consumption' or number(item.get('tierMinimumUnits')) != 0:
        raise GuardError('quote must be USD Consumption base tier')
    if utc(item['effectiveStartDate']) > start:
        raise GuardError('quote not effective at planned start')
    price = priced_number(item['retailPrice'])
    if number(item['unitPrice']) != price:
        raise GuardError('inconsistent Retail API unit price')
    quantity = priced_number(component['quantity'], positive=True)
    if item['unitOfMeasure'] == '1 Hour' and quantity < hours:
        raise GuardError('hourly quantity below planned duration')
    record = {'category': component['category'], 'price_usd': str(price),
              'quantity': str(quantity), 'unit': item['unitOfMeasure'], 'selector': selector,
              'quote_sha256': hashlib.sha256(raw).hexdigest(), 'quote_source_path': str(Path(component['quote']).resolve()),
              'quote_url': quote['url'], 'retrieved_at': quote['retrieved_at']}
    return record, price * quantity, raw


def check_quota(region, requested):
    rows = az('vm', 'list-usage', '--location', region)
    cores = [r for r in rows if r.get('name', {}).get('value') == 'cores']
    if len(cores) != 1 or number(cores[0]['limit']) != 6:
        raise GuardError('cannot confirm regional 6-vCPU quota')
    if number(cores[0]['currentValue']) + requested > Decimal(6):
        raise GuardError('insufficient remaining regional vCPU quota')


def check_priced_profile(spec, component):
    """Only configurations whose billing identity is explicitly supported."""
    s, category = component['selector'], component['category']
    blob = {'serviceName': 'Storage', 'productName': 'General Block Blob v2',
            'skuName': 'Hot LRS', 'armSkuName': ''}
    disk = {'serviceName': 'Storage', 'productName': 'Standard HDD Managed Disks',
            'skuName': 'S4 LRS', 'armSkuName': ''}
    if spec['kind'] == 'vm' and category == 'vm':
        expected = {'serviceName': 'Virtual Machines', 'productName': 'Virtual Machines BS Series',
                    'skuName': 'B2s', 'armSkuName': 'Standard_B2s', 'meterName': 'B2s', 'unitOfMeasure': '1 Hour'}
    elif spec['kind'] == 'vm' and category == 'os_disk':
        # Standard HDD 30–32 GiB is billed at S4 (32 GiB), not S1–S3.
        expected = {**disk, 'meterName': 'S4 LRS Disk', 'unitOfMeasure': '1/Month'}
    elif spec['kind'] == 'vm' and category == 'storage_operations':
        expected = {**disk, 'meterName': 'S4 LRS Disk Operations', 'unitOfMeasure': '10K'}
    elif category in {'storage_capacity', 'logs'}:
        expected = {**blob, 'meterName': 'Hot LRS Data Stored', 'unitOfMeasure': '1 GB/Month'}
    elif category == 'storage_operations':
        expected = {**blob, 'unitOfMeasure': '10K'}
        if s['meterName'] not in {'Hot Read Operations', 'Hot LRS Write Operations',
                                  'LRS List and Create Container Operations', 'All Other Operations'}:
            raise GuardError('unsupported storage operation meter for Hot LRS flat blob profile')
    else:
        return  # IP/network usage remains explicitly priced by its own selector.
    if any(s.get(k) != v for k, v in expected.items()):
        raise GuardError('quote billing identity does not match supported resource configuration')


def reserve(plan, ledger, md):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', plan['session']):
        raise GuardError('session identifier required')
    if not plan['resources']:
        raise GuardError('reservation must include resources')
    records, snapshots, requested_cores = [], {}, {}
    for spec in plan['resources']:
        rid, kind = resource_id(spec['id']), spec['kind']
        if kind not in REQUIRED:
            raise GuardError('unsupported kind; AKS node RG is not authorized')
        if rid.split('/providers/')[1].rsplit('/', 1)[0] != RESOURCE_TYPES[kind]:
            raise GuardError('resource type does not match declared cost profile')
        region, sku = spec['region'], spec['sku']
        if not re.fullmatch('[a-z][a-z0-9]+', region) or not isinstance(sku, str) or not sku:
            raise GuardError('explicit Azure region and SKU required')
        if kind == 'storage' and (sku != 'Hot LRS' or spec.get('product') != 'General Block Blob v2'):
            raise GuardError('only General Block Blob v2 Hot LRS storage profile is supported')
        start, end = utc(spec['start']), utc(spec['end'])
        if end <= start:
            raise GuardError('planned end must follow start')
        hours = Decimal(str((end-start).total_seconds())) / Decimal(3600)
        categories = [c['category'] for c in spec['components']]
        if set(categories) != REQUIRED[kind]:
            raise GuardError('complete cost categories required')
        meters = [(c['category'], c['selector']['meterId']) for c in spec['components']]
        if len(set(meters)) != len(meters):
            raise GuardError('duplicate category/meter')
        if kind == 'vm':
            # No GPU, premium disk, Marketplace image, or unknown VM profile.
            if (sku != 'Standard_B2s' or spec.get('billing') != 'on_demand'
                    or spec.get('product') != 'Virtual Machines BS Series'):
                raise GuardError('only on-demand Linux Standard_B2s compute profile is supported')
            if spec.get('os_disk_sku') != 'Standard_LRS' or spec.get('os_disk_gb') not in (30, 31, 32) or spec.get('image') != 'Ubuntu2204':
                raise GuardError('VM requires Ubuntu2204 and 30–32GB Standard_LRS OS disk')
            requested_cores[region] = requested_cores.get(region, Decimal(0)) + Decimal(1 if sku == 'Standard_B1s' else 2)
        components, amount = [], Decimal(0)
        for c in spec['components']:
            check_priced_profile(spec, c)
            record, cost, raw = quote_component(c, region, start, hours)
            if (kind == 'vm' and c['category'] == 'vm' and record['selector']['armSkuName'] != sku):
                raise GuardError('VM meter SKU does not match resource SKU')
            components.append(record)
            amount += cost
            snapshots[record['quote_sha256']] = raw
        reservation = str(uuid.uuid4())
        tags = {'project': 'warden', 'owner': 'codex-warden', 'ttl': spec['end'],
                'est_usd_per_hour': str((amount / hours).quantize(Decimal('0.000000000001'), rounding=ROUND_CEILING)),
                'warden_session': plan['session'], 'warden_reservation': reservation}
        records.append({'reservation': reservation, 'session': plan['session'], 'id': rid,
                        'kind': kind, 'sku': sku, 'region': region, 'start': spec['start'],
                        'end': spec['end'], 'estimate_usd': str(amount), 'deleted_at': None,
                        'tags': tags, 'components': components,
                        'configuration': {k: spec[k] for k in ['product', 'billing', 'image', 'os_disk_sku', 'os_disk_gb'] if k in spec}})
    with ledger_lock(ledger):
        data = read_ledger(ledger)
        if requested_cores:
            account_and_group()
            # Include outstanding project VM commitments in addition to Azure's
            # current usage: conservative double-counting prevents two planned
            # batches from independently spending the same vCPU headroom.
            for r in data['reservations']:
                if r['kind'] == 'vm' and r['deleted_at'] is None:
                    requested_cores[r['region']] = requested_cores.get(r['region'], Decimal(0)) + Decimal(1 if r['sku'] == 'Standard_B1s' else 2)
            for region, requested in requested_cores.items():
                check_quota(region, requested)
        ids = [r['id'].lower() for r in data['reservations'] + records]
        if len(set(ids)) != len(ids):
            raise GuardError('resource already reserved; historical IDs cannot be reused')
        total = sum((number(r['estimate_usd']) for r in data['reservations'] + records), Decimal(0))
        if total > LIMIT:
            raise GuardError('cumulative estimate exceeds $5.40')
        quotes = Path(str(ledger) + '.quotes')
        quotes.mkdir(exist_ok=True)
        for digest, raw in snapshots.items():
            atomic_write(quotes / (digest + '.json'), raw.decode())
        data['reservations'].extend(records)
        save_ledger(ledger, md, data)
    audit('reserved', total_usd=str(total), resources=records)


def reap(dry_run, session, ledger, md):
    if account_and_group() is None:
        return
    resources = az('resource', 'list', '--resource-group', GROUP)
    if not isinstance(resources, list):
        raise GuardError('resource list is not an array')
    with ledger_lock(ledger):
        data = read_ledger(ledger)
        candidates = []
        unresolved = []
        seen = set()
        for r in resources:
            rid = resource_id(r['id'])
            if rid.lower() in seen:
                raise GuardError('duplicate ID in Azure resource response')
            seen.add(rid.lower())
            tags = r.get('tags') or {}
            known = [x for x in data['reservations'] if session and x['session'] == session
                     and x['id'].lower() == rid.lower() and x['deleted_at'] is None
                     and number(x['tags']['est_usd_per_hour']) > Decimal('0.02')]
            if known and (len(known) != 1 or known[0]['tags'] != tags):
                unresolved.append(rid)
                audit('unresolved-session-cleanup', id=rid, session=session,
                      reason='known high-cost resource lost its complete reservation/ownership binding')
                continue
            if tags.get('project') != 'warden' or tags.get('owner') != 'codex-warden':
                audit('retain-unowned', id=rid)
                continue
            expiry, rate = tags_valid(tags)
            bound = [x for x in data['reservations'] if x['id'] == rid and
                     x['reservation'] == tags.get('warden_reservation') and
                     x['session'] == tags.get('warden_session') == session and x['tags'] == tags]
            if expiry <= utc_now() or (session and rate > Decimal('0.02') and len(bound) == 1):
                candidates.append(r)
            else:
                audit('retain-unexpired', id=rid)
        if unresolved:
            raise GuardError('unresolved high-cost session cleanup; retained uncertain resources; no deletion attempted')
        # Re-read every selected resource before the first deletion, preventing
        # list/show ownership changes from becoming partially applied cleanup.
        for r in candidates:
            current = az('resource', 'show', '--ids', r['id'])
            if current.get('id') != r['id'] or current.get('tags') != r.get('tags'):
                raise GuardError('resource changed during cleanup; no deletion attempted')
            tags_valid(current.get('tags'))
        for r in candidates:
            audit('would-delete' if dry_run else 'delete', id=r['id'], reason='session-end' if session else 'expired')
            if dry_run:
                continue
            az('resource', 'delete', '--ids', r['id'])
            for entry in data['reservations']:
                if entry['id'] == r['id']:
                    entry['deleted_at'] = stamp(utc_now())
            save_ledger(ledger, md, data)


def down(dry_run, ledger, md):
    if account_and_group() is None:
        return
    audit('would-delete-group' if dry_run else 'delete-group', id=GROUP_ID,
          warning='rg-mlinfra-westus is always protected; never operate on it')
    if not dry_run:
        with ledger_lock(ledger):
            data = read_ledger(ledger)
            az('group', 'delete', '--name', GROUP, '--yes')
            for r in data['reservations']:
                if r['deleted_at'] is None:
                    r['deleted_at'] = stamp(utc_now())
            save_ledger(ledger, md, data)


def preflight(additional, memory, download):
    additional, memory, download = (number(x) for x in (additional, memory, download))
    # Count allocated project files, including caches and tools. No cleanup.
    used = 0
    def unreadable(exc):
        raise exc
    for directory, dirs, files in os.walk(ROOT, followlinks=False, onerror=unreadable):
        for name in files:
            p = Path(directory) / name
            if not p.is_symlink():
                used += p.stat().st_blocks * 512
    free = shutil.disk_usage(ROOT).free
    if used + additional + download > 12_000_000_000:
        raise GuardError('Warden project disk would exceed 12GB')
    if memory > 16_000_000_000:
        raise GuardError('aggregate resident service memory exceeds 16GB')
    if download > 5_000_000_000 and free < 50_000_000_000 + download:
        raise GuardError('large download requires 50GB plus download size free')
    audit('local-preflight', project_allocated_bytes=used, free_bytes=free,
          additional_bytes=str(additional), download_bytes=str(download), service_memory_bytes=str(memory))


def main():
    parser = argparse.ArgumentParser(description='Warden guards: rg-mlinfra-westus is always protected. No resource creation.')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ['reap', 'down', 'reserve', 'render']:
        p = commands.add_parser(name)
        if name in {'reap', 'down'}:
            p.add_argument('--dry-run', action='store_true')
        if name == 'reserve':
            p.add_argument('plan', type=Path)
        if name == 'reap':
            p.add_argument('--end-session', help='opaque reservation session ID')
        p.add_argument('--ledger', type=Path, default=DEFAULT_LEDGER,
                       help='alternate offline ledger for tests/planning; never deployment authorization')
        p.add_argument('--markdown', type=Path, default=DEFAULT_MARKDOWN)
    p = commands.add_parser('preflight')
    for flag in ['additional-bytes', 'service-memory-bytes', 'download-bytes']:
        p.add_argument('--' + flag, default='0')
    args = parser.parse_args()
    try:
        with localcontext() as ctx:
            ctx.prec = 50
            if args.command == 'reap':
                reap(args.dry_run, args.end_session, args.ledger, args.markdown)
            elif args.command == 'down':
                down(args.dry_run, args.ledger, args.markdown)
            elif args.command == 'reserve':
                reserve(read_json(args.plan), args.ledger, args.markdown)
            elif args.command == 'render':
                with ledger_lock(args.ledger):
                    atomic_write(args.markdown, markdown(read_ledger(args.ledger)))
            else:
                preflight(args.additional_bytes, args.service_memory_bytes, args.download_bytes)
    except (GuardError, KeyError, TypeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print('guard refused: ' + str(exc), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
