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
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
# The repository itself, for repository-relative paths in the ledger (ROOT is
# what the disk preflight measures; tests point it elsewhere).
REPO = Path(__file__).resolve().parents[1]
# The expected Azure for Students subscription is read only from this untracked
# file: one line, the subscription ID, a regular file of this user that group
# and others cannot write. No real subscription or tenant ID is kept in tracked
# files, and no CLI argument or environment variable may replace this scope; a
# missing or unusable file stops the guard before any az call. The ledger keeps
# only the ID's SHA-256. Set up: docs/azure-budget-tools.md.
SCOPE_FILE = ROOT / '.cache' / 'azure-subscription'
GUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
GROUP = 'rg-warden-lab'
LIMIT = Decimal('5.40')
# AKS, for Task 7's live drill. The user approved on 2026-11-13: one AKS
# cluster; the AKS-managed node resource group NODE_GROUP besides GROUP; $2 for
# the drill inside Warden's $6. All other rules here hold for both groups.
NODE_GROUP = 'rg-warden-lab-aks-nodes'
AKS_CLUSTER = 'warden-lab-aks'
AKS_IDENTITY = 'warden-lab-controlplane'
# The subscription's policy "Allowed resource deployment regions" (deny)
# allows norwayeast, francecentral, denmarkeast, swedencentral and westus;
# aks_preconditions() reads it again before every AKS reservation.
AKS_REGION = 'swedencentral'
AKS_DRILL_LIMIT = Decimal('1.80')  # 90 % of the drill's $2, the same gate as LIMIT
# The user's decisions of 2026-11-13 on what the first approval did not
# cover. reserve() refuses an AKS cluster while either is False.
#  premium_os_disk: this subscription can run only B-series v2 sizes for the
#    node, which have no ephemeral OS disk, so AKS gives it a Premium SSD
#    (P4 at 30 GiB), which AZURE-BUDGET.md 2.7 otherwise forbids. Allowed for
#    this drill.
#  network_watcher_autocreate: if the region has no Network Watcher, Azure
#    adds one to NetworkWatcherRG with the cluster's VNet. Allowed only if
#    the drill deletes it afterwards, and only the one it caused: down()
#    deletes NetworkWatcher_<region> only when the reservation recorded that
#    there was none before. One that was there (swedencentral has one) is
#    never modified; teardown_check() compares it with its recorded state.
AKS_APPROVALS = {'premium_os_disk': True, 'network_watcher_autocreate': True}
# Where the drill keeps what holds IDs (principals, raw Azure answers): never
# in the repository.
AKS_PRIVATE = Path.home() / 'Desktop/warden-private-scratch/aks-drill'
# The one cluster the drill may reserve; scripts/aks_drill.py creates it from
# this. Free tier, one 2-vCPU node, Azure CNI overlay with the Cilium
# dataplane, no add-ons, no Log Analytics or diagnostic settings, no ACNS.
# dns_prefix is explicit: the CLI's default embeds part of the subscription ID.
AKS_PROFILE = {'tier': 'free', 'kubernetes_version': '1.36.5', 'dns_prefix': 'warden-lab-aks', 'node_count': 1,
               'node_vm_size': 'Standard_B2as_v2',
               'node_vcpus': 2, 'quota_family': 'standardBasv2Family', 'max_pods': 30, 'os_disk_type': 'Managed',
               'os_disk_gb': 30, 'os_disk_sku': 'Premium_LRS', 'node_resource_group': NODE_GROUP,
               'network_plugin': 'azure', 'network_plugin_mode': 'overlay', 'network_dataplane': 'cilium',
               'outbound_type': 'loadBalancer', 'load_balancer_sku': 'standard', 'outbound_ips': 1,
               'oidc_issuer': True, 'workload_identity': True, 'addons': [], 'acns': False,
               'log_analytics': False, 'diagnostic_settings': False, 'csi_drivers': False, 'ssh': False,
               'local_accounts': True, 'auto_upgrade': 'none', 'node_os_upgrade': 'None'}
# What the cluster is billed for, by Retail Prices API meter: category ->
# (serviceName, productName, skuName, armSkuName, meterName, unitOfMeasure,
# armRegionName, tierMinimumUnits). Load Balancer meters are Global. Egress is
# priced at the first paid tier: the 100 GB a month at $0 is shared by every
# project in the subscription.
AKS_METERS = {
    'aks_control_plane': ('Azure Kubernetes Service', 'Azure Kubernetes Service', 'FreeTierInfrastructureCost',
                          'FreeTierInfrastructureCost', 'FreeTierInfrastructureCost Uptime SLA', '1 Hour', AKS_REGION, 0),
    'vm': ('Virtual Machines', 'Virtual Machines Basv2 Series', 'B2as v2', 'Standard_B2as_v2', 'B2as v2', '1 Hour', AKS_REGION, 0),
    'os_disk': ('Storage', 'Premium SSD Managed Disks', 'P4 LRS', '', 'P4 LRS Disk', '1/Month', AKS_REGION, 0),
    'load_balancer': ('Load Balancer', 'Load Balancer', 'Standard', '', 'Standard Included LB Rules and Outbound Rules',
                      '1 Hour', 'Global', 0),
    'load_balancer_data': ('Load Balancer', 'Load Balancer', 'Standard', '', 'Standard Data Processed', '1 GB', 'Global', 0),
    'public_ip': ('Virtual Network', 'IP Addresses', 'Standard', '', 'Standard IPv4 Static Public IP', '1 Hour', AKS_REGION, 0),
    'network': ('Bandwidth', 'Rtn Preference: MGN', 'Standard', '', 'Standard Data Transfer Out', '1 GB', AKS_REGION, 100),
}
HOURS_PER_MONTH = Decimal(730)
# The Retail Prices API filter whose empty answer prices a managed identity at $0.
NO_METER_FILTERS = {'identity': "serviceName eq 'Managed Identity'"}
# How long down() waits for AKS to remove NODE_GROUP: (tries, seconds apart).
NODE_GROUP_WAIT = (60, 30)
ABSENT_CODES = {'ResourceGroupNotFound', 'ResourceNotFound'}
# AZURE-BUDGET.md 2.9: Warden's new-disk share (doubled to 24 GB on 2026-10-27).
DISK_SHARE_BYTES = 24_000_000_000
DEFAULT_LEDGER = ROOT / 'docs/azure-spend.json'
DEFAULT_MARKDOWN = ROOT / 'docs/azure-spend.md'
# Entra directory objects (app registrations, service principals, role
# assignments, client secrets) are not subscription resources and are never
# reserved; the ledger lists them with their $0 estimate, price source and dates.
DIRECTORY_OBJECT_FIELDS = ('task', 'objects', 'created', 'deleted', 'estimate_usd', 'price_source',
                           'price_checked', 'evidence')
REQUIRED = {'storage': {'storage_capacity', 'storage_operations', 'logs'},
            'vm': {'vm', 'os_disk', 'public_ip', 'network', 'storage_operations', 'logs'},
            'aks': set(AKS_METERS), 'identity': set()}
RESOURCE_TYPES = {'storage': 'Microsoft.Storage/storageAccounts',
                  'keyvault': 'Microsoft.KeyVault/vaults',
                  'vm': 'Microsoft.Compute/virtualMachines',
                  'aks': 'Microsoft.ContainerService/managedClusters',
                  'identity': 'Microsoft.ManagedIdentity/userAssignedIdentities'}
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
    'aks_control_plane': {'1 Hour'}, 'load_balancer': {'1 Hour'}, 'load_balancer_data': {'1 GB'},
}


class GuardError(ValueError):
    pass


_scope = []


def subscription():
    """The expected subscription ID from SCOPE_FILE (read once per process)."""
    if not _scope:
        _scope.append(read_scope(SCOPE_FILE))
    return _scope[0]


def read_scope(path):
    hint = f'expected subscription: put the Azure for Students subscription ID in {path} (one line, mode 0600)'
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise GuardError('missing or unreadable ' + hint) from None
    with os.fdopen(fd) as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise GuardError('unsafe ' + hint)
        text = f.read(100)
    value = text[:-1] if text.endswith('\n') else text
    if not GUID.fullmatch(value):
        raise GuardError('malformed ' + hint)
    return value


def group_id():
    return f'/subscriptions/{subscription()}/resourceGroups/{GROUP}'


def node_group_id():
    return f'/subscriptions/{subscription()}/resourceGroups/{NODE_GROUP}'


def aks_id():
    return group_id() + '/providers/Microsoft.ContainerService/managedClusters/' + AKS_CLUSTER


def identity_id():
    return group_id() + '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/' + AKS_IDENTITY


def watcher_id(group, name):
    return f'/subscriptions/{subscription()}/resourceGroups/{group}/providers/Microsoft.Network/networkWatchers/{name}'


# Tracked ledgers keep resource IDs relative to the subscription
# ("resourceGroups/rg-warden-lab/providers/..."): the full ID, which names the
# subscription, is put together only at run time.
def relative_id(full):
    prefix = f'/subscriptions/{subscription()}/'
    if not full.startswith(prefix):
        raise GuardError('resource outside the pinned subscription')
    return full[len(prefix):]


def full_id(relative):
    if not isinstance(relative, str) or relative.startswith('/'):
        raise GuardError('ledger IDs are relative to the subscription')
    return f'/subscriptions/{subscription()}/' + relative


def repo_path(path):
    """path relative to the repository, or a placeholder: no home directory
    or temporary path goes into a tracked ledger."""
    try:
        return str(Path(path).resolve().relative_to(REPO))
    except ValueError:
        return '<outside the repository>'


def subscription_digest():
    return hashlib.sha256(subscription().encode()).hexdigest()


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
    prefix = group_id() + '/providers/'
    if not isinstance(value, str) or not value.startswith(prefix):
        raise GuardError('resource outside the pinned Warden scope')
    parts = value[len(prefix):].split('/')
    if len(parts) < 3 or len(parts) % 2 != 1:
        raise GuardError('invalid resource ID')
    if any(not re.fullmatch(r'[A-Za-z0-9_.()-]+', x) or x in {'.', '..'} for x in parts):
        raise GuardError('invalid resource ID segment')
    if any(x.lower() in {'providers', 'subscriptions', 'resourcegroups'} for x in parts):
        raise GuardError('nested scope forbidden')
    return value


def tags_valid(tags):
    if not isinstance(tags, dict) or tags.get('project') != 'warden' or tags.get('owner') != 'warden-lab':
        raise GuardError('missing or mismatched ownership tags')
    expiry = utc(tags.get('ttl'))
    rate = number(tags.get('est_usd_per_hour'))
    return expiry, rate


def az(*args, absent_ok=False, timeout=120, empty_ok=False):
    command = ['az', *args, '--subscription', subscription(), '--output', 'json', '--only-show-errors']
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        # An exact Azure error code is required; arbitrary text mentioning 404
        # or ResourceGroupNotFound is not evidence of absence.
        code = re.search(r'^ERROR: \(([A-Za-z0-9]+)\)', result.stderr, re.MULTILINE)
        if absent_ok and code and code.group(1) in ABSENT_CODES:
            return None
        raise GuardError('Azure command failed: ' + (code.group(1) if code else 'unclassified error'))
    if (empty_ok or args[:2] in (('resource', 'delete'), ('group', 'delete'), ('aks', 'delete'))) and not result.stdout.strip():
        return None  # Azure CLI delete commands (and the caller's empty_ok ones) legitimately have no JSON body.
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise GuardError('Azure returned invalid JSON') from None


def account_and_group():
    account = az('account', 'show')
    if account.get('id') != subscription() or account.get('name') != 'Azure for Students' or account.get('state') != 'Enabled':
        raise GuardError('pinned Azure for Students account mismatch')
    group = az('group', 'show', '--name', GROUP, absent_ok=True)
    if group is None:
        audit('group-absent', id=group_id())
        return None
    if group.get('id') != group_id() or group.get('name') != GROUP:
        raise GuardError('resource group identity mismatch; rg-mlinfra-westus is always protected')
    tags_valid(group.get('tags'))
    return group


def node_group():
    """NODE_GROUP as Azure has it, or None when it does not exist. It must be
    exactly that group, managed by the drill's cluster, with the four tags
    (AKS copies the cluster's tags to it). Any other node group, MC_* ones
    included, is never accepted."""
    group = az('group', 'show', '--name', NODE_GROUP, absent_ok=True)
    if group is None:
        audit('node-group-absent', id=node_group_id())
        return None
    if (group.get('id') != node_group_id() or group.get('name') != NODE_GROUP
            or (group.get('managedBy') or '').lower() != aks_id().lower()):
        raise GuardError(f'node resource group identity mismatch: only {NODE_GROUP} managed by {AKS_CLUSTER}')
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
    return {'version': 2, 'subscription_sha256': subscription_digest(), 'group': GROUP, 'reservations': []}


def read_ledger(path):
    path = Path(path)
    if not path.exists():
        if path == DEFAULT_LEDGER:
            raise GuardError('authoritative project ledger is missing; reconcile before reserving')
        return initial_ledger()
    data = read_json(path)
    if (data.get('version'), data.get('subscription_sha256'), data.get('group')) != (2, subscription_digest(), GROUP):
        raise GuardError('ledger scope or version mismatch')
    seen = set()
    for r in data['reservations']:
        rid = resource_id(full_id(r['id']))
        if rid.lower() in seen:
            raise GuardError('duplicate resource in ledger')
        seen.add(rid.lower())
        number(r['estimate_usd'])
        tags_valid(r['tags'])
    if sum((number(r['estimate_usd']) for r in data['reservations']), Decimal(0)) > LIMIT:
        raise GuardError('ledger exceeds hard gate')
    directory_objects(data)
    return data


def directory_objects(data):
    entries = data.get('directory_objects', [])
    if not isinstance(entries, list):
        raise GuardError('directory objects must be a list')
    for o in entries:
        if not isinstance(o, dict) or set(o) != set(DIRECTORY_OBJECT_FIELDS) or \
                not all(isinstance(o[k], str) and o[k].strip() for k in DIRECTORY_OBJECT_FIELDS):
            raise GuardError('malformed directory object entry')
        try:
            free = number(o['estimate_usd']) == 0
            utc(o['price_checked'])
        except GuardError as exc:
            raise GuardError(f'directory object entry: {exc}') from None
        if not free:
            raise GuardError('a directory object with a price must be reserved like a resource')
    return entries


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


def table_row(cells):
    return '| ' + ' | '.join(str(c).replace('|', '\\|').replace('\n', ' ') for c in cells) + ' |\n'


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
        text += table_row(cells)
    entries = data.get('directory_objects', [])
    if entries:
        text += '''
## Entra目录对象（不是订阅资源，不预留，按$0计）

Task 6、8、14只建过Entra目录对象，都归登录用户、名字以warden-lab-开头、标签project=warden，测完即删；合计应用13、服务主体12、用户本人的appRoleAssignment 2（Task 6）、客户端密钥12。它们不在rg-warden-lab里，所以不进上面的预留表。每个对象的ID和时间在各行的记录文件里。

| 任务 | 对象（数量） | 创建UTC | 删除UTC | 承诺估算USD | 单价来源 | 取价UTC | 记录 |
|---|---|---|---|---|---|---|---|
'''
        for o in entries:
            text += table_row([o[k] for k in DIRECTORY_OBJECT_FIELDS])
        text += '''
- **流程偏差：取价晚于创建。** 这些对象都是2026-11-11（UTC）建的，单价核对是2026-11-12才做的（Retail Prices API 06:42:01Z，微软定价页06:49:07Z，记录见evidence/task-14/azure-entra-objects-20261111.txt），不是开通前先查单价、记台账。$0是事后核对的结果。
- 核对结果：Retail Prices API里Entra相关的计量只有Domain Services、External ID、Verified ID、SCIM provisioning API和B2C/B2X，没有按应用注册、服务主体、角色分配或客户端密钥计费的。
- 按令牌计费的只有External ID的M2M Authentication计量（$0.001/个）。它按认证事务计费，微软定价页把它列为External租户配置的附加项；这个租户是工作区租户（ARM /tenants：tenantType AAD、tenantCategory Home），订阅里External ID/B2C的计费关联资源（guestUsages、ciamDirectories、b2cDirectories）都是0个，所以不适用。假如适用：Task 14三次演练用实验密钥发出11134个client credentials请求（run0 1212、run1 4362、run2 5560），按每个请求一次事务算约$11.13；只算换到的6632个令牌也约$6.63；两者都超过$5.40门槛。
'''
    return text + '''
## 开通前规则与边界

- 精确Retail API meter/region/SKU/USD/Consumption/单位，原始报价快照与获取时间保留在JSON及其旁边的quotes目录；不默认免费层为0。
- 在任何创建前预留全部适用VM、OS HDD Standard_LRS 30–32GB、IP、网络、存储容量/操作、AKS基础计量与日志；锁内校验累计≤$5.40。
- 仅rg-warden-lab，所有资源（包括组）四标签齐全；rg-mlinfra-westus永远不可修改/删除；不设置订阅级提醒。
- >$0.02/h同会话销毁；结束时使用本会话reservation绑定清理。删除时间仅表示已收到Azure删除成功响应，费用不归零。
- 工具只做预留，不会创建资源。AKS：用户2026-11-13批准一个集群（warden-lab-aks，swedencentral）、AKS托管的节点资源组rg-warden-lab-aks-nodes（只认这一个名字，不认MC_*），演练上限$2（门槛$1.80，在$5.40之内，并计入其他worktree的台账）；同日批准节点用Premium SSD OS盘，以及由演练造成、演练后删除的Network Watcher（已有的不许动）。见aks-drill.md。部署代码必须独立审查成本覆盖、使用量上限和配额后才可开通。
- 台账里的资源ID只写到订阅之下（resourceGroups/...），报价路径只写仓库内相对路径；完整ID只在运行时由订阅文件拼出。
- 2026-10-23至2026-11-12：未开通Azure资源；留有记录的reaper运行结果都是rg-warden-lab不存在（group-absent，见evidence/azure-budget、evidence/task-6/entra-objects-20261110.txt、evidence/task-14/azure-entra-objects-20261111.txt）。
- Entra目录对象见上一节。
'''


def save_ledger(path, md, data):
    atomic_write(path, json.dumps(data, indent=2, ensure_ascii=False) + '\n')
    atomic_write(md, markdown(data))


def quote_component(component, region, start, hours, kind=None):
    raw = Path(component['quote']).read_bytes()
    quote = parse_json(raw)
    url = urlsplit(quote['url'])
    if url.scheme != 'https' or url.netloc != 'prices.azure.com' or url.path != '/api/retail/prices':
        raise GuardError('quote source must be Azure Retail Prices API')
    if utc(quote['retrieved_at']) > start:
        raise GuardError('quote acquired after planned start')
    selector = component['selector']
    category = component['category']
    regions = {region, 'Global'} if kind == 'aks' and category.startswith('load_balancer') else {region}
    if set(selector) != SELECTORS or selector['armRegionName'] not in regions or not region:
        raise GuardError('exact meter/region/SKU/unit selector required')
    if selector['unitOfMeasure'] not in UNITS:
        raise GuardError('unsupported billing unit')
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
    disk = r'P4 LRS' if kind == 'aks' else r'S[1-4] LRS'
    if category == 'os_disk' and (selector['serviceName'] != 'Storage' or not re.fullmatch(disk, selector['skuName'])):
        raise GuardError('only Standard HDD S1–S4 LRS disk meters allowed (an AKS node: Premium SSD P4 only)')
    if category == 'aks_control_plane' and selector['serviceName'] != 'Azure Kubernetes Service':
        raise GuardError('AKS control plane category requires an Azure Kubernetes Service meter')
    if category.startswith('load_balancer') and selector['serviceName'] != 'Load Balancer':
        raise GuardError('load balancer category requires a Load Balancer meter')
    tier = number(component.get('tier_minimum_units', 0))
    if tier and category != 'network':
        raise GuardError('only egress may be priced at a paid tier')
    if category in {'public_ip', 'network'} and selector['serviceName'] not in {'Virtual Network', 'Bandwidth'}:
        raise GuardError('IP/network category requires Virtual Network or Bandwidth meter')
    response = quote['response']
    if response.get('NextPageLink'):
        raise GuardError('quote pagination incomplete')
    matches = [item for item in response['Items'] if all(item.get(k) == v for k, v in selector.items())
               and item.get('currencyCode') == 'USD' and item.get('type') == 'Consumption'
               and number(item.get('tierMinimumUnits')) == tier]
    if len(matches) != 1:
        raise GuardError('quote missing or ambiguous')
    item = matches[0]
    if item.get('currencyCode') != 'USD' or item.get('type') != 'Consumption' or number(item.get('tierMinimumUnits')) != tier:
        raise GuardError('quote must be USD Consumption at the declared tier')
    if utc(item['effectiveStartDate']) > start:
        raise GuardError('quote not effective at planned start')
    price = priced_number(item['retailPrice'])
    if number(item['unitPrice']) != price:
        raise GuardError('inconsistent Retail API unit price')
    quantity = priced_number(component['quantity'], positive=True)
    if item['unitOfMeasure'] == '1 Hour' and quantity < hours:
        raise GuardError('hourly quantity below planned duration')
    if kind == 'aks' and item['unitOfMeasure'] == '1/Month' and quantity * HOURS_PER_MONTH < hours:
        raise GuardError('monthly quantity below planned duration')
    record = {'category': component['category'], 'price_usd': str(price),
              'quantity': str(quantity), 'unit': item['unitOfMeasure'], 'selector': selector,
              'quote_sha256': hashlib.sha256(raw).hexdigest(), 'quote_source_path': repo_path(component['quote']),
              'quote_url': quote['url'], 'retrieved_at': quote['retrieved_at']}
    if tier:
        record['tier_minimum_units'] = str(tier)
    return record, price * quantity, raw


def check_quota(region, requested, families=None):
    rows = az('vm', 'list-usage', '--location', region)
    cores = [r for r in rows if r.get('name', {}).get('value') == 'cores']
    if len(cores) != 1 or number(cores[0]['limit']) != 6:
        raise GuardError('cannot confirm regional 6-vCPU quota')
    if number(cores[0]['currentValue']) + requested > Decimal(6):
        raise GuardError('insufficient remaining regional vCPU quota')
    for family, want in (families or {}).items():
        row = [r for r in rows if r.get('name', {}).get('value', '').lower() == family.lower()]
        if len(row) != 1 or number(row[0]['currentValue']) + want > number(row[0]['limit']):
            raise GuardError(f'insufficient {family} vCPU quota')


def check_priced_profile(spec, component):
    """Only configurations whose billing identity is explicitly supported."""
    s, category = component['selector'], component['category']
    blob = {'serviceName': 'Storage', 'productName': 'General Block Blob v2',
            'skuName': 'Hot LRS', 'armSkuName': ''}
    disk = {'serviceName': 'Storage', 'productName': 'Standard HDD Managed Disks',
            'skuName': 'S4 LRS', 'armSkuName': ''}
    if spec['kind'] == 'aks':
        service, product, sku, arm, meter, unit, region, tier = AKS_METERS[category]
        expected = {'serviceName': service, 'productName': product, 'skuName': sku, 'armSkuName': arm,
                    'meterName': meter, 'unitOfMeasure': unit, 'armRegionName': region}
        if number(component.get('tier_minimum_units', 0)) != tier:
            raise GuardError('quote tier does not match the drill billing identity')
    elif spec['kind'] == 'vm' and category == 'vm':
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
    records, snapshots, requested_cores, families = [], {}, {}, {}
    kinds = [spec['kind'] for spec in plan['resources']]
    if 'aks' in kinds:
        pending = [k for k, approved in AKS_APPROVALS.items() if not approved]
        if pending:
            raise GuardError("AKS needs the user's approval first: " + ', '.join(k.replace('_', ' ') for k in pending)
                             + ' (docs/aks-drill.md)')
    if ('aks' in kinds or 'identity' in kinds) and sorted(kinds) != ['aks', 'identity']:
        raise GuardError('the AKS drill is reserved as one batch: the cluster and its control-plane identity')
    for spec in plan['resources']:
        rid, kind = resource_id(spec['id']), spec['kind']
        if kind not in REQUIRED:
            raise GuardError('unsupported kind')
        if rid.split('/providers/')[1].rsplit('/', 1)[0] != RESOURCE_TYPES[kind]:
            raise GuardError('resource type does not match declared cost profile')
        region, sku = spec['region'], spec['sku']
        if not re.fullmatch('[a-z][a-z0-9]+', region) or not isinstance(sku, str) or not sku:
            raise GuardError('explicit Azure region and SKU required')
        if kind == 'storage' and (sku != 'Hot LRS' or spec.get('product') != 'General Block Blob v2'):
            raise GuardError('only General Block Blob v2 Hot LRS storage profile is supported')
        if kind == 'aks' and (rid != aks_id() or region != AKS_REGION or sku != 'free'
                              or spec.get('product') != 'Azure Kubernetes Service'
                              or spec.get('configuration') != AKS_PROFILE):
            raise GuardError(f'only the approved drill cluster {AKS_CLUSTER} (free tier, {AKS_REGION}, AKS_PROFILE) is supported')
        if kind == 'identity' and (rid != identity_id() or region != AKS_REGION or sku != 'UserAssigned'
                                   or spec.get('product') != 'Managed Identity'):
            raise GuardError(f'only the drill identity {AKS_IDENTITY} is supported')
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
        if kind == 'aks':
            vcpus = Decimal(AKS_PROFILE['node_vcpus'] * AKS_PROFILE['node_count'])
            requested_cores[region] = requested_cores.get(region, Decimal(0)) + vcpus
            families[AKS_PROFILE['quota_family']] = families.get(AKS_PROFILE['quota_family'], Decimal(0)) + vcpus
        components, amount = [], Decimal(0)
        if kind == 'identity':
            snapshots.update(no_meter(spec, kind, start))
        for c in spec['components']:
            check_priced_profile(spec, c)
            record, cost, raw = quote_component(c, region, start, hours, kind)
            if (kind == 'vm' and c['category'] == 'vm' and record['selector']['armSkuName'] != sku):
                raise GuardError('VM meter SKU does not match resource SKU')
            if kind == 'aks' and c['category'] == 'vm' and number(c['quantity']) < hours * AKS_PROFILE['node_count']:
                raise GuardError('node hours below planned duration')
            components.append(record)
            amount += cost
            snapshots[record['quote_sha256']] = raw
        reservation = str(uuid.uuid4())
        rate = (amount / hours).quantize(Decimal('0.000000000001'), rounding=ROUND_CEILING)
        tags = {'project': 'warden', 'owner': 'warden-lab', 'ttl': spec['end'],
                'est_usd_per_hour': str(rate) if rate else '0',
                'warden_session': plan['session'], 'warden_reservation': reservation}
        records.append({'reservation': reservation, 'session': plan['session'], 'id': relative_id(rid),
                        'kind': kind, 'sku': sku, 'region': region, 'start': spec['start'],
                        'end': spec['end'], 'estimate_usd': str(amount), 'deleted_at': None,
                        'tags': tags, 'components': components,
                        'configuration': spec['configuration'] if kind == 'aks' else
                        {k: repo_path(spec[k]) if k == 'no_meter_quote' else spec[k]
                         for k in ['product', 'billing', 'image', 'os_disk_sku', 'os_disk_gb', 'no_meter_quote'] if k in spec}})
    with ledger_lock(ledger):
        data = read_ledger(ledger)
        # Every Warden worktree has its own ledger and lock: the others are read
        # (not locked) and count toward the same caps, each reservation once.
        ours = {r['reservation'] for r in data['reservations']}
        others = [r for r in worktree_reservations(ledger) if r['reservation'] not in ours]
        committed = data['reservations'] + others
        if 'aks' in kinds:
            if any(r['kind'] == 'aks' for r in committed):
                raise GuardError('the approval covers one AKS cluster, and a Warden ledger already has it')
            drill = sum((number(r['estimate_usd']) for r in committed + records if r['kind'] in {'aks', 'identity'}),
                        Decimal(0))
            if drill > AKS_DRILL_LIMIT:
                raise GuardError(f'AKS drill estimate ${drill} exceeds ${AKS_DRILL_LIMIT} (90 % of its $2)')
            account_and_group()
            pre = aks_preconditions(AKS_REGION)
            for r in records:
                if r['kind'] == 'aks':
                    r['preconditions'] = pre
        if requested_cores:
            account_and_group()
            # Include outstanding project VM commitments in addition to Azure's
            # current usage: conservative double-counting prevents two planned
            # batches from independently spending the same vCPU headroom.
            for r in committed:
                if r['kind'] == 'vm' and r['deleted_at'] is None:
                    requested_cores[r['region']] = requested_cores.get(r['region'], Decimal(0)) + Decimal(1 if r['sku'] == 'Standard_B1s' else 2)
            for region, requested in requested_cores.items():
                check_quota(region, requested, families if region == AKS_REGION else None)
        ids = [r['id'].lower() for r in committed + records]
        if len(set(ids)) != len(ids):
            raise GuardError('resource already reserved; historical IDs cannot be reused')
        total = sum((number(r['estimate_usd']) for r in committed + records), Decimal(0))
        if total > LIMIT:
            raise GuardError('cumulative estimate exceeds $5.40')
        quotes = Path(str(ledger) + '.quotes')
        quotes.mkdir(exist_ok=True)
        for digest, raw in snapshots.items():
            atomic_write(quotes / (digest + '.json'), raw.decode())
        data['reservations'].extend(records)
        save_ledger(ledger, md, data)
    audit('reserved', total_usd=str(total), resources=records)


def no_meter(spec, kind, start):
    """A resource the Retail Prices API has no meter for, priced at $0 from
    an empty answer to NO_METER_FILTERS[kind]. Returns {sha256: raw quote}."""
    if spec['components']:
        raise GuardError('a resource without a meter has no priced components')
    raw = Path(spec['no_meter_quote']).read_bytes()
    quote = parse_json(raw)
    url = urlsplit(quote['url'])
    if url.scheme != 'https' or url.netloc != 'prices.azure.com' or url.path != '/api/retail/prices':
        raise GuardError('quote source must be Azure Retail Prices API')
    query = parse_qs(url.query)
    if query.get('$filter') != [NO_METER_FILTERS[kind]] or query.get('currencyCode') != ['USD']:
        raise GuardError('no-meter quote must be the exact Retail Prices API filter for this kind')
    if utc(quote['retrieved_at']) > start:
        raise GuardError('quote acquired after planned start')
    response = quote['response']
    if response.get('NextPageLink') or response.get('Items') != []:
        raise GuardError('the Retail Prices API has a meter for this resource; price it')
    return {hashlib.sha256(raw).hexdigest(): raw}


def worktree_reservations(ledger):
    """The reservations in the ledgers of the repository's other worktrees
    (git worktree list), read only. A ledger for another subscription or
    group, or a listing that fails, stops the reservation."""
    result = subprocess.run(['git', '-C', str(REPO), 'worktree', 'list', '--porcelain'], capture_output=True, text=True,
                            timeout=60)
    if result.returncode:
        raise GuardError('cannot list the Warden worktrees to read their ledgers')
    here = Path(ledger).resolve()
    out = []
    for line in result.stdout.splitlines():
        if not line.startswith('worktree '):
            continue
        tree = Path(line[len('worktree '):])
        other = tree / 'docs/azure-spend.json'
        if tree.resolve() == REPO or other.resolve() == here or not other.exists():
            continue
        data = read_json(other)
        # Version 1 (older branches) named the subscription itself; version 2 its digest.
        scope = {1: ('subscription', subscription()), 2: ('subscription_sha256', subscription_digest())}.get(data.get('version'))
        if scope is None or data.get(scope[0]) != scope[1] or data.get('group') != GROUP:
            raise GuardError(f'the ledger of worktree {other.parent.parent.name} is for another scope or version')
        for r in data['reservations']:
            number(r['estimate_usd'])
            out.append(r)
    return out


def aks_preconditions(region):
    """Read-only checks before the AKS reservation, and what they found (kept
    in the reservation): the subscription's location policies allow the
    region; the node group does not exist yet; Defender for Containers bills
    nothing; the region's Network Watcher, as it is now (or that there is
    none, if its auto-creation is approved)."""
    allowed = None
    for a in az('policy', 'assignment', 'list', '--disable-scope-strict-match'):
        if a.get('enforcementMode', 'Default') != 'Default':
            continue
        definition = a.get('policyDefinitionId') or ''
        locations = ((a.get('parameters') or {}).get('listOfAllowedLocations') or {}).get('value')
        if locations is None and '/policydefinitions/' in definition.lower():
            # A location policy (the built-in Allowed locations and its kin
            # take listOfAllowedLocations) can leave the list to its default.
            param = (az('policy', 'definition', 'show', '--name', definition.rsplit('/', 1)[-1]).get('parameters')
                     or {}).get('listOfAllowedLocations')
            if param is None:
                continue
            locations = param.get('defaultValue')
            if not isinstance(locations, list):
                raise GuardError(f'location policy {a.get("name")} does not show its allowed locations')
        if locations is None:
            continue
        if not isinstance(locations, list) or region not in locations:
            raise GuardError(f'location policy {a.get("name")} does not allow {region}')
        allowed = locations if allowed is None else [x for x in allowed if x in locations]
    if node_group() is not None:
        raise GuardError(f'{NODE_GROUP} already exists')
    for plan in ('Containers', 'KubernetesService'):
        tier = az('security', 'pricing', 'show', '--name', plan).get('pricingTier')
        if tier != 'Free':
            raise GuardError(f'Defender plan {plan} is {tier}, not Free: the cluster would be billed for it')
    watcher = watcher_state(region)
    if not watcher['existed'] and not AKS_APPROVALS['network_watcher_autocreate']:
        raise GuardError(f'no Network Watcher in {region}; Azure would create one outside both groups')
    return {'allowed_locations': allowed, 'network_watcher': watcher}


def watcher_record(w):
    keep = {k: w.get(k) for k in ('id', 'name', 'resourceGroup', 'location', 'tags', 'provisioningState', 'etag')}
    return hashlib.sha256(json.dumps(keep, sort_keys=True).encode()).hexdigest()


def watcher_state(region):
    """The region's Network Watcher: its name and group, and a digest of its
    ID, tags, state and etag (the ID names the subscription, so only the
    digest is kept)."""
    found = [w for w in az('network', 'watcher', 'list') if w.get('location') == region]
    if len(found) > 1:
        raise GuardError(f'more than one Network Watcher in {region}')
    if not found:
        return {'existed': False, 'name': f'NetworkWatcher_{region}', 'resourceGroup': 'NetworkWatcherRG'}
    w = found[0]
    return {'existed': True, 'name': w.get('name'), 'resourceGroup': w.get('resourceGroup'), 'sha256': watcher_record(w)}


def drill_watcher(data):
    """The Network Watcher state the AKS reservation recorded, or None."""
    rows = [r for r in data['reservations'] if r['kind'] == 'aks']
    return rows[-1].get('preconditions', {}).get('network_watcher') if rows else None


def judge_watcher(before, region):
    """(problem or None, summary): the region's Network Watcher compared with
    its state before the drill."""
    if before is None:
        return None, 'no AKS reservation in the ledger: not judged'
    now = [w for w in az('network', 'watcher', 'list') if w.get('location') == region]
    if before['existed']:
        if len(now) != 1 or now[0].get('name') != before['name'] or now[0].get('resourceGroup') != before['resourceGroup']:
            return 'the Network Watcher that was there before is gone', 'missing'
        if watcher_record(now[0]) != before['sha256']:
            return 'the Network Watcher that was there before has changed', 'changed'
        return None, 'unchanged'
    if now:
        return 'the Network Watcher the drill caused is still there', 'still there'
    return None, 'absent, as before the drill'


def reap(dry_run, session, ledger, md):
    if account_and_group() is None:
        if node_group() is not None:
            raise GuardError(f'{NODE_GROUP} exists without {GROUP}; no deletion attempted')
        return
    # Its resources belong to the cluster: deleting the cluster removes them.
    node_group()
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
                     and full_id(x['id']).lower() == rid.lower() and x['deleted_at'] is None
                     and number(x['tags']['est_usd_per_hour']) > Decimal('0.02')]
            if known and (len(known) != 1 or known[0]['tags'] != tags):
                unresolved.append(rid)
                audit('unresolved-session-cleanup', id=rid, session=session,
                      reason='known high-cost resource lost its complete reservation/ownership binding')
                continue
            if tags.get('project') != 'warden' or tags.get('owner') != 'warden-lab':
                audit('retain-unowned', id=rid)
                continue
            expiry, rate = tags_valid(tags)
            bound = [x for x in data['reservations'] if full_id(x['id']) == rid and
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
            # A managed cluster takes minutes to delete (and removes NODE_GROUP).
            az('resource', 'delete', '--ids', r['id'], timeout=3600)
            for entry in data['reservations']:
                if full_id(entry['id']) == r['id']:
                    entry['deleted_at'] = stamp(utc_now())
            save_ledger(ledger, md, data)


def down(dry_run, ledger, md):
    group = account_and_group()
    nodes = node_group()
    if group is None:
        if nodes is not None:
            raise GuardError(f'{NODE_GROUP} exists without {GROUP}; no deletion attempted')
        return
    cluster = az('aks', 'show', '--resource-group', GROUP, '--name', AKS_CLUSTER, absent_ok=True)
    if cluster is not None and (cluster.get('id', '').lower() != aks_id().lower()
                                or cluster.get('nodeResourceGroup') != NODE_GROUP):
        raise GuardError('cluster identity mismatch; no deletion attempted')
    verb = 'would-delete' if dry_run else 'delete'
    if cluster is not None:
        audit(verb + '-cluster', id=aks_id(), node_group=node_group_id())
    audit(verb + '-group', id=group_id(), warning='rg-mlinfra-westus is always protected; never operate on it')
    if not dry_run:
        with ledger_lock(ledger):
            data = read_ledger(ledger)
            if cluster is not None:
                # Deleting the cluster first makes AKS remove NODE_GROUP before the group goes.
                az('aks', 'delete', '--resource-group', GROUP, '--name', AKS_CLUSTER, '--yes', timeout=3600)
            az('group', 'delete', '--name', GROUP, '--yes', timeout=3600)
            for r in data['reservations']:
                if r['deleted_at'] is None:
                    r['deleted_at'] = stamp(utc_now())
            save_ledger(ledger, md, data)
        tries, every = NODE_GROUP_WAIT
        for _ in range(tries):
            if node_group() is None:
                break
            time.sleep(every)
        else:
            if node_group() is not None:
                raise GuardError(f'{NODE_GROUP} still exists after {GROUP} was deleted')
        delete_caused_watcher(read_ledger(ledger))


def delete_caused_watcher(data):
    """Deletes NetworkWatcher_<region> in NetworkWatcherRG only when the
    AKS reservation recorded that the region had none before the drill
    (AKS_APPROVALS: the drill deletes what it caused, nothing else)."""
    before = drill_watcher(data)
    if not before or before['existed'] or before['name'] != f'NetworkWatcher_{AKS_REGION}' \
            or before['resourceGroup'] != 'NetworkWatcherRG':
        return
    want = watcher_id('NetworkWatcherRG', before['name']).lower()
    for w in az('network', 'watcher', 'list'):
        if w.get('location') == AKS_REGION and (w.get('id') or '').lower() == want:
            audit('delete-caused-network-watcher', name=before['name'], group='NetworkWatcherRG')
            az('resource', 'delete', '--ids', w['id'], timeout=900)


def teardown_check(ledger):
    """Read-only: nothing of the AKS drill is left anywhere in the
    subscription, no role assignment it caused remains, and the region's
    Network Watcher is as it was before the drill (or gone, if the drill
    caused it)."""
    account = az('account', 'show')
    if account.get('id') != subscription() or account.get('name') != 'Azure for Students' or account.get('state') != 'Enabled':
        raise GuardError('pinned Azure for Students account mismatch')
    found = {
        'group': az('group', 'show', '--name', GROUP, absent_ok=True) is not None,
        'node_group': az('group', 'show', '--name', NODE_GROUP, absent_ok=True) is not None,
        'clusters': [c.get('name') for c in az('aks', 'list') if c.get('name') == AKS_CLUSTER
                     or c.get('resourceGroup') in {GROUP, NODE_GROUP} or c.get('nodeResourceGroup') == NODE_GROUP],
        'tagged_resources': [r.get('id', '').split('/providers/', 1)[-1] for r in az('resource', 'list', '--tag', 'project=warden')],
        'groups': [g.get('name') for g in az('group', 'list') if g.get('name') in {GROUP, NODE_GROUP}
                   or (g.get('name', '').startswith('MC_') and 'warden' in g.get('name', '').lower())
                   or '/resourcegroups/rg-warden-lab/' in (g.get('managedBy') or '').lower()],
        'identities': [i.get('name') for i in az('identity', 'list') if i.get('name', '').startswith('warden-lab')
                       or i.get('resourceGroup') in {GROUP, NODE_GROUP}],
    }
    groups = ('/resourcegroups/' + GROUP.lower(), '/resourcegroups/' + NODE_GROUP.lower())
    principals = set()
    principals_file = AKS_PRIVATE / 'principals.json'
    if principals_file.exists():
        principals = {v for v in read_json(principals_file).values() if v}
    left = []
    for a in az('role', 'assignment', 'list', '--all'):
        scope = (a.get('scope') or '').lower()
        if any(scope.endswith(g) or g + '/' in scope for g in groups) or a.get('principalId') in principals:
            left.append(a.get('roleDefinitionName') or 'role')
    found['role_assignments'] = left
    problem, watcher = judge_watcher(drill_watcher(read_ledger(ledger)), AKS_REGION)
    if problem:
        found['network_watcher'] = problem
    ok = not any(found.values())
    audit('teardown-check', ok=ok, found=found, network_watcher=watcher,
          principals_checked=len(principals))
    if not ok:
        raise GuardError('AKS drill resources are still there: ' + ', '.join(k for k, v in found.items() if v))


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
    if used + additional + download > DISK_SHARE_BYTES:
        raise GuardError('Warden project disk would exceed 24GB')
    if memory > 16_000_000_000:
        raise GuardError('aggregate resident service memory exceeds 16GB')
    if download > 5_000_000_000 and free < 50_000_000_000 + download:
        raise GuardError('large download requires 50GB plus download size free')
    audit('local-preflight', project_allocated_bytes=used, free_bytes=free,
          additional_bytes=str(additional), download_bytes=str(download), service_memory_bytes=str(memory))


def main():
    parser = argparse.ArgumentParser(description='Warden guards: rg-mlinfra-westus is always protected. No resource creation.')
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('teardown-check')
    p.add_argument('--ledger', type=Path, default=DEFAULT_LEDGER)
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
            elif args.command == 'teardown-check':
                teardown_check(args.ledger)
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
