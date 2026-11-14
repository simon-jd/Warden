#!/usr/bin/env bash
# Counts long-lived credentials in the Azure tenant/subscription (Task 8,
# TestNoLongLivedKeys; the plan's AWS access keys / GCP SA keys map to these):
#   - Entra app registrations: unexpired client secrets and certificates
#   - storage accounts whose shared-key access is not disabled
# Federated (workload identity) credentials are not secrets and are not counted.
#
# usage: longlived_keys_audit.sh [--fixture DIR] [--now ISO8601] [--project NAME] [--allow-empty] [--scope-file FILE]
#   --fixture DIR     read DIR/account.json, DIR/apps.json and DIR/storage.json instead of calling az
#   --project NAME    list every finding but count only NAME's: apps tagged project=NAME or untagged,
#                     storage tagged project=NAME or in rg-NAME-lab or its AKS node groups MC_rg-NAME-lab_*
#   --allow-empty     an empty scope (nothing to audit) exits 0 instead of 3
#   --scope-file FILE the expected subscription (default .cache/azure-subscription, as for azure_guard.py)
# Prints a JSON report. Exit 0: none found; 1: found; 2: input error, or az is
# signed in to another subscription than the expected one; 3: nothing in scope.
# Scope: the tenant is a university directory, so only Entra apps the signed-in
# user owns (`--show-mine`, Graph /me/ownedObjects; az follows @odata.nextLink;
# Warden apps owned by anyone else are not seen) and the storage accounts of the
# expected subscription (ARM Reader). It never lists the directory's other apps,
# users or groups. The report says the subscription matched; it holds no
# subscription, tenant or user ID.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fixture="" opts=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fixture) fixture=$2; shift 2 ;;
    --now|--project|--scope-file) opts+=("$1" "$2"); shift 2 ;;
    --allow-empty) opts+=("$1"); shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [[ -n "$fixture" ]]; then
  dir=$fixture
else
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' EXIT
  az account show -o json >"$dir/account.json" || { echo "az account show failed" >&2; exit 2; }
  sub=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$dir/account.json") ||
    { echo "az account show: no subscription" >&2; exit 2; }
  az ad app list --show-mine --all -o json >"$dir/apps.json" || { echo "az ad app list failed" >&2; exit 2; }
  az storage account list --subscription "$sub" -o json >"$dir/storage.json" || { echo "az storage account list failed" >&2; exit 2; }
fi
python3 -I -B "$here/longlived_keys_audit.py" --account "$dir/account.json" --apps "$dir/apps.json" \
  --storage "$dir/storage.json" "${opts[@]}"
