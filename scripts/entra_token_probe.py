#!/usr/bin/env python3
"""Ask Entra for a new delegated token now, bypassing the Azure CLI's token cache.

`az account get-access-token` returns a cached access token until it nearly
expires, so it cannot show when an unassignment starts to block new tokens.
This probe runs under the Azure CLI's own Python (it needs msal), loads the CLI
token cache read-only into memory, and calls acquire_token_silent_with_error
with force_refresh=True: one real token request to Entra with the cached
refresh token. Nothing is written back to ~/.azure, and only a summary
(success, AADSTS codes, latency) is printed, never a token.

  /opt/az/bin/python3 -I -B scripts/entra_token_probe.py --tenant <id> --username <upn> --scope <scope>
"""

import argparse
import json
import os
import re
import sys
import time

AZURE_CLI = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"


def summarize(result, ms):
    """Success flag, AADSTS codes and the OAuth error name; never token values."""
    result = result or {}
    ok = bool(result.get("access_token"))
    codes = sorted(set(re.findall(r"AADSTS\d+", result.get("error_description") or "")))
    return {"ok": ok, "ms": ms, "aadsts": codes, "error": None if ok else result.get("error")}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--cache", default=os.path.expanduser("~/.azure/msal_token_cache.json"))
    args = parser.parse_args(argv)
    import msal  # only available in the Azure CLI's Python

    cache = msal.SerializableTokenCache()
    with open(args.cache, encoding="utf-8") as f:
        cache.deserialize(f.read())
    app = msal.PublicClientApplication(AZURE_CLI, authority=f"https://login.microsoftonline.com/{args.tenant}",
                                       token_cache=cache)
    accounts = app.get_accounts(args.username)
    if len(accounts) != 1:
        print(json.dumps({"ok": False, "ms": 0, "aadsts": [], "error": f"{len(accounts)} cached accounts"}))
        return 2
    start = time.perf_counter()
    result = app.acquire_token_silent_with_error([args.scope], accounts[0], force_refresh=True)
    ms = round((time.perf_counter() - start) * 1000, 1)
    print(json.dumps(summarize(result, ms)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
