"""Offline checks of identity/terraform/idp.tf against what the Go verifier accepts.

terraform validate only proves the file is well formed. These tests pin the
properties the control plane depends on: a v2 access token (issuer and ver),
the exact scope authn requires, a single-tenant app, and no client credential.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TF = ROOT / "identity" / "terraform" / "idp.tf"
LOCK = ROOT / "identity" / "terraform" / ".terraform.lock.hcl"
VERIFIER = ROOT / "controlplane" / "internal" / "authn" / "verifier.go"
AZURE_CLI = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"


def strip_comments(text):
    """Drop #, // and /* */ comments outside string literals."""
    out, i, in_string = [], 0, False
    while i < len(text):
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
        elif c == "#" or text.startswith("//", i):
            while i < len(text) and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = len(text) if end < 0 else end + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def blocks(text, kind, label=None):
    """Bodies of top-level `kind "label" "name" { ... }` blocks (brace matched)."""
    pattern = r'^%s\s+"%s"(?:\s+"[^"]+")?\s*\{' % (re.escape(kind), re.escape(label) if label else '[^"]+')
    bodies = []
    for m in re.finditer(pattern, text, re.M):
        depth, i = 1, m.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        bodies.append(text[m.end():i - 1])
    return bodies


def unlabeled(text, kind):
    """Bodies of top-level `kind { ... }` blocks such as locals."""
    bodies = []
    for m in re.finditer(r'^%s\s*\{' % re.escape(kind), text, re.M):
        depth, i = 1, m.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        bodies.append(text[m.end():i - 1])
    return bodies


class IdpTerraformTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = TF.read_text(encoding="utf-8") if TF.exists() else ""
        cls.tf = strip_comments(cls.raw)

    def test_file_exists(self):
        self.assertTrue(TF.is_file(), f"{TF} missing")

    def test_scope_matches_verifier(self):
        required = re.search(r'requiredScope\s*=\s*"([^"]+)"', VERIFIER.read_text()).group(1)
        apps = blocks(self.tf, "resource", "azuread_application")
        self.assertEqual(len(apps), 1, "exactly one azuread_application")
        scopes = re.findall(r'oauth2_permission_scope\s*\{(.*?)\n\s*\}', apps[0], re.S)
        self.assertEqual(len(scopes), 1, "exactly one delegated scope")
        self.assertRegex(scopes[0], r'\bvalue\s*=\s*"%s"' % re.escape(required))
        self.assertRegex(scopes[0], r'\benabled\s*=\s*true')
        self.assertRegex(scopes[0], r'\btype\s*=\s*"User"')

    def test_v2_single_tenant_tokens(self):
        app = blocks(self.tf, "resource", "azuread_application")[0]
        # The verifier accepts only https://login.microsoftonline.com/<tid>/v2.0 and ver 2.0,
        # with aud equal to the client ID: that is what version 2 issues.
        self.assertRegex(app, r'requested_access_token_version\s*=\s*2\b')
        self.assertRegex(app, r'sign_in_audience\s*=\s*"AzureADMyOrg"')
        self.assertNotRegex(app, r'group_membership_claims')

    def test_identifier_uri_is_api_client_id(self):
        uris = blocks(self.tf, "resource", "azuread_application_identifier_uri")
        self.assertEqual(len(uris), 1)
        self.assertRegex(uris[0], r'identifier_uri\s*=\s*"api://\$\{azuread_application\.\w+\.client_id\}"')

    def test_no_client_credentials(self):
        for kind in ("azuread_application_password", "azuread_service_principal_password",
                     "azuread_application_certificate", "azuread_service_principal_certificate",
                     "azuread_application_federated_identity_credential"):
            self.assertNotIn(kind, self.tf)
        self.assertNotRegex(self.tf, r'\bpassword\s*\{')
        self.assertNotRegex(self.tf, r'client_secret|client_certificate')
        self.assertRegex(self.tf, r'fallback_public_client_enabled\s*=\s*false')

    def test_lab_names_tags_and_ownership(self):
        names = re.findall(r'(?<!\w)display_name\s*=\s*"([^"]*)"', self.tf)
        self.assertTrue(names, "display_name missing")
        for name in names:
            self.assertTrue(name.startswith("warden-lab-"), name)
        for kind in ("azuread_application", "azuread_service_principal"):
            body = blocks(self.tf, "resource", kind)
            self.assertEqual(len(body), 1, kind)
            self.assertRegex(body[0], r'\btags\s*=\s*local\.tags\b', kind)
            self.assertRegex(body[0], r'owners\s*=\s*\[data\.azuread_client_config\.current\.object_id\]', kind)
        locals_ = unlabeled(self.tf, "locals")
        self.assertEqual(len(locals_), 1)
        self.assertRegex(locals_[0], r'tags\s*=\s*\[[^\]]*"project=warden"')

    def test_preauthorized_clients_are_explicit(self):
        pre = blocks(self.tf, "resource", "azuread_application_pre_authorized")
        self.assertEqual(len(pre), 1)
        self.assertRegex(pre[0], r'permission_ids\s*=\s*\[local\.scope_id\]')
        variable = blocks(self.tf, "variable", "preauthorized_client_ids")
        self.assertEqual(len(variable), 1)
        self.assertIn(AZURE_CLI, variable[0], "lab default: the Azure CLI gets warden.access without consent")

    def test_provider_pinned_and_locked(self):
        self.assertRegex(self.tf, r'source\s*=\s*"hashicorp/azuread"')
        pinned = re.search(r'version\s*=\s*"=?\s*(\d+\.\d+\.\d+)"', self.tf)
        self.assertIsNotNone(pinned, "azuread provider must be an exact version")
        self.assertTrue(LOCK.is_file(), "commit .terraform.lock.hcl")
        lock = LOCK.read_text()
        self.assertIn('provider "registry.terraform.io/hashicorp/azuread"', lock)
        self.assertIn(f'version     = "{pinned.group(1)}"', lock)
        self.assertNotIn("hashicorp/random", lock, "scope ID is a literal, no extra provider")

    def test_strip_comments_keeps_strings(self):
        self.assertEqual(strip_comments('a = "x#y" # c\nb = 1 // d\n/* e */c'), 'a = "x#y" \nb = 1 \nc')


if __name__ == "__main__":
    unittest.main()
