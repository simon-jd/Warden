"""Throwaway OpenSearch container and fixture loading for detect.sigma.test_rules.

Only `make test-opensearch` (WARDEN_LIVE_OPENSEARCH=1) starts a container. The
container is named warden-opensearch-*, bound to 127.0.0.1, memory-capped and
removed with its anonymous volumes when the test class finishes.
"""

import json
import os
import secrets
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

SIGMA_DIR = Path(__file__).parent
TESTS_DIR = SIGMA_DIR / "tests"
MAPPING = SIGMA_DIR / "opensearch-mapping.json"
IMAGE = os.environ.get("WARDEN_OPENSEARCH_IMAGE", "opensearchproject/opensearch:2.19.1")
# 512 MiB heap inside a 1.5 GiB container: well inside the project's 16 GB share.
HEAP = "512m"
MEMORY = "1536m"
INDEX = "warden-sigma-fixtures"


def load_manifest() -> dict:
    return json.loads((TESTS_DIR / "manifest.json").read_text())


def rule_documents(row: dict) -> list[dict]:
    """Every indexed document for one manifest row, with its expected label."""
    directory = TESTS_DIR / row["id"]
    docs = [
        {"id": row["document_ids"]["positive"], "name": "pos",
         "expected": True, "event": json.loads((directory / row["pair"]["positive"]).read_text())},
        {"id": row["document_ids"]["negative"], "name": "neg",
         "expected": False, "event": json.loads((directory / row["pair"]["negative"]).read_text())},
    ]
    for case in json.loads((directory / row["cases"]).read_text()):
        if type(case["expected_match"]) is not bool:
            raise ValueError(f"{row['id']}/{case['name']}: expected_match must be a bool")
        docs.append({"id": case["document_id"], "name": case["name"],
                     "expected": case["expected_match"], "event": case["event"]})
    return docs


def all_documents(manifest: dict) -> dict[str, list[dict]]:
    out = {}
    seen = set()
    for row in manifest["rules"]:
        docs = rule_documents(row)
        for doc in docs:
            if doc["id"] in seen:
                raise ValueError(f"duplicate document id {doc['id']}")
            seen.add(doc["id"])
        out[row["id"]] = docs
    return out


def bulk_body(index: str, docs: list[dict]) -> bytes:
    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": index, "_id": doc["id"]}}))
        lines.append(json.dumps(doc["event"], separators=(",", ":")))
    return ("\n".join(lines) + "\n").encode()


def scoped_query(lucene: str, ids: list[str] | None, size: int) -> dict:
    """The backend's Lucene string is a JSON value, never concatenated with IDs."""
    query: dict = {"query_string": {"query": lucene}}
    if ids is not None:
        query = {"bool": {"must": [query], "filter": [{"ids": {"values": list(ids)}}]}}
    return {"query": query, "size": size, "_source": False, "track_total_hits": True}


class Container:
    def __init__(self, image: str = IMAGE):
        self.image = image
        self.name = f"warden-opensearch-{os.getpid()}-{secrets.token_hex(4)}"
        self.url = ""

    def _docker(self, *args: str, timeout: float = 120) -> str:
        return subprocess.run(["docker", *args], check=True, capture_output=True,
                              text=True, timeout=timeout).stdout.strip()

    def start(self, deadline: float = 240) -> None:
        self._docker(
            "run", "-d", "--name", self.name, "--label", "warden.test=task12",
            "--memory", MEMORY, "--memory-swap", MEMORY, "--cpus", "2", "--pids-limit", "512",
            "-p", "127.0.0.1::9200",
            "-e", "discovery.type=single-node",
            "-e", "DISABLE_SECURITY_PLUGIN=true",
            "-e", "DISABLE_INSTALL_DEMO_CONFIG=true",
            "-e", f"OPENSEARCH_JAVA_OPTS=-Xms{HEAP} -Xmx{HEAP}",
            self.image, timeout=900)
        port = self._docker("port", self.name, "9200/tcp").splitlines()[0].rsplit(":", 1)[1]
        self.url = f"http://127.0.0.1:{port}"
        end = time.monotonic() + deadline
        while True:
            try:
                health = self.request("GET", "/_cluster/health?wait_for_status=yellow&timeout=5s")
                if health.get("status") in ("yellow", "green"):
                    return
            except (OSError, urllib.error.URLError, ValueError):
                pass
            if time.monotonic() > end:
                raise TimeoutError(f"OpenSearch not ready after {deadline}s:\n" + self.logs())
            time.sleep(1)

    def logs(self) -> str:
        try:
            return subprocess.run(["docker", "logs", "--tail", "40", self.name],
                                  capture_output=True, text=True, timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def image_digest(self) -> str:
        return self._docker("image", "inspect", "--format", "{{json .RepoDigests}}", self.image)

    def stats(self) -> str:
        return self._docker("stats", "--no-stream", "--format", "{{.MemUsage}}", self.name)

    def remove(self) -> None:
        subprocess.run(["docker", "rm", "-f", "-v", self.name], capture_output=True, timeout=120)

    def request(self, method: str, path: str, body: bytes | dict | None = None,
                content_type: str = "application/json") -> dict:
        if isinstance(body, dict):
            body = json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=body, method=method,
                                     headers={"Content-Type": content_type})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as err:
            raise RuntimeError(f"{method} {path}: HTTP {err.code}: {err.read()[:2000]!r}") from None
