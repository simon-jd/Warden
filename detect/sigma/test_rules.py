"""Sigma rules against a real OpenSearch index (Task 12).

The offline tests check how fixtures become documents and queries. The live
class starts a throwaway OpenSearch container, indexes every pos/neg/case
document with detect/sigma/opensearch-mapping.json, runs each rule's pySigma
Lucene query and asserts that exactly the expected documents match. It only
runs with WARDEN_LIVE_OPENSEARCH=1 (`make test-opensearch`); OS_OUT=<file>
keeps the raw result JSON.
"""

import json
import os
import platform
import time
import unittest

from detect.sigma import opensearch_live as live
from detect.sigma.convert import RULES_DIR, convert_rule


class FixtureDocumentTest(unittest.TestCase):
    def test_every_fixture_becomes_one_labelled_document(self):
        manifest = live.load_manifest()
        docs = live.all_documents(manifest)
        self.assertEqual(len(docs), 32)
        total = sum(len(d) for d in docs.values())
        self.assertEqual(total, 64 + 197)
        for row in manifest["rules"]:
            with self.subTest(rule=row["number"]):
                by_name = {d["name"]: d for d in docs[row["id"]]}
                self.assertTrue(by_name["pos"]["expected"])
                self.assertFalse(by_name["neg"]["expected"])
                self.assertEqual(by_name["pos"]["id"], row["document_ids"]["positive"])

    def test_bulk_body_is_ndjson_with_explicit_ids(self):
        docs = [{"id": "a", "event": {"class_uid": 1}}, {"id": "b", "event": {"class_uid": 2}}]
        lines = live.bulk_body("ix", docs).decode().splitlines()
        self.assertEqual(len(lines), 4)
        self.assertEqual(json.loads(lines[0]), {"index": {"_index": "ix", "_id": "a"}})
        self.assertEqual(json.loads(lines[3]), {"class_uid": 2})

    def test_scoped_query_keeps_lucene_as_a_value(self):
        hostile = 'x:1 OR _id:"b"'
        body = live.scoped_query(hostile, ["a"], 10)
        self.assertEqual(body["query"]["bool"]["must"][0]["query_string"]["query"], hostile)
        self.assertEqual(body["query"]["bool"]["filter"][0]["ids"]["values"], ["a"])
        self.assertNotIn("bool", live.scoped_query(hostile, None, 10)["query"])


@unittest.skipUnless(os.environ.get("WARDEN_LIVE_OPENSEARCH") == "1",
                     "live OpenSearch: run `make test-opensearch`")
class OpenSearchRuleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = live.load_manifest()
        cls.docs = live.all_documents(cls.manifest)
        cls.container = live.Container()
        cls.addClassCleanup(cls.container.remove)
        started = time.monotonic()
        cls.container.start()
        cls.startup_s = round(time.monotonic() - started, 1)
        cls.container.request("PUT", f"/{live.INDEX}", json.loads(live.MAPPING.read_text()))
        every = [doc for docs in cls.docs.values() for doc in docs]
        resp = cls.container.request("POST", "/_bulk?refresh=wait_for",
                                     live.bulk_body(live.INDEX, every), "application/x-ndjson")
        cls.bulk_errors = [item["index"] for item in resp["items"] if item["index"].get("error")]
        cls.indexed = cls.container.request("GET", f"/{live.INDEX}/_count")["count"]
        cls.version = cls.container.request("GET", "/")["version"]["number"]
        cls.results = []

    @classmethod
    def tearDownClass(cls):
        out = os.environ.get("OS_OUT")
        if out:
            failed = [r for r in cls.results if not r["pass"]]
            report = {
                "opensearch_version": cls.version,
                "image": cls.container.image,
                "image_repo_digests": json.loads(cls.container.image_digest()),
                "heap": live.HEAP, "container_memory_limit": live.MEMORY,
                "container_mem_usage_at_end": cls.container.stats(),
                "startup_seconds": cls.startup_s,
                "documents_indexed": cls.indexed, "bulk_errors": cls.bulk_errors,
                "rules": len(cls.results), "rules_passed": len(cls.results) - len(failed),
                "rules_failed": [r["rule"] for r in failed],
                "host": {"nproc": os.cpu_count(), "loadavg": os.getloadavg(),
                         "kernel": platform.release()},
                "results": cls.results,
            }
            with open(out, "w") as fh:
                json.dump(report, fh, indent=2)
                fh.write("\n")

    def test_index_accepts_every_fixture(self):
        self.assertEqual(self.bulk_errors, [])
        self.assertEqual(self.indexed, 64 + 197)

    def test_each_rule_matches_exactly_its_expected_documents(self):
        for row in self.manifest["rules"]:
            docs = self.docs[row["id"]]
            query = convert_rule((RULES_DIR / row["rule"]).read_text())[0]
            scoped = self.container.request(
                "POST", f"/{live.INDEX}/_search", live.scoped_query(query, [d["id"] for d in docs], 100))
            hits = {h["_id"] for h in scoped["hits"]["hits"]}
            # Same query over the whole index: other rules' fixtures can match
            # too; recorded, not asserted.
            whole = self.container.request("POST", f"/{live.INDEX}/_search",
                                           live.scoped_query(query, None, 0))
            expected = {d["id"] for d in docs if d["expected"]}
            wrong = [{"name": d["name"], "expected": d["expected"], "matched": d["id"] in hits}
                     for d in docs if (d["id"] in hits) != d["expected"]]
            self.results.append({
                "rule": row["rule"], "id": row["id"], "query": query,
                "documents": len(docs), "expected_hits": len(expected), "hits": len(hits),
                "pos_hit": row["document_ids"]["positive"] in hits,
                "neg_hit": row["document_ids"]["negative"] in hits,
                "whole_index_hits": whole["hits"]["total"]["value"],
                "mismatches": wrong, "pass": not wrong,
            })
            with self.subTest(rule=row["rule"]):
                self.assertEqual(wrong, [], query)


if __name__ == "__main__":
    unittest.main()
