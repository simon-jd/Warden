"""Convert the bounded Warden OCSF rule subset with the real Sigma backend.

No event matching occurs here. OpenSearch query execution remains separate.
"""

from pathlib import Path

import yaml
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations.values import CaseTransformation


RULES_DIR = Path(__file__).parent / "rules"
FIELDS = frozenset({
    "class_uid", "metadata.product.name", "status_id", "api.operation",
    "actor.user.uid", "unmapped.objectRef.resource", "unmapped.objectRef.subresource",
    "process.name", "actor.process.name", "dst_endpoint.ip", "dst_endpoint.port",
    "unmapped.direction",
})
MODIFIERS = {(), ("endswith",), ("startswith",), ("exists",)}


def read_rule(text: str) -> dict:
    """Reject unsupported authoring syntax before invoking the backend."""
    rule = yaml.safe_load(text)
    if not isinstance(rule, dict) or not isinstance(rule.get("detection"), dict):
        raise ValueError("a Sigma rule with a detection map is required")
    for selection, fields in rule["detection"].items():
        if selection == "condition":
            if not isinstance(fields, str):
                raise ValueError("one string condition is required")
            continue
        if not isinstance(fields, dict) or not fields:
            raise ValueError("only nonempty field selections are supported")
        for key, values in fields.items():
            parts = key.split("|")
            if parts[0] not in FIELDS or tuple(parts[1:]) not in MODIFIERS:
                raise ValueError(f"unsupported field or modifier: {key}")
            values = values if isinstance(values, list) else [values]
            if not values:
                raise ValueError("selection values cannot be empty")
            for value in values:
                if type(value) not in (str, bool, int):
                    raise ValueError("only ASCII strings, booleans and integers are supported")
                if isinstance(value, str) and (not value or not value.isascii()):
                    raise ValueError("rule strings must be nonempty ASCII")
    return rule


def ocsf_pipeline() -> ProcessingPipeline:
    """Fold only detection string values; leave dotted OCSF field names intact."""
    return ProcessingPipeline(
        items=[ProcessingItem(transformation=CaseTransformation(method="lower"))]
    )


def convert_rule(text: str) -> list[str]:
    """Return real backend Lucene output, never fixture hit/miss decisions."""
    read_rule(text)
    collection = SigmaCollection.from_yaml(text, collect_errors=False)
    if len(collection.rules) != 1:
        raise ValueError("exactly one Sigma rule is required")
    queries = OpensearchLuceneBackend(
        ocsf_pipeline(), collect_errors=False
    ).convert(collection)
    if len(queries) != 1 or not isinstance(queries[0], str) or not queries[0].strip():
        raise ValueError("backend must emit one nonempty Lucene query")
    return queries


def compile_catalogue(rule_dir: Path = RULES_DIR) -> list[dict]:
    paths = sorted(rule_dir.glob("*.yml"))
    if not paths:
        raise ValueError("rule catalogue cannot be empty")
    compiled = []
    for path in paths:
        text = path.read_text()
        compiled.append({"file": path.name, "rule": read_rule(text), "queries": convert_rule(text)})
    return compiled
