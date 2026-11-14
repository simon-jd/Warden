"""Derive tag coverage; actual conversion is distinct from indexed detection."""

import argparse
import re
from pathlib import Path
from uuid import UUID


TECHNIQUE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)$")


def summarize_rules(rules: list[dict]) -> dict:
    if not rules:
        raise ValueError("coverage input cannot be empty")
    rows = []
    seen = set()
    techniques = {}
    for rule in rules:
        rule_id = rule["id"]
        if str(UUID(rule_id)) != rule_id or rule_id in seen:
            raise ValueError("rule IDs must be unique canonical UUIDs")
        seen.add(rule_id)
        title = rule["title"]
        tags = rule.get("tags", [])
        if not isinstance(title, str) or not title or not isinstance(tags, list):
            raise ValueError("nonempty title and tag list required")
        ids = set()
        for tag in tags:
            if not isinstance(tag, str):
                raise ValueError("tags must be strings")
            match = TECHNIQUE.fullmatch(tag)
            if match:
                ids.add(match.group(1).upper())
            elif tag.startswith("attack.t"):
                raise ValueError(f"malformed ATT&CK technique tag: {tag}")
        for technique in ids:
            techniques.setdefault(technique, []).append(rule_id)
        rows.append({"id": rule_id, "title": title, "techniques": sorted(ids)})
    tagged = sum(bool(row["techniques"]) for row in rows)
    return {
        "rule_count": len(rows),
        "tagged_rule_count": tagged,
        "unassigned_rule_count": len(rows) - tagged,
        "technique_count": len(techniques),
        "rules": sorted(rows, key=lambda row: row["id"]),
        "techniques": [
            {"id": technique, "rule_ids": sorted(techniques[technique])}
            for technique in sorted(techniques)
        ],
    }


def render_markdown(summary: dict, converted_ids: set[str]) -> str:
    if converted_ids != {row["id"] for row in summary["rules"]}:
        raise ValueError("all reported rules require actual backend conversion")
    lines = [
        "# ATT&CK tag coverage and local conversion",
        "",
        "Generated from the actual Sigma tags after local pySigma/OpenSearch-backend conversion.",
        "Tags describe related investigation scenarios. They are not technique success or detection-rate evidence.",
        "Fixture events are synthetic. Fixture contract results belong to the local cover evidence.",
        "OpenSearch indexed queries and live telemetry/detection remain UNRUN. Whole Task12 remains OPEN.",
        "",
        f"Rules: {summary['rule_count']}; tagged: {summary['tagged_rule_count']}; "
        f"unassigned: {summary['unassigned_rule_count']}; related techniques: {summary['technique_count']}.",
        "",
        "| Rule ID | Action / indicator | Related tags | Local conversion | Indexed query | Live detection |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in summary["rules"]:
        title = row["title"].replace("|", "\\|").replace("\n", " ")
        tags = ", ".join(row["techniques"]) or "unassigned"
        lines.append(f"| {row['id']} | {title} | {tags} | PASS | UNRUN | UNRUN |")
    lines += ["", "| Related technique | Rule IDs |", "| --- | --- |"]
    for row in summary["techniques"]:
        lines.append(f"| {row['id']} | {', '.join(row['rule_ids'])} |")
    lines += [
        "",
        "Pending upstream contracts: trusted Warden denial context; privileged-Pod Request projection; runtime connect/Pod attribution.",
        "Kubernetes objectRef is conditional bounded passthrough, not demonstrated live collection.",
        "",
    ]
    return "\n".join(lines)


def build_report(rule_dir: Path | None = None) -> dict:
    from detect.sigma.convert import RULES_DIR, compile_catalogue

    compiled = compile_catalogue(RULES_DIR if rule_dir is None else rule_dir)
    summary = summarize_rules([item["rule"] for item in compiled])
    text = render_markdown(summary, {item["rule"]["id"] for item in compiled})
    return {"compiled": compiled, "summary": summary, "markdown": text}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("docs/evidence/attack-coverage.md"))
    args = parser.parse_args()
    args.output.write_text(build_report()["markdown"])


if __name__ == "__main__":
    main()
