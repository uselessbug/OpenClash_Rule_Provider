#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_CLASSICAL = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
}
SKIPPED_CLASSICAL = {"USER-AGENT", "PROCESS-NAME"}


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("payload"), list):
        raise ValueError(f"{path}: expected YAML mapping with a payload list")
    return data


def normalize_domain_value(value: str, behavior: str) -> tuple[str, str]:
    value = value.strip()
    if not value:
        raise ValueError("empty domain value")

    if behavior == "domain":
        if value.startswith("+."):
            return "domain_suffix", value[2:]
        if value.startswith("."):
            return "domain_suffix", value[1:]
        return "domain", value

    raise ValueError(f"unsupported domain behavior: {behavior}")


def validate_domain(value: str, source: str) -> None:
    if any(ch.isspace() for ch in value):
        raise ValueError(f"{source}: invalid domain value with whitespace: {value!r}")


def validate_cidr(value: str, source: str) -> str:
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise ValueError(f"{source}: invalid CIDR {value!r}") from exc


def add_value(bucket: dict[str, set[str]], key: str, value: str, source: str) -> None:
    if key == "ip_cidr":
        value = validate_cidr(value, source)
    else:
        validate_domain(value, source)
    bucket[key].add(value)


def parse_classical_entry(entry: str, source: str, bucket: dict[str, set[str]], warnings: list[str]) -> None:
    parts = [part.strip() for part in entry.split(",")]
    if len(parts) < 2:
        raise ValueError(f"{source}: malformed classical rule: {entry!r}")

    rule_type = parts[0].upper()
    value = parts[1]

    if rule_type in SKIPPED_CLASSICAL:
        warnings.append(f"{source}: skipped Android-incompatible/unsupported rule: {entry}")
        return

    mapped = SUPPORTED_CLASSICAL.get(rule_type)
    if mapped is None:
        raise ValueError(f"{source}: unsupported rule type {rule_type!r}: {entry}")

    add_value(bucket, mapped, value, source)


def build_rules(bucket: dict[str, set[str]], keys: list[str]) -> list[dict[str, list[str]]]:
    rules: list[dict[str, list[str]]] = []
    for key in keys:
        values = sorted(bucket.get(key, set()))
        if values:
            # Separate rule objects are intentional: distinct sing-box match fields are ANDed.
            rules.append({key: values})
    return rules


def write_json(path: Path, rules: list[dict[str, list[str]]]) -> None:
    payload = {"version": 1, "rules": rules}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert OpenClash rule providers to sing-box source rule-sets")
    parser.add_argument("--manifest", default="config/sources.yaml")
    parser.add_argument("--output", default="dist/source")
    parser.add_argument("--metadata", default="dist/metadata.json")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    manifest_path = repo_root / args.manifest
    output_dir = repo_root / args.output
    metadata_path = repo_root / args.metadata

    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    sources = manifest.get("sources") if isinstance(manifest, dict) else None
    if not isinstance(sources, list) or not sources:
        raise ValueError(f"{manifest_path}: expected non-empty sources list")

    bucket: dict[str, set[str]] = defaultdict(set)
    warnings: list[str] = []
    source_stats: dict[str, dict[str, int]] = {}

    for source in sources:
        if not isinstance(source, dict):
            raise ValueError(f"{manifest_path}: invalid source entry: {source!r}")

        name = str(source.get("name") or "").strip()
        rel_path = str(source.get("path") or "").strip()
        behavior = str(source.get("behavior") or "").strip().lower()
        if not name or not rel_path or behavior not in {"domain", "classical"}:
            raise ValueError(f"{manifest_path}: invalid source definition: {source!r}")

        path = repo_root / rel_path
        data = load_yaml(path)
        local_counts: dict[str, int] = defaultdict(int)

        for idx, raw in enumerate(data["payload"], start=1):
            if not isinstance(raw, str):
                raise ValueError(f"{rel_path}: payload item {idx} is not a string")
            entry = raw.strip()
            if not entry:
                continue
            source_label = f"{rel_path}:{idx}"

            before = {key: len(values) for key, values in bucket.items()}
            if behavior == "domain":
                key, value = normalize_domain_value(entry, behavior)
                add_value(bucket, key, value, source_label)
            else:
                parse_classical_entry(entry, source_label, bucket, warnings)

            after = {key: len(values) for key, values in bucket.items()}
            for key, count in after.items():
                if count > before.get(key, 0):
                    local_counts[key] += count - before.get(key, 0)

        source_stats[name] = dict(sorted(local_counts.items()))

    output_dir.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)

    domain_keys = ["domain", "domain_suffix", "domain_keyword"]
    ip_keys = ["ip_cidr"]

    domain_rules = build_rules(bucket, domain_keys)
    ip_rules = build_rules(bucket, ip_keys)
    all_rules = domain_rules + ip_rules

    write_json(output_dir / "direct-domain.json", domain_rules)
    write_json(output_dir / "direct-ip.json", ip_rules)
    write_json(output_dir / "direct-all.json", all_rules)

    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    generated_at = (
        datetime.fromtimestamp(int(source_date_epoch), timezone.utc)
        if source_date_epoch
        else datetime.now(timezone.utc)
    )

    metadata = {
        "generated_at": generated_at.isoformat().replace("+00:00", "Z"),
        "format_version": 1,
        "sources": source_stats,
        "output": {
            "direct-domain": {key: len(bucket.get(key, set())) for key in domain_keys},
            "direct-ip": {key: len(bucket.get(key, set())) for key in ip_keys},
        },
        "warnings": warnings,
    }
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    for warning in warnings:
        print(f"WARN: {warning}")

    print("Generated:")
    for filename in ("direct-domain.json", "direct-ip.json", "direct-all.json"):
        print(f"  {output_dir / filename}")
    print(f"  {metadata_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
