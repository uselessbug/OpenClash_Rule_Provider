#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

RULE_KEYS = [
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
    "source_ip_cidr",
    "port",
    "port_range",
    "source_port",
    "source_port_range",
    "network",
]


def load_yaml_text(text: str, source: str) -> dict[str, Any]:
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or not isinstance(data.get("payload"), list):
        raise ValueError(f"{source}: expected YAML mapping with a payload list")
    return data


def load_source(source: dict[str, Any], repo_root: Path) -> tuple[dict[str, Any], str]:
    rel_path = str(source.get("path") or "").strip()
    url = str(source.get("url") or "").strip()
    if bool(rel_path) == bool(url):
        raise ValueError(f"source {source!r}: define exactly one of path or url")

    if rel_path:
        path = repo_root / rel_path
        return load_yaml_text(path.read_text(encoding="utf-8"), rel_path), rel_path

    request = urllib.request.Request(url, headers={"User-Agent": "OpenClash_Rule_Provider"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            text = response.read().decode("utf-8")
    except (urllib.error.URLError, UnicodeDecodeError) as exc:
        raise ValueError(f"{url}: failed to download source") from exc
    return load_yaml_text(text, url), url


def validate_domain(value: str, source: str) -> None:
    if not value or any(ch.isspace() for ch in value):
        raise ValueError(f"{source}: invalid domain value: {value!r}")


def validate_cidr(value: str, source: str) -> str:
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise ValueError(f"{source}: invalid CIDR {value!r}") from exc


def canonical_port_range(value: str, source: str) -> str:
    start, sep, end = value.partition("-")
    if not sep:
        raise ValueError(f"{source}: invalid port range {value!r}")
    if not start or not end:
        raise ValueError(f"{source}: open port ranges are not supported: {value!r}")
    start_port = int(start)
    end_port = int(end)
    if not (1 <= start_port <= end_port <= 65535):
        raise ValueError(f"{source}: invalid port range {value!r}")
    return f"{start_port}:{end_port}"


def add_value(bucket: dict[str, set[Any]], key: str, value: Any, source: str) -> None:
    if key in {"ip_cidr", "source_ip_cidr"}:
        value = validate_cidr(str(value), source)
    elif key in {"domain", "domain_suffix", "domain_keyword", "domain_regex"}:
        validate_domain(str(value), source)
    elif key in {"port", "source_port"}:
        value = int(value)
        if not 1 <= value <= 65535:
            raise ValueError(f"{source}: invalid port {value}")
    elif key in {"port_range", "source_port_range"}:
        value = canonical_port_range(str(value), source)
    elif key == "network":
        value = str(value).lower()
        if value not in {"tcp", "udp"}:
            raise ValueError(f"{source}: unsupported network {value!r}")
    bucket[key].add(value)


def add_or_warn(
    bucket: dict[str, set[Any]], key: str, value: Any, source: str, warnings: list[str]
) -> None:
    try:
        add_value(bucket, key, value, source)
    except (TypeError, ValueError) as exc:
        warnings.append(str(exc))


def domain_labels_to_regex(value: str, source: str) -> str:
    labels = value.split(".")
    if any(not label for label in labels):
        raise ValueError(f"{source}: invalid domain wildcard {value!r}")

    regex_labels: list[str] = []
    for label in labels:
        if label == "*":
            regex_labels.append(r"[^.]+")
        elif "*" in label or "+" in label:
            raise ValueError(f"{source}: unsupported Clash domain wildcard {value!r}")
        else:
            regex_labels.append(re.escape(label))
    return r"\.".join(regex_labels)


def parse_domain_entry(
    entry: str, source: str, bucket: dict[str, set[Any]], warnings: list[str]
) -> None:
    value = entry.strip()
    try:
        validate_domain(value, source)

        if value.startswith("+."):
            body = value[2:]
            if "*" not in body:
                if "+" in body:
                    raise ValueError(f"{source}: unsupported Clash domain wildcard {value!r}")
                add_value(bucket, "domain_suffix", body, source)
                return
            regex = r"^(?:[^.]+\.)*" + domain_labels_to_regex(body, source) + "$"
            add_value(bucket, "domain_regex", regex, source)
            return

        if value.startswith("."):
            body = value[1:]
            regex = r"^(?:[^.]+\.)+" + domain_labels_to_regex(body, source) + "$"
            add_value(bucket, "domain_regex", regex, source)
            return

        if "*" in value:
            regex = "^" + domain_labels_to_regex(value, source) + "$"
            add_value(bucket, "domain_regex", regex, source)
            return

        if "+" in value:
            raise ValueError(f"{source}: unsupported Clash domain wildcard {value!r}")

        add_value(bucket, "domain", value, source)
    except ValueError as exc:
        warnings.append(str(exc))


def clash_rule_wildcard_to_regex(value: str) -> str:
    escaped = re.escape(value)
    return "^" + escaped.replace(r"\*", ".*").replace(r"\?", ".") + "$"


def parse_port_rule(
    value: str,
    exact_key: str,
    range_key: str,
    source: str,
    bucket: dict[str, set[Any]],
    warnings: list[str],
) -> None:
    for token in re.split(r"[/,]", value):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            add_or_warn(bucket, range_key, token, source, warnings)
        else:
            add_or_warn(bucket, exact_key, token, source, warnings)


def parse_classical_entry(
    entry: str, source: str, bucket: dict[str, set[Any]], warnings: list[str]
) -> None:
    if "," not in entry:
        warnings.append(f"{source}: skipped malformed classical rule: {entry}")
        return

    rule_type, value = entry.split(",", 1)
    rule_type = rule_type.strip().upper()
    value = value.strip()

    if rule_type in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}:
        cidr = value.split(",", 1)[0].strip()
        key = "source_ip_cidr" if rule_type == "SRC-IP-CIDR" else "ip_cidr"
        add_or_warn(bucket, key, cidr, source, warnings)
        return

    if rule_type == "DOMAIN":
        add_or_warn(bucket, "domain", value, source, warnings)
        return
    if rule_type == "DOMAIN-SUFFIX":
        add_or_warn(bucket, "domain_suffix", value, source, warnings)
        return
    if rule_type == "DOMAIN-KEYWORD":
        add_or_warn(bucket, "domain_keyword", value, source, warnings)
        return
    if rule_type == "DOMAIN-REGEX":
        add_or_warn(bucket, "domain_regex", value, source, warnings)
        return
    if rule_type == "DOMAIN-WILDCARD":
        add_or_warn(bucket, "domain_regex", clash_rule_wildcard_to_regex(value), source, warnings)
        return
    if rule_type == "DST-PORT":
        parse_port_rule(value, "port", "port_range", source, bucket, warnings)
        return
    if rule_type == "SRC-PORT":
        parse_port_rule(value, "source_port", "source_port_range", source, bucket, warnings)
        return
    if rule_type == "NETWORK":
        for network in value.split("/"):
            add_or_warn(bucket, "network", network.strip(), source, warnings)
        return

    warnings.append(f"{source}: skipped unsupported rule: {entry}")


def sorted_values(values: set[Any]) -> list[Any]:
    return sorted(values, key=lambda value: (isinstance(value, str), str(value)))


def build_rules(bucket: dict[str, set[Any]]) -> list[dict[str, list[Any]]]:
    rules: list[dict[str, list[Any]]] = []
    for key in RULE_KEYS:
        values = sorted_values(bucket.get(key, set()))
        if values:
            # Separate rule objects are intentional: distinct sing-box match fields are ANDed.
            rules.append({key: values})
    return rules


def write_json(path: Path, rules: list[dict[str, list[Any]]]) -> None:
    payload = {"version": 1, "rules": rules}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert OpenClash rule providers to sing-box source rule-set")
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

    bucket: dict[str, set[Any]] = defaultdict(set)
    warnings: list[str] = []
    source_stats: dict[str, dict[str, int]] = {}

    for source in sources:
        if not isinstance(source, dict):
            raise ValueError(f"{manifest_path}: invalid source entry: {source!r}")

        name = str(source.get("name") or "").strip()
        behavior = str(source.get("behavior") or "").strip().lower()
        if not name or behavior not in {"domain", "classical"}:
            raise ValueError(f"{manifest_path}: invalid source definition: {source!r}")

        data, source_name = load_source(source, repo_root)
        local_bucket: dict[str, set[Any]] = defaultdict(set)

        for idx, raw in enumerate(data["payload"], start=1):
            if not isinstance(raw, str):
                warnings.append(f"{source_name}:{idx}: skipped non-string payload item")
                continue
            entry = raw.strip()
            if not entry:
                continue
            source_label = f"{source_name}:{idx}"

            if behavior == "domain":
                parse_domain_entry(entry, source_label, local_bucket, warnings)
            else:
                parse_classical_entry(entry, source_label, local_bucket, warnings)

        for key, values in local_bucket.items():
            bucket[key].update(values)
        source_stats[name] = {
            key: len(values) for key, values in sorted(local_bucket.items()) if values
        }

    output_dir.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)

    rules = build_rules(bucket)
    write_json(output_dir / "direct.json", rules)

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
            "direct": {key: len(bucket.get(key, set())) for key in RULE_KEYS if bucket.get(key)}
        },
        "warnings": warnings,
    }
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    for warning in warnings:
        print(f"WARN: {warning}")

    print("Generated:")
    print(f"  {output_dir / 'direct.json'}")
    print(f"  {metadata_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
