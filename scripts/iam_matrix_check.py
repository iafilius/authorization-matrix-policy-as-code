#!/usr/bin/env python3
"""
Enterprise IAM Authorization Matrix Policy-as-Code Checker (4-Layer Demo CLI).

Runs all four governance layers in a single command with zero external Python packages:
  Layer 0: Declarative JSON Schema validation (schemas/matrix.schema.json)
  Layer 1: Static content analysis, heuristics (>10 NPAs/resources), CIA & SoD (OPA)
  Layer 2: External AD/Entra & CMDB context enrichment into an immutable snapshot
  Layer 3: TSCM drift findings grouped by business_owner + CI exit codes

Exit codes:
  0  Passed (auto_approved or approval_required, and no strict TSCM blockers)
  1  Blocked by OPA guardrails (or critical/high TSCM findings with --strict-tscm)
  2  Layer 0 schema error, invalid JSON/file, or missing `opa` CLI

Usage examples:
  ./scripts/iam_matrix_check.py --matrix examples/data/diff_valid_tier0_high_cia.json
  ./scripts/iam_matrix_check.py --matrix examples/data/diff_violations.json
  ./scripts/iam_matrix_check.py \\
      --matrix examples/data/tscm_sweep_enriched.json \\
      --ad examples/mock_sources/ad_accounts.json \\
      --cmdb examples/mock_sources/cmdb_machines.json \\
      --save-snapshot /tmp/audit_snapshot.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCHEMA = REPO_ROOT / "schemas" / "matrix.schema.json"
DEFAULT_POLICIES = REPO_ROOT / "policies"

OPA_QUERY = '{"approval": data.iam.matrix.approval.decision, "tscm": data.iam.matrix.tscm.report}'


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Failed to load JSON from '{path}': {exc}") from exc


def validate_matrix_section(section: Any, label: str, schema: dict[str, Any]) -> list[str]:
    """Validate a single matrix object (standalone, before, or after) against schema rules."""
    errors: list[str] = []
    if not isinstance(section, dict):
        return [f"{label}: expected JSON object, got {type(section).__name__}"]

    defs = schema.get("$defs", {})
    cia_levels = set(defs.get("cia_level", {}).get("enum", []))
    entry_def = defs.get("entry", {})
    required_fields = entry_def.get("required", [])
    props = entry_def.get("properties", {})

    if "cia_rating" in section:
        cia = section["cia_rating"]
        if not isinstance(cia, dict):
            errors.append(f"{label}.cia_rating: expected object")
        else:
            for dim in ("confidentiality", "integrity", "availability"):
                if dim in cia and cia[dim] not in cia_levels:
                    errors.append(
                        f"{label}.cia_rating.{dim}: invalid value '{cia[dim]}' "
                        f"(allowed: {sorted(cia_levels)})"
                    )

    entries = section.get("entries")
    if not isinstance(entries, list):
        errors.append(f"{label}.entries: required array is missing or not a list")
        return errors

    for idx, entry in enumerate(entries):
        prefix = f"{label}.entries[{idx}]"
        if not isinstance(entry, dict):
            errors.append(f"{prefix}: expected object")
            continue

        for req in required_fields:
            if req not in entry or entry[req] is None or (isinstance(entry[req], str) and not entry[req].strip()):
                errors.append(f"{prefix}.{req}: required field missing or empty")

        for field, rule in props.items():
            if field not in entry or entry[field] is None:
                continue
            val = entry[field]
            if "enum" in rule and val not in rule["enum"]:
                errors.append(
                    f"{prefix}.{field}: invalid value '{val}' (allowed: {rule['enum']})"
                )
            if rule.get("type") == "integer":
                if not isinstance(val, int) or isinstance(val, bool):
                    errors.append(f"{prefix}.{field}: expected integer, got {type(val).__name__}")
                elif "minimum" in rule and val < rule["minimum"]:
                    errors.append(f"{prefix}.{field}: value {val} is below minimum {rule['minimum']}")

    return errors


def validate_payload(payload: Any, schema: dict[str, Any]) -> list[str]:
    if not isinstance(payload, dict):
        return [f"Root payload must be a JSON object, got {type(payload).__name__}"]

    errors: list[str] = []
    if "before" in payload or "after" in payload:
        if "before" in payload:
            errors.extend(validate_matrix_section(payload["before"], "before", schema))
        if "after" in payload:
            errors.extend(validate_matrix_section(payload["after"], "after", schema))
        else:
            errors.append("Diff payload with 'before' must also include 'after'")
    else:
        errors.extend(validate_matrix_section(payload, "matrix", schema))
    return errors


def enrich_payload(
    payload: dict[str, Any],
    ad_path: Path | None,
    cmdb_path: Path | None,
) -> dict[str, Any]:
    """Attach external AD/CMDB context snapshot (without mutating the input dict)."""
    enriched = json.loads(json.dumps(payload))
    if not ad_path and not cmdb_path:
        return enriched

    context = dict(enriched.get("context", {}))
    context["evaluated_at"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if ad_path:
        context["accounts"] = load_json(ad_path)
    if cmdb_path:
        context["machines"] = load_json(cmdb_path)
    enriched["context"] = context
    return enriched


def evaluate_opa(payload: dict[str, Any], policies_dir: Path) -> dict[str, Any]:
    opa_bin = shutil.which("opa")
    if not opa_bin:
        raise RuntimeError("`opa` CLI not found in PATH. Install OPA (e.g. `brew install opa`).")

    # Normalize standalone matrix into diff shape so approval + guardrails + tscm all work cleanly.
    opa_input = payload
    if "after" not in payload and "entries" in payload:
        opa_input = {"before": {"entries": []}, "after": payload}
        if "context" in payload:
            opa_input["context"] = payload["context"]

    proc = subprocess.run(
        [opa_bin, "eval", "-d", str(policies_dir), "--stdin-input", "--format=json", OPA_QUERY],
        input=json.dumps(opa_input),
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"OPA evaluation failed (exit {proc.returncode}): {proc.stderr.strip()}")

    raw = json.loads(proc.stdout)
    return raw["result"][0]["expressions"][0]["value"]


def colorize(text: str, code: str, use_color: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if use_color else text


def render_text_report(
    matrix_path: Path,
    result: dict[str, Any],
    use_color: bool,
    enriched_from_files: bool,
) -> str:
    approval = result["approval"]
    tscm = result["tscm"]
    status = approval["status"]

    badge_map = {
        "blocked": ("BLOCKED", "1;31"),
        "auto_approved": ("AUTO-APPROVED", "1;32"),
        "approval_required": ("APPROVAL REQUIRED", "1;34"),
    }
    label, color = badge_map.get(status, (status.upper(), "1;37"))

    lines = [
        "=" * 74,
        f"IAM Matrix Policy-as-Code Report  |  {matrix_path.name}",
        "=" * 74,
        f"Layer 0 (Schema)   : {colorize('PASS', '1;32', use_color)}",
        f"Layer 1 (OPA Gate) : {colorize(label, color, use_color)}",
        f"Layer 2 (Context)  : {'Enriched from external AD/CMDB files' if enriched_from_files else ('Embedded snapshot' if tscm['evaluated_at'] != 'not_provided' else 'Static only (no context)')}",
        f"Summary            : +{approval['summary']['added_or_changed_count']} added/changed, "
        f"-{approval['summary']['removed_count']} removed, "
        f"{approval['summary']['violation_count']} deny, "
        f"{approval['summary']['warning_count']} warn",
    ]

    if approval["required_approvers"]:
        lines.append(f"Required Approvers : {', '.join(approval['required_approvers'])}")

    if approval["violations"]:
        lines.append("")
        lines.append(colorize("DENY Violations (Hard Block):", "1;31", use_color))
        for v in approval["violations"]:
            lines.append(f"  [DENY] {v}")

    if approval["warnings"]:
        lines.append("")
        lines.append(colorize("WARN Heuristics (Review Triggers):", "1;33", use_color))
        for w in approval["warnings"]:
            lines.append(f"  [WARN] {w}")

    findings = tscm.get("findings", [])
    if findings:
        lines.append("")
        s = tscm["summary"]
        lines.append(
            colorize(
                f"Layer 3 (TSCM Findings: {s['total']} total — "
                f"{s['critical']} critical, {s['high']} high, {s['medium']} medium):",
                "1;36",
                use_color,
            )
        )
        by_owner: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for f in findings:
            by_owner[f.get("business_owner", "unassigned")].append(f)

        sev_order = {"critical": 0, "high": 1, "medium": 2}
        sev_color = {"critical": "1;31", "high": "1;35", "medium": "1;33"}
        for owner in sorted(by_owner):
            lines.append(f"  Owner: {owner}")
            for f in sorted(by_owner[owner], key=lambda item: (sev_order.get(item["severity"], 9), item["entry_id"])):
                sev = colorize(f["severity"].upper(), sev_color.get(f["severity"], "0"), use_color)
                lines.append(f"    - [{sev}] ({f['entry_id']} / {f['rule']}) {f['message']}")

    lines.append("=" * 74)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the 4-layer Enterprise IAM Authorization Matrix Policy-as-Code pipeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 scripts/iam_matrix_check.py --matrix examples/data/diff_valid_tier0_high_cia.json\n"
            "  python3 scripts/iam_matrix_check.py --matrix examples/data/diff_violations.json\n"
            "  python3 scripts/iam_matrix_check.py --matrix examples/data/diff_valid_tier0_high_cia.json \\\n"
            "      --ad examples/mock_sources/ad_accounts.json --cmdb examples/mock_sources/cmdb_machines.json"
        ),
    )
    parser.add_argument("--matrix", required=True, type=Path, help="Path to matrix or before/after diff JSON")
    parser.add_argument("--ad", type=Path, help="Optional AD/Entra accounts JSON export for Layer 2 enrichment")
    parser.add_argument("--cmdb", type=Path, help="Optional CMDB machines JSON export for Layer 2 enrichment")
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA, help=f"Layer 0 schema JSON (default: {DEFAULT_SCHEMA.name})")
    parser.add_argument("--policies", type=Path, default=DEFAULT_POLICIES, help="OPA policies directory (default: policies/)")
    parser.add_argument("--save-snapshot", type=Path, help="Optional path to save the immutable enriched JSON snapshot")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Output format (default: text)")
    parser.add_argument("--strict-tscm", action="store_true", help="Exit with code 1 if any critical/high TSCM findings exist")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="ANSI color mode (default: auto)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        schema = load_json(args.schema)
        payload = load_json(args.matrix)
    except ValueError as exc:
        print(f"ERROR (Layer 0): {exc}", file=sys.stderr)
        return 2

    schema_errors = validate_payload(payload, schema)
    if schema_errors:
        print("ERROR: Layer 0 Schema Validation Failed:", file=sys.stderr)
        for err in schema_errors:
            print(f"  - {err}", file=sys.stderr)
        return 2

    try:
        enriched = enrich_payload(payload, args.ad, args.cmdb)
        if args.save_snapshot:
            args.save_snapshot.parent.mkdir(parents=True, exist_ok=True)
            args.save_snapshot.write_text(json.dumps(enriched, indent=2) + "\n", encoding="utf-8")
        result = evaluate_opa(enriched, args.policies)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    use_color = args.color == "always" or (args.color == "auto" and sys.stdout.isatty())
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(render_text_report(args.matrix, result, use_color, bool(args.ad or args.cmdb)))

    if result["approval"]["status"] == "blocked":
        return 1
    if args.strict_tscm and result["tscm"]["summary"]["blocking_count"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
