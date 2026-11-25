#!/usr/bin/env python3
"""Automated unit & integration tests for scripts/iam_matrix_check.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CLI = REPO_ROOT / "scripts" / "iam_matrix_check.py"
DATA_DIR = REPO_ROOT / "examples" / "data"
MOCK_DIR = REPO_ROOT / "examples" / "mock_sources"


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        text=True,
        capture_output=True,
        check=False,
    )


class TestIamMatrixCheckCLI(unittest.TestCase):
    def test_help_flag_exits_zero(self) -> None:
        proc = run_cli("--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--matrix", proc.stdout)
        self.assertIn("--strict-tscm", proc.stdout)

    def test_layer0_schema_rejects_invalid_enum_with_exit_2(self) -> None:
        bad_payload = {
            "entries": [
                {
                    "id": "ACC-BAD",
                    "principal": "grp-test",
                    "principal_type": "human_standard",
                    "target_resource": "srv-01",
                    "target_tier": "super-prod",
                    "access_level": "read",
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            bad_file = Path(tmp) / "bad.json"
            bad_file.write_text(json.dumps(bad_payload), encoding="utf-8")
            proc = run_cli("--matrix", str(bad_file))
            self.assertEqual(proc.returncode, 2)
            self.assertIn("target_tier", proc.stderr)
            self.assertIn("super-prod", proc.stderr)

    def test_valid_nonprod_json_output_exits_zero(self) -> None:
        proc = run_cli("--matrix", str(DATA_DIR / "diff_valid_nonprod.json"), "--format", "json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout)
        self.assertEqual(parsed["approval"]["status"], "approval_required")
        self.assertEqual(parsed["approval"]["required_approvers"], ["system_owner"])
        self.assertEqual(parsed["tscm"]["summary"]["total"], 0)

    def test_removal_auto_approved_exits_zero(self) -> None:
        proc = run_cli("--matrix", str(DATA_DIR / "diff_removal.json"), "--color", "never")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("AUTO-APPROVED", proc.stdout)

    def test_violations_blocked_exits_one(self) -> None:
        proc = run_cli("--matrix", str(DATA_DIR / "diff_violations.json"), "--color", "never")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("BLOCKED", proc.stdout)
        self.assertIn("SoD violation", proc.stdout)

    def test_enrichment_from_ad_and_cmdb_saves_snapshot_and_enforces_strict_tscm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot_path = Path(tmp) / "snapshot.json"
            proc = run_cli(
                "--matrix",
                str(DATA_DIR / "tscm_sweep_enriched.json"),
                "--ad",
                str(MOCK_DIR / "ad_accounts.json"),
                "--cmdb",
                str(MOCK_DIR / "cmdb_machines.json"),
                "--save-snapshot",
                str(snapshot_path),
                "--strict-tscm",
                "--color",
                "never",
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("TSCM Findings", proc.stdout)
            self.assertIn("cia_classification_drift", proc.stdout)
            self.assertTrue(snapshot_path.exists())
            saved = json.loads(snapshot_path.read_text(encoding="utf-8"))
            self.assertIn("context", saved)
            self.assertIn("evaluated_at", saved["context"])
            self.assertIn("svc-pay-batch", saved["context"]["accounts"])
            self.assertIn("prod-legacy-09", saved["context"]["machines"])


if __name__ == "__main__":
    unittest.main()
