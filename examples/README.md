# Runnable OPA / Rego Enterprise IAM Matrix Examples

These examples demonstrate the four-layer Policy-as-Code model described in [AUTHORIZATION_MATRIX_POLICY_AS_CODE.md](../README.md) using **Open Policy Agent (OPA)** (`import rego.v1`) and a zero-dependency Python 3 CLI (`scripts/iam_matrix_check.py`).

## 1. One-Command 4-Layer Live Demo (Recommended for Presentations)

```bash
make run-demo
```

Or run the self-documenting CLI directly on any matrix + mock AD/CMDB sources:

```bash
python3 scripts/iam_matrix_check.py --help

# Compliant Tier-0 / High-CIA change (routes to system_owner + iam_security)
python3 scripts/iam_matrix_check.py --matrix examples/data/diff_valid_tier0_high_cia.json

# Content heuristics warning (>10 NPAs, >10 resources, shared-* account)
python3 scripts/iam_matrix_check.py --matrix examples/data/diff_heuristics_warn.json

# Blocked change (exits 1: service-account SSH, wildcard, transitive SoD)
python3 scripts/iam_matrix_check.py --matrix examples/data/diff_violations.json

# Dynamic AD + CMDB enrichment & TSCM sweep (saves immutable audit snapshot)
python3 scripts/iam_matrix_check.py \
  --matrix examples/data/tscm_sweep_enriched.json \
  --ad examples/mock_sources/ad_accounts.json \
  --cmdb examples/mock_sources/cmdb_machines.json \
  --save-snapshot /tmp/audit_snapshot.json \
  --strict-tscm
```

## 2. Run All Automated Tests (OPA + CLI)

```bash
make lint && make test && make test-cli
```

## 3. Raw `opa eval` Commands

```bash
opa eval -d policies -i examples/data/diff_valid_nonprod.json "data.iam.matrix.approval.decision"
opa eval -d policies -i examples/data/diff_valid_tier0_high_cia.json "data.iam.matrix.approval.decision"
opa eval -d policies -i examples/data/diff_removal.json "data.iam.matrix.approval.decision"
opa eval -d policies -i examples/data/diff_heuristics_warn.json "data.iam.matrix.approval.decision"
opa eval -d policies -i examples/data/diff_violations.json "data.iam.matrix.approval.decision"
opa eval -d policies -i examples/data/tscm_sweep_enriched.json "data.iam.matrix.tscm.report"
```
