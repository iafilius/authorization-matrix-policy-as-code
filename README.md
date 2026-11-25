# Enterprise IAM Authorization Matrices with Policy as Code

![Enterprise IAM Policy-as-Code Vision](docs/images/hero-iam-policy-as-code.jpg)

**Scope:** Research and architectural blueprint for using Policy as Code (PaC) — specifically **Open Policy Agent (OPA / Rego)** — to **auto-verify, enrich, continuously audit (TSCM), approve, and store** enterprise IAM authorization matrices governing access from accounts/identities to machines, servers, and infrastructure resources.

---

## 1. Executive Summary

Moving an authorization matrix out of Excel spreadsheets into an automated workflow solves *data entry and provisioning*, but it does not automatically solve **governance, content quality, compliance verification, or drift detection**. When an entire IAM department reviews authorization matrices manually, institutional knowledge ("more than 10 NPAs in one matrix looks wrong", "High CIA systems need PAM/JIT and 4-eyes") stays trapped in reviewers' heads.

Two architectural principles unlock Policy as Code for Enterprise IAM:

1. **Separate Verification/Governance from Matrix Storage:** Keep the matrix as **structured data** (in your existing automated IAM tool, YAML/JSON, or CUE) and keep `.rego` strictly for **policy logic** — never store raw access rows as `.rego` code.
2. **Use One Policy Engine Across Four Progressive Layers:** Combine **Schema validation**, **Static Content Analysis (heuristics & CIA-driven rules)**, **Dynamic Context-Enriched Checks** (at request time), and **Periodic TSCM Sweeps** (continuous compliance across all active matrices).

### Key Recommendations

| Question | Recommendation |
| :--- | :--- |
| **Should we use OPA (Rego) to review & auto-verify matrices?** | **Yes — strongest fit.** OPA evaluates JSON/YAML from any source, encodes IAM heuristics (`>10 NPAs`, `>10 resources`), enforces CIA-rating policies and transitive SoD, and drives risk-based approval routing. |
| **Should we store the authorization matrix *itself* in Rego?** | **No.** Mixing hundreds of account-to-machine rows into `.rego` code hurts readability for IAM admins and auditors, creates noisy diffs, and complicates downstream provisioning. |
| **Should OPA call AD/CMDB APIs directly (`http.send`) for dynamic checks?** | **No — enrich *before* OPA.** A small enrichment script fetches AD/Entra, PAM, CMDB, and HR data in bulk into an immutable `context_snapshot.json`. OPA stays fast, stateless, easy to unit-test, and 100% reproducible for audits. |
| **What is the lowest-friction path to start?** | Keep your company's newly automated matrix system as the store and plug **OPA in as a shadow-mode gate & periodic TSCM scanner** over exported JSON snapshots/diffs. |

---

## 2. The Four-Layer Verification & Continuous Compliance Model

![Four-Layer Enterprise IAM Policy-as-Code Architecture](docs/images/four-layer-opa-architecture.jpg)

```text
+-------------------------------------------------------------------------+
| LAYER 0: Syntax & Schema Validation (JSON Schema / CUE)                 |
| "Is the matrix technically well-formed?"                                |
|  - Required fields, valid data types, allowed enums (CIA, tiers, types) |
+-------------------------------------------------------------------------+
                                   |
                                   v
+-------------------------------------------------------------------------+
| LAYER 1: Static Content Analysis in OPA (zero external calls)           |
| "Does the content make sense, and does it meet CIA & IAM guardrails?"   |
|  - Content Heuristics / Anomalies (WARN -> forces human review):        |
|    * > 10 Non-Personal Accounts (NPAs) in one matrix -> suspicious      |
|    * > 10 target machines/resources in one rule/matrix -> over-scoped   |
|  - CIA-Rating Driven Policies (C / I / A = low | medium | high):        |
|    * C = high -> PAM/JIT only, <= 4h session, IAM Security approval     |
|    * I = high -> strict SoD (incl. nested groups) + 4-eyes approval     |
|    * A = high -> no ad-hoc prod admin without PAM/break-glass           |
|    * C/I/A = low -> lighter controls / faster approval                  |
|  - Hard Guardrails (DENY):                                              |
|    * No interactive SSH/RDP for service accounts (NPAs)                 |
|    * No wildcard targets (*) in production tiers                        |
|    * Mandatory governance metadata (business_owner, review_date)        |
+-------------------------------------------------------------------------+
                                   |
                                   v
+-------------------------------------------------------------------------+
| LAYER 2: Dynamic Context-Enriched Analysis (Change / Request Time)      |
| "Does this request match live reality in AD, PAM, CMDB, and HR?"        |
|  - External enrichment script builds context_snapshot.json              |
|  - OPA checks:                                                          |
|    * Does the NPA exist and is it enabled in AD/Entra?                  |
|    * Is password/credential rotation within policy limits?              |
|    * Has the account been used recently (or is it dormant)?             |
|    * Are all target machines actively deployed in the CMDB?             |
|    * Does the matrix CIA rating match the CMDB classification?          |
+-------------------------------------------------------------------------+
                                   |
                                   v
+-------------------------------------------------------------------------+
| LAYER 3: Periodic TSCM Sweep (Daily / Weekly / Monthly)                 |
| "Do ALL existing matrices still comply with policy AND reality?"        |
|  - Runs the exact same OPA rules + fresh context across ALL matrices    |
|  - Outputs structured findings (severity, owner, remediation)           |
|  - Catches dormant NPAs, expired rotations, decommissioned servers,     |
|    departed owners, and newly introduced security policy drift          |
+-------------------------------------------------------------------------+
```

---

## 3. Why Three Decision Outcomes Matter (`deny`, `warn`, `approval`)

![IAM Policy-as-Code & TSCM Review Console Mockup](docs/images/opa-iam-review-dashboard.jpg)

A common misconception is that Policy as Code can only say "allow" or "deny." For an Enterprise IAM team, three distinct outputs make OPA dramatically more practical:

1. **`deny` (Hard Block):** Non-negotiable security or factual failures — e.g., service account requesting interactive SSH, SoD conflict on an `I=high` system, or requesting access to a decommissioned server.
2. **`warn` (Content Heuristics / Review Triggers):** Rules that capture experienced IAM reviewer intuition — e.g., *"Matrix references 14 NPAs (threshold: 10)"* or *"Principal accesses 15 machines (threshold: 10)."* Warnings do not necessarily hard-block a legitimate exception, but they **prevent auto-approval** and highlight *why* a human reviewer should look closer.
3. **`required_approvers` / `auto_approve` (Risk-Based Routing):** Inspects `before` vs `after` diffs combined with the system's **CIA rating**:
   - Permission removals/narrowing (with zero `deny` and zero `warn`) -> `auto_approve`
   - Low-CIA non-prod additions -> `["system_owner"]`
   - High-CIA (`C/I/A = high`), Tier-0, or privileged additions -> `["system_owner", "iam_security"]` (4-eyes)

### Heuristic Idea Generator (Static & Diff "Smells" for IAM Reviews)

Most manual IAM matrix reviews rely on experienced engineers spotting patterns that *might* be legitimate, but warrant a second look. OPA can codify this tribal knowledge as `warn` rules — preventing auto-approval, annotating the change request with *exact reasons*, and giving reviewers a consistent checklist every time:

| Category | Example Heuristic (`warn`) | What It Catches in Practice | Why IAM Reviewers Care |
| :--- | :--- | :--- | :--- |
| **Blast Radius** | **> 10 NPAs** in a single matrix | One matrix bundling 15 service accounts across unrelated components | Signals missing separation of duties/components; hard to audit or revoke cleanly. |
| **Blast Radius** | **> 10 target machines/resources** per role or matrix | A single role granting access to 25 servers across a subnet | Over-scoped blast radius; role should likely be split by subsystem or tier. |
| **Blast Radius** | **Cross-environment principal** (same account/NPA in `non-prod` and `prod`) | `svc-etl-01` granted access to both `dev-db-01` and `prod-db-01` | Lateral-movement risk: a compromised dev host/credential can pivot straight to prod. |
| **Blast Radius** | **Cross-tier group** (same AD/Entra group in `tier-0` and `tier-1`/`non-prod`) | `grp-infra-ops` mapped to both domain controllers and dev app servers | Breaks the Enterprise Access / Tiering Model; exposes Tier-0 credentials to lower-trust hosts. |
| **Least Privilege** | **High admin-to-read ratio** (> 50% of entries are `ssh_sudo` / `rdp_admin`) | 8 out of 10 entries in a new app matrix request full admin | Classic "everyone got admin by default" smell instead of read-only + JIT elevation. |
| **Least Privilege** | **Overlapping / redundant grants** (same principal has both `read` and `ssh_sudo` on the same target) | Two rows for `grp-app-ops` on `prod-web-01` with different levels | Causes hidden privilege persistence: removing one row later leaves the other intact. |
| **Identity Hygiene** | **Named individual accounts** instead of AD/Entra RBAC groups | `j.smith` listed directly instead of `grp-payments-ops` | Breaks Joiner/Mover/Leaver (JML) automation and leaves orphaned access after role changes. |
| **Identity Hygiene** | **Generic / shared account patterns** (`shared-*`, `team-*`, `admin*`, `svc-generic`) | `team-dba-admin` assigned to interactive RDP | Destroys individual accountability and audit non-repudiation. |
| **Identity Hygiene** | **External / vendor accounts on High-CIA or prod** (`ext-*`, `vendor-*`, `contractor-*`) | Third-party support account requesting access to a `C=high` database | Requires explicit vendor-risk sign-off, PAM session recording, and shorter expiry. |
| **Accountability** | **Fragmented ownership** (> 2 distinct `business_owner` teams in one matrix) | Entries owned by 4 different teams inside a single matrix | Blurred accountability during audits and recertification ("if everyone owns it, nobody owns it"). |
| **Lifecycle** | **Overly distant `review_date`** (> 12 months standard, > 6 months for High CIA / Tier-0) | `review_date` set 3 years out | Quietly bypasses periodic access recertification cycles. |
| **Lifecycle** | **Standing-privilege creep** (`max_session_hours > 8` or missing session cap on privileged roles) | PAM/JIT group configured with 24-hour or unlimited sessions | Turns intended Just-In-Time access into de-facto standing privilege. |
| **Change Velocity** | **Bulk privilege spike** (single diff adds > 5 privileged entries or grows matrix > 50%) | One ticket suddenly doubles the number of prod servers in a matrix | Anti-rubber-stamp gate: forces senior/security review on large scope expansions. |
| **Bypass Detection** | **Silent CIA downgrade paired with new access** (`cia_rating` lowered in the same diff as new entries) | `integrity` changed from `high` to `medium` while adding `ssh_sudo` | High-signal red flag for accidental or intentional weakening of controls to bypass stricter policies. |
| **Governance** | **Missing change/ticket justification** on privileged or exception entries | New `rdp_admin` row added with no `justification` or ITSM ticket ID | Ensures auditors can trace *why* privileged access was granted months later. |

> **Why this resonates with IAM teams:** Every heuristic can start as a non-blocking `warn` (advisory) rule. After a month of shadow-mode metrics (*"caught 14 real issues, 1 false positive"*), the IAM Lead Engineer can tune thresholds and selectively promote proven rules from `warn` to hard `deny`.

---

## 4. Dynamic Context Enrichment: Why Enrich *Before* OPA (Not `http.send`)

Although OPA provides an `http.send` built-in, calling live AD, PAM, or CMDB APIs directly from inside `.rego` policies is an anti-pattern at enterprise scale:

| Dimension | OPA calls APIs via `http.send` | Enrichment Script -> Pure OPA (Recommended) |
| :--- | :--- | :--- |
| **Audit Reproducibility** | Low — live CMDB/AD changes over time, so you cannot replay a 6-month-old approval decision. | **100% reproducible** — archive `(matrix, context_snapshot, decision)` together; re-running `opa eval` always yields the exact same output. |
| **Performance & Reliability** | N+1 network calls per matrix row; one slow CMDB endpoint breaks evaluation. | Batch/cached queries once per run; OPA evaluates thousands of rows in milliseconds with zero network I/O. |
| **Testability** | Requires HTTP mocking or fragile integration environments. | Trivially unit-tested with static JSON fixtures via `opa test`. |
| **Credential Isolation** | API tokens and auth logic leak into the policy engine. | OPA stays completely networkless; only the enrichment job holds read-only API credentials. |

### High-Value Continuous TSCM Checks

Running Layer 2 + Layer 3 on a daily, weekly, or monthly schedule turns OPA into a **Technical Security Compliance Monitoring (TSCM)** engine for IAM:

- **NPA Lifecycle Hygiene:** Detect non-personal accounts that are disabled, missing, unused for >90 days (dormant cleanup candidates), or overdue for password/secret rotation.
- **CMDB Reality & Drift Check:** Flag matrix entries pointing to decommissioned or unknown machines, or where the matrix claims `CIA = low` while the CMDB classifies the asset as `high`.
- **Policy-Evolution Impact Analysis:** Whenever Security adds a new Rego rule (e.g., *"no standing RDP on `A=high` servers"*), a single TSCM sweep immediately reveals every existing matrix that is now out of compliance — grouped by `business_owner` for automated remediation tickets.

---

## 5. Tool Landscape Comparison

### A. Tools for Auto-Verifying & Gating an Authorization Matrix

| Tool | Paradigm | Strengths for Enterprise IAM | Tradeoffs |
| :--- | :--- | :--- | :--- |
| **OPA / Rego (+ Conftest)** | Declarative Policy Engine | **Best all-rounder.** Consumes JSON/YAML from any tool; handles heuristics, CIA policies, transitive group graphs (`graph.reachable`), diff approval routing, and TSCM findings. | Learning curve for Rego; verification is test-based (`opa test`) rather than mathematically exhaustive. |
| **CUE (`cuelang`)** | Constraint & Schema Data Language | Unifies schema, data, and static constraints in one language. Ideal for Layer 0 (catching typos, invalid enums, missing fields). | Less ergonomic than Rego for multi-hop graph traversal, diff approval routing, or TSCM sweeps. Best paired *with* OPA. |
| **Cedar (w/ Analysis)** | Purpose-Built AuthZ DSL + Formal Verification | **SMT-backed mathematical proofs** (*"prove no rule lets a non-prod account reach Tier-0"*) and semantic diffing. | Requires modeling the matrix in Cedar's own entity/policy schema; higher friction alongside an external IAM tool. |
| **Python / `pytest` / SQL** | General-Purpose Code | Zero new DSL to learn; natural for writing the *enrichment script* that pulls AD/CMDB data. | Imperative logic is harder to govern and audit as declarative "policy as code" than Rego. |

### B. Tools for Storing the Authorization Matrix

| Storage Option | Best Fit When... | Pros | Cons |
| :--- | :--- | :--- | :--- |
| **Existing Automated IAM Tool + OPA Gate** | Your company already invested in an automated IAM/IGA/ITSM workflow and the real gap is automated review & TSCM. | Lowest organizational friction; no migration; immediate governance value. | Relies on the existing tool's JSON export/API/webhook support. |
| **YAML / JSON + JSON Schema in Git (+ OPA)** | You want GitOps (PR workflow, Git blame, versioned history) with minimal tooling complexity. | Team only learns Rego; very readable; easy to render to HTML/CSV for auditors. | Can accumulate boilerplate at very large scale without generators. |
| **CUE in Git (+ OPA)** | You want GitOps at scale with strict typing, modular team files, and compile-time validation. | Eliminates boilerplate; catches structural errors before OPA runs; exports cleanly to JSON. | Team learns both CUE and Rego. |

> **Note on Application-Runtime AuthZ Tools (OpenFGA, SpiceDB, Cerbos, Oso):** These tools excel at *in-app* microservice/document-sharing authorization, not enterprise infrastructure IAM matrices. Unless you are building a custom application needing runtime API authorization, **Data + Enrichment + OPA** is simpler and better aligned.

---

## 6. Reference Architectures

### Option A: Non-Invasive Policy Gate + Periodic TSCM (Lowest Friction)

```text
[Existing Automated IAM Tool]        [AD / Entra / PAM / CMDB / HR]
             |                                      |
             | export matrix / diff JSON            | enrichment script
             v                                      v
      +---------------------------------------------------+
      |              OPA / Rego Policy Engine             |
      |  (Guardrails + Heuristics + CIA + Context/TSCM)   |
      +---------------------------------------------------+
        |                       |                       |
        v                       v                       v
  [Change Gate]         [Approval Routing]      [TSCM Findings]
  deny / warn           Owner / IAM Security    Tickets per owner
```

### Option B: Git-Backed Matrix (YAML/JSON or CUE + OPA)

```text
[Git: matrix/*.yaml or *.cue] --> [Layer 0: Schema / cue vet]
                                              |
                                              v
[AD / CMDB Enrichment] ----------> [Layer 1-3: OPA / Rego]
                                              |
                     +------------------------+------------------------+
                     v                                                 v
        [Provisioning: AD/Entra, PAM, TF]                 [Auditor HTML/CSV + TSCM]
```

---

## 7. Concrete Example: Data + OPA Policies

### Example Matrix Entry with CIA Rating (JSON/YAML)

```yaml
cia_rating:
  confidentiality: "high"   # low | medium | high
  integrity: "high"         # low | medium | high
  availability: "medium"    # low | medium | high
entries:
  - id: "ACC-1042"
    principal: "grp-payments-sre"
    principal_type: "pam_jit_group"     # human_standard | pam_jit_group | service_account
    target_resource: "prod-pay-db-01"
    target_tier: "tier-0"               # tier-0 | tier-1 | non-prod
    access_level: "ssh_sudo"            # read | ssh_standard | ssh_sudo | rdp_admin | prod_deploy | audit_log_admin
    max_session_hours: 4
    business_owner: "payments-platform-lead"
    review_date: "2027-05-01"
```

### Example OPA Rules (Heuristics, CIA Policy, & Context Check)

```rego
package iam.matrix

import rego.v1

# Static Content Heuristic (WARN): flag matrices with > 10 distinct NPAs
warn contains msg if {
    npas := {e.principal | some e in input.after.entries; e.principal_type == "service_account"}
    count(npas) > 10
    msg := sprintf("Heuristic warning: matrix references %d NPAs (threshold: 10); review scope", [count(npas)])
}

# CIA-Driven Guardrail (DENY): High Confidentiality requires PAM/JIT with <= 4h session
deny contains msg if {
    input.after.cia_rating.confidentiality == "high"
    some e in input.after.entries
    e.principal_type == "human_standard"
    msg := sprintf("Entry %s: High Confidentiality requires PAM/JIT instead of standard human account '%s'", [e.id, e.principal])
}

# Dynamic Context / TSCM Finding: flag decommissioned target machines from CMDB snapshot
tscm_findings contains finding if {
    some e in input.after.entries
    machine := input.context.machines[e.target_resource]
    machine.status == "decommissioned"
    finding := {
        "severity": "high",
        "entry_id": e.id,
        "business_owner": e.business_owner,
        "rule": "cmdb_decommissioned_machine",
        "message": sprintf("Target '%s' is decommissioned in CMDB", [e.target_resource]),
    }
}
```

---

## 8. Suggested Phased Adoption Roadmap

1. **Phase 1 — Shadow-Mode Static & Heuristic Verification (Week 1–2)**
   - Export snapshots from the existing automated matrix tool as JSON.
   - Run OPA in report-only mode with Layer 1 rules (service-account hygiene, wildcards, `>10 NPAs` / `>10 resources` heuristics, CIA-driven rules, and SoD).
   - Review findings with the IAM Lead Engineer to tune thresholds and eliminate false positives.
2. **Phase 2 — Change-Time Gating & Risk-Based Approval Routing**
   - Integrate `before`/`after` diff evaluation into the change workflow.
   - Block hard `deny` violations, surface `warn` heuristics to reviewers, auto-approve safe access reductions, and route High-CIA / Tier-0 changes to `system_owner` + `iam_security`.
3. **Phase 3 — Context Enrichment & Scheduled TSCM Sweeps**
   - Add a read-only enrichment script pulling AD/Entra (NPA existence, password age, last logon) and CMDB (machine status, official CIA rating).
   - Run OPA on a weekly/monthly schedule across *all* active matrices, routing structured TSCM findings to each `business_owner`.
4. **Phase 4 (Optional) — GitOps Matrix Storage & Auditor Views**
   - If the existing IAM portal ever becomes a bottleneck, evaluate storing matrices in Git (YAML + JSON Schema or CUE) with auto-generated HTML/CSV views for auditors.

---

## 9. Runnable OPA / Rego Proof of Concept (Included in This Repository)

All four layers are implemented as runnable, tested OPA/Rego (`import rego.v1`) policies in this repository so they can be demonstrated live with zero external dependencies:

- **Policies & Unit Tests:** [policies/guardrails.rego](policies/guardrails.rego), [policies/approval.rego](policies/approval.rego), [policies/context_tscm.rego](policies/context_tscm.rego) (+ `*_test.rego`)
- **Demo Fixtures & Walkthrough:** [examples/README.md](examples/README.md) and [examples/data/](examples/data/)

```bash
# Run all automated policy unit tests
opa test -v policies/

# Evaluate a blocked change (service-account SSH, wildcard, transitive SoD)
opa eval -d policies -i examples/data/diff_violations.json "data.iam.matrix.approval.decision"

# Evaluate a heuristics warning (>10 NPAs, >10 resources, shared-* account)
opa eval -d policies -i examples/data/diff_heuristics_warn.json "data.iam.matrix.approval.decision"

# Evaluate a dynamic context-enriched TSCM sweep (AD + CMDB snapshot)
opa eval -d policies -i examples/data/tscm_sweep_enriched.json "data.iam.matrix.tscm.report"
```

---

*Author: **Arjan Filius** | Date: **24 November 2026***
