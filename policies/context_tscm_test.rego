package iam.matrix.tscm_test

import data.iam.matrix.tscm
import rego.v1

test_no_context_returns_empty_findings if {
	matrix := {"entries": [{
		"id": "ACC-1",
		"principal": "svc-missing",
		"principal_type": "service_account",
		"target_resource": "prod-db-01",
		"target_tier": "tier-1",
		"access_level": "read",
		"business_owner": "db-lead",
		"review_date": "2027-05-01",
	}]}
	count(tscm.findings) == 0 with input as matrix
}

test_missing_and_disabled_npa_emit_critical_findings if {
	payload := {
		"after": {"entries": [
			{
				"id": "ACC-1",
				"principal": "svc-ghost-01",
				"principal_type": "service_account",
				"target_resource": "prod-app-01",
				"target_tier": "tier-1",
				"access_level": "read",
				"business_owner": "app-lead",
				"review_date": "2027-05-01",
			},
			{
				"id": "ACC-2",
				"principal": "svc-legacy-02",
				"principal_type": "service_account",
				"target_resource": "prod-app-01",
				"target_tier": "tier-1",
				"access_level": "read",
				"business_owner": "app-lead",
				"review_date": "2027-05-01",
			},
		]},
		"context": {
			"evaluated_at": "2026-11-24T18:00:00Z",
			"accounts": {"svc-legacy-02": {"status": "disabled", "password_age_days": 50, "days_since_last_use": 10}},
			"machines": {"prod-app-01": {"status": "active", "cia_rating": {"confidentiality": "low", "integrity": "low", "availability": "low"}}},
		},
	}
	res := tscm.findings with input as payload
	critical_npa := {f | some f in res; f.rule == "npa_missing_or_disabled"; f.severity == "critical"}
	count(critical_npa) == 2
}

test_password_rotation_dormant_decommissioned_and_cia_drift if {
	payload := {
		"after": {
			"cia_rating": {"confidentiality": "high", "integrity": "low", "availability": "low"},
			"entries": [{
				"id": "ACC-9",
				"principal": "svc-pay-batch",
				"principal_type": "service_account",
				"target_resource": "prod-legacy-09",
				"target_tier": "tier-1",
				"access_level": "read",
				"business_owner": "payments-lead",
				"review_date": "2027-05-01",
			}],
		},
		"context": {
			"evaluated_at": "2026-11-24T18:00:00Z",
			"accounts": {"svc-pay-batch": {"status": "active", "password_age_days": 140, "days_since_last_use": 125}},
			"machines": {"prod-legacy-09": {
				"status": "decommissioned",
				"cia_rating": {"confidentiality": "high", "integrity": "high", "availability": "low"},
			}},
		},
	}
	res := tscm.findings with input as payload
	rules := {f.rule | some f in res}
	"npa_password_rotation_overdue" in rules
	"account_dormant" in rules
	"cmdb_machine_inactive_or_missing" in rules
	"cia_classification_drift" in rules

	s := tscm.summary with input as payload
	s.critical == 1
	s.high == 2
	s.medium == 1
	s.total == 4
}
