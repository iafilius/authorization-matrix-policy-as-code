package iam.matrix.guardrails_test

import data.iam.matrix.guardrails
import rego.v1

base_valid_entry := {
	"id": "ACC-1001",
	"principal": "grp-payments-sre",
	"principal_type": "pam_jit_group",
	"target_resource": "prod-pay-db-01",
	"target_tier": "tier-0",
	"access_level": "ssh_sudo",
	"max_session_hours": 4,
	"business_owner": "payments-lead",
	"review_date": "2027-05-01",
}

test_compliant_tier0_entry_has_no_denies_or_warnings if {
	matrix := {
		"cia_rating": {"confidentiality": "high", "integrity": "high", "availability": "high"},
		"entries": [base_valid_entry],
	}
	count(guardrails.deny) == 0 with input as matrix
	count(guardrails.warn) == 0 with input as matrix
}

test_service_account_interactive_ssh_denied if {
	matrix := {"entries": [{
		"id": "ACC-2001",
		"principal": "svc-billing-01",
		"principal_type": "service_account",
		"target_resource": "prod-bill-01",
		"target_tier": "tier-1",
		"access_level": "ssh_sudo",
		"business_owner": "billing-lead",
		"review_date": "2027-05-01",
	}]}
	some msg in guardrails.deny with input as matrix
	contains(msg, "ACC-2001")
	contains(msg, "interactive access")
}

test_service_account_read_allowed if {
	matrix := {"entries": [{
		"id": "ACC-2002",
		"principal": "svc-billing-ro",
		"principal_type": "service_account",
		"target_resource": "prod-bill-01",
		"target_tier": "tier-1",
		"access_level": "read",
		"business_owner": "billing-lead",
		"review_date": "2027-05-01",
	}]}
	count(guardrails.deny) == 0 with input as matrix
}

test_tier0_requires_pam_jit_and_max_4h_session if {
	matrix := {"entries": [
		{
			"id": "ACC-3001",
			"principal": "grp-devs",
			"principal_type": "human_standard",
			"target_resource": "prod-core-01",
			"target_tier": "tier-0",
			"access_level": "read",
			"business_owner": "core-lead",
			"review_date": "2027-05-01",
		},
		{
			"id": "ACC-3002",
			"principal": "grp-core-pam",
			"principal_type": "pam_jit_group",
			"target_resource": "prod-core-02",
			"target_tier": "tier-0",
			"access_level": "ssh_sudo",
			"max_session_hours": 8,
			"business_owner": "core-lead",
			"review_date": "2027-05-01",
		},
	]}
	denies := guardrails.deny with input as matrix
	count(denies) == 2
}

test_prod_wildcard_denied_but_nonprod_wildcard_allowed if {
	prod_matrix := {"entries": [{
		"id": "ACC-4001",
		"principal": "grp-ops",
		"principal_type": "pam_jit_group",
		"target_resource": "prod-app-*",
		"target_tier": "tier-1",
		"access_level": "read",
		"business_owner": "ops-lead",
		"review_date": "2027-05-01",
	}]}
	some msg in guardrails.deny with input as prod_matrix
	contains(msg, "wildcard")

	nonprod_matrix := {"entries": [{
		"id": "ACC-4002",
		"principal": "grp-devs",
		"principal_type": "human_standard",
		"target_resource": "dev-app-*",
		"target_tier": "non-prod",
		"access_level": "read",
		"business_owner": "dev-lead",
		"review_date": "2027-05-01",
	}]}
	count(guardrails.deny) == 0 with input as nonprod_matrix
}

test_missing_governance_metadata_denied if {
	matrix := {"entries": [{
		"id": "ACC-5001",
		"principal": "grp-devs",
		"principal_type": "human_standard",
		"target_resource": "dev-web-01",
		"target_tier": "non-prod",
		"access_level": "read",
		"business_owner": "",
	}]}
	denies := guardrails.deny with input as matrix
	count(denies) == 2
}

test_direct_and_transitive_sod_conflict_denied if {
	matrix := {
		"group_memberships": {
			"grp-eng-all": ["grp-release", "grp-audit-parent"],
			"grp-audit-parent": ["grp-sec-audit"],
		},
		"entries": [
			{
				"id": "ACC-6001",
				"principal": "grp-release",
				"principal_type": "pam_jit_group",
				"target_resource": "prod-app-01",
				"target_tier": "tier-1",
				"access_level": "prod_deploy",
				"business_owner": "platform-lead",
				"review_date": "2027-05-01",
			},
			{
				"id": "ACC-6002",
				"principal": "grp-sec-audit",
				"principal_type": "pam_jit_group",
				"target_resource": "prod-siem-01",
				"target_tier": "tier-1",
				"access_level": "audit_log_admin",
				"business_owner": "sec-lead",
				"review_date": "2027-05-01",
			},
		],
	}
	some msg in guardrails.deny with input as matrix
	contains(msg, "SoD violation")
	contains(msg, "grp-eng-all")
}

test_cia_high_confidentiality_and_availability_guardrails if {
	matrix := {
		"cia_rating": {"confidentiality": "high", "integrity": "medium", "availability": "high"},
		"entries": [{
			"id": "ACC-7001",
			"principal": "grp-support",
			"principal_type": "human_standard",
			"target_resource": "prod-app-01",
			"target_tier": "tier-1",
			"access_level": "rdp_admin",
			"business_owner": "app-lead",
			"review_date": "2027-05-01",
		}],
	}
	denies := guardrails.deny with input as matrix
	count(denies) == 2
}

test_heuristics_warn_above_10_npas_and_resources if {
	entries := [e |
		some i in numbers.range(1, 11)
		e := {
			"id": sprintf("ACC-80%02d", [i]),
			"principal": sprintf("svc-worker-%02d", [i]),
			"principal_type": "service_account",
			"target_resource": sprintf("dev-host-%02d", [i]),
			"target_tier": "non-prod",
			"access_level": "read",
			"business_owner": "dev-lead",
			"review_date": "2027-05-01",
		}
	]
	matrix := {"entries": entries}
	count(guardrails.deny) == 0 with input as matrix
	warnings := guardrails.warn with input as matrix
	count(warnings) == 2
}

test_heuristics_no_warn_at_exactly_10_npas_and_resources if {
	entries := [e |
		some i in numbers.range(1, 10)
		e := {
			"id": sprintf("ACC-81%02d", [i]),
			"principal": sprintf("svc-worker-%02d", [i]),
			"principal_type": "service_account",
			"target_resource": sprintf("dev-host-%02d", [i]),
			"target_tier": "non-prod",
			"access_level": "read",
			"business_owner": "dev-lead",
			"review_date": "2027-05-01",
		}
	]
	matrix := {"entries": entries}
	count(guardrails.deny) == 0 with input as matrix
	count(guardrails.warn) == 0 with input as matrix
}

test_diff_input_shape_evaluates_after_matrix if {
	diff_input := {
		"before": {"entries": []},
		"after": {"entries": [base_valid_entry]},
	}
	count(guardrails.deny) == 0 with input as diff_input
}
