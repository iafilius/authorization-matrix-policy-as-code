package iam.matrix.approval_test

import data.iam.matrix.approval
import rego.v1

nonprod_entry := {
	"id": "ACC-101",
	"principal": "grp-dev-team",
	"principal_type": "human_standard",
	"target_resource": "dev-app-01",
	"target_tier": "non-prod",
	"access_level": "read",
	"business_owner": "app-lead",
	"review_date": "2027-05-01",
}

tier0_entry := {
	"id": "ACC-102",
	"principal": "grp-pay-pam",
	"principal_type": "pam_jit_group",
	"target_resource": "prod-pay-db-01",
	"target_tier": "tier-0",
	"access_level": "ssh_sudo",
	"max_session_hours": 4,
	"business_owner": "payments-lead",
	"review_date": "2027-05-01",
}

test_removal_without_violations_or_warnings_is_auto_approved if {
	diff := {
		"before": {"entries": [nonprod_entry, tier0_entry]},
		"after": {"entries": [nonprod_entry]},
	}
	d := approval.decision with input as diff
	d.status == "auto_approved"
	d.auto_approve == true
	count(d.required_approvers) == 0
	d.summary.removed_count == 1
}

test_low_cia_nonprod_addition_requires_system_owner_only if {
	diff := {
		"before": {"cia_rating": {"confidentiality": "low", "integrity": "low", "availability": "low"}, "entries": []},
		"after": {"cia_rating": {"confidentiality": "low", "integrity": "low", "availability": "low"}, "entries": [nonprod_entry]},
	}
	d := approval.decision with input as diff
	d.status == "approval_required"
	d.auto_approve == false
	d.required_approvers == ["system_owner"]
}

test_tier0_addition_requires_system_owner_and_iam_security if {
	diff := {
		"before": {"entries": [nonprod_entry]},
		"after": {"entries": [nonprod_entry, tier0_entry]},
	}
	d := approval.decision with input as diff
	d.status == "approval_required"
	d.auto_approve == false
	d.required_approvers == ["iam_security", "system_owner"]
}

test_high_cia_addition_triggers_iam_security_even_on_nonprod_read if {
	diff := {
		"before": {"cia_rating": {"confidentiality": "low", "integrity": "high", "availability": "low"}, "entries": []},
		"after": {"cia_rating": {"confidentiality": "low", "integrity": "high", "availability": "low"}, "entries": [nonprod_entry]},
	}
	d := approval.decision with input as diff
	d.status == "approval_required"
	d.required_approvers == ["iam_security", "system_owner"]
}

test_guardrail_violation_blocks_change if {
	bad_entry := object.union(nonprod_entry, {"principal_type": "service_account", "access_level": "ssh_sudo"})
	diff := {
		"before": {"entries": []},
		"after": {"entries": [bad_entry]},
	}
	d := approval.decision with input as diff
	d.status == "blocked"
	d.auto_approve == false
	d.summary.violation_count == 1
}

test_heuristic_warning_prevents_auto_approve if {
	entries := [e |
		some i in numbers.range(1, 11)
		e := {
			"id": sprintf("ACC-90%02d", [i]),
			"principal": sprintf("svc-job-%02d", [i]),
			"principal_type": "service_account",
			"target_resource": "dev-shared-01",
			"target_tier": "non-prod",
			"access_level": "read",
			"business_owner": "dev-lead",
			"review_date": "2027-05-01",
		}
	]
	diff := {
		"before": {"entries": entries},
		"after": {"entries": entries},
	}
	d := approval.decision with input as diff
	d.status == "approval_required"
	d.auto_approve == false
	d.required_approvers == ["system_owner"]
	d.summary.warning_count == 1
}
