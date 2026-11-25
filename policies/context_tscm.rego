package iam.matrix.tscm

import rego.v1

dormant_days_threshold := 90

max_password_age_high := 90

max_password_age_standard := 365

cia_rank := {
	"low": 1,
	"medium": 2,
	"high": 3,
}

target_matrix := input.after if {
	input.after
} else := input

has_context if {
	input.context
}

matrix_has_high_cia if {
	cia := object.get(target_matrix, "cia_rating", {})
	some _, rating in cia
	rating == "high"
}

max_rotation_days(entry) := max_password_age_high if {
	entry.target_tier == "tier-0"
} else := max_password_age_high if {
	matrix_has_high_cia
} else := max_password_age_standard

# 1. NPA missing from AD/Entra context
findings contains finding if {
	has_context
	accounts := object.get(input.context, "accounts", {})
	some entry in target_matrix.entries
	entry.principal_type == "service_account"
	not accounts[entry.principal]
	finding := {
		"severity": "critical",
		"rule": "npa_missing_or_disabled",
		"entry_id": entry.id,
		"business_owner": object.get(entry, "business_owner", "unassigned"),
		"message": sprintf("Service account '%s' does not exist in AD/Entra context", [entry.principal]),
	}
}

# 2. NPA disabled in AD/Entra context
findings contains finding if {
	has_context
	accounts := object.get(input.context, "accounts", {})
	some entry in target_matrix.entries
	entry.principal_type == "service_account"
	acct := accounts[entry.principal]
	acct.status == "disabled"
	finding := {
		"severity": "critical",
		"rule": "npa_missing_or_disabled",
		"entry_id": entry.id,
		"business_owner": object.get(entry, "business_owner", "unassigned"),
		"message": sprintf("Service account '%s' is disabled in AD/Entra", [entry.principal]),
	}
}

# 3. Active NPA password rotation overdue
findings contains finding if {
	has_context
	accounts := object.get(input.context, "accounts", {})
	some entry in target_matrix.entries
	entry.principal_type == "service_account"
	acct := accounts[entry.principal]
	acct.status == "active"
	limit := max_rotation_days(entry)
	acct.password_age_days > limit
	finding := {
		"severity": "high",
		"rule": "npa_password_rotation_overdue",
		"entry_id": entry.id,
		"business_owner": object.get(entry, "business_owner", "unassigned"),
		"message": sprintf("Service account '%s' password age is %d days (limit: %d days)", [
			entry.principal,
			acct.password_age_days,
			limit,
		]),
	}
}

# 4. Dormant account (> 90 days since last use)
findings contains finding if {
	has_context
	accounts := object.get(input.context, "accounts", {})
	some entry in target_matrix.entries
	acct := accounts[entry.principal]
	acct.days_since_last_use > dormant_days_threshold
	finding := {
		"severity": "medium",
		"rule": "account_dormant",
		"entry_id": entry.id,
		"business_owner": object.get(entry, "business_owner", "unassigned"),
		"message": sprintf("Principal '%s' has not been used for %d days (threshold: %d days); least-privilege cleanup candidate", [
			entry.principal,
			acct.days_since_last_use,
			dormant_days_threshold,
		]),
	}
}

# 5a. CMDB target machine missing (non-wildcard)
findings contains finding if {
	has_context
	machines := object.get(input.context, "machines", {})
	some entry in target_matrix.entries
	not contains(entry.target_resource, "*")
	not machines[entry.target_resource]
	finding := {
		"severity": "high",
		"rule": "cmdb_machine_inactive_or_missing",
		"entry_id": entry.id,
		"business_owner": object.get(entry, "business_owner", "unassigned"),
		"message": sprintf("Target machine '%s' was not found in CMDB inventory", [entry.target_resource]),
	}
}

# 5b. CMDB target machine decommissioned
findings contains finding if {
	has_context
	machines := object.get(input.context, "machines", {})
	some entry in target_matrix.entries
	not contains(entry.target_resource, "*")
	machine := machines[entry.target_resource]
	machine.status == "decommissioned"
	finding := {
		"severity": "high",
		"rule": "cmdb_machine_inactive_or_missing",
		"entry_id": entry.id,
		"business_owner": object.get(entry, "business_owner", "unassigned"),
		"message": sprintf("Target machine '%s' is decommissioned in CMDB", [entry.target_resource]),
	}
}

# 6. CIA classification drift (CMDB rating strictly higher than matrix rating)
findings contains finding if {
	has_context
	machines := object.get(input.context, "machines", {})
	matrix_cia := object.get(target_matrix, "cia_rating", {})
	some entry in target_matrix.entries
	machine := machines[entry.target_resource]
	cmdb_cia := object.get(machine, "cia_rating", {})
	some dim in {"confidentiality", "integrity", "availability"}
	cmdb_val := cmdb_cia[dim]
	matrix_val := object.get(matrix_cia, dim, "low")
	cia_rank[cmdb_val] > cia_rank[matrix_val]
	finding := {
		"severity": "critical",
		"rule": "cia_classification_drift",
		"entry_id": entry.id,
		"business_owner": object.get(entry, "business_owner", "unassigned"),
		"message": sprintf("CIA drift on '%s' (%s): matrix declares '%s' but CMDB classifies it as '%s'", [
			entry.target_resource,
			dim,
			matrix_val,
			cmdb_val,
		]),
	}
}

blocking_findings contains f if {
	some f in findings
	f.severity in {"critical", "high"}
}

summary := {
	"critical": count({f | some f in findings; f.severity == "critical"}),
	"high": count({f | some f in findings; f.severity == "high"}),
	"medium": count({f | some f in findings; f.severity == "medium"}),
	"total": count(findings),
	"blocking_count": count(blocking_findings),
}

report := {
	"evaluated_at": object.get(object.get(input, "context", {}), "evaluated_at", "not_provided"),
	"summary": summary,
	"findings": findings,
}
