package iam.matrix.guardrails

import rego.v1

interactive_levels := {"ssh_standard", "ssh_sudo", "rdp_admin"}

privileged_levels := {"ssh_sudo", "rdp_admin", "prod_deploy", "audit_log_admin"}

sod_conflicts := {["prod_deploy", "audit_log_admin"]}

max_npas := 10

max_resources := 10

max_tier0_session_hours := 4

target_matrix := input.after if {
	input.after
} else := input

# 1. Hard Guardrail: Service accounts must never receive interactive shell/RDP access
deny contains msg if {
	some entry in target_matrix.entries
	entry.principal_type == "service_account"
	entry.access_level in interactive_levels
	msg := sprintf("Entry %s: service account '%s' cannot have interactive access '%s'", [
		entry.id,
		entry.principal,
		entry.access_level,
	])
}

# 2a. Hard Guardrail: Tier-0 resources require PAM/JIT groups
deny contains msg if {
	some entry in target_matrix.entries
	entry.target_tier == "tier-0"
	entry.principal_type != "pam_jit_group"
	msg := sprintf("Entry %s: Tier-0 target '%s' requires a pam_jit_group (got '%s')", [
		entry.id,
		entry.target_resource,
		entry.principal_type,
	])
}

# 2b. Hard Guardrail: Tier-0 PAM/JIT sessions must be > 0 and <= 4 hours
deny contains msg if {
	some entry in target_matrix.entries
	entry.target_tier == "tier-0"
	entry.principal_type == "pam_jit_group"
	hours := object.get(entry, "max_session_hours", 0)
	invalid_tier0_session(hours)
	msg := sprintf("Entry %s: Tier-0 PAM/JIT session duration must be between 1 and %d hours (got %v)", [
		entry.id,
		max_tier0_session_hours,
		hours,
	])
}

invalid_tier0_session(hours) if {
	hours <= 0
}

invalid_tier0_session(hours) if {
	hours > max_tier0_session_hours
}

# 3. Hard Guardrail: No wildcard targets in production tiers
deny contains msg if {
	some entry in target_matrix.entries
	entry.target_tier in {"tier-0", "tier-1"}
	contains(entry.target_resource, "*")
	msg := sprintf("Entry %s: wildcard target '%s' is forbidden in %s", [
		entry.id,
		entry.target_resource,
		entry.target_tier,
	])
}

# 4a. Hard Guardrail: Mandatory business_owner
deny contains msg if {
	some entry in target_matrix.entries
	trim_space(object.get(entry, "business_owner", "")) == ""
	msg := sprintf("Entry %s: missing required governance metadata 'business_owner'", [entry.id])
}

# 4b. Hard Guardrail: Mandatory review_date
deny contains msg if {
	some entry in target_matrix.entries
	trim_space(object.get(entry, "review_date", "")) == ""
	msg := sprintf("Entry %s: missing required governance metadata 'review_date'", [entry.id])
}

# 5. Hard Guardrail: Segregation of Duties (direct and transitive via nested groups)
all_principals contains p if {
	some entry in target_matrix.entries
	p := entry.principal
}

all_principals contains p if {
	memberships := object.get(target_matrix, "group_memberships", {})
	some p, _ in memberships
}

membership_graph[p] := object.get(memberships, p, []) if {
	memberships := object.get(target_matrix, "group_memberships", {})
	some p in all_principals
}

effective_access_levels(principal) := levels if {
	reachable := graph.reachable(membership_graph, {principal})
	levels := {entry.access_level |
		some entry in target_matrix.entries
		entry.principal in reachable
	}
}

deny contains msg if {
	some principal in all_principals
	levels := effective_access_levels(principal)
	some pair in sod_conflicts
	pair[0] in levels
	pair[1] in levels
	msg := sprintf("SoD violation: principal '%s' holds conflicting access levels '%s' and '%s' (direct or transitive)", [
		principal,
		pair[0],
		pair[1],
	])
}

# 6a. CIA Guardrail: High Confidentiality forbids standard human accounts
deny contains msg if {
	cia := object.get(target_matrix, "cia_rating", {})
	object.get(cia, "confidentiality", "low") == "high"
	some entry in target_matrix.entries
	entry.principal_type == "human_standard"
	msg := sprintf("Entry %s: High Confidentiality requires pam_jit_group instead of human_standard ('%s')", [
		entry.id,
		entry.principal,
	])
}

# 6b. CIA Guardrail: High Confidentiality caps PAM/JIT sessions at 4 hours
deny contains msg if {
	cia := object.get(target_matrix, "cia_rating", {})
	object.get(cia, "confidentiality", "low") == "high"
	some entry in target_matrix.entries
	entry.principal_type == "pam_jit_group"
	entry.target_tier != "tier-0"
	hours := object.get(entry, "max_session_hours", 0)
	invalid_tier0_session(hours)
	msg := sprintf("Entry %s: High Confidentiality requires PAM/JIT session duration between 1 and %d hours (got %v)", [
		entry.id,
		max_tier0_session_hours,
		hours,
	])
}

# 6c. CIA Guardrail: High Availability forbids non-PAM privileged admin access
deny contains msg if {
	cia := object.get(target_matrix, "cia_rating", {})
	object.get(cia, "availability", "low") == "high"
	some entry in target_matrix.entries
	entry.access_level in {"ssh_sudo", "rdp_admin"}
	entry.principal_type != "pam_jit_group"
	msg := sprintf("Entry %s: High Availability requires pam_jit_group for privileged access '%s' (got '%s')", [
		entry.id,
		entry.access_level,
		entry.principal_type,
	])
}

# 7a. Content Heuristic (WARN): > 10 distinct NPAs in one matrix
warn contains msg if {
	npas := {entry.principal |
		some entry in target_matrix.entries
		entry.principal_type == "service_account"
	}
	count(npas) > max_npas
	msg := sprintf("Heuristic warning: matrix references %d distinct NPAs (threshold: %d); review scope", [
		count(npas),
		max_npas,
	])
}

# 7b. Content Heuristic (WARN): > 10 distinct target resources in one matrix
warn contains msg if {
	resources := {entry.target_resource | some entry in target_matrix.entries}
	count(resources) > max_resources
	msg := sprintf("Heuristic warning: matrix references %d distinct target resources (threshold: %d); consider splitting", [
		count(resources),
		max_resources,
	])
}

# 7c. Content Heuristic (WARN): Cross-environment principal (both non-prod and prod)
warn contains msg if {
	some a in target_matrix.entries
	some b in target_matrix.entries
	a.principal == b.principal
	a.target_tier == "non-prod"
	b.target_tier in {"tier-0", "tier-1"}
	msg := sprintf("Heuristic warning: principal '%s' spans both non-prod and production (%s); lateral-movement risk", [
		a.principal,
		b.target_tier,
	])
}

# 7d. Content Heuristic (WARN): Generic/shared account naming pattern
warn contains msg if {
	some entry in target_matrix.entries
	lower_name := lower(entry.principal)
	generic_prefix(lower_name)
	msg := sprintf("Entry %s: principal '%s' matches a generic/shared naming pattern; verify individual accountability", [
		entry.id,
		entry.principal,
	])
}

generic_prefix(name) if {
	startswith(name, "shared-")
}

generic_prefix(name) if {
	startswith(name, "team-")
}
