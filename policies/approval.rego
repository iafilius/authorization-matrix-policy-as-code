package iam.matrix.approval

import data.iam.matrix.guardrails
import rego.v1

before_entries := object.get(object.get(input, "before", {}), "entries", [])

after_entries := object.get(object.get(input, "after", {}), "entries", [])

added_or_changed contains entry if {
	some entry in after_entries
	not entry in before_entries
}

removed contains entry if {
	some entry in before_entries
	not entry in after_entries
}

violations := guardrails.deny

warnings := guardrails.warn

has_high_cia if {
	cia := object.get(object.get(input, "after", {}), "cia_rating", {})
	some _, rating in cia
	rating == "high"
}

requires_security_review if {
	some entry in added_or_changed
	entry.target_tier == "tier-0"
}

requires_security_review if {
	some entry in added_or_changed
	entry.access_level in guardrails.privileged_levels
}

requires_security_review if {
	count(added_or_changed) > 0
	has_high_cia
}

required_approvers contains "system_owner" if {
	count(violations) == 0
	count(added_or_changed) > 0
}

required_approvers contains "system_owner" if {
	count(violations) == 0
	count(warnings) > 0
}

required_approvers contains "iam_security" if {
	count(violations) == 0
	requires_security_review
}

default auto_approve := false

auto_approve if {
	count(violations) == 0
	count(warnings) == 0
	count(added_or_changed) == 0
}

status := "blocked" if {
	count(violations) > 0
} else := "auto_approved" if {
	auto_approve
} else := "approval_required"

decision := {
	"status": status,
	"auto_approve": auto_approve,
	"required_approvers": sort([a | some a in required_approvers]),
	"violations": sort([v | some v in violations]),
	"warnings": sort([w | some w in warnings]),
	"summary": {
		"added_or_changed_count": count(added_or_changed),
		"removed_count": count(removed),
		"violation_count": count(violations),
		"warning_count": count(warnings),
	},
}
