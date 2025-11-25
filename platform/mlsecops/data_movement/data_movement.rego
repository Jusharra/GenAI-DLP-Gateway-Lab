package data.movement

default allow := false
default reason := "no matching flow"

# input schema:
# input = {
#   "from": "dlp_gateway|rag_orchestrator|llm|user|pinecone|evidence_s3",
#   "to":   "...",
#   "state": {
#       "classification_label": "...",
#       "policy_decision": {"action":"allow|mask|block"},
#       "redaction_applied": true|false
#   }
# }
#
# data.flows is loaded from flows.yaml (converted to json)

allow if {
  some f in data.flows
  f.from == input.from
  f.to == input.to
  f.allowed == true
  conditions_ok(f.conditions, input.state)
}

reason := r if {
  not allow
  r := deny_reason
}

deny_reason := msg if {
  some f in data.flows
  f.from == input.from
  f.to == input.to
  msg := sprintf("flow %s denied: %s", [f.id, condition_failure(f.conditions, input.state)])
}

# If no conditions, it's allowed
conditions_ok(conds, state) if {
  conds == null
}

conditions_ok(conds, state) if {
  conds != null
  not condition_failed(conds, state)
}

condition_failed(conds, state) if {
  some c in conds
  violates(c, state)
}

condition_failure(conds, state) = out if {
  some c in conds
  violates(c, state)
  out := c
}

# --- Condition evaluators ---
violates(c, state) if {
  startswith(c, "classification_label not_in")
  labels := extract_list(c)
  state.classification_label in labels
}

violates(c, state) if {
  c == "redaction_applied == true"
  not state.redaction_applied
}

violates(c, state) if {
  startswith(c, "policy_decision.action in")
  actions := extract_list(c)
  not state.policy_decision.action in actions
}

# crude list parser: [A, B, C]
extract_list(c) := xs if {
  start := indexof(c, "[")
  end := indexof(c, "]")
  inner := substring(c, start+1, end-start-1)
  parts := split(inner, ",")
  xs := { trim_space(p) | p := parts[_] }
}



