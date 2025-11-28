package movement

# -------- Defaults so OPA never returns undefined --------

default allow := false
default reason := "no matching flow"

# input schema:
# input = {
#   "from": "user|dlp_gateway|rag_orchestrator|llm|pinecone|evidence_s3",
#   "to":   "...",
#   "state": {
#       "classification_label": "INTERNAL|RESTRICTED_PII|RESTRICTED_PHI|PUBLIC",
#       "policy_decision": {"action": "allow|mask|block"},
#       "redaction_applied": true|false
#   }
# }
#
# data.flows is loaded from flows.json (compiled from flows.yaml)
# each flow:
# {
#   "id": "u_to_gateway_internal",
#   "from": "...",
#   "to": "...",
#   "allowed": true/false,
#   "conditions": [
#       "classification_label not_in [RESTRICTED_PII, RESTRICTED_PHI]",
#       "policy_decision.action in [allow,mask]"
#   ]
# }

# -------- Special-case: RAG → LLM for non-restricted data --------

allow if {
  input.from == "rag_orchestrator"
  input.to == "llm"

  state := input.state
  not state.classification_label in {"RESTRICTED_PHI", "RESTRICTED_PII"}
  state.policy_decision.action in {"allow", "mask"}
}

deny_reason := msg if {
  some f in data.flows
  f.from == input.from
  f.to == input.to
  msg := sprintf("flow %s denied: %s", [f.id, condition_failure(f.conditions, input.state)])
}

reason := msg if {
  input.from == "rag_orchestrator"
  input.to == "llm"

  state := input.state
  not state.classification_label in {"RESTRICTED_PHI", "RESTRICTED_PII"}
  state.policy_decision.action in {"allow", "mask"}
  msg := sprintf(
    "rag_orchestrator → llm allowed (label=%s, action=%s)",
    [state.classification_label, state.policy_decision.action],
  )
}

# -------- Generic flow-based allow / deny --------

# Allow when a matching flow exists and all conditions pass and allowed==true
allow if {
  some f in data.flows
  f.from == input.from
  f.to == input.to
  f.allowed == true
  conditions_ok(f.conditions, input.state)
}

# If we match a flow but conditions fail, explain why
reason := msg if {
  some f in data.flows
  f.from == input.from
  f.to == input.to
  not conditions_ok(f.conditions, input.state)
  fc := failed_condition(f.conditions, input.state)
  msg := sprintf("flow %s denied: %s", [f.id, fc])
}

# If we match an allowed flow and conditions pass, explain success
reason := msg if {
  some f in data.flows
  f.from == input.from
  f.to == input.to
  f.allowed == true
  conditions_ok(f.conditions, input.state)
  msg := sprintf("flow %s allowed", [f.id])
}

# -------- Condition helpers --------

# If no conditions, it's okay
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

failed_condition(conds, state) := c if {
  some c in conds
  violates(c, state)
}

# Return the first failing condition string (used in deny_reason)
condition_failure(conds, state) := out if {
  some c in conds
  violates(c, state)
  out := c
}


# --- Condition evaluators ---

violates(c, state) if {
  startswith(c, "classification_label not_in")
  labels := parse_list(c)
  state.classification_label in labels
}

violates(c, state) if {
  c == "redaction_applied == true"
  not state.redaction_applied
}

violates(c, state) if {
  startswith(c, "policy_decision.action in")
  actions := parse_list(c)
  not state.policy_decision.action in actions
}

# crude list parser: turns "classification_label not_in [A,B,C]" into {"A","B","C"}
parse_list(c) := xs if {
  start := indexof(c, "[")
  end   := indexof(c, "]")
  inner := substring(c, start+1, end-start-1)
  parts := split(inner, ",")
  xs := { trim_space(p) | p := parts[_] }
}

trim_space(s) := out if {
  out := trim(s, " ")
}