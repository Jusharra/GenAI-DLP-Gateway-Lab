package terraform.guardrails

# Terraform Plan JSON from: terraform show -json tfplan > tfplan.json
# OPA eval example:
# opa eval -d . -i tfplan.json "data.terraform.guardrails.deny"

default deny := []

# Aggregate deny messages from all control modules.
deny[msg] {
  some m
  msg := data.terraform.controls[m].deny[_]
}

# Optional: produce allow summary
allow {
  count(deny) == 0
}
