package terraform.controls.iso27001_access

# ---- Control metadata (for evidence/traceability) ----
control_id := {
  "iso27001": ["A.5.15", "A.5.16", "A.5.17", "A.8.2"]
}
control_name := "ISO27001 Access Control & Identity Guardrails"

deny[msg] {
  # Example: IAM users should not be created (force roles/federation)
  r := input.resource_changes[_]
  r.type == "aws_iam_user"
  r.change.after != null
  msg := sprintf("[%s] Block direct IAM user creation. Use roles/federation. Resource: %s",
    [control_id.iso27001[0], r.address])
}

deny[msg] {
  # Example: Admin policies must not be attached to identities
  r := input.resource_changes[_]
  r.type == "aws_iam_policy_attachment"
  pol := lower(r.change.after.policy_arn)
  contains(pol, "administratoraccess")
  msg := sprintf("[%s] Admin policy attachment prohibited. Resource: %s",
    [control_id.iso27001[3], r.address])
}

deny[msg] {
  # Example: No wildcard actions in IAM policies
  r := input.resource_changes[_]
  r.type == "aws_iam_policy"
  doc := r.change.after.policy
  contains(doc, "\"Action\": \"*\"")  # simple scan; safe for lab
  msg := sprintf("[%s] Wildcard IAM actions prohibited. Resource: %s",
    [control_id.iso27001[0], r.address])
}

deny[msg] {
  # Example: MFA required for console users (if any exist)
  r := input.resource_changes[_]
  r.type == "aws_iam_user_login_profile"
  r.change.after != null
  msg := sprintf("[%s] Console login profiles require MFA; disallow in lab. Resource: %s",
    [control_id.iso27001[2], r.address])
}
