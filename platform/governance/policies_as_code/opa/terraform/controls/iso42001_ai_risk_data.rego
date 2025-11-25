# We enforce infra hooks that support those requirements.
package terraform.controls.iso42001_ai_risk_data

control_id := {
  "iso42001": ["6.1", "8.2", "8.3", "8.4", "9.1"]
}
control_name := "ISO42001 AI Risk & Data Governance Guardrails"

deny[msg] {
  # RAG/vector store must be private (no public endpoints)
  r := input.resource_changes[_]
  r.type == "aws_opensearch_domain"
  ep := r.change.after.endpoint_options[_]
  ep.enforce_https != true
  msg := sprintf("[%s] AI data stores must enforce HTTPS private endpoints. Resource: %s",
    [control_id.iso42001[3], r.address])
}

deny[msg] {
  # Any AI-related logging bucket must be encrypted (supports monitoring & auditability)
  r := input.resource_changes[_]
  r.type == "aws_s3_bucket"
  name := lower(r.name)
  contains(name, "evidence")  # lab convention
  not encrypted_kms_bucket(r)
  msg := sprintf("[%s] AI evidence/log buckets must be KMS-encrypted. Resource: %s",
    [control_id.iso42001[4], r.address])
}

encrypted_kms_bucket(r) if {
  some e
  e := input.resource_changes[_]
  e.type == "aws_s3_bucket_server_side_encryption_configuration"
  e.address != null
  contains(e.address, r.address)
  rule := e.change.after.rule[_]
  rule.apply_server_side_encryption_by_default.sse_algorithm == "aws:kms"
}
