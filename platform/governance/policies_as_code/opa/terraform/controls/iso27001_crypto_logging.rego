package terraform.controls.iso27001_crypto_logging

control_id := {
  "iso27001": ["A.8.24", "A.8.15", "A.8.16"]
}
control_name := "ISO27001 Cryptography & Logging Guardrails"

deny[msg] {
  # S3 must be encrypted with KMS
  r := input.resource_changes[_]
  r.type == "aws_s3_bucket_server_side_encryption_configuration"
  rule := r.change.after.rule[_]
  alg := rule.apply_server_side_encryption_by_default.sse_algorithm
  alg != "aws:kms"
  msg := sprintf("[%s] S3 encryption must use aws:kms. Resource: %s",
    [control_id.iso27001[0], r.address])
}

deny[msg] {
  # S3 bucket must have public access block
  r := input.resource_changes[_]
  r.type == "aws_s3_bucket_public_access_block"
  pab := r.change.after
  not pab.block_public_acls
  msg := sprintf("[%s] S3 must block public ACLs. Resource: %s",
    [control_id.iso27001[1], r.address])
}

deny[msg] {
  # CloudTrail must be enabled
  r := input.resource_changes[_]
  r.type == "aws_cloudtrail"
  r.change.after.is_multi_region_trail != true
  msg := sprintf("[%s] CloudTrail must be multi-region. Resource: %s",
    [control_id.iso27001[2], r.address])
}
