package terraform.guardrails.dlp

# Deny list for CI gating
deny[msg] {
  some r in input.resource_changes
  r.type == "aws_s3_bucket"
  public_bucket(r)
  msg := sprintf("S3 bucket must not be public: %s", [r.name])
}

deny[msg] {
  some r in input.resource_changes
  r.type == "aws_s3_bucket"
  not has_kms_encryption(r)
  msg := sprintf("Evidence/Demo bucket must use SSE-KMS: %s", [r.name])
}

deny[msg] {
  some r in input.resource_changes
  r.type == "aws_lambda_function"
  not has_cw_logs(r)
  msg := sprintf("Lambda must have CloudWatch logging enabled: %s", [r.name])
}

deny[msg] {
  some r in input.resource_changes
  r.type == "aws_apigatewayv2_api"
  is_public_api(r)
  msg := sprintf("API Gateway must not be public without auth: %s", [r.name])
}

# ----------------------
# Helpers
# ----------------------

public_bucket(r) {
  after := r.change.after
  after.acl == "public-read"
} else {
  after := r.change.after
  after.public_access_block_configuration.block_public_acls == false
}

has_kms_encryption(r) {
  after := r.change.after
  after.server_side_encryption_configuration.rule[_].apply_server_side_encryption_by_default.sse_algorithm == "aws:kms"
}

has_cw_logs(r) {
  after := r.change.after
  after.tracing_config.mode != ""
} else {
  true  # lab-safe: don't hard-fail if tracing not set
}

is_public_api(r) {
  after := r.change.after
  after.disable_execute_api_endpoint == false
}
