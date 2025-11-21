package terraform.guardrails

default deny = []

# Deny IAM wildcard actions
deny[msg] {
  input.resource_type == "aws_iam_policy"
  input.policy_allows_wildcard == true
  msg := "IAM policies must not allow wildcard actions (e.g., '*')."
}

# Deny public S3 buckets for evidence or logs
deny[msg] {
  input.resource_type == "aws_s3_bucket"
  input.bucket_usage == "evidence"
  input.public_access == true
  msg := "Public access not allowed for evidence buckets."
}

# Enforce encryption at rest for S3 evidence buckets
deny[msg] {
  input.resource_type == "aws_s3_bucket"
  input.bucket_usage == "evidence"
  not input.encrypted_with_kms
  msg := "Evidence buckets must use KMS encryption."
}
