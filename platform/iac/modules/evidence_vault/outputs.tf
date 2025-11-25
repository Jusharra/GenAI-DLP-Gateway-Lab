output "bucket_arn" {
  value = aws_s3_bucket.evidence_bucket.arn
}

output "kms_key_arn" {
  value = aws_kms_key.evidence_kms_key.arn
}
