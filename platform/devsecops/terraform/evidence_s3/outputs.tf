output "evidence_bucket_name" {
  value       = aws_s3_bucket.evidence.id
  description = "The name of the evidence S3 bucket."
}
