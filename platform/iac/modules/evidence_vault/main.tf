terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# KMS key for evidence vault
resource "aws_kms_key" "evidence_kms_key" {
  description         = "KMS key for evidence vault bucket"
  enable_key_rotation = true

  tags = var.tags
}

# Evidence S3 bucket (immutable/logging-friendly)
resource "aws_s3_bucket" "evidence_bucket" {
  bucket              = var.bucket_name
  object_lock_enabled = var.enable_object_lock

  tags = var.tags
}

# Versioning (needed for Object Lock)
resource "aws_s3_bucket_versioning" "evidence_bucket_versioning" {
  bucket = aws_s3_bucket.evidence_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Default SSE with KMS
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_bucket_sse" {
  bucket = aws_s3_bucket.evidence_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence_kms_key.arn
    }
  }
}
