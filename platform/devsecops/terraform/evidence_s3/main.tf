resource "aws_s3_bucket" "evidence" {
  bucket = var.bucket_name

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }

  lifecycle_rule {
    id      = "retain-evidence"
    enabled = true

    noncurrent_version_expiration {
      days = 365
    }
  }

  tags = merge(
    {
      "Purpose" = "ComplianceEvidence"
    },
    var.tags
  )
}
