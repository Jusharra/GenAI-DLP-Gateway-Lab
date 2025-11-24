provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

# ----------------------------
# KMS for evidence + demo data
# ----------------------------
resource "aws_kms_key" "dlp_kms" {
  description             = "${var.project_name}-${var.environment}-dlp-kms"
  deletion_window_in_days = 7

  tags = {
    Project     = var.project_name
    Environment = var.environment
    Purpose     = "GenAI-DLP"
  }
}

resource "aws_kms_alias" "dlp_kms_alias" {
  name          = "alias/${var.project_name}-${var.environment}-dlp"
  target_key_id = aws_kms_key.dlp_kms.key_id
}

# ----------------------------
# S3 Evidence Vault
# ----------------------------
resource "aws_s3_bucket" "evidence" {
  bucket = var.evidence_bucket_name

  tags = {
    Project     = var.project_name
    Environment = var.environment
    Purpose     = "DLP-Evidence"
    DataClass   = "Restricted"
  }
}

resource "aws_s3_bucket_versioning" "evidence_versioning" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_sse" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.dlp_kms.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence_block" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ----------------------------
# S3 Demo Data Lake
# ----------------------------
resource "aws_s3_bucket" "demo" {
  bucket = var.demo_bucket_name

  tags = {
    Project     = var.project_name
    Environment = var.environment
    Purpose     = "Demo-Data"
    DataClass   = "Mixed"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "demo_sse" {
  bucket = aws_s3_bucket.demo.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.dlp_kms.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "demo_block" {
  bucket                  = aws_s3_bucket.demo.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ----------------------------
# S3 Qurantine
# ----------------------------

resource "aws_s3_bucket" "quarantine" {
  bucket = var.quarantine_bucket_name

  tags = {
    Project     = var.project_name
    Environment = var.environment
    DataClass   = "Restricted"
    Purpose     = "DLP-Quarantine"
  }
}

resource "aws_s3_bucket_public_access_block" "quarantine_block" {
  bucket = aws_s3_bucket.quarantine.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "quarantine_versioning" {
  bucket = aws_s3_bucket.quarantine.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "quarantine_sse" {
  bucket = aws_s3_bucket.quarantine.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.dlp_kms.arn
    }
  }
}


# ----------------------------
# IAM Governance Roles
# ----------------------------
locals {
  account_id = data.aws_caller_identity.current.account_id
}

# Data Owner - full access to sensitive + evidence
resource "aws_iam_role" "data_owner" {
  name = "${var.project_name}-${var.environment}-DataOwnerRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect="Allow",
      Principal={ Service="lambda.amazonaws.com" },
      Action="sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "data_owner_policy" {
  name = "${var.project_name}-${var.environment}-DataOwnerPolicy"

  policy = jsonencode({
    Version="2012-10-17",
    Statement=[
      {
        Effect="Allow",
        Action=["s3:*"],
        Resource=[
          aws_s3_bucket.demo.arn,
          "${aws_s3_bucket.demo.arn}/*",
          aws_s3_bucket.evidence.arn,
          "${aws_s3_bucket.evidence.arn}/*"
        ]
      },
      {
        Effect="Allow",
        Action=["kms:Decrypt","kms:Encrypt","kms:GenerateDataKey"],
        Resource=[aws_kms_key.dlp_kms.arn]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "data_owner_attach" {
  role       = aws_iam_role.data_owner.name
  policy_arn = aws_iam_policy.data_owner_policy.arn
}

# Data Steward - can write classifications + embeddings, read sensitive
resource "aws_iam_role" "data_steward" {
  name = "${var.project_name}-${var.environment}-DataStewardRole"
  assume_role_policy = aws_iam_role.data_owner.assume_role_policy
}

resource "aws_iam_policy" "data_steward_policy" {
  name = "${var.project_name}-${var.environment}-DataStewardPolicy"

  policy = jsonencode({
    Version="2012-10-17",
    Statement=[
      {
        Effect="Allow",
        Action=["s3:GetObject","s3:PutObject","s3:ListBucket"],
        Resource=[
          aws_s3_bucket.demo.arn,
          "${aws_s3_bucket.demo.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "data_steward_attach" {
  role       = aws_iam_role.data_steward.name
  policy_arn = aws_iam_policy.data_steward_policy.arn
}

# RAG Ingest - read CLEAN only (prefix lock)
resource "aws_iam_role" "rag_ingest" {
  name = "${var.project_name}-${var.environment}-RAGIngestRole"
  assume_role_policy = aws_iam_role.data_owner.assume_role_policy
}

resource "aws_iam_policy" "rag_ingest_policy" {
  name = "${var.project_name}-${var.environment}-RAGIngestPolicy"

  policy = jsonencode({
    Version="2012-10-17",
    Statement=[
      {
        Effect="Allow",
        Action=["s3:GetObject","s3:ListBucket"],
        Resource=[
          aws_s3_bucket.demo.arn,
          "${aws_s3_bucket.demo.arn}/clean/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rag_ingest_attach" {
  role       = aws_iam_role.rag_ingest.name
  policy_arn = aws_iam_policy.rag_ingest_policy.arn
}

# DLP Gateway - evidence + secrets read
resource "aws_iam_role" "dlp_gateway" {
  name = "${var.project_name}-${var.environment}-DLPGatewayRole"
  assume_role_policy = aws_iam_role.data_owner.assume_role_policy
}

resource "aws_iam_policy" "dlp_gateway_policy" {
  name = "${var.project_name}-${var.environment}-DLPGatewayPolicy"

  policy = jsonencode({
    Version="2012-10-17",
    Statement=[
      {
        Effect="Allow",
        Action=["s3:PutObject","s3:GetObject","s3:ListBucket"],
        Resource=[
          aws_s3_bucket.evidence.arn,
          "${aws_s3_bucket.evidence.arn}/*"
        ]
      },
      {
        Effect="Allow",
        Action=["secretsmanager:GetSecretValue"],
        Resource=["arn:aws:secretsmanager:*:*:secret:pinecone-api-key*"]
      },
      {
        Effect="Allow",
        Action=["kms:Decrypt","kms:Encrypt","kms:GenerateDataKey"],
        Resource=[aws_kms_key.dlp_kms.arn]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "dlp_gateway_attach" {
  role       = aws_iam_role.dlp_gateway.name
  policy_arn = aws_iam_policy.dlp_gateway_policy.arn
}

resource "aws_iam_role" "auditor_ro" {
  name = "${var.project_name}-${var.environment}-AuditorReadOnlyRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Project     = var.project_name
    Environment = var.environment
    Purpose     = "Auditor-ReadOnly"
  }
}

