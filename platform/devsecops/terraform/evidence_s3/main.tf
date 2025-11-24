terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# KMS key for evidence & lambda env encryption
resource "aws_kms_key" "evidence" {
  description         = "${var.project_name} evidence KMS key"
  enable_key_rotation = true
}

# Evidence S3 bucket
resource "aws_s3_bucket" "evidence" {
  bucket = var.evidence_bucket_name

  tags = {
    Project     = var.project_name
    Environment = var.environment
    Owner       = "Jusharra"
    Purpose     = "GenAI-DLP-Evidence"
    DataClass   = "Sensitive"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.evidence.arn
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
}

# IAM assume role document for Lambdas
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# DLP Lambda Role
resource "aws_iam_role" "dlp_lambda_role" {
  name               = "${var.project_name}-dlp-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy" "dlp_policy" {
  role = aws_iam_role.dlp_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.evidence.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.evidence.arn
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = "*"
      }
    ]
  })
}

# RAG Lambda Role
resource "aws_iam_role" "rag_lambda_role" {
  name               = "${var.project_name}-rag-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy" "rag_policy" {
  role = aws_iam_role.rag_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.evidence.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.evidence.arn
      },
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = "*"
      }
    ]
  })
}

# Lambda functions (expect packages to be built into platform/devsecops/python/dist)
resource "aws_lambda_function" "dlp_filter" {
  function_name = "${var.project_name}-dlp-filter"
  role          = aws_iam_role.dlp_lambda_role.arn
  handler       = "dlp_handler.lambda_handler"
  runtime       = "python3.11"

  filename = "${path.module}/../../python/dist/dlp_package.zip"

  environment {
    variables = merge(
      {
        "EVIDENCE_BUCKET_NAME" = aws_s3_bucket.evidence.bucket
        "RAG_LAMBDA_NAME"      = "${var.project_name}-rag-orchestrator"
      },
      var.dlp_lambda_env
    )
  }
}

resource "aws_lambda_function" "rag_orchestrator" {
  function_name = "${var.project_name}-rag-orchestrator"
  role          = aws_iam_role.rag_lambda_role.arn
  handler       = "rag_handler.lambda_handler"
  runtime       = "python3.11"

  filename = "${path.module}/../../python/dist/rag_package.zip"

  environment {
    variables = merge(
      {
        "EVIDENCE_BUCKET_NAME"  = aws_s3_bucket.evidence.bucket
      },
      var.rag_lambda_env
    )
  }
}

# API Gateway HTTP API
resource "aws_apigatewayv2_api" "dlp_api" {
  name          = "${var.project_name}-api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "dlp_integration" {
  api_id                 = aws_apigatewayv2_api.dlp_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.dlp_filter.arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "chat_route" {
  api_id    = aws_apigatewayv2_api.dlp_api.id
  route_key = "POST /chat"
  target    = "integrations/${aws_apigatewayv2_integration.dlp_integration.id}"
}

resource "aws_lambda_permission" "allow_apigw_dlp" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.dlp_filter.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.dlp_api.execution_arn}/*/*"
}
