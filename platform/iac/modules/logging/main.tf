# CloudTrail to the vault, encrypted, validated.
resource "aws_iam_role" "cloudtrail" {
  name = "genai-dlp-cloudtrail-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "cloudtrail.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_cloudtrail" "trail" {
  name                          = var.cloudtrail_name
  s3_bucket_name                = split(":::",
                                  var.log_bucket_arn)[1]
  kms_key_id                    = var.kms_key_arn
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  tags                          = var.tags
}

resource "aws_iam_role" "config" {
  name = "genai-dlp-config-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "config.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

output "config_role_arn" {
  value = aws_iam_role.config.arn
}
