# Baseline AWS Config rules. Deterministic compliance.
resource "aws_config_configuration_recorder" "recorder" {
  name     = "genai-dlp-recorder"
  role_arn = var.config_role_arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "channel" {
  name           = "genai-dlp-channel"
  s3_bucket_name = "vhc-dlp-evidence-logs-dev"
  depends_on     = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_configuration_recorder_status" "status" {
  name       = aws_config_configuration_recorder.recorder.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.channel]
}

# Guardrail rules
resource "aws_config_config_rule" "s3_public_block" {
  name = "s3-bucket-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}

resource "aws_config_config_rule" "kms_rotation" {
  name = "kms-key-rotation-enabled"
  source {
    owner             = "AWS"
    source_identifier = "KMS_KEY_ROTATION_ENABLED"
  }
}

resource "aws_config_config_rule" "cloudtrail_enabled" {
  name = "cloudtrail-enabled"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }
}
