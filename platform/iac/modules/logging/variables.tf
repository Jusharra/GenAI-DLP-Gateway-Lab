variable "cloudtrail_name" {
  description = "Name for the CloudTrail trail"
  type        = string
}

variable "log_bucket_arn" {
  description = "ARN of the S3 bucket where CloudTrail should log"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN used to encrypt CloudTrail logs"
  type        = string
}

variable "tags" {
  description = "Tags to apply to logging resources"
  type        = map(string)
  default     = {}
}
