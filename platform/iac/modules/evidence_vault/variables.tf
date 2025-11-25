variable "bucket_name" {
  description = "Name of the evidence vault S3 bucket"
  type        = string
}

variable "enable_object_lock" {
  description = "Whether to enable S3 Object Lock (immutability)"
  type        = bool
  default     = true
}

variable "kms_key_rotation_days" {
  description = "Number of days for KMS key rotation"
  type        = number
  default     = 365
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}
