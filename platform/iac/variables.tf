variable "region" {
  type        = string
  description = "AWS region for the lab"
  default     = "us-west-2"
}

variable "evidence_bucket_name" {
  type        = string
  description = "S3 bucket for immutable evidence"
  validation {
    condition     = can(regex("^[a-z0-9-]{3,63}$", var.evidence_bucket_name))
    error_message = "Bucket name must be lowercase, 3-63 chars, letters/numbers/hyphens."
  }
}

variable "cloudtrail_name" {
  type        = string
  default     = "genai-dlp-gateway-trail"
}

variable "tags" {
  type        = map(string)
  default     = {
    project = "GenAI-DLP-Gateway-Lab"
    owner   = "Jusharra"
  }
}
