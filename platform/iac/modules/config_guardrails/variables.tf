variable "config_role_arn" {
  description = "IAM role ARN used by AWS Config"
  type        = string
}

variable "tags" {
  description = "Tags to apply to config guardrail resources"
  type        = map(string)
  default     = {}
}
