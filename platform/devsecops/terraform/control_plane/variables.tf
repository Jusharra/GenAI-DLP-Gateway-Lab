variable "project_name" { type = string }
variable "environment"  { type = string }

variable "evidence_bucket_name" { type = string }
variable "demo_bucket_name"     { type = string }
variable "quarantine_bucket_name" { type = string }

variable "region" {
  type    = string
  default = "us-east-1"
}
