variable "project_name" {
  type        = string
  description = "Short name for the DLP RAG Gateway project"
}

variable "region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region"
}

variable "evidence_bucket_name" {
  type        = string
  description = "Name of the S3 evidence bucket"
}

variable "environment" {
  type        = string
  description = "Deployment environment (dev/staging/prod)"
}

variable "dlp_lambda_env" {
  type        = map(string)
  default     = {}
  description = "Environment variables for the DLP Lambda"
}

variable "rag_lambda_env" {
  type        = map(string)
  default     = {}
  description = "Environment variables for the RAG Lambda"
}

