terraform {
  required_version = ">= 1.6.0"
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

module "evidence_vault" {
  source                = "./modules/evidence_vault"
  bucket_name           = var.evidence_bucket_name
  enable_object_lock    = true
  kms_key_rotation_days = 365
  tags                  = var.tags
}

module "logging" {
  source              = "./modules/logging"
  cloudtrail_name     = var.cloudtrail_name
  log_bucket_arn      = module.evidence_vault.bucket_arn
  kms_key_arn         = module.evidence_vault.kms_key_arn
  tags                = var.tags
}

module "config_guardrails" {
  source          = "./modules/config_guardrails"
  config_role_arn = module.logging.config_role_arn
  tags            = var.tags
}
