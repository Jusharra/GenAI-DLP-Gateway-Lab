# GenAI DLP Gateway – Terraform Stack

This module provisions the core AWS infrastructure for the **GenAI DLP Gateway Lab**:

- KMS key for evidence and Lambda environment encryption  
- Versioned, KMS-encrypted S3 evidence bucket  
- DLP Filter Lambda + RAG Orchestrator Lambda  
- IAM roles with least-privilege policies  
- API Gateway HTTP API exposing `POST /chat` as the DLP entrypoint  

## Usage

```bash
cd platform/devsecops/terraform/evidence_s3

terraform init

terraform plan \
  -var 'project_name=genai-dlp-gateway' \
  -var 'evidence_bucket_name=your-unique-evidence-bucket'

terraform apply

