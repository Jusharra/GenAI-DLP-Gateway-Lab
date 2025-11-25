# Compliance as Code — Checkov (DLP Gateway Lab)

This folder provides custom Checkov policies that enforce:
- S3 evidence encryption + integrity
- No public buckets / APIs
- DLP lambda policy wiring
- Governance artifacts existence

## Run locally
From repo root:

```bash
pip install checkov
checkov -d platform/devsecops/terraform/evidence_s3 \
  --external-checks-dir platform/governance/compliance_as_code/checkov/checks \
  --config-file platform/governance/compliance_as_code/checkov/.checkov.yml
