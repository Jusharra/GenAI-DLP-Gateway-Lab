# Platform Architecture Overview

This platform is designed to keep every lab aligned with:

- GRC Engineering (governance-first)
- DevSecOps (automated guardrails and evidence)
- MLSecOps (secure ML lifecycle)

Key layers:

1. Governance
   - Control catalogs (SOC 2, ISO, NIST, NIST AI RMF)
   - Risk register
   - Policies-as-code

2. DevSecOps
   - GitLab CI templates for validation, testing, security, and audit
   - Terraform baseline modules (evidence bucket, etc.)
   - Python tooling for scanning and evidence reporting

3. MLSecOps
   - Base ML project template with data quality and security checks
   - Drift monitoring config
   - Model card documenting risks and controls
