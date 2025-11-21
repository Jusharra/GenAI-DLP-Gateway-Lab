# Governance Platform

This directory defines the GRC engineering backbone for all labs:

- Control catalogs (SOC 2, ISO, NIST, etc.)
- Risk register
- Policies-as-code (OPA/Rego, schemas)
- Mappings from controls → technical enforcement

Every project in `../projects/` must reference at least:
- One framework control
- One risk
- One enforcement mechanism (CI job, Terraform module, guardrail)
