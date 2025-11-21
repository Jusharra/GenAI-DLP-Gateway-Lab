# DevSecOps Platform

This directory defines reusable automation and guardrails for all labs:

- GitLab CI/CD templates
- Terraform baseline modules
- Python tooling configuration
- Shared scripts for governance-aware checks and evidence generation

Projects in `../projects/` should **include** this CI config and **reuse**
Terraform modules whenever possible.
