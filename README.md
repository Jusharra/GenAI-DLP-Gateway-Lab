📘 GenAI DLP Gateway Lab
A Zero-Trust, Policy-Driven DLP Enforcement Layer for RAG & LLM Pipelines

A hands-on, 1–2 hour AWS lab designed to showcase enterprise-grade AI governance, DLP enforcement, and compliance-as-code guardrails.
This project demonstrates how to secure a GenAI/RAG pipeline with policy-driven filtering, least-privilege IAM, encrypted evidence logging, and continuous compliance controls.

🚀 Executive Summary

Zero-trust DLP enforcement for GenAI — Every prompt and every LLM/RAG response is scanned for PII/PHI using a DLP Lambda before hitting the model or the user.

Policy-as-code guardrails prevent insecure deployments — OPA/Rego blocks Terraform applies if the DLP gateway, evidence logging, or IAM restrictions aren’t correctly configured.

Audit-ready architecture — All DLP decisions, masks, blocks, and logs are stored in a KMS-encrypted evidence vault and mapped to SOC 2, ISO 27001, ISO 42001, and HIPAA controls.

📂 Repository Structure

This lab uses the platform baseline architecture:

platform/
  devsecops/
    gitlab/
      .gitlab-ci.yml
      base-ci.yml
    python/
      requirements-dev.txt
    scripts/
      check_controls_mapping.py
      generate_evidence_report.py
    terraform/
      evidence_s3/
        main.tf
        outputs.tf
        variables.tf
        README.md

  docs/
    architecture/
      platform-architecture.md
    standards/
      coding-standards.md

  governance/
    control_catalog/
      soc2_controls.yaml
    policies_as_code/
      opa/
        terraform_guardrails.rego
    risk_register/
      risk_register.yaml
      README.md

  mlsecops/
    templates/
      README.md

.gitignore
README.md

🧩 Project Overview
Objective

Build a DLP Gateway that sits in front of a GenAI RAG pipeline using Pinecone as the vector database.
This gateway inspects prompts and responses for PII/PHI, applying OPA/Rego policies to block, mask, or allow traffic before reaching the LLM.

What You’ll Build

User → API Gateway → DLP Lambda → RAG Orchestrator Lambda → Pinecone → LLM → DLP Check → User

Core features:

Prompt & response PII/PHI detection

Rego-based block/allow/mask/redact

Evidence logging to KMS-encrypted S3

Least-privilege IAM roles

Pinecone for vector DB retrieval

Optionally Bedrock for LLM inference

Terraform IaC + GitLab CI/CD

Policy-as-code deployment gates

Automated GRC evidence generation

🛠️ Tech Stack
AI + RAG

AWS Bedrock (or a stubbed local LLM)

Pinecone (vector store)

Embeddings + context retrieval

DLP

Microsoft Presidio (or regex fallback)

Custom DLP policy layer

OPA/Rego runtime policies

AWS Infrastructure

API Gateway (restricted)

Lambda (DLP Filter + RAG Orchestrator)

S3 Evidence Vault (versioned + KMS encrypted)

IAM least-privilege roles

CloudWatch logs

Secrets Manager or SSM Parameters

Governance & Compliance

SOC 2, ISO 27001, ISO 42001, HIPAA mappings

Evidence logs + decision tracking

Continuous monitoring

Risk register entries

Control-by-control mapping

Automation

GitLab CI/CD

Terraform guardrails

SAST + secrets scanning

PaC enforcement

🔐 Security & Governance Principles Demonstrated
1. Zero-Trust for GenAI Workloads

No prompt or response bypasses DLP.
Enforced by architecture + Terraform + Rego policies.

2. Least-Privilege Access

DLP + RAG Lambdas get tightly scoped IAM policies.

3. Defense-in-Depth

Two DLP scans:

Pre-LLM (prompt)

Post-LLM (response)

4. Crypto Hygiene

KMS encryption for:

Evidence storage

Logs

Secrets

5. Continuous Compliance

Control mappings surface in:

soc2_controls.yaml

risk_register.yaml

Evidence in S3

CI logs

OPA policy checks

📜 Compliance Mapping

This lab aligns to key controls across frameworks:

SOC 2

CC6.1 – Logical access controls

CC7.2 – Change management

CC7.3 – Monitoring for anomalous activity

ISO 27001

A.8 – Information handling & classification

A.9 – Access control

A.12 – Logging & monitoring

ISO 42001

8.5 – AI system operational controls

HIPAA

164.312(a)(1) – Access control

164.312(e)(1) – Transmission security

All mapped inside soc2_controls.yaml.

🧪 CI/CD Workflow
Pipeline Stages

validate – Terraform/Python/YAML lint

test – DLP & RAG unit tests

security – SAST + secrets scanning

policy-check – OPA/Rego

Deny public API

Deny missing evidence bucket

Deny missing DLP Lambda integration

deploy – Terraform Apply

evidence – Generate audit package from DLP logs

This workflow ensures the system cannot deploy in a noncompliant state.

📊 Evidence & Audit Artifacts

Stored automatically in S3:

Prompt DLP decisions

Response DLP decisions

Role-based policy outcomes

Masked/blocked samples

GitLab pipeline results

JSON evidence reports

Markdown GRC summary

Terraform state + plan logs

This gives auditors direct, immutable evidence of DLP and AI governance enforcement.

📚 Documentation

Located under /docs/architecture:

System architecture diagram

Deployment flow

DLP enforcement logic

IAM permissions model

Threat model

GRC mapping

Evidence validation workflow

▶️ Optional Loom Video

A short (under 5 minutes) video demonstrating:

Clean vs. PII prompt

Block/mask outcomes

RAG retrieval

Evidence logs

CI policy enforcement

🧩 Skills Demonstrated

This lab showcases:

AI Governance Engineering

AWS Security Architecture

IaC + Policy-as-Code Guardrails

DevSecOps CI/CD pipelines

RAG system architecture

Zero-trust AI deployment

SOC 2 & ISO compliance-by-design

Lambda-based secure microservices

Pinecone + Bedrock integration

This is a hire-me showcase project for GRC Engineering, DevSecOps, and AI Security roles.
