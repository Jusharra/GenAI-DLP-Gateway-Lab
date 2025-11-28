# GenAI DLP Gateway Lab – RAG Visibility Demo

End-to-end lab for **AI-native DLP** and **governed RAG**:

> User prompt → DLP classification → OPA data-movement policies → Pinecone RAG → evidence bundle for auditors.

This repo is designed as a **portfolio-ready** and **client-ready** reference implementation of a GenAI DLP gateway with:

- **DLP classification** and entity detection on prompts
- **OPA / Rego policies** enforcing data-movement guardrails
- **MITRE ATLAS–style RAG corpus** in Pinecone
- **GitLab CI/CD** with Python tests, OPA tests, Checkov, Terraform plan, and an **evidence bundle** generator
- **Streamlit UI** for live demos

---

## 1. High-level architecture

Logical flow:

1. **User → DLP Gateway**
   - Streamlit app sends the prompt through `dlp_utils.classify_text` and `detect_entities`.
   - Output: label (e.g., `INTERNAL`, `RESTRICTED_PII`, `RESTRICTED_PHI`) + detected entities.

2. **DLP → OPA policy engine**
   - For each hop (`user → dlp_gateway → rag_orchestrator → pinecone`),
     we call `_run_opa()` with:
     ```json
     {
       "from": "user|dlp_gateway|rag_orchestrator",
       "to": "dlp_gateway|rag_orchestrator|pinecone",
       "state": {
         "classification_label": "...",
         "policy_decision": { "action": "allow|mask|block" },
         "redaction_applied": false
       }
     }
     ```
   - Rego in `platform/mlsecops/data_movement/data_movement.rego`
     and flows in `platform/mlsecops/data_movement/flows.json`
     decide `allow` + `reason`.

3. **RAG retrieval (Pinecone)**
   - If **all hops are allowed**, the prompt is embedded with OpenAI and
     queried against the Pinecone index (`vhc-rag-index` / `vhc-default`).
   - Metadata is expected to contain **ATLAS / AI attack technique** fields
     (e.g. `title`, `tactic`, `description`).

4. **RAG assistant explanation**
   - The top matches are summarized by an OpenAI chat model to produce a
     short explanation of:
     - Which ATLAS / AI techniques were retrieved
     - Why they are relevant to the user’s prompt
     - What risk they illustrate

5. **Evidence bundle**
   - GitLab jobs run:
     - Python unit tests
     - `opa test` for policies
     - Checkov against `platform/iac`
     - Terraform plan with JSON output
   - `platform/devsecops/python/scripts/generate_evidence_report.py`
     merges Checkov, Terraform, and mapping files into
     `platform/evidence/evidence_unified.json`.

---

## 2. Repo layout

```text
GenAI-DLP-Gateway-Lab/
├── platform/
│   ├── devsecops/
│   │   └── python/
│   │       ├── dlp_utils.py
│   │       └── scripts/
│   │           └── generate_evidence_report.py
│   ├── mlsecops/
│   │   └── data_movement/
│   │       ├── data_movement.rego
│   │       ├── flows.json
│   │       └── build_flows_json.py
│   ├── governance/
│   │   └── control_catalog/
│   │       ├── unified_controls.yaml
│   │       ├── opa_to_unified_controls.yaml
│   │       └── checkov_to_unified_controls.yaml
│   ├── iac/
│   │   └── ... Terraform for evidence S3, etc.
│   └── evidence/
│       └── (generated artifacts)
├── streamlit_app.py
├── checkov.yml
├── .gitlab-ci.yml
└── sample_payload.json
3. Local setup
# clone repo
git clone <repo-url>
cd GenAI-DLP-Gateway-Lab

# create virtualenv (example)
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# install Python deps
pip install -r platform/devsecops/python/requirements-dev.txt
pip install streamlit pinecone-client python-dotenv

Environment variables

Create a .env file:

OPENAI_API_KEY=sk-...
OPENAI_EMBED_MODEL=text-embedding-3-small

OPENAI_CHAT_MODEL=gpt-4o-mini

PINECONE_API_KEY=pc-...
PINECONE_INDEX_NAME=vhc-rag-index
PINECONE_NAMESPACE=vhc-default

# Optional: path to local OPA binary for dlp_utils._run_opa
OPA_BIN=/c/Tools/OPA/opa.exe

4. Running the Streamlit demo
streamlit run streamlit_app.py


Demo flow:

Enter a prompt (e.g. non-sensitive: “Help me plan a limo pickup at LAX for four people.”).

Click “Run DLP + RAG flow”.

Inspect:

DLP classification – label & entities

Data movement decisions – OPA allow/deny + human-readable reason

RAG retrieval – Pinecone matches + RAG assistant explanation

Repeat with sensitive prompts:

Here is the client's SSN: 123-45-6789.

This patient tested positive for strep. What meds should they ask their doctor about?

For restricted prompts, observe:

Labels RESTRICTED_PII / RESTRICTED_PHI

One or more hops denied with a clear Rego reason

RAG section showing that the query was not executed due to policy.

5. CI/CD pipeline (GitLab)

.gitlab-ci.yml stages:

validate

python-tests: run unit tests on DLP utils and scripts.

opa

opa-tests: run opa test over Rego policies.

checkov

checkov_scan: scan platform/iac with checkov.yml config.

terraform

terraform-plan: terraform init/validate/plan, export JSON plan to platform/evidence/terraform_plan.json.

evidence

evidence-bundle: run generate_evidence_report.py to create platform/evidence/evidence_unified.json.

Artifacts are retained for auditors as machine-readable evidence of:

Policy coverage → unified controls mapping

IaC security posture → Checkov

Planned infra changes → Terraform JSON plan

Runtime DLP & data-movement design → RAG gateway demo

6. What this lab demonstrates

How to wrap GenAI/RAG behind a DLP gateway with explainable decisions.

How to encode AI data-movement policies in OPA/Rego using MITRE ATLAS-style flows.

How to combine runtime behavior + static checks into a single evidence bundle
that speaks auditor language (controls, mappings, artifacts).

How to provide both:

Operator view → Streamlit demo

Auditor view → evidence JSON from CI/CD