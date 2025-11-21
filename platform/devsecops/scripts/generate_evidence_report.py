import json
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = ROOT / "reports" / "evidence"
REPORTS_DIR.mkdir(exist_ok=True, parents=True)


def main():
  # In real projects you'll aggregate:
  # - CI jobs that ran
  # - Security scan artifacts
  # - Terraform validation results
  # - MLSecOps test outputs
  # For now, this is a structured placeholder.
  evidence = {
    "generated_at": datetime.utcnow().isoformat() + "Z",
    "pipeline_context": {
      "ci_project": "${CI_PROJECT_PATH}",
      "ci_pipeline_id": "${CI_PIPELINE_ID}",
      "ci_commit_sha": "${CI_COMMIT_SHA}",
    },
    "checks": {
      "controls_mapping": "reports/controls_mapping.json",
      "bandit_report": "reports/bandit.json",
      "safety_report": "reports/safety.txt",
      "mlsecops_tests": "tests/test_model_security.py",
    },
  }

  out = REPORTS_DIR / "evidence_summary.json"
  with out.open("w", encoding="utf-8") as f:
    json.dump(evidence, f, indent=2)

  print(f"[generate_evidence_report] Wrote evidence summary to {out}")


if __name__ == "__main__":
  main()
