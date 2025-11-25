import json, subprocess, sys
from pathlib import Path

import yaml  # already in your venv

REPO_ROOT = Path(__file__).resolve().parents[3]
CATALOG_MAP = REPO_ROOT / "platform" / "governance" / "control_catalog" / "checkov_to_unified_controls.yaml"
EVIDENCE_OUT = REPO_ROOT / "platform" / "devsecops" / "evidence" / "checkov_evidence.json"

def run_checkov(tf_dir: Path):
    cmd = [
        sys.executable, "-m", "checkov",
        "-d", str(tf_dir),
        "-o", "json"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode not in (0, 1):  # 1 = failed checks, valid output
        raise RuntimeError(res.stderr or res.stdout)
    return json.loads(res.stdout)

def load_mapping():
    with open(CATALOG_MAP, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def map_findings(checkov_json, mapping):
    findings = []
    for f in checkov_json.get("results", {}).get("failed_checks", []):
        check_id = f.get("check_id")
        m = mapping.get(check_id, {})
        unified = m.get("unified_controls", [])

        findings.append({
            "tool": "checkov",
            "check_id": check_id,
            "check_title": f.get("check_name"),
            "resource": f.get("resource"),
            "file_path": f.get("file_path"),
            "severity": f.get("severity"),
            "guideline": f.get("guideline"),
            "unified_controls": unified,   # <-- the money shot
        })
    return findings

def main():
    tf_dir = REPO_ROOT / "terraform"
    if not tf_dir.exists():
        tf_dir = REPO_ROOT  # fallback scan

    mapping = load_mapping()
    ck = run_checkov(tf_dir)
    findings = map_findings(ck, mapping)

    EVIDENCE_OUT.parent.mkdir(parents=True, exist_ok=True)
    evidence = {
        "summary": {
            "failed": len(findings),
            "passed": len(ck.get("results", {}).get("passed_checks", [])),
            "skipped": len(ck.get("results", {}).get("skipped_checks", [])),
        },
        "findings": findings
    }

    with open(EVIDENCE_OUT, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    print(f"Wrote evidence to: {EVIDENCE_OUT}")

if __name__ == "__main__":
    main()
