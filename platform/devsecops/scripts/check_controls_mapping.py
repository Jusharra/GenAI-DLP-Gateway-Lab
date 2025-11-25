# This validates your unified catalog has artifacts tied to each control.
import json, yaml
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "governance" / "control_catalog" / "unified_controls.yaml"
OUT = ROOT / "evidence" / "controls_mapping.json"

def load_catalog():
    with open(CATALOG, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def validate_controls(controls):
    missing = []
    for c in controls:
        if not c.get("evidence"):
            missing.append({"control_id": c["id"], "reason": "no evidence mapping"})
            continue
        ev = c["evidence"]
        if not any(ev.get(k) for k in ["opa_policy", "checkov_check", "terraform_guardrail", "test_case"]):
            missing.append({"control_id": c["id"], "reason": "evidence fields empty"})
    return missing

def main():
    data = load_catalog()
    controls = data["controls"]

    missing = validate_controls(controls)
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_controls": len(controls),
        "missing_evidence_count": len(missing),
        "missing": missing,
        "controls": controls,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2))
    print(f"[OK] Control mapping report -> {OUT}")

if __name__ == "__main__":
    main()
