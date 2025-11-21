import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
GOVERNANCE_DIR = ROOT / "platform" / "governance"
REPORTS_DIR = ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True, parents=True)


def load_yaml(path: Path):
  with path.open("r", encoding="utf-8") as f:
    return yaml.safe_load(f)


def main():
  soc2_path = GOVERNANCE_DIR / "control_catalog" / "soc2_controls.yaml"
  risk_path = GOVERNANCE_DIR / "risk_register" / "risk_register.yaml"

  soc2 = load_yaml(soc2_path)
  risks = load_yaml(risk_path)

  controls = {c["id"]: c for c in soc2.get("controls", [])}
  risk_items = risks.get("risks", [])

  # Simple mapping: which risks reference which controls
  mapping = []
  for r in risk_items:
    for fw in r.get("frameworks", []):
      if "SOC 2:" in fw:
        control_id = fw.split("SOC 2:")[-1].strip()
        if control_id in controls:
          mapping.append(
            {
              "risk_id": r["id"],
              "risk_title": r["title"],
              "control_id": control_id,
              "control_name": controls[control_id]["name"],
            }
          )

  out = REPORTS_DIR / "controls_mapping.json"
  with out.open("w", encoding="utf-8") as f:
    json.dump(mapping, f, indent=2)

  print(f"[check_controls_mapping] Wrote {len(mapping)} mappings to {out}")


if __name__ == "__main__":
  main()
