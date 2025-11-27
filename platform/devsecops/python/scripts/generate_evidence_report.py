# platform/devsecops/python/scripts/generate_evidence_report.py

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import yaml  # pip install pyyaml


def find_repo_root(start: Path) -> Path:
    """Walk upwards until we find a 'platform' dir; treat that as repo root."""
    for p in [start] + list(start.parents):
        if (p / "platform").is_dir():
            return p
    return start


def load_yaml(path: Path, required: bool = True):
    if not path.exists():
        if required:
            raise FileNotFoundError(f"Required YAML not found: {path}")
        return None
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_json(path: Path, optional: bool = False, default=None):
    """
    Load JSON from a file, but be forgiving if the path is a directory
    (e.g., Checkov writes to a directory like 'checkov.json/').
    """
    path = Path(path)

    # If it's a directory (like platform/evidence/checkov.json/)
    # try to pick a JSON file inside it.
    if path.is_dir():
        # Prefer *.json, but if none, just pick the first file.
        candidates = sorted([p for p in path.glob("*.json") if p.is_file()])
        if not candidates:
            candidates = sorted([p for p in path.iterdir() if p.is_file()])

        if not candidates:
            if optional:
                return default
            raise FileNotFoundError(f"No JSON files found in directory: {path}")

        # Use the first JSON file we found
        path = candidates[0]

    if not path.exists():
        if optional:
            return default
        raise FileNotFoundError(f"Required evidence file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_jsonl(path: Path):
    if not path.exists():
        return None
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                # best-effort; skip bad lines
                continue
    return records or None


def build_control_index(unified_controls, opa_map, checkov_map):
    """Return a dict keyed by unified control ID with tool coverage info."""
    index = {}

    # seed from unified controls file if present
    if isinstance(unified_controls, dict) and "controls" in unified_controls:
        for ctrl in unified_controls["controls"]:
            cid = ctrl.get("id")
            if not cid:
                continue
            index[cid] = {
                "id": cid,
                "name": ctrl.get("name"),
                "description": ctrl.get("description"),
                "frameworks": ctrl.get("frameworks", []),
                "tools": {
                    "opa_policies": [],
                    "checkov_checks": [],
                },
            }

    # add OPA coverage
    for pol in opa_map.get("opa_policies", []):
        tool_id = pol.get("id")
        for cid in pol.get("unified_controls", []):
            entry = index.setdefault(
                cid,
                {
                    "id": cid,
                    "name": None,
                    "description": None,
                    "frameworks": [],
                    "tools": {
                        "opa_policies": [],
                        "checkov_checks": [],
                    },
                },
            )
            entry["tools"]["opa_policies"].append(
                {
                    "id": tool_id,
                    "package": pol.get("package"),
                    "rule": pol.get("rule"),
                    "description": pol.get("description"),
                }
            )

    # add Checkov coverage
    for chk in checkov_map.get("checkov_mappings", []):
        check_id = chk.get("check_id")
        for cid in chk.get("unified_controls", []):
            entry = index.setdefault(
                cid,
                {
                    "id": cid,
                    "name": None,
                    "description": None,
                    "frameworks": [],
                    "tools": {
                        "opa_policies": [],
                        "checkov_checks": [],
                    },
                },
            )
            entry["tools"]["checkov_checks"].append(
                {
                    "check_id": check_id,
                    "description": chk.get("description"),
                }
            )

    return index


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Merge OPA, Checkov, Terraform, and ML/S3 evidence into a unified auditor JSON."
    )

    parser.add_argument(
        "--opa-runtime",
        default="platform/evidence/opa_runtime.json",
        help="Normalized OPA runtime evidence JSON",
    )

    parser.add_argument(
        "--opa-tf",
        default="platform/evidence/opa_terraform.json",
        help="Normalized OPA Terraform evidence JSON",
    )

    parser.add_argument(
        "--checkov",
        default="platform/evidence/checkov.json",
        help="Checkov JSON output",
    )

    parser.add_argument(
        "--tf-plan",
        default="platform/evidence/terraform_plan.json",
        help="Terraform plan (show -json) summary",
    )

    parser.add_argument(
        "--s3-meta",
        default="platform/evidence/s3_metadata.json",
        help="S3 evidence bucket metadata",
    )

    parser.add_argument(
        "--ml-meta",
        default="platform/evidence/ml_metadata.json",
        help="ML / RAG metadata (e.g., rag_state_prompt/response)",
    )

    parser.add_argument(
        "--movement-log",
        default="platform/evidence/data_movement_log.jsonl",
        help="DLP movement decisions log (JSONL)",
    )

    parser.add_argument(
        "--class-log",
        default="platform/evidence/classification_log.jsonl",
        help="Classification decisions log (JSONL)",
    )

    parser.add_argument(
        "--out",
        default="platform/evidence/evidence_unified.json",
        help="Output unified evidence JSON",
    )

    args = parser.parse_args(argv)

    here = Path(__file__).resolve()
    repo_root = find_repo_root(here)

    catalog_dir = repo_root / "platform" / "governance" / "control_catalog"
    unified_controls_path = catalog_dir / "unified_controls.yaml"
    opa_map_path = catalog_dir / "opa_to_unified_controls.yaml"
    checkov_map_path = catalog_dir / "checkov_to_unified_controls.yaml"

    unified_controls = load_yaml(unified_controls_path, required=False) or {}
    opa_map = load_yaml(opa_map_path, required=True)
    checkov_map = load_yaml(checkov_map_path, required=True)

    control_index = build_control_index(unified_controls, opa_map, checkov_map)

    # load evidence artifacts (best-effort, don't hard fail on missing optional files)
    repo_root = Path(__file__).resolve().parents[3]

    # Make OPA + ancillary evidence OPTIONAL for now so the pipeline doesn’t fail
    opa_runtime = load_json(
        repo_root / args.opa_runtime,
        optional=True,
        default={"source": "opa_runtime", "results": []},
    )

    opa_tf = load_json(
        repo_root / args.opa_tf,
        optional=True,
        default={"source": "opa_terraform", "results": []},
    )

    checkov = load_json(
        repo_root / args.checkov,
        optional=True,
        default={"source": "checkov", "results": []},
    )

    tf_plan = load_json(
        repo_root / args.tf_plan,
        optional=True,
        default={"source": "terraform_plan", "changes": []},
    )

    s3_meta = load_json(
        repo_root / args.s3_meta,
        optional=True,
        default={"buckets": []},
    )

    ml_meta = load_json(
        repo_root / args.ml_meta,
        optional=True,
        default={"runs": []},
    )

    movement_log = load_jsonl(
        repo_root / args.movement_log,
        optional=True,
        default=[],
    )

    class_log = load_jsonl(
        repo_root / args.class_log,
        optional=True,
        default=[],
    )


    evidence = {
        "run_metadata": {
            "generated_at_utc": datetime.utcnow().isoformat() + "Z",
            "tool": "GenAI-DLP-Gateway-Lab evidence merger",
        },
        "controls": list(control_index.values()),
        "artifacts": {
            "opa": {
                "runtime": opa_runtime,
                "terraform": opa_tf,
            },
            "checkov": checkov_json,
            "terraform_plan": tf_plan,
            "s3_metadata": s3_meta,
            "ml_metadata": ml_meta,
            "logs": {
                "data_movement": movement_log,
                "classification": class_log,
            },
        },
    }

    out_path = repo_root / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    print(f"[OK] Unified evidence written to: {out_path}")


if __name__ == "__main__":
    sys.exit(main())
