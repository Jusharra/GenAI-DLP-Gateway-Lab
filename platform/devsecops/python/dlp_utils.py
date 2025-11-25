import json
import logging
import os
import uuid
from datetime import datetime
import shutil
import tempfile
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
import boto3

ROOT = Path(__file__).resolve().parent
OPA_BIN = os.getenv("OPA_BIN", "opa")


logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")

Decision = Literal["allow", "block", "mask"]
# ----------------------------
# Locate real repo root:
# the FIRST parent that contains a "platform/" directory
# ----------------------------
def find_repo_root(start: Path) -> Path:
    for p in [start] + list(start.parents):
        if (p / "platform").exists() and (p / "platform").is_dir():
            return p
    return start.parent  # fallback

REPO_ROOT = find_repo_root(Path(__file__).resolve())

OPA_CLASSIFY_POLICY = (
    REPO_ROOT
    / "platform"
    / "governance"
    / "policies_as_code"
    / "opa"
    / "classification"
    / "classification_rules.rego"
)

CATALOG_DIR = (
    REPO_ROOT
    / "platform"
    / "governance"
    / "classification_catalog"
)

DATA_MOVEMENT_POLICY = (
    REPO_ROOT / "platform" / "mlsecops" / "data_movement" / "data_movement.rego"
)

CATALOG_DIR = (
    REPO_ROOT / "platform" / "governance" / "classification_catalog"
)
# --- OPA binary lookup (Windows + Git Bash safe) ---
OPA_BIN = os.getenv("OPA_BIN") or shutil.which("opa") or shutil.which("opa.exe")

# ----------------------------
# YAML loader
# ----------------------------
def _load_yaml(path: Path) -> Dict[str, Any]:
    import yaml
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def classify_text(entities: List[Dict[str, Any]]) -> str:
    taxonomy = _load_yaml(CATALOG_DIR / "pii_entities.yaml")

    payload = {"entities": entities, "taxonomy": taxonomy}

    if not OPA_BIN:
        raise RuntimeError(
            "OPA binary not found. Install opa.exe and set OPA_BIN "
            "env var to full path, e.g. OPA_BIN=C:\\Tools\\opa\\opa.exe"
        )

    cmd = [
        OPA_BIN, "eval",
        "-d", str(OPA_CLASSIFY_POLICY),
        "--format", "json",
        "data.classification.rules.label",
        "--input"  # file path will be appended
    ]

    # Windows-safe: write input to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
        json.dump(payload, tf)
        tf.flush()
        tmp_path = tf.name

    cmd.append(tmp_path)

    res = subprocess.run(
        cmd,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True
    )

    output = json.loads(res.stdout)
    # adapt to your policy output schema
    return output["result"][0]["expressions"][0]["value"]

def classify_string(text: str) -> str:
    """
    Convenience: detect -> classify
    """
    from dlp_utils import detect_pii  # reuse your existing detector
    entities = detect_pii(text)
    return classify_text(entities)

def decision_bundle(text: str, user_role: str = "anonymous", context: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """
    One-stop shop for gateway: detect -> classify -> evaluate_policy
    Returns a dict ready to log as evidence.
    """
    from dlp_utils import detect_pii, evaluate_policy
    context = context or {"channel": "chat"}
    entities = detect_pii(text)
    label = classify_text(entities)
    policy = evaluate_policy(entities, user_role=user_role, context=context)
    return {
        "classification_label": label,
        "pii_entities": entities,
        "policy_decision": policy,  # e.g., {"action":"mask","reason":"..."}
    }
    
def safe_preview(text: Optional[str], max_len: int = 200) -> str:
    if not text:
        return ""
    return text[:max_len]


def detect_pii(text: str) -> List[Dict[str, Any]]:
    """
    Very simple PII/PHI heuristic for the lab.

    PRODUCTION NOTE:
      Replace this with Microsoft Presidio or another DLP engine.
      The shape of the return value is intentionally generic so a real engine
      can be swapped in with minimal change.
    """
    findings: List[Dict[str, Any]] = []
    if not text:
        return findings

    lowered = text.lower()

    if "ssn" in lowered or "social security" in lowered:
        findings.append({"type": "SSN"})

    if "credit card" in lowered or "card number" in lowered:
        findings.append({"type": "CREDIT_CARD"})

    if "patient" in lowered or "phi" in lowered or "diagnosis" in lowered:
        findings.append({"type": "PHI"})

    return findings


def evaluate_policy(role: str, pii_findings: List[Dict[str, Any]]) -> Decision:
    """
    Simple policy model:

      - No PII -> allow
      - PII + privileged role -> mask
      - PII + non-privileged -> block

    Privileged roles can see content in a more redacted way.
    In practice, this logic would be expressed as Rego (OPA) and mirrored here.
    """
    if not pii_findings:
        return "allow"

    privileged_roles = {"dlp-admin", "security-engineer"}

    if role in privileged_roles:
        return "mask"

    return "block"


def log_decision(
    *,
    stage: Literal["request", "response"],
    decision: Decision,
    role: str,
    pii_findings: List[Dict[str, Any]],
    content_preview: str,
    evidence_bucket: str,
) -> str:
    """
    Writes a structured DLP decision record to S3.

    This is the core "audit evidence" artifact:
      - Immutable (versioned bucket)
      - Encrypted (KMS)
      - Structured (JSON)
    """
    decision_id = str(uuid.uuid4())
    now = datetime.utcnow()

    record = {
        "decision_id": decision_id,
        "timestamp": now.isoformat() + "Z",
        "stage": stage,
        "decision": decision,
        "role": role or "unknown",
        "pii_findings": pii_findings,
        "content_preview": content_preview,
    }

    key = f"dlp-decisions/{stage}/{now.date()}/{decision_id}.json"

    logger.info(
        json.dumps(
            {
                "event": "dlp_decision",
                "decision_id": decision_id,
                "stage": stage,
                "decision": decision,
                "role": role,
                "pii_types": [f["type"] for f in pii_findings],
            }
        )
    )

    s3.put_object(
        Bucket=evidence_bucket,
        Key=key,
        Body=json.dumps(record).encode("utf-8"),
    )

    return decision_id


def get_evidence_bucket_from_env() -> str:
    bucket = os.environ.get("EVIDENCE_BUCKET_NAME")
    if not bucket:
        raise RuntimeError("EVIDENCE_BUCKET_NAME environment variable is required")
    return bucket

# --- Data Movement as Code (OPA) ---
DATA_MOVEMENT_POLICY = (
    REPO_ROOT / "platform" / "mlsecops" / "data_movement" / "data_movement.rego"
)
FLOWS_JSON = (
    REPO_ROOT / "platform" / "mlsecops" / "data_movement" / "flows.json"
)

# Back-compat alias (in case any script references the old name)
DATA_MOVEMENT_FLOWS = FLOWS_JSON


def check_data_movement(src: str, dst: str, state: dict) -> dict:
    """
    Enforce Data Movement as Code.
    Returns {"allow": bool, "reason": str}
    """
    payload = {
        "from": src,
        "to": dst,
        "state": state or {}
    }

    # --- Windows-safe temp input file (avoid stdin "open -" issues) ---
    import tempfile, os
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tf:
        json.dump(payload, tf)
        tmp_path = tf.name

    # OPA v1 expects ONE query string
    query = "data.movement.allow; data.movement.reason"

    cmd = [
        OPA_BIN, "eval",
        "-d", str(DATA_MOVEMENT_POLICY),
        "-d", str(FLOWS_JSON),
        "--format", "json",
        query,
        "--input", tmp_path
    ]

    try:
        res = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            check=True
        )
        output = json.loads(res.stdout)

        # Defensive parse: if OPA returns undefined/empty, no "result" key
        if "result" not in output or not output["result"]:
            return {"allow": False, "reason": "OPA returned undefined result"}

        exprs = output["result"][0]["expressions"]
        allow_val = exprs[0]["value"]
        reason_val = exprs[1]["value"]
        return {"allow": allow_val, "reason": reason_val}

    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


OPA_DLP_POLICY = ROOT.parents[2] / "governance" / "policies_as_code" / "opa" / "dlp_runtime" / "dlp_runtime.rego"
OPA_DLP_DATA   = ROOT.parents[2] / "governance" / "policies_as_code" / "opa" / "dlp_runtime" / "dlp_runtime_data.json"

def evaluate_dlp_policy(direction: str, user_role: str, text: str, entities: list, classification_label: str, movement: dict, context=None):
    """
    direction: ingress|egress
    returns OPA decision dict {"action","reason","labels","entities"}
    """
    context = context or {"channel":"chat"}
    payload = {
        "direction": direction,
        "user": {"role": user_role},
        "text": text,
        "entities": entities,
        "classification_label": classification_label,
        "movement": movement,
        "context": context
    }

    cmd = [
        "opa","eval",
        "-d", str(OPA_DLP_POLICY),
        "-d", str(OPA_DLP_DATA),
        "--format","json",
        "data.dlp.runtime.decision",
        "--input","-"
    ]
    res = subprocess.run(cmd, input=json.dumps(payload), text=True, capture_output=True, check=True)
    out = json.loads(res.stdout)
    return out["result"][0]["expressions"][0]["value"]






