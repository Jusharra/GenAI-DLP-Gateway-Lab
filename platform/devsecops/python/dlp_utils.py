import json
import logging
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")

Decision = Literal["allow", "block", "mask"]


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
