import json
import logging
import os
from typing import Any, Dict, Optional

import boto3

from dlp_utils import (
    Decision,
    detect_pii,
    evaluate_policy,
    get_evidence_bucket_from_env,
    log_decision,
    safe_preview,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

lambda_client = boto3.client("lambda")

EVIDENCE_BUCKET = get_evidence_bucket_from_env()
RAG_LAMBDA_NAME = os.environ.get("RAG_LAMBDA_NAME", "")

if not RAG_LAMBDA_NAME:
    raise RuntimeError("RAG_LAMBDA_NAME environment variable is required")


def build_response(status_code: int, body: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def parse_body(event: Dict[str, Any]) -> Dict[str, Any]:
    raw_body: Optional[str] = event.get("body")
    if not raw_body:
        return {}
    try:
        return json.loads(raw_body)
    except (TypeError, ValueError):
        return {}


def lambda_handler(event, context):
    """
    API Gateway → DLP Filter.

    Expected request body:
      {
        "user_id": "123",
        "role": "analyst",
        "prompt": "User prompt..."
      }
    """
    logger.info(json.dumps({"event": "incoming_request", "raw_event": str(event)[:500]}))

    body = parse_body(event)
    prompt = body.get("prompt")
    role = body.get("role", "unknown")

    if not prompt:
        return build_response(400, {"error": "Missing 'prompt' in request body"})

    # 1) Detect PII/PHI in the prompt
    pii_findings = detect_pii(prompt)

    # 2) Evaluate policy for this role
    decision: Decision = evaluate_policy(role, pii_findings)

    # 3) Log decision as evidence
    decision_id = log_decision(
        stage="request",
        decision=decision,
        role=role,
        pii_findings=pii_findings,
        content_preview=safe_preview(prompt),
        evidence_bucket=EVIDENCE_BUCKET,
    )

    if decision == "block":
        logger.info(
            json.dumps(
                {
                    "event": "prompt_blocked",
                    "decision_id": decision_id,
                    "role": role,
                    "reason": "DLP policy",
                }
            )
        )
        return build_response(
            400,
            {
                "error": "Prompt blocked by DLP policy.",
                "decision_id": decision_id,
            },
        )

    # In a more advanced version, you'd mask PII here if decision == "mask".
    forward_payload = {
        "prompt": prompt,
        "user_role": role,
        "original_decision_id": decision_id,
    }

    try:
        invoke_resp = lambda_client.invoke(
            FunctionName=RAG_LAMBDA_NAME,
            InvocationType="RequestResponse",
            Payload=json.dumps(forward_payload).encode("utf-8"),
        )
    except Exception as exc:
        logger.exception("Failed to invoke RAG lambda")
        return build_response(
            500,
            {
                "error": "Internal error invoking RAG orchestrator.",
                "details": str(exc),
                "decision_id": decision_id,
            },
        )

    try:
        rag_payload = json.loads(invoke_resp["Payload"].read())
    except Exception:
        return build_response(
            500,
            {
                "error": "Invalid response from RAG orchestrator.",
                "decision_id": decision_id,
            },
        )

    # RAG lambda already returns a JSON-friendly structure
    return build_response(200, rag_payload)

from dlp_utils import detect_pii, classify_text, check_data_movement, evaluate_dlp_policy

def handle_ingress(prompt_text, user_role="anonymous"):
    entities = detect_pii(prompt_text)
    label = classify_text(entities)

    movement = check_data_movement(
        "dlp_gateway",
        "rag_orchestrator",
        {
            "classification_label": label,
            "policy_decision": {"action": "allow"},
            "redaction_applied": label not in {"RESTRICTED_PHI","RESTRICTED_PII"}
        }
    )

    decision = evaluate_dlp_policy(
        direction="ingress",
        user_role=user_role,
        text=prompt_text,
        entities=entities,
        classification_label=label,
        movement=movement
    )

    return decision, entities, label
