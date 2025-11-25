import json
import logging
import os
from typing import Any, Dict, Optional

import boto3
import pinecone

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

EVIDENCE_BUCKET = get_evidence_bucket_from_env()

PINECONE_API_KEY = os.environ.get("PINECONE_API_KEY")
PINECONE_ENV = os.environ.get("PINECONE_ENVIRONMENT")
PINECONE_INDEX_NAME = os.environ.get("PINECONE_INDEX_NAME")
MODEL_ID = os.environ.get("MODEL_ID", "stub-model")

# Bedrock client (can be stubbed if you don't have Bedrock)
bedrock = boto3.client(
    "bedrock-runtime",
    region_name=os.environ.get("AWS_REGION", "us-east-1"),
)

# Initialize Pinecone (lab-friendly; in prod you'd handle errors more strictly)
if PINECONE_API_KEY and PINECONE_ENV and PINECONE_INDEX_NAME:
    pinecone.init(api_key=PINECONE_API_KEY, environment=PINECONE_ENV)
    pinecone_index = pinecone.Index(PINECONE_INDEX_NAME)
else:
    pinecone_index = None
    logger.warning("Pinecone environment variables not fully set; RAG will use empty context.")


def retrieve_context(prompt: str) -> str:
    """
    RAG context retrieval: queries Pinecone by a dummy vector in this lab.

    PRODUCTION NOTE:
      Replace with real embedding generation and vector query.
    """
    if pinecone_index is None:
        return ""

    dummy_vector = [0.0] * 16  # dimension must match index; for demo only

    try:
        results = pinecone_index.query(vector=dummy_vector, top_k=3, include_metadata=True)
    except Exception as exc:
        logger.warning("Pinecone query failed: %s", exc)
        return ""

    matches = results.get("matches") or []
    snippets = []

    for m in matches:
        metadata = m.get("metadata") or {}
        text = metadata.get("text")
        if text:
            snippets.append(text)

    return "\n---\n".join(snippets)


def call_llm(prompt: str, context_text: str) -> str:
    """
    Calls Bedrock or returns a stubbed answer if MODEL_ID == 'stub-model'.
    """
    if MODEL_ID == "stub-model":
        return f"[STUBBED ANSWER]\n\nContext:\n{context_text}\n\nPrompt:\n{prompt}"

    body = {
        "prompt": f"Context:\n{context_text}\n\nUser prompt:\n{prompt}",
        "temperature": 0.2,
        "max_tokens": 512,
    }

    try:
        resp = bedrock.invoke_model(modelId=MODEL_ID, body=json.dumps(body))
        raw = resp["body"].read()
        data = json.loads(raw)
    except Exception as exc:
        logger.exception("Bedrock invocation failed: %s", exc)
        return f"[ERROR CALLING MODEL]: {exc}"

    # Adjust based on model output schema; generic fallback here
    return data.get("output_text") or json.dumps(data)

def handle_egress(response_text, user_role="anonymous"):
    entities = detect_pii(response_text)
    label = classify_text(entities)

    movement = check_data_movement(
        "dlp_gateway",
        "user",
        {
            "classification_label": label,
            "policy_decision": {"action": "allow"},
            "redaction_applied": True
        }
    )

    decision = evaluate_dlp_policy(
        direction="egress",
        user_role=user_role,
        text=response_text,
        entities=entities,
        classification_label=label,
        movement=movement
    )

    return decision, entities, label


def lambda_handler(event, context):
    """
    Invoked by DLP Lambda.

    Expected event:
      {
        "prompt": "...",
        "user_role": "...",
        "original_decision_id": "..."
      }
    """
    logger.info(json.dumps({"event": "rag_invoke", "payload_preview": str(event)[:300]}))

    prompt: Optional[str] = event.get("prompt")
    role: str = event.get("user_role", "unknown")

    if not prompt:
        return {"error": "Missing 'prompt' in event payload"}

    # 1) Retrieve context from Pinecone (RAG)
    context_text = retrieve_context(prompt)

    # 2) Call LLM (Bedrock or stub)
    answer = call_llm(prompt, context_text)

    # 3) DLP on response
    pii_findings = detect_pii(answer)
    decision: Decision = evaluate_policy(role, pii_findings)

    # 4) Log DLP decision on response
    decision_id = log_decision(
        stage="response",
        decision=decision,
        role=role,
        pii_findings=pii_findings,
        content_preview=safe_preview(answer),
        evidence_bucket=EVIDENCE_BUCKET,
    )

    if decision == "block":
        safe_answer = "Response blocked by DLP policy."
    elif decision == "mask":
        safe_answer = "[PII REDACTED] " + answer
    else:
        safe_answer = answer

    return {
        "answer": safe_answer,
        "decision_id": decision_id,
        "role": role,
    }
