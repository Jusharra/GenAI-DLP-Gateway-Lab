# dlp_utils.py
import os
import re
import json
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]

DATA_MOVEMENT_REGO = REPO_ROOT / "platform" / "mlsecops" / "data_movement" / "data_movement.rego"
FLOWS_JSON = REPO_ROOT / "platform" / "mlsecops" / "data_movement" / "flows.json"


# ------------------------------------------------------------------------------------
# 1. Entity detection + classification
# ------------------------------------------------------------------------------------

def detect_entities(text: str) -> List[Dict[str, Any]]:
    """
    Ultra-simple detector for demo purposes.
    We tag some common PII/PHI-style patterns.
    """
    entities: List[Dict[str, Any]] = []
    lowered = text.lower()

    # SSN pattern: 123-45-6789
    ssn_match = re.search(r"\b\d{3}-\d{2}-\d{4}\b", text)
    if ssn_match:
        entities.append({"type": "SSN", "value": ssn_match.group(0), "score": 0.99})

    # US routing number (9 digits) when "routing" mentioned nearby
    routing_match = re.search(r"routing (number )?(\d{9})", lowered)
    if routing_match:
        entities.append(
            {"type": "ROUTING", "value": routing_match.group(2), "score": 0.98}
        )

    # Passport-like token when "passport" appears
    passport_match = re.search(r"passport.*?\b([A-Z0-9]{6,10})\b", text, re.IGNORECASE)
    if passport_match:
        entities.append(
            {"type": "PASSPORT", "value": passport_match.group(1), "score": 0.97}
        )

    # Medical-ish hints → very crude MRN/PHI marker
    if re.search(r"\bmrn\b", lowered):
        entities.append({"type": "MRN", "value": "unknown", "score": 0.99})

    if re.search(
        r"\b(patient|diagnosis|diagnosed|medication|strep|test(ed)? positive)\b",
        lowered,
    ):
        entities.append({"type": "PHI_HINT", "value": "medical_context", "score": 0.9})

    return entities


# --- simple detectors (tight enough for a demo, not toy “random” flags) ---

SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
ROUTING_RE = re.compile(r"\b\d{9}\b")
MRN_RE = re.compile(r"\bMRN[:\s]*\d+\b", re.IGNORECASE)

def classify_text(text: str) -> Dict[str, Any]:
    """
    Classify text into INTERNAL / RESTRICTED_PII / RESTRICTED_PHI
    and return detected entities.

    Returns:
        {
          "label": <str>,
          "entities": [ { "type", "value", "score" }, ... ]
        }
    """
    # Fresh state on every call – no leakage between prompts.
    entities: List[Dict[str, Any]] = []

    t = text.strip()
    lower = t.lower()

    # ---- PII: SSN ----
    for m in SSN_RE.finditer(t):
        entities.append(
            {"type": "SSN", "value": m.group(0), "score": 0.99}
        )

    # ---- PII: routing number (only if context says “routing”/“aba”) ----
    for m in ROUTING_RE.finditer(t):
        window = lower[max(0, m.start() - 25): m.end() + 25]
        if "routing" in window or "aba" in window:
            entities.append(
                {"type": "ROUTING", "value": m.group(0), "score": 0.98}
            )

    # ---- PII: passport (rough but deterministic) ----
    if "passport" in lower:
        tokens = t.split()
        for i, tok in enumerate(tokens):
            if tok.lower().startswith("passport"):
                if i + 1 < len(tokens):
                    candidate = tokens[i + 1].strip(",. ")
                    if 5 <= len(candidate) <= 12:
                        entities.append(
                            {
                                "type": "PASSPORT",
                                "value": candidate,
                                "score": 0.90,
                            }
                        )
                break

    # ---- PHI: MRN + general medical context ----
    for m in MRN_RE.finditer(t):
        entities.append(
            {"type": "MRN", "value": m.group(0), "score": 0.95}
        )

    if any(
        kw in lower
        for kw in [
            "patient",
            "diagnosed",
            "diagnosis",
            "tested positive",
            "test came back",
            "prescription",
            "medications",
            "medical history",
        ]
    ):
        entities.append(
            {"type": "PHI_HINT", "value": "medical_context", "score": 0.90}
        )

    # ---- label decision logic ----
    label = "INTERNAL"  # default – no sensitive data

    # PHI has highest sensitivity
    if any(e["type"] in ("MRN", "PHI_HINT") for e in entities):
        label = "RESTRICTED_PHI"
    # PII next
    elif any(e["type"] in ("SSN", "ROUTING", "PASSPORT") for e in entities):
        label = "RESTRICTED_PII"

    return {
        "label": label,
        "entities": entities,
    }

# ------------------------------------------------------------------------------------
# 2. OPA bridge
# ------------------------------------------------------------------------------------

def _run_opa(input_payload: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Runtime evaluator for data-movement policies, aligned with flows.json.

    We *mirror* the Rego logic in Python for the demo instead of shelling out
    to the OPA binary. OPA is still used in CI/CD (opa test), but the UI
    uses this function for stability.

    input_payload = {
      "from": "user|dlp_gateway|rag_orchestrator|llm|pinecone|evidence_s3",
      "to":   "...",
      "state": {
          "classification_label": "INTERNAL|RESTRICTED_PII|RESTRICTED_PHI|PUBLIC",
          "policy_decision": {"action": "allow|mask|block"},
          "redaction_applied": bool
      }
    }

    Returns: (allow: bool, reason: str)
    """
    # -----------------------------
    # 1) Load flows.json once
    # -----------------------------
    try:
        with FLOWS_JSON.open("r", encoding="utf-8") as f:
            flows_doc = json.load(f)
    except FileNotFoundError:
        return False, "policy files missing: flows.json not found"
    except Exception as e:
        return False, f"failed to load flows.json: {e}"

    # flows.json is expected as:
    # { "flows": [ { id, from, to, allowed, conditions? }, ... ] }
    flows = flows_doc.get("flows", [])
    if not isinstance(flows, list):
        return False, "invalid flows.json structure: 'flows' must be a list"

    src = input_payload.get("from")
    dst = input_payload.get("to")
    state = input_payload.get("state") or {}

    label = state.get("classification_label", "INTERNAL")
    action = (state.get("policy_decision") or {}).get("action", "allow")
    redacted = bool(state.get("redaction_applied", False))

    # -----------------------------
    # 2) Special-case: RAG → LLM
    # -----------------------------
    if src == "rag_orchestrator" and dst == "llm":
        if label not in {"RESTRICTED_PII", "RESTRICTED_PHI"} and action in {
            "allow",
            "mask",
        }:
            return True, (
                f"rag_orchestrator → llm allowed "
                f"(label={label}, action={action})"
            )
        else:
            return False, (
                f"rag_orchestrator → llm blocked due to label/action "
                f"(label={label}, action={action})"
            )

    # -----------------------------
    # 3) Generic flow matching
    # -----------------------------
    matching_flows = [
        f for f in flows if f.get("from") == src and f.get("to") == dst
    ]

    if not matching_flows:
        return False, "no matching flow definition in policy"

    # Evaluate each matching flow until one is clearly allowed/denied
    for f in matching_flows:
        fid = f.get("id", "<unknown>")
        allowed_flag = bool(f.get("allowed", False))
        conds = f.get("conditions")

        # If no conditions, we just respect allowed_flag
        if not conds:
            if allowed_flag:
                return True, f"flow {fid} allowed (no additional conditions)"
            else:
                return False, f"flow {fid} explicitly denied (no additional conditions)"

        # Evaluate conditions (mirror Rego semantics)
        violated = _flow_violations(conds, label, action, redacted)
        if violated:
            return (
                False,
                f"flow {fid} denied: {violated}",
            )

        # All conditions pass
        if allowed_flag:
            return True, f"flow {fid} allowed (conditions satisfied)"
        else:
            return False, f"flow {fid} denied (allowed=false despite conditions passing)"

    # If we somehow got here, be safe and deny with a reason
    return False, "no matching flow after evaluation"


def _flow_violations(
    conds: List[str],
    label: str,
    action: str,
    redacted: bool,
) -> str | None:
    """
    Mirror the condition strings used in flows.json, similar to Rego:

      - 'classification_label not_in [RESTRICTED_PII, RESTRICTED_PHI]'
      - 'policy_decision.action in [allow,mask]'
      - 'redaction_applied == true'

    Returns the first violated condition as a string, or None if all pass.
    """
    for c in conds or []:
        c = c.strip()

        # classification_label not_in [A, B, C]
        if c.startswith("classification_label not_in"):
            labels = _parse_list(c)
            if label in labels:
                return c

        # policy_decision.action in [allow,mask]
        elif c.startswith("policy_decision.action in"):
            actions = _parse_list(c)
            if action not in actions:
                return c

        # redaction_applied == true
        elif c == "redaction_applied == true":
            if not redacted:
                return c

        # Unknown condition → treat as non-fatal (don't violate) so demo doesn't break
        else:
            continue

    return None


def _parse_list(cond: str) -> List[str]:
    """
    Parse things like:

      'classification_label not_in [RESTRICTED_PII, RESTRICTED_PHI]'
      'policy_decision.action in [allow,mask]'

    into ['RESTRICTED_PII', 'RESTRICTED_PHI'] or ['allow', 'mask'].
    """
    start = cond.find("[")
    end = cond.find("]")
    if start == -1 or end == -1 or end <= start:
        return []

    inner = cond[start + 1 : end]
    parts = [p.strip() for p in inner.split(",") if p.strip()]
    return parts



# ------------------------------------------------------------------------------------
# 3. Hop evaluation used by Streamlit app
# ------------------------------------------------------------------------------------

def _policy_decision_for_label(label: str) -> Dict[str, Any]:
    """
    Simple "DLP decision" based on label to feed into OPA state.
    """
    if label in {"RESTRICTED_PII", "RESTRICTED_PHI"}:
        action = "block"
    else:
        action = "allow"

    return {
        "action": action,
    }


def _build_state(label: str, entities: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "classification_label": label,
        "policy_decision": _policy_decision_for_label(label),
        # For now, we aren't actually redacting text – just simulating
        "redaction_applied": False,
        "entities": entities,
    }


def check_data_movement(prompt: str) -> Dict[str, Any]:
    """
    Main function called by Streamlit.

    Returns:
    {
      "hops": [
        {
          "from": "...",
          "to": "...",
          "allow": bool,
          "reason": "..."
        },
        ...
      ],
      "blocked": bool  # True if ANY hop is denied
    }
    """
    classification = classify_text(prompt)
    label = classification["label"]
    entities = classification["entities"]
    state = _build_state(label, entities)

    hops = [
        ("user", "dlp_gateway"),
        ("dlp_gateway", "rag_orchestrator"),
        ("rag_orchestrator", "pinecone"),
    ]

    hop_results: List[Dict[str, Any]] = []
    blocked = False

    for frm, to in hops:
        payload = {
            "from": frm,
            "to": to,
            "state": state,
        }
        allow, reason = _run_opa(payload)
        hop_results.append(
            {
                "from": frm,
                "to": to,
                "allow": allow,
                "reason": reason,
            }
        )
        if not allow:
            blocked = True

    return {
        "classification": classification,
        "hops": hop_results,
        "blocked": blocked,
    }
