from dlp_utils import check_data_movement

def test_phi_never_to_pinecone():
    state = {"classification_label": "RESTRICTED_PHI", "redaction_applied": False}
    out = check_data_movement("rag_orchestrator", "pinecone", state)
    assert out["allow"] is False

def test_clean_prompt_to_llm_allowed():
    state = {"classification_label": "INTERNAL", "policy_decision": {"action": "allow"}, "redaction_applied": True}
    out = check_data_movement("rag_orchestrator", "llm", state)
    assert out["allow"] is True

def test_blocked_response_never_to_user():
    state = {"policy_decision": {"action": "block"}}
    out = check_data_movement("dlp_gateway", "user", state)
    assert out["allow"] is False
