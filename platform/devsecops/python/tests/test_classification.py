import json
import dlp_utils

def fake_opa_run(cmd, input, text, capture_output, check):
    payload = json.loads(input)
    entities = payload["entities"]

    # simple deterministic behavior matching your Rego:
    if any(e["type"] == "SSN" for e in entities):
        label = "restricted_pii"
    elif any(e["type"] == "MRN" for e in entities):
        label = "phi"
    else:
        label = "internal"

    class Res:
        stdout = json.dumps({
            "result": [{
                "expressions": [{"value": label}]
            }]
        })
    return Res()

def test_classifies_ssn_as_restricted_pii(monkeypatch):
    monkeypatch.setattr(dlp_utils.subprocess, "run", fake_opa_run)
    entities = [{"type": "SSN", "score": 0.99}]
    assert dlp_utils.classify_text(entities) == "restricted_pii"

def test_no_entities_defaults_to_internal(monkeypatch):
    monkeypatch.setattr(dlp_utils.subprocess, "run", fake_opa_run)
    assert dlp_utils.classify_text([]) == "internal"

def test_health_entities_map_to_phi(monkeypatch):
    monkeypatch.setattr(dlp_utils.subprocess, "run", fake_opa_run)
    entities = [{"type": "MRN", "score": 0.95}]
    assert dlp_utils.classify_text(entities) == "phi"

