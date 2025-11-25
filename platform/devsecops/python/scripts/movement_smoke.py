import sys
import os
import json
from pathlib import Path

# Ensure python dir is on path BEFORE import
CURRENT_FILE = Path(__file__).resolve()
PYTHON_DIR = CURRENT_FILE.parents[1]  # platform/devsecops/python
sys.path.insert(0, str(PYTHON_DIR))

from dlp_utils import check_data_movement

cases = [
    ("rag_orchestrator","pinecone", {"classification_label":"RESTRICTED_PHI","redaction_applied":False}),
    ("rag_orchestrator","pinecone", {"classification_label":"RESTRICTED_PII","redaction_applied":False}),
    ("rag_orchestrator","llm", {"classification_label":"INTERNAL","policy_decision":{"action":"allow"}, "redaction_applied":True}),
    ("dlp_gateway","user", {"policy_decision":{"action":"block"}}),
]

for src, dst, st in cases:
    try:
        result = check_data_movement(src, dst, st)
        print(f"{src} → {dst} = {json.dumps(result)}")
    except Exception as e:
        print(f"{src} → {dst} ERROR:")
        print(str(e))
