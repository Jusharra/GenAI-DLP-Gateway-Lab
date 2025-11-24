import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]   # python dir
sys.path.insert(0, str(ROOT))

from dlp_utils import check_data_movement


cases = [
    ("rag_orchestrator","pinecone", {"classification_label":"RESTRICTED_PHI","redaction_applied":False}),
    ("rag_orchestrator","pinecone", {"classification_label":"RESTRICTED_PII","redaction_applied":False}),
    ("rag_orchestrator","llm", {"classification_label":"INTERNAL","policy_decision":{"action":"allow"}, "redaction_applied":True}),
    ("dlp_gateway","user", {"policy_decision":{"action":"block"}}),
]

for src, dst, st in cases:
    print(src,"→",dst, check_data_movement(src,dst,st))
