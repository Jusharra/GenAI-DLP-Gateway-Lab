import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Ensure parent (python dir) is on sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dlp_utils import classify_text, detect_entities

load_dotenv()


samples = [
    "My name is Sarah Johnson and my SSN is 555-22-1234.",
    "Meeting tomorrow to discuss quarterly revenue growth.",
    "John Doe lives at 500 Sunset Blvd, Los Angeles.",
    "The patient was diagnosed with hypertension and prescribed medication.",
    "Schedule a limo in LA tomorrow.",
    "My SSN is 123-45-6789.",
    "Patient MRN 998877, chest pain since 3am."
]

for s in samples:
    entities = detect_entities(s)          # <-- detect first
    result   = classify_text(entities)     # <-- THEN classify

    print("\n--- SAMPLE ---")
    print(s)
    print("--- ENTITIES ---")
    print(json.dumps(entities, indent=2))
    print("--- RESULT ---")
    print(json.dumps(result, indent=2))
