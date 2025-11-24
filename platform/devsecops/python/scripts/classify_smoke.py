import json
from dlp_utils import classify_text
from detect_utils import detect_entities   # <-- make sure this is here!

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
