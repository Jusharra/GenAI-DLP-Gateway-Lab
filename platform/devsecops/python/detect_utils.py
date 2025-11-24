import re

def detect_entities(text: str):
    entities = []

    # SSN-ish patterns
    if re.search(r"\b\d{3}-\d{2}-\d{4}\b", text):
        entities.append({"type": "SSN", "score": 0.99})

    # MRN-ish patterns (super naive demo)
    if re.search(r"\bMRN\s*\d+\b", text, flags=re.I):
        entities.append({"type": "MRN", "score": 0.95})

    # Address-ish patterns (naive)
    if re.search(r"\b\d+\s+\w+\s+(Blvd|St|Ave|Rd|Drive|Dr)\b", text, flags=re.I):
        entities.append({"type": "ADDRESS", "score": 0.9})

    return entities
