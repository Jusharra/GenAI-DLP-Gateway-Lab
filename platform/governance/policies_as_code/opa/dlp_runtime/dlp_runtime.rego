package dlp.runtime

default decision := {
  "action": "allow",
  "reason": "no policy matched",
  "labels": [],
  "entities": []
}

# input schema
# input = {
#   "direction": "ingress|egress",
#   "user": {"role": "member|admin|professional|anonymous"},
#   "text": "...",
#   "entities": [{"type":"SSN","score":0.99}, ...],
#   "classification_label": "PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED_PII|RESTRICTED_PHI",
#   "movement": {"allow": true|false, "reason": "..."},
#   "context": {"channel":"chat|voice"}
# }

# -------------------------
# Decision chain (single complete rule)
# Priority order:
#   1) PHI hard block
#   2) Movement denied
#   3) High-risk PII block (role-aware)
#   4) Medium-risk PII mask (role-aware)
#   5) Egress + CONFIDENTIAL → mask
#   6) Ingress INTERNAL/CONFIDENTIAL/PUBLIC → allow
#   7) Fallback allow
# -------------------------

decision := out if {
  # 1) Hard block PHI always
  input.classification_label == "RESTRICTED_PHI"

  out := {
    "action": "block",
    "reason": "PHI detected: restricted by classification",
    "labels": [input.classification_label],
    "entities": input.entities
  }

} else := out if {
  # 2) Hard block if movement denied
  input.movement.allow == false

  out := {
    "action": "block",
    "reason": sprintf("data movement denied: %s", [input.movement.reason]),
    "labels": [input.classification_label],
    "entities": input.entities
  }

} else := out if {
  # 3) High-risk PII blocked unless admin
  some e in input.entities
  risk := data.pii_risk[e.type]
  risk == "high"
  not data.roles_allow_high[input.user.role]

  out := {
    "action": "block",
    "reason": sprintf("high-risk PII (%s) blocked for role %s", [e.type, input.user.role]),
    "labels": [input.classification_label],
    "entities": input.entities
  }

} else := out if {
  # 4) Medium-risk PII masked unless role permitted raw access
  some e in input.entities
  risk := data.pii_risk[e.type]
  risk == "medium"
  not data.roles_allow_medium[input.user.role]

  out := {
    "action": "mask",
    "reason": sprintf("medium-risk PII (%s) masked for role %s", [e.type, input.user.role]),
    "labels": [input.classification_label],
    "entities": input.entities
  }

} else := out if {
  # 5) Egress: never allow Confidential to leave raw; mask it
  input.direction == "egress"
  input.classification_label == "CONFIDENTIAL"

  out := {
    "action": "mask",
    "reason": "confidential output masked on egress",
    "labels": [input.classification_label],
    "entities": input.entities
  }

} else := out if {
  # 6) Ingress: allow Internal/Confidential/Public if movement allows
  input.direction == "ingress"
  input.classification_label in {"INTERNAL", "CONFIDENTIAL", "PUBLIC"}

  out := {
    "action": "allow",
    "reason": "classification allowed on ingress",
    "labels": [input.classification_label],
    "entities": input.entities
  }

} else := out if {
  # 7) Final fallback
  out := {
    "action": "allow",
    "reason": "no policy matched",
    "labels": [input.classification_label],
    "entities": input.entities
  }
}
