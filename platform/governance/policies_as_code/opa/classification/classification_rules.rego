package classification.rules

# Default when nothing matches
default label := "INTERNAL"

# Collect entity types from the input
entity_types := {e.type |
  input.entities != null
  e := input.entities[_]
}

has(t) if {
  t in entity_types
}

# --- Restricted PII ---
label = "RESTRICTED_PII" if {
  has("SSN")
} else if {
  has("DL")
} else if {
  has("PASSPORT")
} else if {
  has("BANK_ACCOUNT")
} else if {
  has("CREDIT_CARD")
}

# --- PHI (Healthcare) ---
label = "PHI" if {
  has("MRN")
} else if {
  has("MEDICAL_RECORD")
} else if {
  has("ICD10")
} else if {
  has("HEALTH_PLAN_BENEFICIARY")
} else if {
  has("PRESCRIPTION")
}

# --- Confidential (lower sensitivity PII) ---
label = "CONFIDENTIAL_PII" if {
  has("EMAIL")
} else if {
  has("PHONE_NUMBER")
} else if {
  has("ADDRESS")
} else if {
  has("DOB")
}
