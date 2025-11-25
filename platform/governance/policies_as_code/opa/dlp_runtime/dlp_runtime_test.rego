package dlp.runtime

test_block_phi_always if {
  test_input := {
    "direction":"ingress",
    "user":{"role":"member"},
    "entities":[{"type":"MRN","score":0.9}],
    "classification_label":"RESTRICTED_PHI",
    "movement":{"allow":true,"reason":""}
  }

  decision := data.dlp.runtime.decision with input as test_input
  decision.action == "block"
}

test_block_high_risk_pii_for_member if {
  test_input := {
    "direction":"ingress",
    "user":{"role":"member"},
    "entities":[{"type":"SSN","score":0.99}],
    "classification_label":"RESTRICTED_PII",
    "movement":{"allow":true,"reason":""}
  }

  decision := data.dlp.runtime.decision with input as test_input
  decision.action == "block"
}

test_mask_medium_pii_for_member if {
  test_input := {
    "direction":"egress",
    "user":{"role":"member"},
    "entities":[{"type":"EMAIL_ADDRESS","score":0.95}],
    "classification_label":"RESTRICTED_PII",
    "movement":{"allow":true,"reason":""}
  }

  decision := data.dlp.runtime.decision with input as test_input
  decision.action == "mask"
}

test_allow_internal_ingress if {
  test_input := {
    "direction":"ingress",
    "user":{"role":"anonymous"},
    "entities":[],
    "classification_label":"INTERNAL",
    "movement":{"allow":true,"reason":""}
  }

  decision := data.dlp.runtime.decision with input as test_input
  decision.action == "allow"
}

test_block_when_movement_denied if {
  test_input := {
    "direction":"ingress",
    "user":{"role":"admin"},
    "entities":[],
    "classification_label":"PUBLIC",
    "movement":{"allow":false,"reason":"restricted PHI"}
  }

  decision := data.dlp.runtime.decision with input as test_input
  decision.action == "block"
}
