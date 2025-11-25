package dlp.behavior

violation["Unapproved medical diagnosis"] {
    contains(lower(input.model_output), "diagnose")
    not input.context.approved_medical_provider
}
