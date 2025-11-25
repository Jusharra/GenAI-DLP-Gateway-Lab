package dlp.evidence

violation["Missing evidence field"] {
    f := ["opa_decision", "classification", "raw_prompt"][_]
    not input.evidence[f]
}
