package dlp.output

violation["Sensitive data leaked in LLM output"] {
    re_match("[0-9]{3}-[0-9]{2}-[0-9]{4}", input.model_output)
}
