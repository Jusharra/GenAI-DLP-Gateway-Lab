package dlp.agentic

violation["Unauthorized agentic action"] {
    input.agent_action == "api_call"
    not input.permissions.allow_api
}
