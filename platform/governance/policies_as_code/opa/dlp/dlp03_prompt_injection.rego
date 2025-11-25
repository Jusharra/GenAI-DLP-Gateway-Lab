package dlp.prompt_injection

patterns := [
  "ignore previous instructions",
  "override system",
  "jailbreak",
  "forget rules",
  "act as"
]

violation[msg] {
    pattern := patterns[_]
    contains(lower(input.prompt), pattern)
    msg := sprintf("Prompt injection attempt detected: %v", [pattern])
}
