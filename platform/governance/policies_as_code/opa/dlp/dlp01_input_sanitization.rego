package dlp.input

default allow = false

violation[msg] {
    input.entities[_].type == "SSN"
    msg := "Restricted PII detected — SSN not allowed in prompts."
}

violation[msg] {
    input.entities[_].type == "MRN"
    msg := "PHI detected — blocking inference."
}

allow {
    not violation[_]
}
