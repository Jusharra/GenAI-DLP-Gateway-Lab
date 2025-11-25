package dlp.classification

class = output {
    some e
    e := input.entities[_]

    e.type == "SSN"        => output := "RESTRICTED_PII"
    e.type == "MRN"        => output := "PHI"
    e.type == "ADDRESS"    => output := "MODERATE_PII"
    else                   => output := "INTERNAL"
}
