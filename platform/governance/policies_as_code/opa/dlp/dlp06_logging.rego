package dlp.logging

required_fields := ["timestamp", "user", "action", "decision", "classification"]

violation[f] {
    f := required_fields[_]
    not input.log[f]
}
