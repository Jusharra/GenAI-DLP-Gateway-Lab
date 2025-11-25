package dlp.dataflow

violation["Unapproved data flow detected"] {
    not input.flow.allowed
}
