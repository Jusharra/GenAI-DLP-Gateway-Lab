package dlp.training

violation["Untrusted data source"] {
    not input.source in data.trusted_sources
}
