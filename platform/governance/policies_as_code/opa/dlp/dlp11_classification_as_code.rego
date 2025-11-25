package dlp.taxonomy

violation["Unknown classification token"] {
    not input.entity_type == data.taxonomy.allowed[_]
}
