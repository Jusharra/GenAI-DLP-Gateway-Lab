package dlp.rag_acl

default allow = false

allow {
    input.user_role == data.roles.allowed[input.embedding.record_type]
}
