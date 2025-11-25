package dlp.enforcement

default allow = false

allow {
    input.opa_decisions[_].allow == true
}
