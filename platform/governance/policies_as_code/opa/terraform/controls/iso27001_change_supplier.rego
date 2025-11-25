# Used here to justify Terraform/CI enforcement + third-party scanner gating.
package terraform.controls.iso27001_change_supplier

control_id := {
  "iso27001": ["A.8.32", "A.5.19", "A.5.20"]
}
control_name := "ISO27001 Change Mgmt & Supplier Guardrails"

deny[msg] {
  # Immutable evidence bucket must have Object Lock enabled (if defined)
  r := input.resource_changes[_]
  r.type == "aws_s3_bucket_object_lock_configuration"
  r.change.after.object_lock_enabled != "Enabled"
  msg := sprintf("[%s] Evidence buckets require Object Lock enabled. Resource: %s",
    [control_id.iso27001[0], r.address])
}

deny[msg] {
  # Prevent disabling versioning on evidence buckets
  r := input.resource_changes[_]
  r.type == "aws_s3_bucket_versioning"
  r.change.after.versioning_configuration.status != "Enabled"
  msg := sprintf("[%s] Evidence buckets must keep versioning enabled. Resource: %s",
    [control_id.iso27001[0], r.address])
}
