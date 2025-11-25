# You can clone that pattern for other modules. Super lightweight, still auditor-credible.
package terraform.controls.iso27001_access_test

import data.terraform.controls.iso27001_access.deny

test_blocks_iam_user {
  input := {"resource_changes":[{"type":"aws_iam_user","address":"aws_iam_user.bad","change":{"after":{"name":"bob"}}}]}
  deny[_] with input as input
}
