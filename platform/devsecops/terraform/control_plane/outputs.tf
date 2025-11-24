output "evidence_bucket" { value = aws_s3_bucket.evidence.bucket }
output "demo_bucket"     { value = aws_s3_bucket.demo.bucket }

output "data_owner_role_arn"  { value = aws_iam_role.data_owner.arn }
output "data_steward_role_arn"{ value = aws_iam_role.data_steward.arn }
output "rag_ingest_role_arn"  { value = aws_iam_role.rag_ingest.arn }
output "dlp_gateway_role_arn" { value = aws_iam_role.dlp_gateway.arn }
