output "dlp_api_url" {
  description = "Invoke URL for the DLP API Gateway"
  value       = aws_apigatewayv2_api.dlp_api.api_endpoint
}

output "evidence_bucket_name" {
  description = "Evidence S3 bucket name"
  value       = aws_s3_bucket.evidence.bucket
}

output "dlp_lambda_arn" {
  description = "DLP filter Lambda ARN"
  value       = aws_lambda_function.dlp_filter.arn
}

output "rag_lambda_arn" {
  description = "RAG orchestrator Lambda ARN"
  value       = aws_lambda_function.rag_orchestrator.arn
}

