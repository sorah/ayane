output "function_arn" {
  value       = aws_lambda_function.this.arn
  description = "ARN of the deployed Lambda function"
}

output "function_name" {
  value       = aws_lambda_function.this.function_name
  description = "Name of the deployed Lambda function"
}

output "function_url" {
  value       = aws_lambda_function_url.this.function_url
  description = "Lambda function URL endpoint"
}

output "function_url_domain" {
  value       = replace(replace(aws_lambda_function_url.this.function_url, "https://", ""), "/", "")
  description = "Host of the Lambda function URL, for use as the cloudfront module origin_domain"
}

output "dynamodb_table_name" {
  value       = var.dynamodb_table_name
  description = "Name of the DynamoDB state table"
}

output "dynamodb_table_arn" {
  value       = var.create_dynamodb_table ? aws_dynamodb_table.table[0].arn : null
  description = "ARN of the DynamoDB state table, when created by this module"
}
