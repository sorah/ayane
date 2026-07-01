output "distribution_domain_name" {
  value       = aws_cloudfront_distribution.ayane.domain_name
  description = "Domain name of the CloudFront distribution"
}

output "distribution_id" {
  value       = aws_cloudfront_distribution.ayane.id
  description = "ID of the CloudFront distribution"
}

output "distribution_arn" {
  value       = aws_cloudfront_distribution.ayane.arn
  description = "ARN of the CloudFront distribution"
}

output "distribution_hosted_zone_id" {
  value       = aws_cloudfront_distribution.ayane.hosted_zone_id
  description = "Route 53 hosted zone ID for the distribution, for alias records"
}
