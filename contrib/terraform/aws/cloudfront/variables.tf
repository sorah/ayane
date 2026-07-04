variable "origin_domain" {
  type        = string
  description = "Origin host to forward to, i.e. the web module's function_url_domain"
}

variable "alias" {
  type        = string
  description = "Alternate domain name (CNAME) for the distribution"
}

variable "acm_certificate_arn" {
  type        = string
  description = "ACM certificate ARN (must be in us-east-1) covering the alias"
}

variable "price_class" {
  type        = string
  description = "CloudFront price class"
  default     = "PriceClass_100"
}

variable "minimum_protocol_version" {
  type        = string
  description = "Minimum TLS version the distribution enforces for viewer connections"
  default     = "TLSv1.3_2025"
}

variable "comment" {
  type        = string
  description = "Comment for the distribution"
  default     = "ayane"
}
