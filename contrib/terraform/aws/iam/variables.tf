variable "role_name" {
  type        = string
  description = "IAM role name to create"
}

variable "role_description" {
  type        = string
  description = "IAM role description"
  default     = "sorah/ayane lambda execution role"
}

variable "role_permissions_boundary" {
  type        = string
  description = "IAM role permissions boundary ARN"
  default     = null
}

variable "kms_key_arns" {
  type        = set(string)
  description = "KMS key ARNs of the CA signing key(s). Grants kms:Sign and kms:GetPublicKey"
  default     = []
}

variable "dynamodb_table_arn" {
  type        = string
  description = "DynamoDB state table ARN. Takes precedence over dynamodb_table_name"
  default     = null
}

variable "dynamodb_table_name" {
  type        = string
  description = "DynamoDB state table name, used to derive the ARN when dynamodb_table_arn is unset"
  default     = null
}

variable "event_bus_arns" {
  type        = set(string)
  description = "EventBridge event bus ARNs for audit events. Grants events:PutEvents"
  default     = []
}

variable "webhook_function_arns" {
  type        = set(string)
  description = "Lambda function ARNs invoked as issuance webhooks. Grants lambda:InvokeFunction"
  default     = []
}

locals {
  dynamodb_table_arn = var.dynamodb_table_arn != null ? var.dynamodb_table_arn : (
    var.dynamodb_table_name != null ? "arn:aws:dynamodb:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:table/${var.dynamodb_table_name}" : null
  )
}
