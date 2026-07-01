variable "function_name" {
  type        = string
  description = "Lambda function name"
}

variable "source_url" {
  type        = string
  description = "URL to download the ayane-server Lambda zip package"
}

variable "source_sha512" {
  type        = string
  description = "SHA-512 checksum of the zip file. When provided, validated via postcondition"
  default     = null
}

variable "iam_role_arn" {
  type        = string
  description = "IAM role ARN for the Lambda function execution"
}

variable "architecture" {
  type        = string
  description = "Lambda function architecture. Must match the architecture the source_url zip was built for"
  default     = "arm64"

  validation {
    condition     = contains(["arm64", "x86_64"], var.architecture)
    error_message = "architecture must be one of: arm64, x86_64."
  }
}

variable "handler" {
  type        = string
  description = "provided.al2023 handler, i.e. the entry binary file name in the zip"
  default     = "bootstrap"
}

variable "memory_size" {
  type        = number
  description = "Lambda function memory in MB"
  default     = 256
}

variable "timeout" {
  type        = number
  description = "Lambda function timeout in seconds"
  default     = 30
}

variable "dynamodb_table_name" {
  type        = string
  description = "DynamoDB state table name. Holds the issued-certificate inventory, revocations, the token denylist, and the configuration document"
  default     = "ayane"
}

variable "create_dynamodb_table" {
  type        = bool
  description = "Create the DynamoDB state table. Set false to use a pre-existing table of dynamodb_table_name"
  default     = true
}

variable "config" {
  type        = any
  description = "ayane configuration as a Terraform object. Stored in the DynamoDB state table and loaded via the storage bootstrap (AYANE_BOOTSTRAP_STORAGE_CONFIG + AYANE_CONFIG_SHA256)"
}

variable "environment" {
  type        = map(string)
  description = "Additional environment variables. Merged with module-managed variables; user values take precedence on collision"
  default     = {}
}
