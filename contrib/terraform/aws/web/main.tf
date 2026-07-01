locals {
  source_hash = sha256("${var.source_url}${var.source_sha512}")

  # ayane expects base64url without padding; base64encode emits standard base64.
  bootstrap_storage_config = replace(replace(replace(base64encode(jsonencode({
    type       = "dynamodb"
    table_name = var.dynamodb_table_name
  })), "=", ""), "+", "-"), "/", "_")

  module_env_vars = {
    AYANE_BOOTSTRAP_STORAGE_CONFIG = local.bootstrap_storage_config
    AYANE_CONFIG_SHA256            = local.config_digest
  }
}

data "http" "source" {
  url = var.source_url

  lifecycle {
    postcondition {
      condition     = var.source_sha512 == null || sha512(self.response_body_base64) == var.source_sha512
      error_message = "SHA-512 checksum mismatch for source zip"
    }
  }
}

resource "local_file" "source" {
  filename       = "${path.module}/.terraform/source-${local.source_hash}.zip"
  content_base64 = sensitive(data.http.source.response_body_base64)
}

resource "aws_lambda_function" "this" {
  function_name    = var.function_name
  filename         = local_file.source.filename
  source_code_hash = local_file.source.content_sha256

  runtime       = "provided.al2023"
  handler       = var.handler
  architectures = [var.architecture]
  role          = var.iam_role_arn
  memory_size   = var.memory_size
  timeout       = var.timeout

  environment {
    variables = merge(local.module_env_vars, var.environment)
  }

  depends_on = [aws_dynamodb_table_item.config]
}

resource "aws_lambda_function_url" "this" {
  function_name      = aws_lambda_function.this.function_name
  authorization_type = "NONE"
}
