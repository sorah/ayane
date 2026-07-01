resource "aws_iam_role" "role" {
  name                 = var.role_name
  description          = var.role_description
  assume_role_policy   = data.aws_iam_policy_document.role-trust.json
  permissions_boundary = var.role_permissions_boundary
}

data "aws_iam_policy_document" "role-trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "role-AWSLambdaBasicExecutionRole" {
  role       = aws_iam_role.role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "role-kms" {
  count  = length(var.kms_key_arns) > 0 ? 1 : 0
  role   = aws_iam_role.role.name
  policy = data.aws_iam_policy_document.role-kms.json
}

data "aws_iam_policy_document" "role-kms" {
  statement {
    effect = "Allow"
    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
    ]
    resources = toset(var.kms_key_arns)
  }
}

resource "aws_iam_role_policy" "role-dynamodb" {
  count  = local.dynamodb_table_arn != null ? 1 : 0
  role   = aws_iam_role.role.name
  policy = data.aws_iam_policy_document.role-dynamodb.json
}

data "aws_iam_policy_document" "role-dynamodb" {
  statement {
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:Query",
    ]
    resources = [
      local.dynamodb_table_arn,
      "${local.dynamodb_table_arn}/index/inverted",
    ]
  }
}

resource "aws_iam_role_policy" "role-events" {
  count  = length(var.event_bus_arns) > 0 ? 1 : 0
  role   = aws_iam_role.role.name
  policy = data.aws_iam_policy_document.role-events.json
}

data "aws_iam_policy_document" "role-events" {
  statement {
    effect    = "Allow"
    actions   = ["events:PutEvents"]
    resources = toset(var.event_bus_arns)
  }
}

resource "aws_iam_role_policy" "role-webhook" {
  count  = length(var.webhook_function_arns) > 0 ? 1 : 0
  role   = aws_iam_role.role.name
  policy = data.aws_iam_policy_document.role-webhook.json
}

data "aws_iam_policy_document" "role-webhook" {
  statement {
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = toset(var.webhook_function_arns)
  }
}
