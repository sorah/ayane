locals {
  config_document = jsonencode(var.config)

  # ayane authenticates the configuration document by its base64url (no padding)
  # SHA-256 digest, which both keys the cache item (config:<digest>) and is pinned
  # via AYANE_CONFIG_SHA256. base64sha256 emits standard base64; rewrite to base64url.
  config_digest = replace(replace(replace(base64sha256(local.config_document), "=", ""), "+", "-"), "/", "_")
}

# The configuration document lives in the storage backend's cache under
# config:<digest>, which get_cache reads as pk = "cache:config:<digest>".
# Keyed by digest with create_before_destroy (the himari config.ru trick): a
# config change is a new key created before the function picks up the new
# AYANE_CONFIG_SHA256, and the old document is removed only after that.
# exp/ttl are far-future so the document is never reaped on read nor by TTL.
resource "aws_dynamodb_table_item" "config" {
  for_each = { (local.config_digest) = local.config_document }

  table_name = var.dynamodb_table_name
  hash_key   = "pk"
  range_key  = "sk"

  item = jsonencode({
    pk    = { S = "cache:config:${each.key}" }
    sk    = { S = "cache" }
    value = { B = base64encode(each.value) }
    exp   = { N = "4102444800" }
    ttl   = { N = "4102444800" }
  })

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [aws_dynamodb_table.table]
}
