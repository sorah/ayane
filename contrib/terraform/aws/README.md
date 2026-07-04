# ayane on AWS Lambda — Terraform modules

Reusable Terraform modules to run [`ayane`](../../../docs/deployment.md) as an AWS
Lambda function behind a Lambda Function URL, optionally fronted by CloudFront.
`ayane-server` auto-detects Lambda mode at runtime, so the same binary that runs
standalone runs here unchanged.

Three independent modules, wired in dependency order:

| Module | Purpose |
| --- | --- |
| [`iam`](iam) | Lambda execution role with least-privilege policies for the configured backends (KMS signing, DynamoDB state, EventBridge audit, Lambda webhooks). |
| [`web`](web) | The `provided.al2023` Lambda function (downloaded from a release zip + SHA-512), the DynamoDB state table, and its Function URL. The configuration document is stored in DynamoDB and loaded via the storage bootstrap. |
| [`cloudfront`](cloudfront) | CloudFront distribution in front of the Function URL, for a stable custom domain and TLS. |

The KMS signing key is **not** created by these modules; create it out of band
(see [deployment docs](../../../docs/deployment.md)) and pass its ARN in. The
DynamoDB state table is created by the `web` module.

## Usage

```hcl
module "ayane_iam" {
  source = "github.com/sorah/ayane//contrib/terraform/aws/iam"

  role_name           = "AyaneLambda"
  kms_key_arns        = ["arn:aws:kms:us-east-1:111122223333:key/abcd1234-..."]
  dynamodb_table_name = "ayane-state"
}

module "ayane_web" {
  source = "github.com/sorah/ayane//contrib/terraform/aws/web"

  function_name       = "ayane"
  source_url          = "https://github.com/sorah/ayane/releases/download/vX.Y.Z/ayane-server-aarch64.zip"
  source_sha512       = "..." # hex SHA-512 of the zip
  iam_role_arn        = module.ayane_iam.role_arn
  dynamodb_table_name = "ayane-state"

  # config is a native Terraform object. The module stores it in DynamoDB and
  # points the function at it via the storage bootstrap. server.external_url MUST
  # match the public URL clients reach (the CloudFront/custom domain) so OTT `aud`
  # and DPoP `htu` validate.
  config = {
    ca = {
      certificate = { file = "ca/intermediate.crt" }
      key = {
        type      = "aws_kms"
        key_id    = "alias/ayane-intermediate"
        algorithm = "ECDSA_SHA256"
      }
      chain = [{ file = "ca/intermediate.crt" }]
      roots = [{ file = "ca/root.crt" }]
    }
    storage = { type = "dynamodb", table_name = "ayane-state" }
    server  = { external_url = "https://ca.example.com" }
  }
}

module "ayane_cloudfront" {
  source = "github.com/sorah/ayane//contrib/terraform/aws/cloudfront"

  origin_domain       = module.ayane_web.function_url_domain
  alias               = "ca.example.com"
  acm_certificate_arn = "arn:aws:acm:us-east-1:111122223333:certificate/..."
}
```

The `ca/*.crt` paths are resolved relative to the function's working directory, so
the certificate/chain/root files must be bundled into the Lambda zip. To avoid
bundling files, use a KMS key for `ca.key` and inline the certificate/chain/root
PEM in the config instead of `file` references.

## Configuration delivery

The `web` module always keeps the configuration document in the DynamoDB state
table and points the function at it via the
[storage bootstrap](../../../docs/deployment.md#configuration-in-storage):

- **`config`** — the whole configuration as a Terraform object. The module
  `jsonencode`s it, writes it to the state table's cache under `config:<digest>`
  (a far-future expiry so it is never reaped), and sets `AYANE_BOOTSTRAP_STORAGE_CONFIG`
  + `AYANE_CONFIG_SHA256` so the function loads and authenticates it. `<digest>`
  is the base64url (no padding) SHA-256 of the document. Following the himari
  `config.ru` pattern, the cache item is keyed by digest with
  `create_before_destroy`, so a config change publishes the new document before
  the function switches over and removes the old one only afterwards.
- **`environment`** — an escape hatch map merged last (caller wins on collision),
  for any other env var (e.g. `RUST_LOG`).

## Notes

- The Function URL is `authorization_type = "NONE"`, so the raw Function URL is
  publicly reachable alongside CloudFront. Set `server.external_url` to your public
  domain so audiences are validated against it regardless of entry point.
- `architecture` defaults to `arm64`; point `source_url` at a matching build.
- `source_sha512`, when set, is enforced as a plan-time postcondition.
