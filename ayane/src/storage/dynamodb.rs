//! AWS DynamoDB [`Storage`](crate::storage::Storage) implementation.
//!
//! A single table holds all three concerns under a composite primary key — a
//! string partition key `pk` and a string sort key `sk`:
//!
//! - issued certificates: `pk = "certificate:{serial}"`, `sk = "cn:{common_name}"`,
//!   carrying the full leaf PEM and its metadata (no TTL — a permanent
//!   inventory). The CN-bearing `sk` groups every serial issued for a common
//!   name under one partition of the inverted index. Because `sk` is no longer a
//!   fixed value, a by-serial lookup queries the base table on `pk` (unique per
//!   serial) rather than issuing a `GetItem`, which would require the full key.
//! - revocations: `pk = "revocation:{serial}"`, `sk = "revocation"`
//! - one-time token ids: `pk = "token:{jti}"`, `sk = "token"`, plus a numeric
//!   `ttl` attribute (epoch seconds) so DynamoDB's TTL feature reaps expired
//!   claims. The `ttl` is set a [`TTL_BUFFER`] beyond the claim's real expiry so
//!   DynamoDB's lazy deletion never removes a still-relevant denylist entry.
//!
//! Listing revocations (e.g. to assemble a CRL) is served by an inverted global
//! secondary index [`INVERTED_INDEX`] whose partition key is the table's `sk`
//! and sort key is the table's `pk`; querying it on `sk = "revocation"` returns
//! every revocation.
//!
//! `record_certificate`, `revoke` and `claim_token` rely on a conditional put
//! (`attribute_not_exists(pk)`) for atomic first-writer-wins semantics: revoke
//! treats the conflict as idempotent success, while claim_token treats it as a
//! replay and returns [`crate::error::Error::Conflict`].

/// Extra retention applied to a token's DynamoDB `ttl` beyond its real expiry, so
/// best-effort TTL deletion never reaps a claim that the validator would still
/// reject as a replay.
const TTL_BUFFER: std::time::Duration = std::time::Duration::from_secs(3600);

/// Sort-key prefix for issued-certificate items, carrying the common name.
const CERTIFICATE_SK_PREFIX: &str = "cn:";
/// Sort-key / inverted-index partition value for revocation items.
const REVOCATION_TYPE: &str = "revocation";
/// Sort-key value for one-time token items.
const TOKEN_TYPE: &str = "token";
/// Name of the inverted GSI (partition `sk`, sort `pk`) used for listing.
const INVERTED_INDEX: &str = "inverted";

/// Build a DynamoDB client from the shared AWS configuration, applying an
/// optional region override.
pub(crate) async fn client(region: Option<&str>) -> aws_sdk_dynamodb::Client {
    let mut builder = aws_sdk_dynamodb::config::Builder::from(crate::aws::shared_config().await);
    if let Some(region) = region {
        builder = builder.region(aws_sdk_dynamodb::config::Region::new(region.to_string()));
    }
    aws_sdk_dynamodb::Client::from_conf(builder.build())
}

/// An issued-certificate inventory, revocation store and anti-replay denylist
/// backed by a DynamoDB table.
#[derive(Debug, Clone)]
pub struct DynamoDbStorage {
    client: aws_sdk_dynamodb::Client,
    table_name: String,
}

impl DynamoDbStorage {
    /// Construct a store over `table_name` using the given DynamoDB client.
    pub fn new(client: aws_sdk_dynamodb::Client, table_name: String) -> DynamoDbStorage {
        DynamoDbStorage { client, table_name }
    }

    fn certificate_pk(serial_number: &str) -> String {
        format!("certificate:{serial_number}")
    }

    /// Sort key grouping every serial issued for a common name under one
    /// inverted-index partition.
    fn certificate_sk(common_name: &str) -> String {
        format!("{CERTIFICATE_SK_PREFIX}{common_name}")
    }

    fn revocation_pk(serial_number: &str) -> String {
        format!("revocation:{serial_number}")
    }

    fn token_pk(jti: &str) -> String {
        format!("token:{jti}")
    }

    fn s(value: impl Into<String>) -> aws_sdk_dynamodb::types::AttributeValue {
        aws_sdk_dynamodb::types::AttributeValue::S(value.into())
    }
}

#[async_trait::async_trait]
impl crate::storage::Storage for DynamoDbStorage {
    async fn record_certificate(
        &self,
        record: crate::storage::CertificateRecord,
    ) -> crate::error::Result<()> {
        let serial_number = record.serial_number.clone();
        let sk = DynamoDbStorage::certificate_sk(&record.subject);
        let mut item: std::collections::HashMap<String, aws_sdk_dynamodb::types::AttributeValue> =
            serde_dynamo::aws_sdk_dynamodb_1::to_item(&record).map_err(|e| {
                crate::error::Error::Internal(format!(
                    "dynamodb serialize certificate {serial_number}: {e}"
                ))
            })?;
        item.insert(
            "pk".to_string(),
            DynamoDbStorage::s(DynamoDbStorage::certificate_pk(&serial_number)),
        );
        item.insert("sk".to_string(), DynamoDbStorage::s(sk));

        let result = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(pk)")
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                let service_err = e.into_service_error();
                Err(crate::error::Error::Internal(format!(
                    "dynamodb PutItem(certificate {}): {}",
                    record.serial_number,
                    aws_smithy_types::error::display::DisplayErrorContext(&service_err)
                )))
            }
        }
    }

    async fn get_certificate(
        &self,
        serial_number: &str,
    ) -> crate::error::Result<Option<crate::storage::CertificateRecord>> {
        // The exact CN-bearing `sk` is unknown here, so query the unique `pk`
        // partition and match the certificate item by its `cn:` sort-key prefix
        // rather than issuing a `GetItem` that needs the full key.
        let resp = self
            .client
            .query()
            .table_name(&self.table_name)
            .key_condition_expression("#pk = :pk AND begins_with(#sk, :sk)")
            .expression_attribute_names("#pk", "pk")
            .expression_attribute_names("#sk", "sk")
            .expression_attribute_values(
                ":pk",
                DynamoDbStorage::s(DynamoDbStorage::certificate_pk(serial_number)),
            )
            .expression_attribute_values(":sk", DynamoDbStorage::s(CERTIFICATE_SK_PREFIX))
            .limit(1)
            .send()
            .await
            .map_err(|e| {
                crate::error::Error::Internal(format!(
                    "dynamodb Query(certificate {serial_number}): {}",
                    aws_smithy_types::error::display::DisplayErrorContext(&e)
                ))
            })?;
        let Some(item) = resp.items().first() else {
            return Ok(None);
        };
        let record = serde_dynamo::aws_sdk_dynamodb_1::from_item(item.clone()).map_err(|e| {
            crate::error::Error::Internal(format!(
                "dynamodb deserialize certificate {serial_number}: {e}"
            ))
        })?;
        Ok(Some(record))
    }

    async fn revoke(&self, record: crate::storage::RevocationRecord) -> crate::error::Result<()> {
        let mut item: std::collections::HashMap<String, aws_sdk_dynamodb::types::AttributeValue> =
            serde_dynamo::aws_sdk_dynamodb_1::to_item(&record).map_err(|e| {
                crate::error::Error::Internal(format!(
                    "dynamodb serialize revocation {}: {e}",
                    record.serial_number
                ))
            })?;
        item.insert(
            "pk".to_string(),
            DynamoDbStorage::s(DynamoDbStorage::revocation_pk(&record.serial_number)),
        );
        item.insert("sk".to_string(), DynamoDbStorage::s(REVOCATION_TYPE));

        let result = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(pk)")
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                let service_err = e.into_service_error();
                // Idempotent: an existing revocation keeps its original record.
                if service_err.is_conditional_check_failed_exception() {
                    Ok(())
                } else {
                    Err(crate::error::Error::Internal(format!(
                        "dynamodb PutItem(revocation {}): {}",
                        record.serial_number,
                        aws_smithy_types::error::display::DisplayErrorContext(&service_err)
                    )))
                }
            }
        }
    }

    async fn get_revocation(
        &self,
        serial_number: &str,
    ) -> crate::error::Result<Option<crate::storage::RevocationRecord>> {
        let resp = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key(
                "pk",
                DynamoDbStorage::s(DynamoDbStorage::revocation_pk(serial_number)),
            )
            .key("sk", DynamoDbStorage::s(REVOCATION_TYPE))
            .send()
            .await
            .map_err(|e| {
                crate::error::Error::Internal(format!(
                    "dynamodb GetItem(revocation {serial_number}): {}",
                    aws_smithy_types::error::display::DisplayErrorContext(&e)
                ))
            })?;
        let Some(item) = resp.item() else {
            return Ok(None);
        };
        let record = serde_dynamo::aws_sdk_dynamodb_1::from_item(item.clone()).map_err(|e| {
            crate::error::Error::Internal(format!(
                "dynamodb deserialize revocation {serial_number}: {e}"
            ))
        })?;
        Ok(Some(record))
    }

    async fn list_revocations(
        &self,
    ) -> crate::error::Result<Vec<crate::storage::RevocationRecord>> {
        let mut out = Vec::new();
        let mut start_key: Option<
            std::collections::HashMap<String, aws_sdk_dynamodb::types::AttributeValue>,
        > = None;
        loop {
            let resp = self
                .client
                .query()
                .table_name(&self.table_name)
                .index_name(INVERTED_INDEX)
                .key_condition_expression("#sk = :sk")
                .expression_attribute_names("#sk", "sk")
                .expression_attribute_values(":sk", DynamoDbStorage::s(REVOCATION_TYPE))
                .set_exclusive_start_key(start_key.take())
                .send()
                .await
                .map_err(|e| {
                    crate::error::Error::Internal(format!(
                        "dynamodb Query(revocations): {}",
                        aws_smithy_types::error::display::DisplayErrorContext(&e)
                    ))
                })?;
            let page: Vec<crate::storage::RevocationRecord> =
                serde_dynamo::aws_sdk_dynamodb_1::from_items(resp.items().to_vec()).map_err(
                    |e| {
                        crate::error::Error::Internal(format!(
                            "dynamodb deserialize revocations: {e}"
                        ))
                    },
                )?;
            out.extend(page);
            match resp.last_evaluated_key() {
                Some(key) if !key.is_empty() => start_key = Some(key.clone()),
                _ => break,
            }
        }
        Ok(out)
    }

    async fn claim_token(
        &self,
        jti: &str,
        expires_at: std::time::SystemTime,
    ) -> crate::error::Result<()> {
        let ttl = (expires_at + TTL_BUFFER)
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| {
                crate::error::Error::Internal(format!("token {jti} expiry before epoch: {e}"))
            })?
            .as_secs();
        let mut item = std::collections::HashMap::new();
        item.insert(
            "pk".to_string(),
            DynamoDbStorage::s(DynamoDbStorage::token_pk(jti)),
        );
        item.insert("sk".to_string(), DynamoDbStorage::s(TOKEN_TYPE));
        item.insert(
            "ttl".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::N(ttl.to_string()),
        );

        let result = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(pk)")
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                let service_err = e.into_service_error();
                if service_err.is_conditional_check_failed_exception() {
                    Err(crate::error::Error::Conflict(format!(
                        "token {jti} already claimed"
                    )))
                } else {
                    Err(crate::error::Error::Internal(format!(
                        "dynamodb PutItem(token {jti}): {}",
                        aws_smithy_types::error::display::DisplayErrorContext(&service_err)
                    )))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    fn client(rules: &[&aws_smithy_mocks::Rule]) -> aws_sdk_dynamodb::Client {
        aws_smithy_mocks::mock_client!(
            aws_sdk_dynamodb,
            aws_smithy_mocks::RuleMode::MatchAny,
            rules
        )
    }

    fn revocation_item(
        serial: &str,
    ) -> std::collections::HashMap<String, aws_sdk_dynamodb::types::AttributeValue> {
        let mut item = std::collections::HashMap::new();
        item.insert(
            "pk".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S(format!("revocation:{serial}")),
        );
        item.insert(
            "sk".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S("revocation".to_string()),
        );
        item.insert(
            "serial_number".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S(serial.to_string()),
        );
        item.insert(
            "reason_code".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::N("4".to_string()),
        );
        item.insert(
            "revoked_at".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S("2026-06-14T00:00:00Z".to_string()),
        );
        item.insert(
            "reason".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S("superseded".to_string()),
        );
        item.insert(
            "provisioner".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S("test".to_string()),
        );
        item
    }

    fn certificate_item(
        serial: &str,
    ) -> std::collections::HashMap<String, aws_sdk_dynamodb::types::AttributeValue> {
        let mut item = std::collections::HashMap::new();
        item.insert(
            "pk".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S(format!("certificate:{serial}")),
        );
        item.insert(
            "sk".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S("cn:host.example".to_string()),
        );
        item.insert(
            "serial_number".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S(serial.to_string()),
        );
        item.insert(
            "subject".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S("host.example".to_string()),
        );
        item.insert(
            "sans".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::L(vec![
                aws_sdk_dynamodb::types::AttributeValue::S("host.example".to_string()),
                aws_sdk_dynamodb::types::AttributeValue::S("alt.example".to_string()),
            ]),
        );
        item.insert(
            "not_before".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S("2026-06-15T00:00:00Z".to_string()),
        );
        item.insert(
            "not_after".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S("2026-09-13T00:00:00Z".to_string()),
        );
        item.insert(
            "issued_at".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S("2026-06-15T00:00:00Z".to_string()),
        );
        item.insert(
            "provisioner".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S("prov1".to_string()),
        );
        item.insert(
            "operation".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S("sign".to_string()),
        );
        item.insert(
            "pem".to_string(),
            aws_sdk_dynamodb::types::AttributeValue::S("-----BEGIN CERTIFICATE-----".to_string()),
        );
        item
    }

    #[tokio::test]
    async fn record_certificate_puts_item() {
        use crate::storage::Storage;
        let put = aws_smithy_mocks::mock!(aws_sdk_dynamodb::Client::put_item).then_output(|| {
            aws_sdk_dynamodb::operation::put_item::PutItemOutput::builder().build()
        });
        let storage = super::DynamoDbStorage::new(client(&[&put]), "tbl".to_string());
        storage
            .record_certificate(crate::storage::CertificateRecord {
                serial_number: "123".to_string(),
                subject: "host.example".to_string(),
                sans: vec!["host.example".to_string()],
                not_before: "2026-06-15T00:00:00Z".to_string(),
                not_after: "2026-09-13T00:00:00Z".to_string(),
                issued_at: "2026-06-15T00:00:00Z".to_string(),
                provisioner: Some("prov1".to_string()),
                operation: "sign".to_string(),
                pem: "-----BEGIN CERTIFICATE-----".to_string(),
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn get_certificate_parses_item() {
        use crate::storage::Storage;
        let query = aws_smithy_mocks::mock!(aws_sdk_dynamodb::Client::query).then_output(|| {
            aws_sdk_dynamodb::operation::query::QueryOutput::builder()
                .set_items(Some(vec![certificate_item("123")]))
                .build()
        });
        let storage = super::DynamoDbStorage::new(client(&[&query]), "tbl".to_string());
        let record = storage.get_certificate("123").await.unwrap().unwrap();
        assert_eq!(record.serial_number, "123");
        assert_eq!(record.subject, "host.example");
        assert_eq!(record.sans, vec!["host.example", "alt.example"]);
        assert_eq!(record.operation, "sign");
        assert_eq!(record.provisioner.as_deref(), Some("prov1"));
    }

    #[tokio::test]
    async fn get_certificate_missing_returns_none() {
        use crate::storage::Storage;
        let query = aws_smithy_mocks::mock!(aws_sdk_dynamodb::Client::query).then_output(|| {
            aws_sdk_dynamodb::operation::query::QueryOutput::builder()
                .set_items(Some(vec![]))
                .build()
        });
        let storage = super::DynamoDbStorage::new(client(&[&query]), "tbl".to_string());
        assert_eq!(storage.get_certificate("404").await.unwrap(), None);
    }

    #[tokio::test]
    async fn revoke_puts_item() {
        use crate::storage::Storage;
        let put = aws_smithy_mocks::mock!(aws_sdk_dynamodb::Client::put_item).then_output(|| {
            aws_sdk_dynamodb::operation::put_item::PutItemOutput::builder().build()
        });
        let storage = super::DynamoDbStorage::new(client(&[&put]), "tbl".to_string());
        storage
            .revoke(crate::storage::RevocationRecord {
                serial_number: "123".to_string(),
                reason_code: 1,
                reason: Some("keyCompromise".to_string()),
                revoked_at: "2026-06-14T00:00:00Z".to_string(),
                provisioner: Some("test".to_string()),
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn revoke_conditional_failure_is_idempotent() {
        use crate::storage::Storage;
        let put = aws_smithy_mocks::mock!(aws_sdk_dynamodb::Client::put_item).then_error(|| {
            aws_sdk_dynamodb::operation::put_item::PutItemError::ConditionalCheckFailedException(
                aws_sdk_dynamodb::types::error::ConditionalCheckFailedException::builder().build(),
            )
        });
        let storage = super::DynamoDbStorage::new(client(&[&put]), "tbl".to_string());
        // Already revoked: a conditional check failure is swallowed as success.
        storage
            .revoke(crate::storage::RevocationRecord {
                serial_number: "123".to_string(),
                reason_code: 1,
                reason: None,
                revoked_at: "2026-06-14T00:00:00Z".to_string(),
                provisioner: None,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn claim_token_puts_item() {
        use crate::storage::Storage;
        let put = aws_smithy_mocks::mock!(aws_sdk_dynamodb::Client::put_item).then_output(|| {
            aws_sdk_dynamodb::operation::put_item::PutItemOutput::builder().build()
        });
        let storage = super::DynamoDbStorage::new(client(&[&put]), "tbl".to_string());
        let expires = std::time::SystemTime::now() + std::time::Duration::from_secs(300);
        storage.claim_token("jti-1", expires).await.unwrap();
    }

    #[tokio::test]
    async fn claim_token_conditional_failure_is_conflict() {
        use crate::storage::Storage;
        let put = aws_smithy_mocks::mock!(aws_sdk_dynamodb::Client::put_item).then_error(|| {
            aws_sdk_dynamodb::operation::put_item::PutItemError::ConditionalCheckFailedException(
                aws_sdk_dynamodb::types::error::ConditionalCheckFailedException::builder().build(),
            )
        });
        let storage = super::DynamoDbStorage::new(client(&[&put]), "tbl".to_string());
        let expires = std::time::SystemTime::now() + std::time::Duration::from_secs(300);
        let err = storage.claim_token("jti-1", expires).await.unwrap_err();
        assert!(matches!(err, crate::error::Error::Conflict(_)));
    }

    #[tokio::test]
    async fn get_revocation_parses_item() {
        use crate::storage::Storage;
        let get = aws_smithy_mocks::mock!(aws_sdk_dynamodb::Client::get_item).then_output(|| {
            aws_sdk_dynamodb::operation::get_item::GetItemOutput::builder()
                .set_item(Some(revocation_item("123")))
                .build()
        });
        let storage = super::DynamoDbStorage::new(client(&[&get]), "tbl".to_string());
        let record = storage.get_revocation("123").await.unwrap().unwrap();
        assert_eq!(
            record,
            crate::storage::RevocationRecord {
                serial_number: "123".to_string(),
                reason_code: 4,
                reason: Some("superseded".to_string()),
                revoked_at: "2026-06-14T00:00:00Z".to_string(),
                provisioner: Some("test".to_string()),
            }
        );
    }

    #[tokio::test]
    async fn get_revocation_missing_returns_none() {
        use crate::storage::Storage;
        let get = aws_smithy_mocks::mock!(aws_sdk_dynamodb::Client::get_item).then_output(|| {
            aws_sdk_dynamodb::operation::get_item::GetItemOutput::builder().build()
        });
        let storage = super::DynamoDbStorage::new(client(&[&get]), "tbl".to_string());
        assert_eq!(storage.get_revocation("404").await.unwrap(), None);
    }

    #[tokio::test]
    async fn list_revocations_queries_inverted_index() {
        use crate::storage::Storage;
        let query = aws_smithy_mocks::mock!(aws_sdk_dynamodb::Client::query)
            .match_requests(|req| req.index_name() == Some("inverted"))
            .then_output(|| {
                aws_sdk_dynamodb::operation::query::QueryOutput::builder()
                    .set_items(Some(vec![super::tests::revocation_item("123")]))
                    .build()
            });
        let storage = super::DynamoDbStorage::new(client(&[&query]), "tbl".to_string());
        let all = storage.list_revocations().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].serial_number, "123");
    }
}
