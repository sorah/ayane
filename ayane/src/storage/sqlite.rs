//! Local SQLite [`Storage`](crate::storage::Storage), backed by `rusqlite`.
//!
//! One database holds all three concerns — the issued-certificate inventory,
//! revocation records and the anti-replay token denylist. The path may be
//! `:memory:` (process-local, non-durable;
//! suitable for development and tests) or a filesystem path (durable for a
//! single node). `rusqlite` is synchronous, so each operation runs on a blocking
//! thread via [`tokio::task::spawn_blocking`], serialized by a single connection
//! behind a mutex (a `:memory:` database is only visible to its own connection).

/// An issued-certificate inventory, revocation store and anti-replay denylist
/// backed by a SQLite database.
pub struct SqliteStorage {
    conn: std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>,
}

impl SqliteStorage {
    /// Open (creating if necessary) a database at `path`, or an in-process
    /// database when `path` is `:memory:`.
    pub fn open(path: &str) -> crate::error::Result<SqliteStorage> {
        let conn = if path == ":memory:" {
            rusqlite::Connection::open_in_memory()
        } else {
            rusqlite::Connection::open(path)
        }
        .map_err(|e| crate::error::Error::Config(format!("open sqlite {path:?}: {e}")))?;
        SqliteStorage::from_connection(conn)
    }

    /// Open an in-process `:memory:` database. Convenient for tests.
    pub fn open_in_memory() -> crate::error::Result<SqliteStorage> {
        SqliteStorage::open(":memory:")
    }

    fn from_connection(conn: rusqlite::Connection) -> crate::error::Result<SqliteStorage> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS certificates (
                 serial_number TEXT PRIMARY KEY,
                 subject       TEXT NOT NULL,
                 sans          TEXT NOT NULL,
                 not_before    TEXT NOT NULL,
                 not_after     TEXT NOT NULL,
                 issued_at     TEXT NOT NULL,
                 provisioner   TEXT,
                 operation     TEXT NOT NULL,
                 pem           TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS revocations (
                 serial_number TEXT PRIMARY KEY,
                 reason_code   INTEGER NOT NULL,
                 reason        TEXT,
                 revoked_at    TEXT NOT NULL,
                 provisioner   TEXT
             );
             CREATE TABLE IF NOT EXISTS tokens (
                 jti        TEXT PRIMARY KEY,
                 expires_at INTEGER NOT NULL
             );",
        )
        .map_err(|e| crate::error::Error::Config(format!("init sqlite schema: {e}")))?;
        Ok(SqliteStorage {
            conn: std::sync::Arc::new(std::sync::Mutex::new(conn)),
        })
    }

    /// Run `f` against the connection on a blocking thread.
    async fn with_conn<F, T>(&self, f: F) -> crate::error::Result<T>
    where
        F: FnOnce(&mut rusqlite::Connection) -> crate::error::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().map_err(|e| {
                crate::error::Error::Internal(format!("sqlite storage poisoned: {e}"))
            })?;
            f(&mut guard)
        })
        .await
        .map_err(|e| crate::error::Error::Internal(format!("sqlite task join: {e}")))?
    }
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<crate::storage::RevocationRecord> {
    Ok(crate::storage::RevocationRecord {
        serial_number: row.get(0)?,
        reason_code: row.get(1)?,
        reason: row.get(2)?,
        revoked_at: row.get(3)?,
        provisioner: row.get(4)?,
    })
}

fn row_to_certificate(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<crate::storage::CertificateRecord> {
    let sans_json: String = row.get(2)?;
    let sans = serde_json::from_str(&sans_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(crate::storage::CertificateRecord {
        serial_number: row.get(0)?,
        subject: row.get(1)?,
        sans,
        not_before: row.get(3)?,
        not_after: row.get(4)?,
        issued_at: row.get(5)?,
        provisioner: row.get(6)?,
        operation: row.get(7)?,
        pem: row.get(8)?,
    })
}

fn unix_secs(t: std::time::SystemTime) -> crate::error::Result<i64> {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| crate::error::Error::Internal(format!("timestamp before epoch: {e}")))
}

const SELECT_REVOCATION: &str =
    "SELECT serial_number, reason_code, reason, revoked_at, provisioner FROM revocations";

const SELECT_CERTIFICATE: &str = "SELECT serial_number, subject, sans, not_before, not_after, \
     issued_at, provisioner, operation, pem FROM certificates";

#[async_trait::async_trait]
impl crate::storage::Storage for SqliteStorage {
    async fn record_certificate(
        &self,
        record: crate::storage::CertificateRecord,
    ) -> crate::error::Result<()> {
        let sans = serde_json::to_string(&record.sans)
            .map_err(|e| crate::error::Error::Internal(format!("serialize SANs: {e}")))?;
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO certificates
                     (serial_number, subject, sans, not_before, not_after,
                      issued_at, provisioner, operation, pem)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    record.serial_number,
                    record.subject,
                    sans,
                    record.not_before,
                    record.not_after,
                    record.issued_at,
                    record.provisioner,
                    record.operation,
                    record.pem,
                ],
            )
            .map_err(|e| {
                crate::error::Error::Internal(format!("sqlite record_certificate: {e}"))
            })?;
            Ok(())
        })
        .await
    }

    async fn get_certificate(
        &self,
        serial_number: &str,
    ) -> crate::error::Result<Option<crate::storage::CertificateRecord>> {
        let serial = serial_number.to_string();
        self.with_conn(move |conn| {
            conn.query_row(
                &format!("{SELECT_CERTIFICATE} WHERE serial_number = ?1"),
                [serial],
                row_to_certificate,
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(crate::error::Error::Internal(format!(
                    "sqlite get_certificate: {other}"
                ))),
            })
        })
        .await
    }

    async fn revoke(&self, record: crate::storage::RevocationRecord) -> crate::error::Result<()> {
        self.with_conn(move |conn| {
            // Idempotent: keep the original record if the serial is already revoked.
            conn.execute(
                "INSERT OR IGNORE INTO revocations
                     (serial_number, reason_code, reason, revoked_at, provisioner)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    record.serial_number,
                    record.reason_code,
                    record.reason,
                    record.revoked_at,
                    record.provisioner,
                ],
            )
            .map_err(|e| crate::error::Error::Internal(format!("sqlite revoke: {e}")))?;
            Ok(())
        })
        .await
    }

    async fn get_revocation(
        &self,
        serial_number: &str,
    ) -> crate::error::Result<Option<crate::storage::RevocationRecord>> {
        let serial = serial_number.to_string();
        self.with_conn(move |conn| {
            conn.query_row(
                &format!("{SELECT_REVOCATION} WHERE serial_number = ?1"),
                [serial],
                row_to_record,
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(crate::error::Error::Internal(format!(
                    "sqlite get_revocation: {other}"
                ))),
            })
        })
        .await
    }

    async fn list_revocations(
        &self,
    ) -> crate::error::Result<Vec<crate::storage::RevocationRecord>> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(&format!("{SELECT_REVOCATION} ORDER BY serial_number"))
                .map_err(|e| {
                    crate::error::Error::Internal(format!("sqlite list_revocations: {e}"))
                })?;
            let rows = stmt.query_map([], row_to_record).map_err(|e| {
                crate::error::Error::Internal(format!("sqlite list_revocations: {e}"))
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|e| {
                    crate::error::Error::Internal(format!("sqlite list_revocations: {e}"))
                })?);
            }
            Ok(out)
        })
        .await
    }

    async fn claim_token(
        &self,
        jti: &str,
        expires_at: std::time::SystemTime,
    ) -> crate::error::Result<()> {
        let jti = jti.to_string();
        let expires_at = unix_secs(expires_at)?;
        let now = unix_secs(std::time::SystemTime::now())?;
        self.with_conn(move |conn| {
            let tx = conn
                .transaction()
                .map_err(|e| crate::error::Error::Internal(format!("sqlite claim_token: {e}")))?;
            // Reclaim an expired claim for the same id before inserting.
            tx.execute(
                "DELETE FROM tokens WHERE jti = ?1 AND expires_at <= ?2",
                rusqlite::params![jti, now],
            )
            .map_err(|e| crate::error::Error::Internal(format!("sqlite claim_token: {e}")))?;
            let inserted = tx
                .execute(
                    "INSERT OR IGNORE INTO tokens (jti, expires_at) VALUES (?1, ?2)",
                    rusqlite::params![jti, expires_at],
                )
                .map_err(|e| crate::error::Error::Internal(format!("sqlite claim_token: {e}")))?;
            if inserted == 0 {
                return Err(crate::error::Error::Conflict(format!(
                    "token {jti} already claimed"
                )));
            }
            tx.commit()
                .map_err(|e| crate::error::Error::Internal(format!("sqlite claim_token: {e}")))?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    fn record(serial: &str) -> crate::storage::RevocationRecord {
        crate::storage::RevocationRecord {
            serial_number: serial.to_string(),
            reason_code: 1,
            reason: Some("keyCompromise".to_string()),
            revoked_at: "2026-06-14T00:00:00Z".to_string(),
            provisioner: Some("test".to_string()),
        }
    }

    fn certificate(serial: &str) -> crate::storage::CertificateRecord {
        crate::storage::CertificateRecord {
            serial_number: serial.to_string(),
            subject: "host.example".to_string(),
            sans: vec!["host.example".to_string(), "alt.example".to_string()],
            not_before: "2026-06-15T00:00:00Z".to_string(),
            not_after: "2026-09-13T00:00:00Z".to_string(),
            issued_at: "2026-06-15T00:00:00Z".to_string(),
            provisioner: Some("prov1".to_string()),
            operation: "sign".to_string(),
            pem: "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----\n".to_string(),
        }
    }

    #[tokio::test]
    async fn record_and_get_certificate_roundtrip() {
        use crate::storage::Storage;
        let storage = super::SqliteStorage::open_in_memory().unwrap();
        assert_eq!(storage.get_certificate("123").await.unwrap(), None);
        storage
            .record_certificate(certificate("123"))
            .await
            .unwrap();
        assert_eq!(
            storage.get_certificate("123").await.unwrap(),
            Some(certificate("123"))
        );
    }

    #[tokio::test]
    async fn record_certificate_rejects_duplicate_serial() {
        use crate::storage::Storage;
        let storage = super::SqliteStorage::open_in_memory().unwrap();
        storage
            .record_certificate(certificate("123"))
            .await
            .unwrap();
        // A reused serial signals a collision and must surface as an error.
        assert!(
            storage
                .record_certificate(certificate("123"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn revoke_and_get_roundtrip() {
        use crate::storage::Storage;
        let storage = super::SqliteStorage::open_in_memory().unwrap();
        assert_eq!(storage.get_revocation("123").await.unwrap(), None);
        storage.revoke(record("123")).await.unwrap();
        assert_eq!(
            storage.get_revocation("123").await.unwrap(),
            Some(record("123"))
        );
    }

    #[tokio::test]
    async fn revoke_is_idempotent_and_keeps_original() {
        use crate::storage::Storage;
        let storage = super::SqliteStorage::open_in_memory().unwrap();
        storage.revoke(record("123")).await.unwrap();

        let mut updated = record("123");
        updated.reason_code = 4;
        updated.reason = Some("superseded".to_string());
        storage.revoke(updated).await.unwrap();

        // The original record is retained, not overwritten.
        assert_eq!(
            storage.get_revocation("123").await.unwrap(),
            Some(record("123"))
        );
    }

    #[tokio::test]
    async fn list_revocations_returns_all() {
        use crate::storage::Storage;
        let storage = super::SqliteStorage::open_in_memory().unwrap();
        storage.revoke(record("10")).await.unwrap();
        storage.revoke(record("2")).await.unwrap();
        let all = storage.list_revocations().await.unwrap();
        let serials: Vec<&str> = all.iter().map(|r| r.serial_number.as_str()).collect();
        assert_eq!(serials.len(), 2);
        assert!(serials.contains(&"10"));
        assert!(serials.contains(&"2"));
    }

    #[tokio::test]
    async fn claim_token_first_ok_second_conflict() {
        use crate::storage::Storage;
        let storage = super::SqliteStorage::open_in_memory().unwrap();
        let expires = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        storage.claim_token("jti-1", expires).await.unwrap();

        let err = storage.claim_token("jti-1", expires).await.unwrap_err();
        assert!(matches!(err, crate::error::Error::Conflict(_)));
    }

    #[tokio::test]
    async fn expired_claim_is_reclaimable() {
        use crate::storage::Storage;
        let storage = super::SqliteStorage::open_in_memory().unwrap();
        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
        storage.claim_token("jti-1", past).await.unwrap();

        // The prior claim has expired, so re-claiming succeeds.
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        storage.claim_token("jti-1", future).await.unwrap();
    }
}
