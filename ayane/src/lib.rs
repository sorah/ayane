//! ayane: an AWS-native X.509 certificate authority.
//!
//! The crate is organized as a set of pluggable abstractions around a core
//! certificate-building engine:
//!
//! - [`key_provider`] — where the CA private key lives and signs (file, AWS KMS)
//! - [`authorizer`] — how an issuance request is authenticated (JWT one-time token)
//! - [`webhook`] — external gates/enrichment for issuance (HTTP, AWS Lambda)
//! - [`event_sink`] — where audit events are emitted (stdout, file, AWS EventBridge)
//! - [`storage`] — revocation records and anti-replay state (SQLite, DynamoDB)
//!
//! These are composed by [`ca::CertificateAuthority`] and the request
//! orchestration in [`service`], and exposed over HTTP by [`http`]/[`server`].

pub mod authorizer;
pub mod aws;
pub mod builder;
pub mod ca;
pub mod config;
pub mod crypto;
pub mod csr;
pub mod dpop;
pub mod duration;
pub mod error;
pub mod event_sink;
pub mod http;
pub mod key_provider;
pub mod san;
pub mod server;
pub mod service;
pub mod storage;
pub mod template;
pub mod tls;
pub mod webhook;
pub mod x509;

#[cfg(test)]
mod e2e;
#[cfg(test)]
pub mod testca;

pub use crate::error::{Error, Result};
