//! OpenShield WAF engine.
//!
//! Server-agnostic core: configuration, rule compilation, per-phase
//! evaluation, and the request/response validators. A host (such as
//! `openshield-pingora`) builds a [`Waf`] from the config, starts a
//! [`Transaction`] per request, feeds it headers and body chunks, and acts
//! on the verdicts it returns.

pub mod challenge;
pub mod compiler;
pub mod config;
pub mod firewall;
pub mod geoip;
pub mod logging;
pub mod redact;
pub mod transaction;
pub mod waf;

pub use firewall::{Settings, Waf};
pub use transaction::{
    BodyVerdict, Intervention, LogRecord, ResponseOutcome, Transaction, Verdict,
};
