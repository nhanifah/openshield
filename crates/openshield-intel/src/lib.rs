//! OpenShield security intelligence.
//!
//! Layers on top of the deterministic firewall (layer 1, `openshield-core`):
//! - layer 2, [`anomaly`]: behavioral detection over the event stream;
//! - layer 3, [`ai`]: asynchronous, advisory AI classification;
//! - layer 4, [`dataset`]: operator labels feeding reviewed datasets.
//!
//! None of these layers sit on the request path. The proxy hands each
//! finished request to [`hub::EventHub::submit`], which never blocks.

pub mod admin;
pub mod ai;
pub mod anomaly;
pub mod config;
pub mod controls;
pub mod dataset;
pub mod event;
pub mod hub;
pub mod metrics;
pub mod policy;
pub mod runtime;
pub mod settings;
pub mod stats;
pub mod store;
pub mod vault;
pub mod webauthn;

pub use runtime::Intel;
