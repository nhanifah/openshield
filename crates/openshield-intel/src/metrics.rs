//! Prometheus metrics for the intelligence pipeline. Registered in the
//! default registry, so the proxy's metrics listener exposes them.

use lazy_static::lazy_static;
use prometheus::{IntGauge, IntGaugeVec, register_int_gauge, register_int_gauge_vec};

use crate::hub::EventHub;

lazy_static! {
    static ref PIPELINE: IntGaugeVec = register_int_gauge_vec!(
        "openshield_intel_events",
        "Intelligence pipeline event counters (cumulative) and queue depth",
        &["kind"]
    )
    .unwrap();
    static ref AI: IntGaugeVec = register_int_gauge_vec!(
        "openshield_ai",
        "AI supervision counters (cumulative) and queue depth",
        &["kind"]
    )
    .unwrap();
    static ref AI_BREAKER_OPEN: IntGauge =
        register_int_gauge!("openshield_ai_breaker_open", "1 while the AI circuit breaker is open").unwrap();
    static ref AI_COST: IntGauge =
        register_int_gauge!("openshield_ai_cost_micro_usd", "Estimated AI provider cost in millionths of USD").unwrap();
    static ref CONTROLS: IntGaugeVec =
        register_int_gauge_vec!("openshield_dynamic_controls", "Active dynamic IP controls", &["kind"]).unwrap();
}

/// Copy current counters into the gauges (called every second).
pub fn update(hub: &EventHub) {
    let s = hub.status();
    for (k, v) in [
        ("submitted", s.submitted),
        ("dropped", s.dropped),
        ("stored", s.stored),
        ("store_dropped", s.store_dropped),
        ("store_errors", s.store_errors),
        ("alerts", s.alerts),
        ("auto_blocks", s.auto_blocks),
        ("queue", s.queue as u64),
        ("tracked_clients", s.tracked_clients as u64),
    ] {
        PIPELINE.with_label_values(&[k]).set(v as i64);
    }
    let (b, a) = hub.controls.counts();
    CONTROLS.with_label_values(&["ip_block"]).set(b as i64);
    CONTROLS.with_label_values(&["ip_allow"]).set(a as i64);
    if let Some(ai) = hub.ai() {
        let st = ai.status();
        for (k, v) in [
            ("queue", st.queue),
            ("analyzed", st.analyzed),
            ("failures", st.failures),
            ("invalid_outputs", st.invalid_outputs),
            ("cache_hits", st.cache_hits),
            ("dropped", st.dropped),
            ("skipped_breaker", st.skipped_breaker),
            ("skipped_budget", st.skipped_budget),
            ("calls", st.calls),
            ("tokens_in", st.tokens_in),
            ("tokens_out", st.tokens_out),
        ] {
            AI.with_label_values(&[k]).set(v as i64);
        }
        AI_BREAKER_OPEN.set((st.state == "open") as i64);
        AI_COST.set((st.cost_usd * 1e6) as i64);
    }
}
