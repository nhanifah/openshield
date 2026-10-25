use prometheus::{
    Histogram, IntCounter, IntCounterVec, IntGauge, register_histogram, register_int_counter,
    register_int_counter_vec, register_int_gauge,
};

lazy_static::lazy_static! {
    pub static ref TOTAL_REQUESTS: IntCounter =
        register_int_counter!("openshield_requests_total", "Total HTTP requests processed").unwrap();
    pub static ref ACTIVE_CONNECTIONS: IntGauge =
        register_int_gauge!("openshield_connections_active", "Currently active connections").unwrap();
    pub static ref BYTES_RECEIVED: IntCounter =
        register_int_counter!("openshield_bytes_received_total", "Total bytes received from clients").unwrap();
    pub static ref DECISIONS: IntCounterVec = register_int_counter_vec!(
        "openshield_decisions_total",
        "Requests by firewall decision (pass, allow, block, challenge) and enforcement",
        &["action", "enforced"]
    )
    .unwrap();
    pub static ref RULE_MATCHES: IntCounterVec = register_int_counter_vec!(
        "openshield_rule_matches_total",
        "Logged rule matches by rule id and action",
        &["rule", "action"]
    )
    .unwrap();
    pub static ref REQUEST_DURATION: Histogram = register_histogram!(
        "openshield_request_duration_seconds",
        "Time from request start to the end of the response",
        vec![0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .unwrap();
    pub static ref BYTES_SENT: IntCounter =
        register_int_counter!("openshield_bytes_sent_total", "Total bytes sent to clients").unwrap();
}
