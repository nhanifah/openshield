//! Dashboard assets, embedded at build time.

use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};

const INDEX: &str = include_str!("../../assets/index.html");
const JS: &str = include_str!("../../assets/app.js");
const CSS: &str = include_str!("../../assets/app.css");

fn asset(body: &'static str, ct: &'static str) -> Response {
    ([(header::CONTENT_TYPE, HeaderValue::from_static(ct))], body).into_response()
}

pub async fn index() -> Response {
    asset(INDEX, "text/html; charset=utf-8")
}

pub async fn js() -> Response {
    asset(JS, "text/javascript; charset=utf-8")
}

pub async fn css() -> Response {
    asset(CSS, "text/css; charset=utf-8")
}
