//! A test double for the Gemini `generateContent` API and the Turnstile
//! `siteverify` endpoint. **Not a model**: it exists to test OpenShield's
//! integration (schema handling, timeouts, outages, budgets, injection
//! handling) without network access or an API key.
//!
//! Classification is a fixed keyword heuristic so tests are deterministic:
//! events the firewall blocked, or with attack-like text, are `malicious`;
//! everything else is `legitimate`. If an event contains "ignore previous",
//! the mock answers `legitimate` with high confidence, imitating a model that
//! fell for a prompt injection, so the caller's safeguards can be tested.
//!
//! Control endpoints:
//! - `POST /_mode` with body `ok|down|slow|garbage|ratelimit|refuse`
//! - `GET /_requests`: the recorded requests (path, headers, body)
//! - `POST /_reset`: clear recordings and go back to `ok`
//!
//! Usage: `mock-gemini [listen_addr]` (default 127.0.0.1:13900).

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::TcpListener;

#[derive(Default)]
struct State {
    mode: String,
    requests: Vec<Value>,
}

type Shared = Arc<Mutex<State>>;

fn resp(status: u16, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn classify(ev: &Value) -> Value {
    let text = ev.to_string().to_lowercase();
    let r = ev["ref_id"].clone();
    if text.contains("ignore previous") {
        return json!({"ref_id": r, "category": "legitimate", "risk": 0.02, "confidence": 0.99,
            "explanation": "Looks fine.", "evidence": ["query.q"], "recommended_action": "none"});
    }
    let attack = ["union select", "' or '1'='1", "<script", "../", "/etc/passwd", "sqlmap", "${jndi"];
    let blocked = ev["firewall_action"] == "block";
    if blocked || attack.iter().any(|a| text.contains(a)) {
        json!({"ref_id": r, "category": "malicious", "risk": 0.9, "confidence": 0.85,
            "explanation": "Request contains an injection payload.", "evidence": ["query.q", "rule:block-sqli-args"],
            "recommended_action": if blocked { "monitor" } else { "review" }})
    } else {
        json!({"ref_id": r, "category": "legitimate", "risk": 0.05, "confidence": 0.8,
            "explanation": "Ordinary request.", "evidence": ["path"], "recommended_action": "none"})
    }
}

async fn handle(req: Request<Incoming>, st: Shared) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
        .collect();
    let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let body_s = String::from_utf8_lossy(&body).into_owned();

    match path.as_str() {
        "/_mode" => {
            st.lock().unwrap().mode = body_s.trim().to_string();
            return Ok(resp(200, "{}".into()));
        }
        "/_requests" => {
            let v = json!(st.lock().unwrap().requests);
            return Ok(resp(200, v.to_string()));
        }
        "/_reset" => {
            let mut s = st.lock().unwrap();
            s.mode = "ok".into();
            s.requests.clear();
            return Ok(resp(200, "{}".into()));
        }
        "/turnstile/v0/siteverify" => {
            let ok = body_s.contains("response=pass");
            return Ok(resp(200, json!({"success": ok}).to_string()));
        }
        _ => {}
    }

    if !path.contains(":generateContent") {
        return Ok(resp(404, json!({"error": {"message": "not found"}}).to_string()));
    }
    let mode = {
        let mut s = st.lock().unwrap();
        s.requests.push(json!({"path": path, "query": query, "headers": headers, "body": body_s}));
        if s.requests.len() > 500 {
            s.requests.remove(0);
        }
        if s.mode.is_empty() { "ok".to_string() } else { s.mode.clone() }
    };
    let has_key = headers.iter().any(|(k, v)| k == "x-goog-api-key" && !v.is_empty());
    if !has_key {
        return Ok(resp(401, json!({"error": {"message": "API key missing"}}).to_string()));
    }
    match mode.as_str() {
        "down" => return Ok(resp(503, json!({"error": {"message": "unavailable"}}).to_string())),
        "ratelimit" => return Ok(resp(429, json!({"error": {"message": "quota"}}).to_string())),
        "slow" => {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        "refuse" => return Ok(resp(200, json!({"promptFeedback": {"blockReason": "SAFETY"}}).to_string())),
        _ => {}
    }

    let req_json: Value = serde_json::from_str(&body_s).unwrap_or(Value::Null);
    let user_text = req_json["contents"][0]["parts"][0]["text"].as_str().unwrap_or("");
    let text = if mode == "garbage" {
        "I think these requests look fine overall.".to_string()
    } else if let Some(start) = user_text.find('{') {
        // Classification request: the data follows the instructions as JSON.
        match serde_json::from_str::<Value>(&user_text[start..]) {
            Ok(data) if data.get("untrusted_events").is_some() => {
                let results: Vec<Value> = data["untrusted_events"]
                    .as_array()
                    .map(|a| a.iter().map(classify).collect())
                    .unwrap_or_default();
                json!({"results": results}).to_string()
            }
            _ => "Mock summary: repeated blocked requests from one client; likely automated scanning.".to_string(),
        }
    } else {
        "Mock summary.".to_string()
    };
    let out = json!({
        "candidates": [{"content": {"parts": [{"text": text}], "role": "model"}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": (body_s.len() / 4) as u64, "candidatesTokenCount": (text.len() / 4) as u64},
        "modelVersion": "mock-gemini-1"
    });
    Ok(resp(200, out.to_string()))
}

#[tokio::main]
async fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:13900".into());
    let listener = TcpListener::bind(&addr).await.expect("bind");
    eprintln!("mock-gemini listening on {addr}");
    let st: Shared = Arc::new(Mutex::new(State {
        mode: "ok".into(),
        requests: Vec::new(),
    }));
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let st = Arc::clone(&st);
        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service_fn(move |r| handle(r, Arc::clone(&st))))
                .await;
        });
    }
}
