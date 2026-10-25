//! A fast upstream for tests and benchmarks.
//!
//! Routes:
//! - `/status/<code>`: reply with that status.
//! - `/slow?ms=<n>`: wait n milliseconds, then reply.
//! - `/bytes/<n>`: reply with n bytes of `a`.
//! - `/secret`: reply with a body containing `secret-token-123`.
//! - `/echo...`: reply with a JSON description of what was received
//!   (method, path, headers, body). Lets tests check what reached the backend.
//! - anything else: `200 ok`.
//!
//! Usage: `echo-upstream [listen_addr]` (default 127.0.0.1:3000).

use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    if let Some(code) = path.strip_prefix("/status/") {
        let code = code.parse::<u16>().unwrap_or(200);
        return Ok(Response::builder()
            .status(code)
            .body(Full::new(Bytes::from_static(b"status")))
            .unwrap());
    }
    if path == "/slow" {
        let ms = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("ms="))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(100);
        tokio::time::sleep(Duration::from_millis(ms)).await;
        return Ok(Response::new(Full::new(Bytes::from_static(b"slow ok"))));
    }
    if let Some(n) = path.strip_prefix("/bytes/") {
        let n = n.parse::<usize>().unwrap_or(0).min(64 * 1024 * 1024);
        return Ok(Response::new(Full::new(Bytes::from(vec![b'a'; n]))));
    }
    if path == "/secret" {
        return Ok(Response::builder()
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from_static(
                b"internal data: secret-token-123\n",
            )))
            .unwrap());
    }
    if path.starts_with("/echo") {
        let method = req.method().to_string();
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = req
            .into_body()
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        let json = serde_json::json!({
            "method": method,
            "path": path,
            "query": query,
            "headers": headers,
            "body_len": body.len(),
            "body": String::from_utf8_lossy(&body[..body.len().min(65536)]),
        });
        return Ok(Response::builder()
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(json.to_string())))
            .unwrap());
    }
    // Drain the body so keep-alive connections stay usable.
    let _ = req.into_body().collect().await;
    Ok(Response::new(Full::new(Bytes::from_static(b"ok"))))
}

#[tokio::main]
async fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:3000".into());
    let listener = TcpListener::bind(&addr).await.expect("bind");
    eprintln!("echo-upstream listening on {addr}");
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let _ = stream.set_nodelay(true);
        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(TokioIo::new(stream), service_fn(handle))
                .await;
        });
    }
}
