use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use super::{AccessLogEntry, AuditLogEntry, Formatter, LogSink};

type Shared = Arc<Mutex<BufWriter<Box<dyn Write + Send>>>>;

/// How often buffered log lines are flushed to their destination.
const FLUSH_EVERY: Duration = Duration::from_millis(200);

/// A sink that writes formatted log entries to `Write` destinations.
///
/// Lines are formatted outside the lock and appended to a 64 KiB buffer
/// under it; a background thread flushes every 200 ms, and dropping the
/// sink flushes what is left. Writing straight to the file made every
/// request take the lock across a `write` system call, which serialized
/// the proxy's worker threads under load.
pub struct WriterSink {
    formatter: Box<dyn Formatter>,
    access_writer: Shared,
    audit_writer: Shared,
}

impl WriterSink {
    pub fn new(
        formatter: Box<dyn Formatter>,
        access_writer: Box<dyn Write + Send>,
        audit_writer: Box<dyn Write + Send>,
    ) -> Self {
        let access_writer: Shared = Arc::new(Mutex::new(BufWriter::with_capacity(64 * 1024, access_writer)));
        let audit_writer: Shared = Arc::new(Mutex::new(BufWriter::with_capacity(64 * 1024, audit_writer)));
        let weak: Vec<Weak<Mutex<BufWriter<Box<dyn Write + Send>>>>> =
            vec![Arc::downgrade(&access_writer), Arc::downgrade(&audit_writer)];
        let _ = std::thread::Builder::new()
            .name("openshield-log-flush".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(FLUSH_EVERY);
                    let mut alive = false;
                    for w in &weak {
                        if let Some(w) = w.upgrade() {
                            alive = true;
                            if let Ok(mut g) = w.lock() {
                                let _ = g.flush();
                            }
                        }
                    }
                    if !alive {
                        break;
                    }
                }
            });
        Self {
            formatter,
            access_writer,
            audit_writer,
        }
    }

    /// Write out buffered lines now.
    pub fn flush(&self) {
        for w in [&self.access_writer, &self.audit_writer] {
            if let Ok(mut g) = w.lock() {
                let _ = g.flush();
            }
        }
    }
}

impl Drop for WriterSink {
    fn drop(&mut self) {
        self.flush();
    }
}

impl LogSink for WriterSink {
    fn on_access(&self, entry: &AccessLogEntry) {
        let bytes = self.formatter.format_access(entry);
        if let Ok(mut writer) = self.access_writer.lock() {
            let _ = writer.write_all(&bytes);
        }
    }

    fn on_audit(&self, entry: &AuditLogEntry) {
        let bytes = self.formatter.format_audit(entry);
        if let Ok(mut writer) = self.audit_writer.lock() {
            let _ = writer.write_all(&bytes);
        }
    }
}

pub fn open_writer(path: &Path) -> Box<dyn Write + Send> {
    match path.to_str() {
        Some("/dev/stdout") => Box::new(std::io::stdout()),
        Some("/dev/stderr") => Box::new(std::io::stderr()),
        _ => {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap_or_else(|e| panic!("Failed to open log file {:?}: {}", path, e));
            Box::new(file)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::logging::{AccessLogEntry, JsonFormatter};

    #[derive(Clone, Default)]
    struct Mem(Arc<Mutex<Vec<u8>>>);
    impl Write for Mem {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn entry() -> AccessLogEntry {
        AccessLogEntry {
            request_id: "r".into(),
            timestamp: "t".into(),
            client_ip: "-".into(),
            method: "GET".into(),
            protocol: "HTTP/1.1".into(),
            host: "h".into(),
            path: "/".into(),
            query: String::new(),
            status: 200,
            duration_ms: 1.0,
            bytes_received: 0,
            bytes_sent: 0,
            error: None,
        }
    }

    #[test]
    fn lines_reach_the_destination_after_flush_or_drop() {
        let out = Mem::default();
        let sink = WriterSink::new(Box::new(JsonFormatter), Box::new(out.clone()), Box::new(Mem::default()));
        sink.on_access(&entry());
        // Buffered: not written yet.
        assert!(out.0.lock().unwrap().is_empty());
        // The background flush writes it within a few periods.
        std::thread::sleep(FLUSH_EVERY * 3);
        assert!(!out.0.lock().unwrap().is_empty());
        sink.on_access(&entry());
        drop(sink);
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().count(), 2, "drop flushes the rest");
    }
}
