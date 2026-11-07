//! Native Apache Arrow IPC HTTP emitter for `MuObserve-collector` (`/v1/metrics` and `/v1/logs`).

use crate::error::SentinelError;
use mu_observable_ipc::{encode_log_batch, encode_metric_batch, OtelLogEntry, OtelMetricEntry};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Minimal, zero-bloat HTTP/1.1 client that encodes `OtelMetricEntry` and `OtelLogEntry` batches
/// into Apache Arrow IPC streams (`application/vnd.apache.arrow.stream`) and POSTs them to
/// `MuObserve-collector` (`http://127.0.0.1:4318`).
#[derive(Debug, Clone)]
pub struct CollectorArrowEmitter {
    host_port: String,
}

impl CollectorArrowEmitter {
    /// Creates a new [`CollectorArrowEmitter`] targeting `collector_url` (e.g., `http://127.0.0.1:4318`).
    pub fn new(collector_url: &str) -> Self {
        let stripped = collector_url
            .trim()
            .strip_prefix("http://")
            .unwrap_or(collector_url.trim())
            .trim_end_matches('/');
        let host_port = if stripped.contains(':') {
            stripped.to_string()
        } else {
            format!("{stripped}:4318")
        };
        Self { host_port }
    }

    /// Returns the normalized `host:port` endpoint.
    #[must_use]
    pub fn host_port(&self) -> &str {
        &self.host_port
    }

    /// Encodes and POSTs a batch of [`OtelMetricEntry`] items to `/v1/metrics`.
    pub async fn emit_metrics(&self, entries: &[OtelMetricEntry]) -> Result<(), SentinelError> {
        if entries.is_empty() {
            return Ok(());
        }
        let payload = encode_metric_batch(entries)?;
        self.post_arrow_stream("/v1/metrics", &payload).await
    }

    /// Encodes and POSTs a batch of [`OtelLogEntry`] items to `/v1/logs`.
    pub async fn emit_logs(&self, entries: &[OtelLogEntry]) -> Result<(), SentinelError> {
        if entries.is_empty() {
            return Ok(());
        }
        let payload = encode_log_batch(entries)?;
        self.post_arrow_stream("/v1/logs", &payload).await
    }

    async fn post_arrow_stream(&self, path: &str, body: &[u8]) -> Result<(), SentinelError> {
        let mut stream = TcpStream::connect(&self.host_port).await?;
        let req_header = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/vnd.apache.arrow.stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.host_port,
            body.len()
        );
        stream.write_all(req_header.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.flush().await?;

        let mut resp_buf = Vec::with_capacity(512);
        stream.read_to_end(&mut resp_buf).await?;
        let resp_str = String::from_utf8_lossy(&resp_buf);
        let status_line = resp_str.lines().next().unwrap_or("");
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(500);

        if (200..300).contains(&status_code) {
            Ok(())
        } else {
            Err(SentinelError::CollectorHttp {
                status: status_code,
                detail: status_line.to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emitter_url_normalization() {
        let emitter = CollectorArrowEmitter::new("http://127.0.0.1:4318/");
        assert_eq!(emitter.host_port(), "127.0.0.1:4318");
    }
}
