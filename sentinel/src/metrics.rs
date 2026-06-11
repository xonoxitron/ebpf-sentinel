use std::sync::Arc;

use prometheus::{Counter, CounterVec, Encoder, Opts, Registry, TextEncoder};

#[derive(Clone)]
pub struct SentinelMetrics {
    registry: Registry,
    events_total: CounterVec,
    alerts_total: CounterVec,
    alerts_suppressed_total: CounterVec,
    ring_parse_errors_total: Counter,
}

impl SentinelMetrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();

        let events_total = CounterVec::new(
            Opts::new("sentinel_events_total", "Telemetry events processed"),
            &["kind", "host"],
        )?;
        registry.register(Box::new(events_total.clone()))?;

        let alerts_total = CounterVec::new(
            Opts::new("sentinel_alerts_total", "Alerts emitted to sinks"),
            &["rule_id", "severity", "host"],
        )?;
        registry.register(Box::new(alerts_total.clone()))?;

        let alerts_suppressed_total = CounterVec::new(
            Opts::new(
                "sentinel_alerts_suppressed_total",
                "Alerts suppressed by rate limiting",
            ),
            &["rule_id"],
        )?;
        registry.register(Box::new(alerts_suppressed_total.clone()))?;

        let ring_parse_errors_total = Counter::new(
            "sentinel_ring_parse_errors_total",
            "Ring buffer records dropped due to invalid size",
        )?;
        registry.register(Box::new(ring_parse_errors_total.clone()))?;

        Ok(Self {
            registry,
            events_total,
            alerts_total,
            alerts_suppressed_total,
            ring_parse_errors_total,
        })
    }

    pub fn inc_event(&self, kind: &str, host: &str) {
        self.events_total.with_label_values(&[kind, host]).inc();
    }

    pub fn inc_alert(&self, rule_id: &str, severity: &str, host: &str) {
        self.alerts_total
            .with_label_values(&[rule_id, severity, host])
            .inc();
    }

    pub fn inc_suppressed(&self, rule_id: &str) {
        self.alerts_suppressed_total
            .with_label_values(&[rule_id])
            .inc();
    }

    pub fn inc_ring_parse_error(&self) {
        self.ring_parse_errors_total.inc();
    }

    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        let metric_families = self.registry.gather();
        let mut buf = Vec::new();
        TextEncoder::new().encode(&metric_families, &mut buf)?;
        Ok(buf)
    }

    pub fn metric_names(&self) -> Vec<&'static str> {
        vec![
            "sentinel_events_total",
            "sentinel_alerts_total",
            "sentinel_alerts_suppressed_total",
            "sentinel_ring_parse_errors_total",
        ]
    }
}

pub async fn serve_metrics(listen: String, metrics: Arc<SentinelMetrics>) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    log::info!("Prometheus metrics on http://{listen}/metrics");

    loop {
        let (mut stream, _) = listener.accept().await?;
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let encoded = metrics.encode().unwrap_or_default();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                encoded.len()
            );
            let _ = stream.write_all(header.as_bytes()).await;
            let _ = stream.write_all(&encoded).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_expected_metric_names() {
        let m = SentinelMetrics::new().expect("metrics");
        let names = m.metric_names();
        assert!(names.contains(&"sentinel_events_total"));
        assert!(names.contains(&"sentinel_alerts_total"));
    }

    #[test]
    fn encodes_prometheus_text() {
        let m = SentinelMetrics::new().expect("metrics");
        m.inc_event("exec", "host1");
        let body = m.encode().expect("encode");
        let text = String::from_utf8(body).expect("utf8");
        assert!(text.contains("sentinel_events_total"));
    }
}
