mod grpc;
mod ndjson;
mod stdout;

use async_trait::async_trait;

use crate::config::SinkConfig;
use crate::event::{Alert, EnrichedEvent};

pub use grpc::GrpcSink;
pub use ndjson::NdjsonSink;
pub use stdout::StdoutSink;

#[async_trait]
pub trait EventSink: Send + Sync {
    async fn emit_event(&self, event: &EnrichedEvent) -> anyhow::Result<()>;
    async fn emit_alert(&self, alert: &Alert) -> anyhow::Result<()>;
    async fn flush(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

pub fn build_sinks(configs: &[SinkConfig]) -> anyhow::Result<Vec<Box<dyn EventSink>>> {
    let configs = if configs.is_empty() {
        std::slice::from_ref(&SinkConfig::Stdout)
    } else {
        configs
    };
    let mut sinks: Vec<Box<dyn EventSink>> = Vec::new();
    for cfg in configs {
        let sink: Box<dyn EventSink> = match cfg {
            SinkConfig::Stdout => Box::new(StdoutSink),
            SinkConfig::Ndjson { path } => Box::new(NdjsonSink::new(path)?),
            SinkConfig::Grpc { endpoint } => Box::new(GrpcSink::new(endpoint)?),
        };
        sinks.push(sink);
    }
    Ok(sinks)
}

pub struct MultiSink {
    sinks: Vec<Box<dyn EventSink>>,
}

impl MultiSink {
    pub fn new(sinks: Vec<Box<dyn EventSink>>) -> Self {
        Self { sinks }
    }

    pub async fn emit_event(&self, event: &EnrichedEvent) -> anyhow::Result<()> {
        for sink in &self.sinks {
            sink.emit_event(event).await?;
        }
        Ok(())
    }

    pub async fn emit_alert(&self, alert: &Alert) -> anyhow::Result<()> {
        for sink in &self.sinks {
            sink.emit_alert(alert).await?;
        }
        Ok(())
    }

    pub async fn flush(&self) -> anyhow::Result<()> {
        for sink in &self.sinks {
            sink.flush().await?;
        }
        Ok(())
    }
}
