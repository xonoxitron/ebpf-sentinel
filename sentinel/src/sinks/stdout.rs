use async_trait::async_trait;

use crate::event::{Alert, EnrichedEvent};
use crate::sinks::EventSink;

pub struct StdoutSink;

#[async_trait]
impl EventSink for StdoutSink {
    async fn emit_event(&self, event: &EnrichedEvent) -> anyhow::Result<()> {
        println!("{}", serde_json::to_string(event)?);
        Ok(())
    }

    async fn emit_alert(&self, alert: &Alert) -> anyhow::Result<()> {
        eprintln!("ALERT {}", serde_json::to_string(alert)?);
        Ok(())
    }
}
