use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::event::{Alert, EnrichedEvent};
use crate::sinks::EventSink;

pub struct NdjsonSink {
    path: String,
    file: Mutex<std::fs::File>,
}

impl NdjsonSink {
    pub fn new(path: &str) -> anyhow::Result<Self> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            path: path.to_string(),
            file: Mutex::new(file),
        })
    }

    fn write_line(&self, value: &impl serde::Serialize) -> anyhow::Result<()> {
        let line = serde_json::to_string(value)?;
        let mut file = self.file.lock().unwrap();
        writeln!(file, "{line}")?;
        file.flush()?;
        Ok(())
    }
}

#[async_trait]
impl EventSink for NdjsonSink {
    async fn emit_event(&self, event: &EnrichedEvent) -> anyhow::Result<()> {
        self.write_line(&serde_json::json!({
            "record_type": "event",
            "data": event,
        }))
    }

    async fn emit_alert(&self, alert: &Alert) -> anyhow::Result<()> {
        self.write_line(&serde_json::json!({
            "record_type": "alert",
            "data": alert,
        }))
    }

    async fn flush(&self) -> anyhow::Result<()> {
        let mut file = self.file.lock().unwrap();
        file.flush()?;
        Ok(())
    }
}

impl Drop for NdjsonSink {
    fn drop(&mut self) {
        log::debug!("closing ndjson sink {}", self.path);
    }
}
