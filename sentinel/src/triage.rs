use serde::{Deserialize, Serialize};

use crate::config::TriageConfig;
use crate::event::{Alert, TriageOutcome};

#[derive(Serialize)]
struct MessagesRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<Message>,
}

#[derive(Serialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct MessagesResponse {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct ContentBlock {
    text: String,
}

#[derive(Deserialize)]
struct TriageResult {
    severity: String,
    summary: String,
    reasoning: String,
    mitre: Vec<String>,
    remediation: Vec<String>,
    false_positive_likelihood: f64,
}

pub struct ClaudeTriage {
    config: TriageConfig,
    client: reqwest::Client,
    api_key: Option<String>,
}

impl ClaudeTriage {
    pub fn new(config: TriageConfig) -> Self {
        let api_key = std::env::var(&config.api_key_env).ok();
        if config.enabled && api_key.is_none() {
            log::warn!("triage enabled but {} is not set", config.api_key_env);
        }
        Self {
            config,
            client: reqwest::Client::new(),
            api_key,
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled && self.api_key.is_some()
    }

    pub async fn triage(&self, alert: &Alert) -> anyhow::Result<TriageOutcome> {
        let api_key = self
            .api_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing anthropic api key"))?;

        let mitre_hint = alert
            .mitre
            .as_ref()
            .map(|m| {
                format!(
                    "Mapped MITRE ATT&CK: tactic={}, technique={}",
                    m.tactic, m.technique
                )
            })
            .unwrap_or_default();

        let prompt = format!(
            "You are a senior detection engineer triaging alerts on Linux nodes that run \
             AI/ML workloads (PyTorch distributed training, GPU inference, large Python \
             processes, checkpoint I/O, and outbound experiment telemetry).\n\
             Distinguish benign ML infrastructure behavior from true positives. Be precise.\n\n\
             Respond ONLY with valid JSON matching this schema:\n\
             {{\n\
               \"severity\": string,\n\
               \"summary\": string,\n\
               \"reasoning\": string,\n\
               \"mitre\": [string],\n\
               \"remediation\": [string],\n\
               \"false_positive_likelihood\": number\n\
             }}\n\n\
             Alert:\n\
             rule_id: {}\n\
             title: {}\n\
             severity: {}\n\
             description: {}\n\
             tags: {:?}\n\
             {}\n\
             event: {}",
            alert.rule_id,
            alert.title,
            alert.severity,
            alert.description,
            alert.tags,
            mitre_hint,
            serde_json::to_string(&alert.event)?
        );

        let body = MessagesRequest {
            model: self.config.model.clone(),
            max_tokens: self.config.max_tokens,
            messages: vec![Message {
                role: "user".into(),
                content: prompt,
            }],
        };

        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("anthropic api error {status}: {text}");
        }

        let parsed: MessagesResponse = resp.json().await?;
        let text = parsed
            .content
            .into_iter()
            .next()
            .map(|b| b.text)
            .unwrap_or_default();

        let triage: TriageResult =
            serde_json::from_str(extract_json(&text)).unwrap_or(TriageResult {
                severity: alert.severity.clone(),
                summary: text.clone(),
                reasoning: "Claude response was not valid JSON; manual review required.".into(),
                mitre: vec![],
                remediation: vec!["Review alert manually.".into()],
                false_positive_likelihood: 0.5,
            });

        Ok(TriageOutcome {
            severity: triage.severity,
            summary: triage.summary,
            reasoning: triage.reasoning,
            mitre: triage.mitre,
            remediation: triage.remediation,
            false_positive_likelihood: triage.false_positive_likelihood,
        })
    }
}

fn extract_json(text: &str) -> &str {
    if let Some(start) = text.find('{') {
        if let Some(end) = text.rfind('}') {
            return &text[start..=end];
        }
    }
    text
}
