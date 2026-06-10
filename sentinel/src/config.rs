use anyhow::Context as _;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default = "default_rules_dir")]
    pub rules_dir: String,
    #[serde(default)]
    pub monitored_paths: Vec<String>,
    #[serde(default)]
    pub sinks: Vec<SinkConfig>,
    #[serde(default)]
    pub triage: TriageConfig,
    #[serde(default = "default_host")]
    pub host: String,
}

fn default_rules_dir() -> String {
    "rules".into()
}

fn default_host() -> String {
    hostname()
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "localhost".into())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SinkConfig {
    Stdout,
    Ndjson { path: String },
    Grpc { endpoint: String },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TriageConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
}

fn default_api_key_env() -> String {
    "ANTHROPIC_API_KEY".into()
}

fn default_model() -> String {
    "claude-sonnet-4-20250514".into()
}

fn default_max_tokens() -> u32 {
    1024
}

impl Default for TriageConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key_env: default_api_key_env(),
            model: default_model(),
            max_tokens: default_max_tokens(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rules_dir: default_rules_dir(),
            monitored_paths: vec![
                "/etc/passwd".into(),
                "/etc/shadow".into(),
                "/etc/sudoers".into(),
            ],
            sinks: vec![SinkConfig::Stdout],
            triage: TriageConfig::default(),
            host: default_host(),
        }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        serde_yaml::from_str(&raw).context("parse config yaml")
    }
}
