use std::collections::HashMap;

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
    #[serde(default)]
    pub suppression: SuppressionConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_max_alerts")]
    pub max_alerts: u32,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

fn default_max_alerts() -> u32 {
    10
}

fn default_window_secs() -> u64 {
    60
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_alerts: default_max_alerts(),
            window_secs: default_window_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SuppressionConfig {
    #[serde(default)]
    pub default: RateLimitConfig,
    #[serde(default)]
    pub rules: HashMap<String, RateLimitConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_listen")]
    pub listen: String,
}

fn default_metrics_listen() -> String {
    "0.0.0.0:9090".into()
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_metrics_listen(),
        }
    }
}

impl Default for SuppressionConfig {
    fn default() -> Self {
        Self {
            default: RateLimitConfig::default(),
            rules: HashMap::new(),
        }
    }
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
            suppression: SuppressionConfig::default(),
            metrics: MetricsConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let mut cfg: Self = serde_yaml::from_str(&raw).context("parse config yaml")?;
        cfg.normalize();
        Ok(cfg)
    }

    pub fn normalize(&mut self) {
        if self.sinks.is_empty() {
            self.sinks.push(SinkConfig::Stdout);
        }
        if self.monitored_paths.is_empty() {
            self.monitored_paths = Self::default().monitored_paths;
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let rules = std::path::Path::new(&self.rules_dir);
        if !rules.is_dir() {
            anyhow::bail!("rules_dir does not exist: {}", rules.display());
        }
        for sink in &self.sinks {
            if let SinkConfig::Ndjson { path } = sink {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    if !parent.as_os_str().is_empty() && !parent.exists() {
                        std::fs::create_dir_all(parent).with_context(|| {
                            format!("create ndjson parent directory {}", parent.display())
                        })?;
                    }
                }
            }
            if let SinkConfig::Grpc { endpoint } = sink {
                if endpoint.is_empty() {
                    anyhow::bail!("grpc sink endpoint must not be empty");
                }
            }
        }
        Ok(())
    }
}
