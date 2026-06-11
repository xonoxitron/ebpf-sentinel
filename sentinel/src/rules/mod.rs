use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::Context as _;
use glob::glob;
use regex::Regex;
use serde::Deserialize;

use crate::event::{Alert, EnrichedEvent, MitreAttack};

#[derive(Debug, Clone, Deserialize)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(alias = "name")]
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub mitre: Option<MitreAttack>,
    pub conditions: ConditionGroup,
    #[serde(default)]
    pub actions: Vec<String>,
}

fn default_severity() -> String {
    "medium".into()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RuleFile {
    Set(RuleSet),
    Single(Box<Rule>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ConditionGroup {
    All { all: Vec<Condition> },
    Any { any: Vec<Condition> },
    Single(Condition),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Condition {
    pub field: String,
    pub op: Operator,
    #[serde(default)]
    pub value: serde_yaml::Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Eq,
    Ne,
    Contains,
    Prefix,
    Suffix,
    #[serde(alias = "matches")]
    Regex,
    Gt,
    Lt,
}

struct CompiledRule {
    rule: Rule,
    regexes: HashMap<String, Regex>,
}

pub struct RuleEngine {
    rules: Vec<CompiledRule>,
}

impl RuleEngine {
    pub fn load_dir(dir: &Path) -> anyhow::Result<Self> {
        let pattern = dir.join("**/*.yaml").to_string_lossy().into_owned();
        let mut rules = Vec::new();

        for entry in glob(&pattern).context("glob rules")? {
            let path = entry.context("glob entry")?;
            if path.extension().and_then(|e| e.to_str()) == Some("yml") {
                continue;
            }
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("read rule file {}", path.display()))?;
            let parsed: RuleFile = serde_yaml::from_str(&raw)
                .with_context(|| format!("parse rules in {}", path.display()))?;
            match parsed {
                RuleFile::Set(set) => rules.extend(set.rules),
                RuleFile::Single(rule) => rules.push(*rule),
            }
        }

        let mut seen = HashSet::new();
        for rule in &rules {
            if !seen.insert(rule.id.clone()) {
                anyhow::bail!("duplicate detection rule id: {}", rule.id);
            }
        }

        let compiled = rules
            .into_iter()
            .map(CompiledRule::new)
            .collect::<anyhow::Result<Vec<_>>>()?;

        if compiled.is_empty() {
            log::warn!("no detection rules loaded from {}", dir.display());
        } else {
            log::info!(
                "loaded {} detection rules from {}",
                compiled.len(),
                dir.display()
            );
        }
        Ok(Self { rules: compiled })
    }

    pub fn evaluate(&self, event: &EnrichedEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let now = event.timestamp_ns;

        for compiled in &self.rules {
            let rule = &compiled.rule;
            if !rule.enabled {
                continue;
            }
            if self.matches(compiled, event) {
                alerts.push(Alert {
                    rule_id: rule.id.clone(),
                    title: rule.title.clone(),
                    severity: rule.severity.clone(),
                    description: rule.description.clone(),
                    tags: rule.tags.clone(),
                    mitre: rule.mitre.clone(),
                    event: event.clone(),
                    triage: None,
                    timestamp_ns: now,
                });
            }
        }
        alerts
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn should_triage(&self, rule_id: &str) -> bool {
        self.rules
            .iter()
            .find(|r| r.rule.id == rule_id)
            .map(|r| r.rule.actions.iter().any(|a| a == "triage"))
            .unwrap_or(false)
    }

    pub fn should_alert(&self, rule_id: &str) -> bool {
        self.rules
            .iter()
            .find(|r| r.rule.id == rule_id)
            .map(|r| r.rule.actions.is_empty() || r.rule.actions.iter().any(|a| a == "alert"))
            .unwrap_or(true)
    }

    fn matches(&self, compiled: &CompiledRule, event: &EnrichedEvent) -> bool {
        match &compiled.rule.conditions {
            ConditionGroup::All { all } => {
                all.iter().all(|c| self.match_condition(compiled, c, event))
            }
            ConditionGroup::Any { any } => {
                any.iter().any(|c| self.match_condition(compiled, c, event))
            }
            ConditionGroup::Single(c) => self.match_condition(compiled, c, event),
        }
    }

    fn match_condition(
        &self,
        compiled: &CompiledRule,
        cond: &Condition,
        event: &EnrichedEvent,
    ) -> bool {
        let field_val = match event.field(&cond.field) {
            Some(v) => v,
            None => return false,
        };

        match cond.op {
            Operator::Eq => value_as_str(&cond.value)
                .map(|expected| field_val.eq_ignore_ascii_case(expected))
                .unwrap_or(false),
            Operator::Ne => value_as_str(&cond.value)
                .map(|expected| !field_val.eq_ignore_ascii_case(expected))
                .unwrap_or(true),
            Operator::Contains => value_as_str(&cond.value)
                .map(|needle| field_val.contains(needle))
                .unwrap_or(false),
            Operator::Prefix => value_as_str(&cond.value)
                .map(|prefix| field_val.starts_with(prefix))
                .unwrap_or(false),
            Operator::Suffix => value_as_str(&cond.value)
                .map(|suffix| field_val.ends_with(suffix))
                .unwrap_or(false),
            Operator::Regex => compiled
                .regexes
                .get(&cond.field)
                .map(|re| re.is_match(&field_val))
                .unwrap_or(false),
            Operator::Gt => parse_u64(&field_val)
                .zip(value_as_u64(&cond.value))
                .map(|(a, b)| a > b)
                .unwrap_or(false),
            Operator::Lt => parse_u64(&field_val)
                .zip(value_as_u64(&cond.value))
                .map(|(a, b)| a < b)
                .unwrap_or(false),
        }
    }
}

impl CompiledRule {
    fn new(rule: Rule) -> anyhow::Result<Self> {
        let mut regexes = HashMap::new();
        for cond in rule.conditions.iter_conditions() {
            if matches!(cond.op, Operator::Regex) {
                if let Some(pattern) = value_as_str(&cond.value) {
                    let re = Regex::new(pattern)
                        .with_context(|| format!("compile regex for rule {}", rule.id))?;
                    regexes.insert(cond.field.clone(), re);
                }
            }
        }
        Ok(Self { rule, regexes })
    }
}

impl ConditionGroup {
    fn iter_conditions(&self) -> Vec<&Condition> {
        match self {
            ConditionGroup::All { all } => all.iter().collect(),
            ConditionGroup::Any { any } => any.iter().collect(),
            ConditionGroup::Single(c) => vec![c],
        }
    }
}

fn value_as_str(value: &serde_yaml::Value) -> Option<&str> {
    value.as_str()
}

fn value_as_u64(value: &serde_yaml::Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_i64().map(|v| v as u64))
}

fn parse_u64(s: &str) -> Option<u64> {
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(kind: &str, path: &str, uid: u32) -> EnrichedEvent {
        EnrichedEvent {
            kind: kind.into(),
            pid: 1000,
            ppid: 1,
            uid,
            gid: 0,
            timestamp_ns: 1,
            timestamp: None,
            comm: "bash".into(),
            parent_comm: "nc".into(),
            path: path.into(),
            addr_family: None,
            dst_addr: None,
            dst_port: None,
            flags: 0,
            lineage: vec![],
            host: "test".into(),
            container_id: None,
            pod_name: None,
            pod_namespace: None,
            pod_image: None,
        }
    }

    #[test]
    fn matches_exec_from_tmp() {
        let engine = RuleEngine {
            rules: vec![CompiledRule::new(Rule {
                id: "exec-from-tmp".into(),
                title: "tmp exec".into(),
                description: String::new(),
                severity: "high".into(),
                enabled: true,
                tags: vec![],
                mitre: None,
                conditions: ConditionGroup::All {
                    all: vec![
                        Condition {
                            field: "kind".into(),
                            op: Operator::Eq,
                            value: serde_yaml::Value::String("exec".into()),
                        },
                        Condition {
                            field: "path".into(),
                            op: Operator::Prefix,
                            value: serde_yaml::Value::String("/tmp/".into()),
                        },
                    ],
                },
                actions: vec!["alert".into()],
            })
            .unwrap()],
        };

        let hit = engine.evaluate(&sample_event("exec", "/tmp/evil", 1000));
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].rule_id, "exec-from-tmp");

        let miss = engine.evaluate(&sample_event("exec", "/usr/bin/ls", 1000));
        assert!(miss.is_empty());
    }

    #[test]
    fn loads_rules_from_directory() {
        let rules_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rules");
        let engine = RuleEngine::load_dir(&rules_dir).expect("load bundled rules");
        assert!(engine.len() >= 5);
    }

    #[test]
    fn matches_reverse_shell_pattern() {
        let engine = RuleEngine {
            rules: vec![CompiledRule::new(Rule {
                id: "T1059.004-001".into(),
                title: "shell from network utility".into(),
                description: String::new(),
                severity: "critical".into(),
                enabled: true,
                tags: vec![],
                mitre: Some(MitreAttack {
                    tactic: "Execution".into(),
                    technique: "T1059.004".into(),
                    subtechnique: None,
                }),
                conditions: ConditionGroup::All {
                    all: vec![
                        Condition {
                            field: "comm".into(),
                            op: Operator::Regex,
                            value: serde_yaml::Value::String("^(bash|sh)$".into()),
                        },
                        Condition {
                            field: "parent_comm".into(),
                            op: Operator::Regex,
                            value: serde_yaml::Value::String("^(nc|ncat)$".into()),
                        },
                    ],
                },
                actions: vec!["alert".into()],
            })
            .unwrap()],
        };

        let hit = engine.evaluate(&sample_event("exec", "/bin/bash", 1000));
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].mitre.as_ref().unwrap().technique, "T1059.004");
    }
}
