use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context as _;
use glob::glob;
use serde_yaml::Value;

use super::{Condition, ConditionGroup, MitreAttack, Operator, Rule};

/// Load Sigma rules from `dir` and translate them into native sentinel rules.
pub fn load_sigma_dir(dir: &Path) -> anyhow::Result<Vec<Rule>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut rules = Vec::new();
    for pattern in [
        dir.join("**/*.yaml").to_string_lossy().into_owned(),
        dir.join("**/*.yml").to_string_lossy().into_owned(),
    ] {
        for entry in glob(&pattern).context("glob sigma rules")? {
            let path = entry.context("glob entry")?;
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("read sigma rule {}", path.display()))?;
            let doc: Value = serde_yaml::from_str(&raw)
                .with_context(|| format!("parse sigma yaml {}", path.display()))?;

            match translate_sigma(&doc) {
                Ok(rule) => rules.push(rule),
                Err(e) => log::warn!("skipping {}: {e:#}", path.display()),
            }
        }
    }

    if !rules.is_empty() {
        log::info!(
            "imported {} Sigma rules from {}",
            rules.len(),
            dir.display()
        );
    }
    Ok(rules)
}

fn translate_sigma(doc: &Value) -> anyhow::Result<Rule> {
    let title = field_str(doc, "title").unwrap_or_else(|| "sigma rule".into());
    let id = field_str(doc, "id").unwrap_or_else(|| title.clone());
    let description = field_str(doc, "description").unwrap_or_default();
    let level = field_str(doc, "level").unwrap_or_else(|| "medium".into());
    let tags: Vec<String> = doc
        .get("tags")
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let detection = doc
        .get("detection")
        .context("sigma rule missing detection section")?;

    let mut selections: BTreeMap<String, Vec<Condition>> = BTreeMap::new();
    if let Some(map) = detection.as_mapping() {
        for (key, value) in map {
            let name = key.as_str().unwrap_or_default();
            if name == "condition" {
                continue;
            }
            if let Some(cond_map) = value.as_mapping() {
                let mut conds = Vec::new();
                for (field_key, field_val) in cond_map {
                    let field_name = field_key.as_str().unwrap_or_default();
                    if let Some(cond) = map_sigma_field(field_name, field_val) {
                        conds.push(cond);
                    }
                }
                if !conds.is_empty() {
                    selections.insert(name.to_string(), conds);
                }
            }
        }
    }

    let condition_expr = detection
        .get("condition")
        .and_then(|v| v.as_str())
        .unwrap_or("selection");

    let kind_condition = logsource_kind(doc.get("logsource"));
    let group = build_condition_group(condition_expr, &selections)?;

    let conditions = match (kind_condition, group) {
        (Some(k), ConditionGroup::All { mut all }) => {
            all.insert(0, k);
            ConditionGroup::All { all }
        }
        (Some(k), other) => {
            let mut all = vec![k];
            all.extend(other.into_conditions());
            ConditionGroup::All { all }
        }
        (None, g) => g,
    };

    let mitre = extract_mitre(&tags);
    Ok(Rule {
        id: format!("sigma-{id}"),
        title,
        description,
        severity: map_level(&level),
        enabled: true,
        tags,
        mitre,
        conditions,
        actions: vec!["alert".into()],
    })
}

trait IntoConditions {
    fn into_conditions(self) -> Vec<Condition>;
}

impl IntoConditions for ConditionGroup {
    fn into_conditions(self) -> Vec<Condition> {
        match self {
            ConditionGroup::All { all } => all,
            ConditionGroup::Any { any } => any,
            ConditionGroup::Single(c) => vec![c],
        }
    }
}

fn build_condition_group(
    expr: &str,
    selections: &BTreeMap<String, Vec<Condition>>,
) -> anyhow::Result<ConditionGroup> {
    let expr = expr.trim();
    if let Some(inner) = expr.strip_prefix("all of ") {
        let names = parse_of_list(inner);
        let mut all = Vec::new();
        for name in names {
            all.extend(selections.get(&name).cloned().unwrap_or_default());
        }
        if all.is_empty() {
            anyhow::bail!("sigma condition references unknown selections");
        }
        return Ok(ConditionGroup::All { all });
    }
    if let Some(inner) = expr.strip_prefix("1 of ") {
        let names = parse_of_list(inner);
        let mut any = Vec::new();
        for name in names {
            any.extend(selections.get(&name).cloned().unwrap_or_default());
        }
        if any.is_empty() {
            anyhow::bail!("sigma condition references unknown selections");
        }
        return Ok(ConditionGroup::Any { any });
    }

    selections
        .get(expr)
        .cloned()
        .map(|all| ConditionGroup::All { all })
        .context("unsupported sigma condition expression")
}

fn parse_of_list(inner: &str) -> Vec<String> {
    let inner = inner.trim();
    if inner.starts_with('[') && inner.ends_with(']') {
        inner[1..inner.len() - 1]
            .split(',')
            .map(|s| s.trim().trim_matches('\'').trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else if inner == "*" {
        vec!["selection".into()]
    } else {
        vec![inner.to_string()]
    }
}

fn map_sigma_field(field: &str, value: &Value) -> Option<Condition> {
    let (name, op) = if let Some((base, modifier)) = field.split_once('|') {
        let op = match modifier {
            "endswith" => Operator::Suffix,
            "startswith" => Operator::Prefix,
            "contains" => Operator::Contains,
            "re" => Operator::Regex,
            _ => Operator::Eq,
        };
        (map_field_name(base), op)
    } else {
        (map_field_name(field), Operator::Eq)
    };

    let mapped_field = name?;
    let yaml_value = normalize_sigma_value(value);
    Some(Condition {
        field: mapped_field,
        op,
        value: yaml_value,
    })
}

fn map_field_name(sigma_field: &str) -> Option<String> {
    Some(
        match sigma_field {
            "Image" => "comm",
            "ParentImage" => "parent_comm",
            "CommandLine" => "path",
            "DestinationIp" => "dst_addr",
            "DestinationPort" => "dst_port",
            "EventID" => "kind",
            _ => return None,
        }
        .into(),
    )
}

fn normalize_sigma_value(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(s.trim_matches('\'').trim_matches('"').into()),
        other => other.clone(),
    }
}

fn logsource_kind(logsource: Option<&Value>) -> Option<Condition> {
    let category = logsource?.get("category")?.as_str()?;
    let kind = match category {
        "process_creation" => "exec",
        "network_connection" => "connect",
        "file_event" => "open",
        _ => return None,
    };
    Some(Condition {
        field: "kind".into(),
        op: Operator::Eq,
        value: Value::String(kind.into()),
    })
}

fn map_level(level: &str) -> String {
    match level.to_lowercase().as_str() {
        "informational" | "low" => "low",
        "medium" => "medium",
        "high" => "high",
        "critical" => "critical",
        _ => "medium",
    }
    .into()
}

fn extract_mitre(tags: &[String]) -> Option<MitreAttack> {
    let technique = tags.iter().find(|t| t.starts_with("attack.t"))?;
    Some(MitreAttack {
        tactic: String::new(),
        technique: technique.trim_start_matches("attack.").to_uppercase(),
        subtechnique: None,
    })
}

fn field_str(doc: &Value, key: &str) -> Option<String> {
    doc.get(key).and_then(|v| v.as_str()).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_minimal_sigma_rule() {
        let yaml = r#"
title: Suspicious Parent
id: test-sigma-001
logsource:
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '/nc'
    Image|endswith: 'bash'
  condition: selection
level: high
tags:
  - attack.t1059.004
"#;
        let doc: Value = serde_yaml::from_str(yaml).unwrap();
        let rule = translate_sigma(&doc).expect("translate");
        assert_eq!(rule.id, "sigma-test-sigma-001");
        assert_eq!(rule.severity, "high");
        assert!(rule.mitre.is_some());
    }
}
