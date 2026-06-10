use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MitreAttack {
    pub tactic: String,
    pub technique: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtechnique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageOutcome {
    pub severity: String,
    pub summary: String,
    pub reasoning: String,
    pub mitre: Vec<String>,
    pub remediation: Vec<String>,
    pub false_positive_likelihood: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedEvent {
    pub kind: String,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_ns: u64,
    pub timestamp: Option<String>,
    pub comm: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub parent_comm: String,
    pub path: String,
    pub dst_addr: Option<String>,
    pub dst_port: Option<u16>,
    pub flags: u32,
    pub lineage: Vec<String>,
    pub host: String,
}

impl EnrichedEvent {
    pub fn field(&self, name: &str) -> Option<String> {
        match name {
            "kind" => Some(self.kind.to_lowercase()),
            "pid" => Some(self.pid.to_string()),
            "ppid" => Some(self.ppid.to_string()),
            "uid" => Some(self.uid.to_string()),
            "gid" => Some(self.gid.to_string()),
            "comm" => Some(self.comm.clone()),
            "parent_comm" => Some(self.parent_comm.clone()),
            "path" | "filename" => Some(self.path.clone()),
            "dst_addr" | "dst" => self.dst_addr.clone(),
            "dst_port" => self.dst_port.map(|p| p.to_string()),
            "flags" => Some(self.flags.to_string()),
            "host" => Some(self.host.clone()),
            "lineage" => Some(self.lineage.join(",")),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mitre: Option<MitreAttack>,
    pub event: EnrichedEvent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triage: Option<TriageOutcome>,
    pub timestamp_ns: u64,
}
