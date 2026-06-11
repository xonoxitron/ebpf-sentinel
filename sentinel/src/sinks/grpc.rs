use async_trait::async_trait;
use tonic::transport::Channel;

use crate::event::{Alert, EnrichedEvent, MitreAttack, TriageOutcome};
use crate::sinks::EventSink;

pub mod pb {
    tonic::include_proto!("sentinel.v1");
}

use pb::sentinel_ingest_client::SentinelIngestClient;
use pb::{Alert as PbAlert, Event as PbEvent, MitreAttack as PbMitre, TriageOutcome as PbTriage};

pub struct GrpcSink {
    endpoint: String,
    client: tokio::sync::Mutex<Option<SentinelIngestClient<Channel>>>,
}

impl GrpcSink {
    pub fn new(endpoint: &str) -> anyhow::Result<Self> {
        Ok(Self {
            endpoint: endpoint.to_string(),
            client: tokio::sync::Mutex::new(None),
        })
    }

    async fn client(&self) -> anyhow::Result<SentinelIngestClient<Channel>> {
        let mut guard = self.client.lock().await;
        if guard.is_none() {
            let channel = Channel::from_shared(self.endpoint.clone())?
                .connect()
                .await?;
            *guard = Some(SentinelIngestClient::new(channel));
        }
        Ok(guard.as_ref().unwrap().clone())
    }
}

fn event_to_pb(event: &EnrichedEvent) -> PbEvent {
    PbEvent {
        kind: event.kind.clone(),
        pid: event.pid,
        ppid: event.ppid,
        uid: event.uid,
        gid: event.gid,
        timestamp_ns: event.timestamp_ns,
        comm: event.comm.clone(),
        path: event.path.clone(),
        dst_addr: event
            .dst_addr
            .as_ref()
            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
            .map(u32::from)
            .unwrap_or(0),
        dst_port: event.dst_port.unwrap_or(0) as u32,
        flags: event.flags,
        lineage: event.lineage.clone(),
        host: event.host.clone(),
        parent_comm: event.parent_comm.clone(),
        addr_family: event.addr_family.unwrap_or(0) as u32,
        dst_addr_v6: if event.addr_family == Some(sentinel_common::AF_INET6) {
            event.dst_addr.clone().unwrap_or_default()
        } else {
            String::new()
        },
        container_id: event.container_id.clone().unwrap_or_default(),
        pod_name: event.pod_name.clone().unwrap_or_default(),
        pod_namespace: event.pod_namespace.clone().unwrap_or_default(),
        pod_image: event.pod_image.clone().unwrap_or_default(),
    }
}

fn mitre_to_pb(m: &MitreAttack) -> PbMitre {
    PbMitre {
        tactic: m.tactic.clone(),
        technique: m.technique.clone(),
        subtechnique: m.subtechnique.clone().unwrap_or_default(),
    }
}

fn triage_to_pb(t: &TriageOutcome) -> PbTriage {
    PbTriage {
        severity: t.severity.clone(),
        summary: t.summary.clone(),
        reasoning: t.reasoning.clone(),
        mitre: t.mitre.clone(),
        remediation: t.remediation.clone(),
        false_positive_likelihood: t.false_positive_likelihood,
    }
}

fn alert_to_pb(alert: &Alert) -> PbAlert {
    PbAlert {
        rule_id: alert.rule_id.clone(),
        title: alert.title.clone(),
        severity: alert.severity.clone(),
        description: alert.description.clone(),
        tags: alert.tags.clone(),
        event: Some(event_to_pb(&alert.event)),
        timestamp_ns: alert.timestamp_ns,
        host: alert.event.host.clone(),
        mitre: alert.mitre.as_ref().map(mitre_to_pb),
        triage: alert.triage.as_ref().map(triage_to_pb),
    }
}

#[async_trait]
impl EventSink for GrpcSink {
    async fn emit_event(&self, event: &EnrichedEvent) -> anyhow::Result<()> {
        let mut client = self.client().await?;
        let _ = client
            .publish_event(tonic::Request::new(event_to_pb(event)))
            .await?;
        Ok(())
    }

    async fn emit_alert(&self, alert: &Alert) -> anyhow::Result<()> {
        let mut client = self.client().await?;
        let _ = client
            .publish_alert(tonic::Request::new(alert_to_pb(alert)))
            .await?;
        Ok(())
    }
}
