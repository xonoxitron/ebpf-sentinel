//! Example SOAR ingest server that receives sentinel events and alerts over gRPC.

use tonic::{transport::Server, Request, Response, Status};

pub mod pb {
    tonic::include_proto!("sentinel.v1");
}

use pb::sentinel_ingest_server::{SentinelIngest, SentinelIngestServer};
use pb::{Alert, Event, StreamAck};

#[derive(Default)]
struct IngestService;

#[tonic::async_trait]
impl SentinelIngest for IngestService {
    async fn publish_event(
        &self,
        request: Request<Event>,
    ) -> Result<Response<StreamAck>, Status> {
        let event = request.into_inner();
        println!(
            "EVENT kind={} pid={} comm={} parent_comm={}",
            event.kind, event.pid, event.comm, event.parent_comm
        );
        Ok(Response::new(StreamAck { received: 1 }))
    }

    async fn publish_alert(
        &self,
        request: Request<Alert>,
    ) -> Result<Response<StreamAck>, Status> {
        let alert = request.into_inner();
        eprintln!(
            "ALERT [{}] {} severity={}",
            alert.rule_id, alert.title, alert.severity
        );
        if let Some(triage) = alert.triage {
            eprintln!("  triage: {} (fp={:.2})", triage.summary, triage.false_positive_likelihood);
            for step in triage.remediation {
                eprintln!("    - {step}");
            }
        }
        Ok(Response::new(StreamAck { received: 1 }))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = std::env::var("SENTINEL_GRPC_ADDR").unwrap_or_else(|_| "0.0.0.0:50051".into());
    let addr = addr.parse()?;

    println!("sentinel gRPC ingest listening on {addr}");
    Server::builder()
        .add_service(SentinelIngestServer::new(IngestService))
        .serve(addr)
        .await?;

    Ok(())
}
