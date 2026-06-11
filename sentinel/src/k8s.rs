use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Context as _;
use regex::Regex;
use tokio::time;

use crate::config::K8sConfig;

pub mod cri {
    tonic::include_proto!("runtime.v1");
}

use cri::runtime_service_client::RuntimeServiceClient;
use cri::{ListContainersRequest, ListPodSandboxRequest};

#[derive(Debug, Clone, Default)]
pub struct ContainerMeta {
    pub container_id: String,
    pub pod_name: String,
    pub pod_namespace: String,
    pub pod_image: String,
    pub pod_uid: String,
}

#[derive(Clone)]
pub struct K8sMetadataCache {
    inner: Arc<RwLock<HashMap<String, ContainerMeta>>>,
    config: K8sConfig,
}

impl K8sMetadataCache {
    pub fn new(config: K8sConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    pub fn lookup_by_pid(&self, pid: u32) -> Option<ContainerMeta> {
        let container_id = container_id_from_pid(pid)?;
        self.lookup_by_container_id(&container_id)
    }

    pub fn lookup_by_container_id(&self, container_id: &str) -> Option<ContainerMeta> {
        let guard = self.inner.read().ok()?;
        guard.get(container_id).cloned()
    }

    pub async fn refresh_loop(self: Arc<Self>) {
        let ttl = Duration::from_secs(self.config.cache_ttl_secs.max(5));
        loop {
            if let Err(e) = self.refresh_once().await {
                log::warn!("CRI metadata refresh failed: {e:#}");
            }
            time::sleep(ttl).await;
        }
    }

    async fn refresh_once(&self) -> anyhow::Result<()> {
        let mut client = connect_cri(&self.config.cri_socket).await?;
        let sandboxes = client
            .list_pod_sandbox(ListPodSandboxRequest::default())
            .await?
            .into_inner()
            .items;

        let mut sandbox_meta = HashMap::new();
        for sb in sandboxes {
            if let Some(meta) = sb.metadata {
                sandbox_meta.insert(sb.id, (meta.name, meta.namespace, meta.uid));
            }
        }

        let containers = client
            .list_containers(ListContainersRequest::default())
            .await?
            .into_inner()
            .containers;

        let mut map = HashMap::new();
        for c in containers {
            let full_id = c.id;
            let short_id = full_id
                .strip_prefix("containerd://")
                .unwrap_or(&full_id)
                .to_string();
            let (pod_name, pod_namespace, pod_uid) = sandbox_meta
                .get(&c.pod_sandbox_id)
                .cloned()
                .unwrap_or_default();
            let image = c
                .image
                .map(|img| img.image)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| c.image_ref.clone());

            let meta = ContainerMeta {
                container_id: short_id.clone(),
                pod_name,
                pod_namespace,
                pod_image: image,
                pod_uid,
            };
            map.insert(short_id, meta.clone());
            if !full_id.is_empty() {
                map.insert(full_id, meta);
            }
        }

        if let Ok(mut guard) = self.inner.write() {
            *guard = map;
            log::debug!("CRI cache refreshed ({} containers)", guard.len());
        }
        Ok(())
    }
}

pub fn container_id_from_pid(pid: u32) -> Option<String> {
    let cgroup_path = format!("/proc/{pid}/cgroup");
    let contents = std::fs::read_to_string(&cgroup_path).ok()?;
    container_id_from_cgroup(&contents)
}

pub fn container_id_from_cgroup(cgroup_data: &str) -> Option<String> {
    static PATTERNS: std::sync::OnceLock<Vec<Regex>> = std::sync::OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        vec![
            Regex::new(r"cri-containerd-([a-f0-9]{64})").expect("regex"),
            Regex::new(r"cri-containerd-([a-f0-9]{12,63})").expect("regex"),
            Regex::new(r"crio-([a-f0-9]{64})").expect("regex"),
            Regex::new(r"docker-([a-f0-9]{64})").expect("regex"),
            Regex::new(r"/([a-f0-9]{64})\.scope").expect("regex"),
        ]
    });

    for line in cgroup_data.lines() {
        for re in patterns {
            if let Some(caps) = re.captures(line) {
                return caps.get(1).map(|m| m.as_str().to_string());
            }
        }
    }
    None
}

#[cfg(unix)]
async fn connect_cri(
    socket_path: &str,
) -> anyhow::Result<RuntimeServiceClient<tonic::transport::Channel>> {
    use std::path::PathBuf;

    use hyper::Uri;
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;
    use tonic::transport::{Channel, Endpoint};
    use tower::service_fn;

    if !Path::new(socket_path).exists() {
        anyhow::bail!("CRI socket not found: {socket_path}");
    }

    let path = PathBuf::from(socket_path);
    let channel = Endpoint::try_from("http://127.0.0.1")?
        .connect_with_connector(service_fn(move |_uri: Uri| {
            let path = path.clone();
            async move {
                let stream = UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .context("connect CRI unix socket")?;

    Ok(RuntimeServiceClient::new(channel))
}

#[cfg(not(unix))]
async fn connect_cri(
    _socket_path: &str,
) -> anyhow::Result<RuntimeServiceClient<tonic::transport::Channel>> {
    anyhow::bail!("CRI socket support requires a Unix platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_containerd_cgroup() {
        let data = "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456.scope\n";
        let id = container_id_from_cgroup(data).expect("id");
        assert_eq!(id.len(), 64);
        assert!(id.starts_with("a1b2"));
    }

    #[test]
    fn parses_crio_cgroup() {
        let data =
            "12:memory:/crio-a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456\n";
        let id = container_id_from_cgroup(data).expect("id");
        assert_eq!(id.len(), 64);
    }
}
