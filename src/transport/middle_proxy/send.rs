use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::error::{ProxyError, Result};
use crate::protocol::constants::RPC_CLOSE_EXT_U32;

use super::MePool;
use super::codec::RpcWriter;
use super::wire::build_proxy_req_payload;

impl MePool {
    pub async fn send_proxy_req(
        &self,
        conn_id: u64,
        client_addr: SocketAddr,
        our_addr: SocketAddr,
        data: &[u8],
        proto_flags: u32,
    ) -> Result<()> {
        let payload = build_proxy_req_payload(
            conn_id,
            client_addr,
            our_addr,
            data,
            self.proxy_tag.as_deref(),
            proto_flags,
        );

        loop {
            let ws = self.writers.read().await;
            if ws.is_empty() {
                return Err(ProxyError::Proxy("All ME connections dead".into()));
            }
            let writers: Vec<Arc<Mutex<RpcWriter>>> = ws.iter().cloned().collect();
            let start = self.rr.fetch_add(1, Ordering::Relaxed) as usize % writers.len();
            drop(ws);

            // Prefer immediately available writer to avoid waiting on stalled connection.
            for offset in 0..writers.len() {
                let idx = (start + offset) % writers.len();
                let w = writers[idx].clone();
                if let Ok(mut guard) = w.try_lock() {
                    let send_res = guard.send(&payload).await;
                    drop(guard);
                    match send_res {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            warn!(error = %e, "ME write failed, removing dead conn");
                            let mut ws = self.writers.write().await;
                            ws.retain(|o| !Arc::ptr_eq(o, &w));
                            if ws.is_empty() {
                                return Err(ProxyError::Proxy("All ME connections dead".into()));
                            }
                            continue;
                        }
                    }
                }
            }

            // All writers are currently busy, wait for the selected one.
            let w = writers[start].clone();
            match w.lock().await.send(&payload).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(error = %e, "ME write failed, removing dead conn");
                    let mut ws = self.writers.write().await;
                    ws.retain(|o| !Arc::ptr_eq(o, &w));
                    if ws.is_empty() {
                        return Err(ProxyError::Proxy("All ME connections dead".into()));
                    }
                }
            }
        }
    }

    pub async fn send_close(&self, conn_id: u64) -> Result<()> {
        let ws = self.writers.read().await;
        if !ws.is_empty() {
            let w = ws[0].clone();
            drop(ws);
            let mut p = Vec::with_capacity(12);
            p.extend_from_slice(&RPC_CLOSE_EXT_U32.to_le_bytes());
            p.extend_from_slice(&conn_id.to_le_bytes());
            if let Err(e) = w.lock().await.send(&p).await {
                debug!(error = %e, "ME close write failed");
                let mut ws = self.writers.write().await;
                ws.retain(|o| !Arc::ptr_eq(o, &w));
            }
        }

        self.registry.unregister(conn_id).await;
        Ok(())
    }

    pub fn connection_count(&self) -> usize {
        self.writers.try_read().map(|w| w.len()).unwrap_or(0)
    }
}
