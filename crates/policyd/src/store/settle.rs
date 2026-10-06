//! Policy store: finish pending approvals the current rules already decide.

use agent_sandbox_core::NetworkRuleKey;

use super::types::{Pending, PolicyStore};

impl PolicyStore {
    /// Finish every pending filesystem, resource, network, and D-Bus approval
    /// that the current declarative and session rules decide.
    ///
    /// A scoped decision on one prompt often covers others queued behind it:
    /// a directory rule covers sibling files, a host rule covers the same host
    /// from another context. Each pending is re-evaluated exactly as a fresh
    /// request would be, so denies still win over allows.
    ///
    /// HTTP scope application settles matching HTTP pendings itself.
    /// Elevation pendings stay queued: approving one runs the command.
    pub(crate) async fn settle_covered_pendings(&self) {
        let pending: Vec<Pending> = self
            .inner
            .lock()
            .await
            .pending
            .pending
            .values()
            .filter(|pending| {
                matches!(
                    pending,
                    Pending::Filesystem(_)
                        | Pending::Resource(_)
                        | Pending::Network(_)
                        | Pending::Dbus(_)
                )
            })
            .cloned()
            .collect();

        for pending in pending {
            match pending {
                Pending::Filesystem(fs) => {
                    let Some(verdict) = self
                        .filesystem_allow_source(&fs.path, fs.access, &fs.ctx)
                        .await
                    else {
                        continue;
                    };

                    if self.take_pending(&fs.id).await {
                        self.finish_filesystem(
                            &fs.id,
                            fs.path,
                            fs.access,
                            verdict.allowed,
                            verdict.source,
                        )
                        .await;
                    }
                }

                Pending::Resource(res) => {
                    let Some(verdict) = self
                        .resource_allow_source(res.kind, &res.path, res.access, &res.ctx)
                        .await
                    else {
                        continue;
                    };

                    if self.take_pending(&res.id).await {
                        self.finish_resource(
                            &res.id,
                            res.kind,
                            res.path,
                            res.access,
                            verdict.allowed,
                            verdict.source,
                        )
                        .await;
                    }
                }

                Pending::Network(net) => {
                    if net.port == 0 {
                        continue;
                    }

                    // A once grant is left for the next fresh check to consume.
                    let Some(verdict) = self
                        .allow_verdict(&net.host, net.port, &net.ctx)
                        .await
                        .filter(|verdict| !verdict.is_once())
                    else {
                        continue;
                    };

                    if self.take_pending(&net.id).await {
                        self.finish_network(
                            &net.id,
                            verdict.allowed,
                            verdict.source,
                            Some(NetworkRuleKey {
                                host: net.host,
                                port: net.port,
                            }),
                        )
                        .await;
                    }
                }

                Pending::Dbus(dbus) => {
                    let Some(verdict) = self.dbus_decided_verdict(&dbus.target, &dbus.ctx).await
                    else {
                        continue;
                    };

                    if self.take_pending(&dbus.id).await {
                        self.finish_dbus(&dbus.id, dbus.target, verdict.allowed, verdict.source)
                            .await;
                    }
                }

                Pending::Elevation(_) | Pending::Http(_) => {}
            }
        }
    }

    /// Remove a pending entry; `false` when a concurrent decision already
    /// took it.
    async fn take_pending(&self, id: &str) -> bool {
        let taken = self.inner.lock().await.pending.pending.remove(id).is_some();

        if taken {
            tracing::info!(pending_id = id, "pending settled by current policy");
        }

        taken
    }
}
