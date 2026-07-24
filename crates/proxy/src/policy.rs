use std::{
    env, fs,
    io::ErrorKind,
    net::IpAddr,
    num::NonZeroU16,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use agent_sandbox_core::{
    AttributionToken, FlowClaimReply, FlowProtocol, HttpCheckReply, HttpRequest, NetworkFlowKey,
    ProxyConnectionId, ProxyReply, ProxyReplyBody, ProxyRequestId, ProxySessionReply,
    ProxySessionToken, RpcClientError, RpcConnection, RpcReply, RpcRequest, policy_rpc,
};

pub struct PolicySession {
    socket: PathBuf,
    _connection: RpcConnection,
    token: ProxySessionToken,
    timeout: Duration,
    ready_path: Option<PathBuf>,
}

impl PolicySession {
    /// Open the long-lived policy session used by this proxy.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy socket cannot be reached or rejects
    /// the session.
    pub async fn open(path: impl AsRef<Path>, timeout: Duration) -> Result<Self, PolicyError> {
        let socket = path.as_ref().to_owned();

        let mut connection = tokio::time::timeout(timeout, async {
            loop {
                match RpcConnection::connect(&socket).await {
                    Ok(connection) => break Ok(connection),
                    Err(RpcClientError::Io(error))
                        if matches!(
                            error.kind(),
                            ErrorKind::NotFound | ErrorKind::ConnectionRefused
                        ) =>
                    {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(error) => break Err(error),
                }
            }
        })
        .await
        .map_err(|_| PolicyError::Rpc("policy RPC timed out".to_owned()))?
        .map_err(|error| PolicyError::Rpc(error.to_string()))?;

        let reply = tokio::time::timeout(timeout, connection.request(RpcRequest::OpenProxySession))
            .await
            .map_err(|_| PolicyError::Rpc("policy RPC timed out".to_owned()))?
            .map_err(|error| PolicyError::Rpc(error.to_string()))?;

        let RpcReply::ProxySession(ProxySessionReply {
            ok: true,
            proxy_session,
        }) = reply
        else {
            return Err(PolicyError::UnexpectedReply("open_proxy_session"));
        };

        let ready_path = session_ready_path();
        Ok(Self {
            socket,
            _connection: connection,
            token: proxy_session,
            timeout,
            ready_path,
        })
    }

    /// Publish the readiness marker after both listeners are bound.
    ///
    /// # Errors
    ///
    /// Returns an error when the systemd invocation ID is invalid or the
    /// marker cannot be installed.
    pub fn mark_ready(&self) -> Result<(), PolicyError> {
        if let Some(path) = &self.ready_path {
            mark_session_ready(path)?;
        }
        Ok(())
    }

    /// Claim one intercepted transport flow for this proxy session.
    ///
    /// # Errors
    ///
    /// Returns an error when policyd rejects or cannot identify the flow.
    pub async fn claim(&self, flow: NetworkFlowKey) -> Result<AttributionToken, PolicyError> {
        let reply = policy_rpc(
            &self.socket,
            RpcRequest::ClaimNetworkFlow {
                proxy_session: self.token.clone(),
                flow,
                connection_id: ProxyConnectionId::new(),
            },
            self.timeout,
        )
        .await
        .map_err(|error| {
            self.clear_session_ready();
            PolicyError::Rpc(error.to_string())
        })?;

        if let RpcReply::FlowClaim(FlowClaimReply {
            ok: true,
            attribution_token,
        }) = reply
        {
            Ok(attribution_token)
        } else {
            self.clear_session_ready();
            Err(PolicyError::UnexpectedReply("claim_network_flow"))
        }
    }

    /// Ask policyd for a decision on one normalized HTTP request.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy RPC fails or has an unexpected reply.
    pub async fn check_http(
        &self,
        request_id: ProxyRequestId,
        attribution_token: AttributionToken,
        request: HttpRequest,
    ) -> Result<HttpCheckReply, PolicyError> {
        let reply = policy_rpc(
            &self.socket,
            RpcRequest::CheckHttp {
                proxy_session: self.token.clone(),
                request_id,
                attribution_token,
                request,
            },
            self.timeout,
        )
        .await
        .map_err(|error| {
            self.clear_session_ready();
            PolicyError::Rpc(error.to_string())
        })?;

        decode_http_check_reply(reply, request_id).inspect_err(|_| {
            self.clear_session_ready();
        })
    }

    /// Cancel a pending HTTP approval request.
    ///
    /// # Errors
    ///
    /// Returns an error when the cancellation RPC fails.
    pub async fn cancel(&self, request_id: ProxyRequestId) -> Result<(), PolicyError> {
        policy_rpc(
            &self.socket,
            RpcRequest::CancelCheck {
                proxy_session: self.token.clone(),
                request_id,
            },
            self.timeout,
        )
        .await
        .map_err(|error| {
            self.clear_session_ready();
            PolicyError::Rpc(error.to_string())
        })?;
        Ok(())
    }

    /// Release a previously claimed intercepted flow.
    ///
    /// # Errors
    ///
    /// Returns an error when the release RPC fails.
    pub async fn release(&self, attribution_token: AttributionToken) -> Result<(), PolicyError> {
        policy_rpc(
            &self.socket,
            RpcRequest::ReleaseNetworkFlow {
                proxy_session: self.token.clone(),
                attribution_token,
            },
            self.timeout,
        )
        .await
        .map_err(|error| {
            self.clear_session_ready();
            PolicyError::Rpc(error.to_string())
        })?;
        Ok(())
    }

    fn clear_session_ready(&self) {
        if let Some(path) = &self.ready_path {
            let _ = fs::remove_file(path);
        }
    }
}

impl Drop for PolicySession {
    fn drop(&mut self) {
        self.clear_session_ready();
    }
}

fn decode_http_check_reply(
    reply: RpcReply,
    request_id: ProxyRequestId,
) -> Result<HttpCheckReply, PolicyError> {
    match reply {
        RpcReply::Proxy(ProxyReply {
            request_id: reply_request_id,
            reply,
        }) if reply_request_id == request_id => match reply {
            ProxyReplyBody::HttpCheck(check) => Ok(check),
            ProxyReplyBody::Error(error) => Err(PolicyError::Rpc(error.error)),
            _ => Err(PolicyError::UnexpectedReply("check_http")),
        },
        _ => Err(PolicyError::UnexpectedReply("check_http")),
    }
}

fn session_ready_path() -> Option<PathBuf> {
    env::var_os("AGENT_SANDBOX_PROXY_SESSION_READY").map(PathBuf::from)
}

fn mark_session_ready(path: &Path) -> Result<(), PolicyError> {
    let invocation_id = env::var("INVOCATION_ID")
        .map_err(|_| PolicyError::Rpc("systemd invocation ID is unavailable".to_owned()))?;

    if invocation_id.len() != 32
        || !invocation_id.bytes().all(|byte| {
            byte.is_ascii_digit() || byte.is_ascii_hexdigit() && byte.is_ascii_lowercase()
        })
    {
        return Err(PolicyError::Rpc(
            "systemd invocation ID is not lowercase hexadecimal".to_owned(),
        ));
    }

    let temporary = PathBuf::from(format!("{}.tmp.{}", path.display(), std::process::id()));
    fs::write(&temporary, format!("{invocation_id}\n"))
        .map_err(|error| PolicyError::Rpc(format!("write proxy readiness marker: {error}")))?;

    #[cfg(unix)]
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644)).map_err(|error| {
        PolicyError::Rpc(format!("set proxy readiness marker permissions: {error}"))
    })?;

    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(PolicyError::Rpc(format!(
            "install proxy readiness marker: {error}"
        )));
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy RPC failed: {0}")]
    Rpc(String),

    #[error("policyd returned an unexpected reply for {0}")]
    UnexpectedReply(&'static str),
}

/// Build the typed flow key used to claim an intercepted TCP connection.
///
/// # Errors
///
/// Returns an error when either socket endpoint has a zero port.
pub fn flow_key(
    source: std::net::SocketAddr,
    destination: std::net::SocketAddr,
) -> Result<NetworkFlowKey, PolicyError> {
    let source_port = NonZeroU16::new(source.port())
        .ok_or_else(|| PolicyError::Rpc("source port must be non-zero".to_owned()))?;

    let destination_port = NonZeroU16::new(destination.port())
        .ok_or_else(|| PolicyError::Rpc("destination port must be non-zero".to_owned()))?;

    Ok(NetworkFlowKey::new(
        FlowProtocol::Tcp,
        source.ip(),
        source_port,
        destination.ip(),
        destination_port,
    ))
}

/// Format a host and port as a policy authority.
#[must_use]
pub fn authority_for_policy(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

/// Normalize an HTTP authority and apply a fallback port when absent.
///
/// # Errors
///
/// Returns an error when the authority is malformed or has no host.
pub fn normalize_authority(value: &str, fallback_port: u16) -> Result<String, PolicyError> {
    let url = url::Url::parse(&format!("http://{value}/"))
        .map_err(|error| PolicyError::Rpc(format!("invalid HTTP authority: {error}")))?;

    let host = url
        .host_str()
        .ok_or_else(|| PolicyError::Rpc("HTTP authority has no host".to_owned()))?;

    Ok(authority_for_policy(
        host,
        url.port().unwrap_or(fallback_port),
    ))
}

#[cfg(test)]
mod tests {
    use agent_sandbox_core::{
        ErrorReply, HttpCheckReply, ProxyReply, ProxyReplyBody, ProxyRequestId, RpcReply,
    };

    use super::{PolicyError, decode_http_check_reply, normalize_authority};

    #[test]
    fn accepts_matching_pipelined_http_reply() -> Result<(), Box<dyn std::error::Error>> {
        let request_id = ProxyRequestId::new();
        let reply = RpcReply::Proxy(ProxyReply {
            request_id,
            reply: ProxyReplyBody::HttpCheck(HttpCheckReply::blocked("approval pending")),
        });

        assert!(!decode_http_check_reply(reply, request_id)?.ok);
        Ok(())
    }

    #[test]
    fn rejects_pipelined_http_reply_for_another_request() {
        let request_id = ProxyRequestId::new();
        let reply = RpcReply::Proxy(ProxyReply {
            request_id: ProxyRequestId::new(),
            reply: ProxyReplyBody::HttpCheck(HttpCheckReply::blocked("approval pending")),
        });

        assert!(decode_http_check_reply(reply, request_id).is_err());
    }

    #[test]
    fn reports_pipelined_policy_errors() {
        let request_id = ProxyRequestId::new();
        let reply = RpcReply::Proxy(ProxyReply {
            request_id,
            reply: ProxyReplyBody::Error(ErrorReply::new("policy unavailable")),
        });

        assert!(matches!(
            decode_http_check_reply(reply, request_id),
            Err(PolicyError::Rpc(message)) if message == "policy unavailable"
        ));
    }

    #[test]
    fn preserves_explicit_alternate_port() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            normalize_authority("example.test:8080", 80)?,
            "example.test:8080"
        );
        Ok(())
    }

    #[test]
    fn formats_ipv6_authority() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            normalize_authority("[2001:db8::1]:8443", 443)?,
            "[2001:db8::1]:8443"
        );
        Ok(())
    }
}
