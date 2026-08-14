use ::h3;

use super::*;

/// HTTP/3 origin used by the transparent harness.
///
/// The origin is a separate process (`h3-origin`) that records request and
/// connection events to a log file, so tests can observe upstream attempts
/// and association release without instrumenting the proxy.
pub struct Http3Origin {
    pub address: SocketAddr,
    log: PathBuf,
    child: Child,
}

pub(super) struct Http3OriginSettings<'a> {
    pub(super) gate: Option<&'a Path>,
    pub(super) alt_svc_file: Option<&'a Path>,
    pub(super) reject_sessions: bool,
    pub(super) refuse_sessions: bool,
    pub(super) drop_first_session: bool,
}

impl Http3Origin {
    pub async fn start(
        ip: IpAddr,
        port: u16,
        certificate: &Path,
        private_key: &Path,
        root: &Path,
        gate: Option<&Path>,
    ) -> Self {
        Self::start_with_settings(
            ip,
            port,
            certificate,
            private_key,
            root,
            Http3OriginSettings {
                gate,
                alt_svc_file: None,
                reject_sessions: false,
                refuse_sessions: false,
                drop_first_session: false,
            },
        )
        .await
    }

    pub(super) async fn start_with_settings(
        ip: IpAddr,
        port: u16,
        certificate: &Path,
        private_key: &Path,
        root: &Path,
        settings: Http3OriginSettings<'_>,
    ) -> Self {
        let address = SocketAddr::new(ip, port);
        let log = root.join("origin.log");
        let mut command = Command::new(env!("CARGO_BIN_EXE_h3-origin"));

        command.args([
            "--port",
            &address.port().to_string(),
            "--address",
            &ip.to_string(),
            "--certificate",
            certificate.to_str().expect("certificate path"),
            "--private-key",
            private_key.to_str().expect("private key path"),
            "--log",
            log.to_str().expect("log path"),
        ]);

        if let Some(gate) = settings.gate {
            command.args(["--gate", gate.to_str().expect("gate path")]);
        }

        if let Some(alt_svc_file) = settings.alt_svc_file {
            command.args([
                "--alt-svc-file",
                alt_svc_file.to_str().expect("alt-svc file path"),
            ]);
        }

        if settings.reject_sessions {
            command.arg("--reject-sessions");
        }

        if settings.refuse_sessions {
            command.arg("--refuse-sessions");
        }

        if settings.drop_first_session {
            command.arg("--drop-first-session");
        }

        let child = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start HTTP/3 origin");

        let mut origin = Self {
            address,
            log,
            child,
        };

        for _ in 0..200 {
            let listening_address = std::fs::read_to_string(&origin.log).ok().and_then(|log| {
                log.lines()
                    .find_map(|line| line.strip_prefix("listening ")?.parse().ok())
            });

            if let Some(listening_address) = listening_address {
                origin.address = listening_address;
                return origin;
            }

            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        panic!("HTTP/3 origin did not start listening");
    }

    /// Path of the origin log file.
    #[must_use]
    pub fn log_path(&self) -> &Path {
        &self.log
    }

    /// Number of requests the origin has received.
    #[must_use]
    pub fn attempts(&self) -> usize {
        self.request_lines().len()
    }

    /// Request heads in the form `METHOD PATH`.
    #[must_use]
    pub fn request_heads(&self) -> Vec<String> {
        self.request_lines()
    }

    /// Number of upstream associations the origin has accepted.
    #[must_use]
    pub fn connections_opened(&self) -> usize {
        self.log_lines()
            .iter()
            .filter(|line| line.as_str() == "conn-opened")
            .count()
    }

    /// Number of upstream associations the origin has seen close.
    #[must_use]
    pub fn connections_closed(&self) -> usize {
        self.log_lines()
            .iter()
            .filter(|line| line.as_str() == "conn-closed")
            .count()
    }

    fn request_lines(&self) -> Vec<String> {
        self.log_lines()
            .into_iter()
            .filter_map(|line| line.strip_prefix("request ").map(str::to_owned))
            .collect()
    }

    fn log_lines(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Drop for Http3Origin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One HTTP/3 response with an incremental body reader.
///
/// The request sender is retained because dropping the last handle closes
/// the client's HTTP/3 connection, which the proxy must treat as a critical
/// stream failure.
pub struct Http3Response {
    status: u16,
    headers: http::HeaderMap,
    stream: Option<H3RequestStream>,
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    _connection: h3::client::Connection<h3_quinn::Connection, bytes::Bytes>,
}

impl Http3Response {
    /// The response status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// The response headers.
    #[must_use]
    pub const fn headers(&self) -> &http::HeaderMap {
        &self.headers
    }

    /// Read the next response body chunk.
    pub async fn next_chunk(&mut self) -> Option<Vec<u8>> {
        let stream = self.stream.as_mut()?;

        match stream.recv_data().await {
            Ok(Some(mut chunk)) => Some(chunk.copy_to_bytes(chunk.remaining()).to_vec()),

            Ok(None) => {
                self.stream = None;
                None
            }

            Err(error) => panic!("response body failed: {error}"),
        }
    }

    /// Read the complete response body.
    pub async fn body(self) -> Vec<u8> {
        self.body_with_trailers().await.0
    }

    /// Read the complete response body and trailers.
    pub async fn body_with_trailers(mut self) -> (Vec<u8>, http::HeaderMap) {
        let mut body = Vec::new();

        let Some(mut stream) = self.stream.take() else {
            return (body, http::HeaderMap::new());
        };

        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .unwrap_or_else(|error| panic!("response body failed: {error}"))
        {
            body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
        }

        let trailers = stream
            .recv_trailers()
            .await
            .unwrap_or_else(|error| panic!("response trailers failed: {error}"))
            .unwrap_or_default();

        (body, trailers)
    }
}

type H3RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>;
const MAX_INFORMATIONAL_RESPONSES: usize = 16;

fn assert_webtransport_response(response: &http::Response<()>) -> Result<(), String> {
    if !response.status().is_success() {
        return Err(format!("WebTransport response was {}", response.status()));
    }

    if response.headers().get("x-origin-webtransport")
        != Some(&http::HeaderValue::from_static("preserved"))
    {
        return Err("WebTransport response header was not preserved".to_owned());
    }

    Ok(())
}

/// HTTP/3 client used by the transparent harness to reach the proxy.
pub struct Http3Client {
    endpoint: quinn::Endpoint,
}

impl Http3Client {
    /// Build a client that trusts the harness CA.
    #[must_use]
    pub fn new(ca_file: &Path) -> Self {
        Self::with_alpn(ca_file, b"h3")
    }

    /// Build a client that offers one explicit ALPN protocol.
    #[must_use]
    pub fn with_alpn(ca_file: &Path, alpn: &[u8]) -> Self {
        Self::with_alpn_and_ip(ca_file, alpn, IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    }

    /// Build an HTTP/3 client bound to one local address family.
    #[must_use]
    pub fn with_local_ip(ca_file: &Path, local_ip: IpAddr) -> Self {
        Self::with_alpn_and_ip(ca_file, b"h3", local_ip)
    }

    /// Build an HTTP/3 client that offers QUIC 0-RTT data.
    #[must_use]
    pub fn with_early_data(ca_file: &Path) -> Self {
        Self::with_alpn_and_ip_and_early_data(
            ca_file,
            b"h3",
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            true,
        )
    }

    /// Build an HTTP/3 client that offers the proxy's ECH configuration.
    ///
    /// `config_list` must be the proxy's own `ECHConfigList` (the same bytes
    /// the sandbox DNS rewrite distributes), so the client's encrypted
    /// `ClientHelloInner` is decryptable by the proxy.
    #[must_use]
    pub fn with_ech(ca_file: &Path, config_list: &[u8]) -> Self {
        let pem = std::fs::read(ca_file).expect("read harness CA");

        let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .expect("parse harness CA");

        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(certificates);
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let config = rustls::client::EchConfig::new(
            rustls::pki_types::EchConfigListBytes::from(config_list),
            agent_sandbox_proxy::http3::hpke::ECH_SUPPORTED_SUITES,
        )
        .expect("proxy ECH configuration is supported");

        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_ech(rustls::client::EchMode::Enable(config))
            .expect("ECH client mode")
            .with_root_certificates(roots)
            .with_no_client_auth();

        let mut tls = tls;
        tls.alpn_protocols = vec![b"h3".to_vec()];

        let client_config =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC client config");

        let client_config = quinn::ClientConfig::new(Arc::new(client_config));

        let mut endpoint =
            quinn::Endpoint::client(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
                .expect("client endpoint");

        endpoint.set_default_client_config(client_config);
        Self { endpoint }
    }

    fn with_alpn_and_ip(ca_file: &Path, alpn: &[u8], local_ip: IpAddr) -> Self {
        Self::with_alpn_and_ip_and_early_data(ca_file, alpn, local_ip, false)
    }

    fn with_alpn_and_ip_and_early_data(
        ca_file: &Path,
        alpn: &[u8],
        local_ip: IpAddr,
        enable_early_data: bool,
    ) -> Self {
        let pem = std::fs::read(ca_file).expect("read harness CA");

        let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .expect("parse harness CA");

        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(certificates);
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();

        tls.alpn_protocols = vec![alpn.to_vec()];

        if enable_early_data {
            tls.enable_early_data = true;
        }

        let client_config =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC client config");

        let client_config = quinn::ClientConfig::new(Arc::new(client_config));

        let mut endpoint =
            quinn::Endpoint::client(SocketAddr::new(local_ip, 0)).expect("client endpoint");

        endpoint.set_default_client_config(client_config);
        Self { endpoint }
    }

    /// Report whether a resumed connection accepts QUIC 0-RTT data.
    ///
    /// Returns `None` when the server does not issue a resumption ticket.
    pub async fn zero_rtt_is_accepted(
        &self,
        server: SocketAddr,
        server_name: &str,
    ) -> Result<Option<bool>, String> {
        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;

        match connecting.into_0rtt() {
            Ok((connection, accepted)) => {
                let accepted = timeout(Duration::from_secs(5), accepted)
                    .await
                    .map_err(|_| "0-RTT acceptance timed out".to_owned())?;
                connection.close(quinn::VarInt::from_u32(0), b"0-RTT probe");
                Ok(Some(accepted))
            }

            Err(connecting) => {
                let connection = timeout(Duration::from_secs(5), connecting)
                    .await
                    .map_err(|_| "QUIC handshake timed out".to_owned())?
                    .map_err(|error| format!("QUIC handshake failed: {error}"))?;
                connection.close(quinn::VarInt::from_u32(0), b"0-RTT unavailable");
                Ok(None)
            }
        }
    }

    /// Send one GET request and return the response.
    pub async fn request(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Http3Response, String> {
        let (_, response) = self
            .request_with_informational(server, server_name, path)
            .await?;

        Ok(response)
    }

    /// Send one GET request and retain informational responses.
    pub async fn request_with_informational(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<(Vec<http::Response<()>>, Http3Response), String> {
        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;

        let connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|error| format!("QUIC handshake failed: {error}"))?;

        let h3 = h3_quinn::Connection::new(connection);

        let (connection, mut send_request) = h3::client::new(h3)
            .await
            .map_err(|error| format!("HTTP/3 setup failed: {error}"))?;

        let request = http::Request::builder()
            .method("GET")
            .uri(format!("https://{server_name}{path}"))
            .body(())
            .expect("client request");

        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|error| format!("request failed: {error}"))?;

        let (informational, response) = stream
            .recv_response_with_informational()
            .await
            .map_err(|error| format!("response failed: {error}"))?;

        Ok((informational, Http3Response {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            stream: Some(stream),
            _send_request: send_request,
            _connection: connection,
        }))
    }

    /// Send a POST request that waits for `100 Continue` before its body.
    pub async fn request_with_expect(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Http3Response, String> {
        self.request_with_body(server, server_name, path, true, false)
            .await
    }

    /// Send a POST request with request trailers.
    pub async fn request_with_trailers(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Http3Response, String> {
        self.request_with_body(server, server_name, path, false, true)
            .await
    }

    async fn request_with_body(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
        expect_continue: bool,
        send_trailers: bool,
    ) -> Result<Http3Response, String> {
        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;

        let connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|error| format!("QUIC handshake failed: {error}"))?;

        let h3 = h3_quinn::Connection::new(connection);

        let (connection, mut send_request) = h3::client::new(h3)
            .await
            .map_err(|error| format!("HTTP/3 setup failed: {error}"))?;

        let mut request = http::Request::builder()
            .method("POST")
            .uri(format!("https://{server_name}{path}"));

        if expect_continue {
            request = request.header("expect", "100-continue");
        }

        if send_trailers {
            request = request.header("trailer", "x-request-trailer");
        }

        let request = request.body(()).expect("client request");

        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|error| format!("request failed: {error}"))?;

        let early_response = if expect_continue {
            let mut informational_count = 0;
            loop {
                let response = stream
                    .recv_response_head()
                    .await
                    .map_err(|error| format!("response failed: {error}"))?;

                if response.status() == http::StatusCode::CONTINUE {
                    break None;
                }

                if response.status().is_informational() {
                    if informational_count == MAX_INFORMATIONAL_RESPONSES {
                        return Err("too many informational responses".to_owned());
                    }
                    informational_count += 1;
                    continue;
                }

                break Some(response);
            }
        } else {
            None
        };

        if let Some(response) = early_response {
            return Ok(Http3Response {
                status: response.status().as_u16(),
                headers: response.headers().clone(),
                stream: Some(stream),
                _send_request: send_request,
                _connection: connection,
            });
        }

        stream
            .send_data(Bytes::from_static(b"request-body"))
            .await
            .map_err(|error| format!("request body failed: {error}"))?;

        if send_trailers {
            let mut trailers = http::HeaderMap::new();

            trailers.insert(
                "x-request-trailer",
                http::HeaderValue::from_static("present"),
            );

            stream
                .send_trailers(trailers)
                .await
                .map_err(|error| format!("request trailers failed: {error}"))?;
        }

        stream
            .finish()
            .await
            .map_err(|error| format!("request finish failed: {error}"))?;

        let (_, response) = stream
            .recv_response_with_informational()
            .await
            .map_err(|error| format!("response failed: {error}"))?;

        Ok(Http3Response {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            stream: Some(stream),
            _send_request: send_request,
            _connection: connection,
        })
    }

    /// Rebind one live HTTP/3 request to a new local UDP address.
    pub async fn request_with_rebind(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
        local_ip: IpAddr,
        release_gate: Option<&Path>,
    ) -> Result<Vec<u8>, String> {
        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;

        let quinn_connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|error| format!("QUIC handshake failed: {error}"))?;

        let h3 = h3_quinn::Connection::new(quinn_connection.clone());

        let (connection, mut send_request) = h3::client::new(h3)
            .await
            .map_err(|error| format!("HTTP/3 setup failed: {error}"))?;

        let request = http::Request::builder()
            .method("GET")
            .uri(format!("https://{server_name}{path}"))
            .body(())
            .expect("client request");

        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|error| format!("request failed: {error}"))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|error| format!("response failed: {error}"))?;

        if !response.status().is_success() {
            return Err(format!("unexpected response status {}", response.status()));
        }

        let mut body = Vec::new();

        if let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|error| format!("response body failed: {error}"))?
        {
            body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
        }

        let socket = std::net::UdpSocket::bind(SocketAddr::new(local_ip, 0))
            .map_err(|error| format!("bind migration socket failed: {error}"))?;

        socket
            .set_nonblocking(true)
            .map_err(|error| format!("set migration socket nonblocking failed: {error}"))?;

        self.endpoint
            .rebind(socket)
            .map_err(|error| format!("rebind QUIC endpoint failed: {error}"))?;

        stream
            .finish()
            .await
            .map_err(|error| format!("finish migration request failed: {error}"))?;

        if let Some(gate) = release_gate {
            std::fs::write(gate, b"open")
                .map_err(|error| format!("open migration stream gate failed: {error}"))?;
        }

        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|error| format!("response body failed: {error}"))?
        {
            body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
        }

        quinn_connection.close(quinn::VarInt::from_u32(0), b"migration complete");
        drop(send_request);
        drop(connection);
        Ok(body)
    }

    pub async fn websocket_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Vec<u8>, String> {
        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;

        let quinn_connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|error| format!("QUIC handshake failed: {error}"))?;

        let h3_quic = h3_quinn::Connection::new(quinn_connection);
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true);

        let (h3_connection, mut send_request) = builder
            .build::<_, _, bytes::Bytes>(h3_quic)
            .await
            .map_err(|error| format!("HTTP/3 setup failed: {error}"))?;

        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://{server_name}{path}"))
            .body(())
            .expect("WebSocket request");

        request
            .extensions_mut()
            .insert(h3::ext::Protocol::WEBSOCKET);

        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|error| format!("WebSocket request failed: {error}"))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|error| format!("WebSocket response failed: {error}"))?;

        if !response.status().is_success() {
            return Err(format!("WebSocket response was {}", response.status()));
        }

        stream
            .send_data(bytes::Bytes::from_static(b"websocket-probe"))
            .await
            .map_err(|error| format!("WebSocket request body failed: {error}"))?;

        stream
            .finish()
            .await
            .map_err(|error| format!("WebSocket request close failed: {error}"))?;

        let mut body = Vec::new();

        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|error| format!("WebSocket response body failed: {error}"))?
        {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }

        drop(stream);
        drop(send_request);
        drop(h3_connection);
        Ok(body)
    }

    /// Open one WebTransport child stream and read the origin response.
    pub async fn webtransport_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Vec<u8>, String> {
        self.webtransport_probe_with_settings(server, server_name, path, true, false)
            .await
    }

    /// Open one WebTransport child stream without HTTP Datagram support.
    pub async fn webtransport_probe_without_datagram(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Vec<u8>, String> {
        self.webtransport_probe_with_settings(server, server_name, path, false, false)
            .await
    }

    /// Open a child stream with an unapproved WebTransport session ID.
    pub async fn webtransport_invalid_session_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<(), String> {
        self.webtransport_probe_with_settings(server, server_name, path, true, true)
            .await
            .map(|_| ())
    }

    async fn webtransport_probe_with_settings(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
        enable_datagram: bool,
        invalid_session: bool,
    ) -> Result<Vec<u8>, String> {
        use h3::quic::{RecvStream as _, SendStream as _};
        use h3_datagram::datagram_handler::HandleDatagramsExt;

        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;

        let quinn_connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|error| format!("QUIC handshake failed: {error}"))?;

        let h3_quic = h3_quinn::Connection::new(quinn_connection.clone());
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true);

        if enable_datagram {
            builder.enable_datagram(true);
        }

        builder.enable_webtransport(true);

        let (h3_connection, mut send_request) = builder
            .build::<_, _, bytes::Bytes>(h3_quic)
            .await
            .map_err(|error| format!("HTTP/3 setup failed: {error}"))?;

        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://{server_name}{path}"))
            .body(())
            .expect("WebTransport request");

        request
            .extensions_mut()
            .insert(h3::ext::Protocol::WEB_TRANSPORT);

        let mut connect_stream = send_request
            .send_request(request)
            .await
            .map_err(|error| format!("WebTransport request failed: {error}"))?;

        let session_id = h3::webtransport::SessionId::from(connect_stream.id());

        let child_session_id = if invalid_session {
            h3::webtransport::SessionId::try_from(4).expect("invalid session id")
        } else {
            session_id
        };

        let response = connect_stream
            .recv_response()
            .await
            .map_err(|error| format!("WebTransport response failed: {error}"))?;

        assert_webtransport_response(&response)?;

        if enable_datagram && !invalid_session {
            let stream_id = connect_stream.id();
            let mut datagram_sender = h3_connection.get_datagram_sender(stream_id);
            let mut datagram_reader = h3_connection.get_datagram_reader();

            datagram_sender
                .send_datagram(bytes::Bytes::from_static(b"\0webtransport-datagram"))
                .map_err(|error| format!("WebTransport datagram send failed: {error}"))?;

            let datagram =
                tokio::time::timeout(Duration::from_secs(5), datagram_reader.read_datagram())
                    .await
                    .map_err(|_| "WebTransport datagram receive timed out".to_owned())?
                    .map_err(|error| format!("WebTransport datagram receive failed: {error}"))?;

            if datagram.stream_id() != stream_id {
                return Err("WebTransport datagram stream context changed".to_owned());
            }

            if datagram.into_payload() != bytes::Bytes::from_static(b"\0webtransport-datagram") {
                return Err("WebTransport datagram payload changed".to_owned());
            }
        }

        let child_quic = h3_quinn::Connection::new(quinn_connection);

        let mut opener =
            <h3_quinn::Connection as h3::quic::Connection<bytes::Bytes>>::opener(&child_quic);

        let mut child = std::future::poll_fn(|context| {
            <h3_quinn::OpenStreams as h3::quic::OpenStreams<bytes::Bytes>>::poll_open_bidi(
                &mut opener,
                context,
            )
        })
        .await
        .map_err(|error| format!("WebTransport child stream failed: {error}"))?;

        child
            .send_data(h3::stream::BidiStreamHeader::WebTransportBidi(
                child_session_id,
            ))
            .map_err(|error| format!("WebTransport child header failed: {error}"))?;

        std::future::poll_fn(|context| child.poll_ready(context))
            .await
            .map_err(|error| format!("WebTransport child header failed: {error}"))?;

        std::future::poll_fn(|context| child.poll_finish(context))
            .await
            .map_err(|error| format!("WebTransport child close failed: {error}"))?;

        let mut body = Vec::new();

        while let Some(mut chunk) = std::future::poll_fn(|context| child.poll_data(context))
            .await
            .map_err(|error| format!("WebTransport child response failed: {error}"))?
        {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }

        drop(connect_stream);
        drop(send_request);
        drop(h3_connection);
        Ok(body)
    }

    pub async fn connect_udp_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Vec<u8>, String> {
        self.connect_udp_probe_with_context(server, server_name, path, false)
            .await
    }

    pub async fn connect_udp_capsule_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<Vec<(u64, Vec<u8>)>, String> {
        self.connect_udp_capsule_probe_with_settings(server, server_name, path, false, true)
            .await
    }

    pub async fn connect_udp_capsule_probe_without_protocol(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<(), String> {
        self.connect_udp_capsule_probe_with_settings(server, server_name, path, false, false)
            .await
            .map(|_| ())
    }

    pub async fn connect_udp_malformed_capsule_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<(), String> {
        self.connect_udp_capsule_probe_with_settings(server, server_name, path, true, true)
            .await
            .map(|_| ())
    }

    async fn connect_udp_capsule_probe_with_settings(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
        malformed: bool,
        capsule_protocol: bool,
    ) -> Result<Vec<(u64, Vec<u8>)>, String> {
        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;

        let quinn_connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|error| format!("QUIC handshake failed: {error}"))?;

        let h3_quic = h3_quinn::Connection::new(quinn_connection);
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true).enable_datagram(true);

        let (h3_connection, mut send_request) = builder
            .build::<_, _, bytes::Bytes>(h3_quic)
            .await
            .map_err(|error| format!("HTTP/3 setup failed: {error}"))?;

        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://{server_name}{path}"))
            .body(())
            .expect("CONNECT-UDP request");

        request
            .extensions_mut()
            .insert(h3::ext::Protocol::CONNECT_UDP);

        if capsule_protocol {
            request
                .headers_mut()
                .insert("capsule-protocol", http::HeaderValue::from_static("?1"));
        }

        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|error| format!("CONNECT-UDP request failed: {error}"))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|error| format!("CONNECT-UDP response failed: {error}"))?;

        if !response.status().is_success() {
            return Err(format!("CONNECT-UDP response was {}", response.status()));
        }

        let body = if malformed {
            vec![0, 5, 1, 2]
        } else {
            [
                encode_test_capsule(0, b"\0capsule-probe"),
                encode_test_capsule(0x21, b"unknown-capsule"),
            ]
            .concat()
        };

        if let Err(error) = stream.send_data(bytes::Bytes::from(body)).await {
            return malformed
                .then_some(Vec::new())
                .ok_or_else(|| format!("CONNECT-UDP Capsule Protocol body failed: {error}"));
        }

        if let Err(error) = stream.finish().await {
            return malformed
                .then_some(Vec::new())
                .ok_or_else(|| format!("CONNECT-UDP Capsule Protocol close failed: {error}"));
        }

        if malformed {
            return match tokio::time::timeout(Duration::from_secs(5), stream.recv_data()).await {
                Ok(Err(_)) => Ok(Vec::new()),
                Ok(Ok(_)) => Err("malformed CONNECT-UDP capsule was accepted".to_owned()),
                Err(_) => Err("malformed CONNECT-UDP capsule was not reset".to_owned()),
            };
        }

        let mut body = Vec::new();

        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|error| format!("CONNECT-UDP capsule response failed: {error}"))?
        {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }

        drop(stream);
        drop(send_request);
        drop(h3_connection);
        decode_test_capsules(&body)
    }

    pub async fn connect_udp_invalid_context_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<(), String> {
        self.connect_udp_probe_with_context(server, server_name, path, true)
            .await
            .map(|_| ())
    }

    pub async fn connect_udp_two_streams_probe(
        &self,
        server: SocketAddr,
        server_name: &str,
        first_path: &str,
        second_path: &str,
    ) -> Result<Vec<Vec<u8>>, String> {
        use h3_datagram::datagram_handler::HandleDatagramsExt;

        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;

        let quinn_connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|error| format!("QUIC handshake failed: {error}"))?;

        let h3_quic = h3_quinn::Connection::new(quinn_connection);
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true).enable_datagram(true);

        let (h3_connection, mut send_request) = builder
            .build::<_, _, bytes::Bytes>(h3_quic)
            .await
            .map_err(|error| format!("HTTP/3 setup failed: {error}"))?;

        let mut streams = Vec::new();

        for path in [first_path, second_path] {
            let mut request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri(format!("https://{server_name}{path}"))
                .body(())
                .expect("CONNECT-UDP request");

            request
                .extensions_mut()
                .insert(h3::ext::Protocol::CONNECT_UDP);

            let mut stream = send_request
                .send_request(request)
                .await
                .map_err(|error| format!("CONNECT-UDP request failed: {error}"))?;

            let response = stream
                .recv_response()
                .await
                .map_err(|error| format!("CONNECT-UDP response failed: {error}"))?;

            if !response.status().is_success() {
                return Err(format!("CONNECT-UDP response was {}", response.status()));
            }

            streams.push(stream);
        }

        let stream_ids = [streams[0].id(), streams[1].id()];

        if stream_ids[0] == stream_ids[1] {
            return Err("CONNECT-UDP request streams reused one ID".to_owned());
        }

        let mut senders = [
            h3_connection.get_datagram_sender(stream_ids[0]),
            h3_connection.get_datagram_sender(stream_ids[1]),
        ];

        for (index, sender) in senders.iter_mut().enumerate() {
            sender
                .send_datagram(bytes::Bytes::from(format!("\0route-{index}")))
                .map_err(|error| format!("CONNECT-UDP datagram send failed: {error}"))?;
        }

        let mut datagram_reader = h3_connection.get_datagram_reader();
        let mut bodies = [None, None];

        for _ in 0..2 {
            let datagram = datagram_reader
                .read_datagram()
                .await
                .map_err(|error| format!("CONNECT-UDP datagram receive failed: {error}"))?;

            let index = stream_ids
                .iter()
                .position(|stream_id| *stream_id == datagram.stream_id())
                .ok_or_else(|| "CONNECT-UDP datagram context changed".to_owned())?;

            let payload = datagram.into_payload();

            if payload.first() != Some(&0) {
                return Err("CONNECT-UDP inner context changed".to_owned());
            }

            bodies[index] = Some(payload.slice(1..).to_vec());
        }

        for stream in &mut streams {
            stream
                .finish()
                .await
                .map_err(|error| format!("CONNECT-UDP session close failed: {error}"))?;
        }

        Ok(bodies
            .into_iter()
            .map(|body| body.expect("two CONNECT-UDP responses"))
            .collect())
    }

    async fn connect_udp_probe_with_context(
        &self,
        server: SocketAddr,
        server_name: &str,
        path: &str,
        invalid_context: bool,
    ) -> Result<Vec<u8>, String> {
        use h3_datagram::datagram_handler::HandleDatagramsExt;

        let connecting = self
            .endpoint
            .connect(server, server_name)
            .map_err(|error| error.to_string())?;

        let quinn_connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .map_err(|_| "QUIC handshake timed out".to_owned())?
            .map_err(|error| format!("QUIC handshake failed: {error}"))?;

        let h3_quic = h3_quinn::Connection::new(quinn_connection);
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true).enable_datagram(true);

        let (h3_connection, mut send_request) = builder
            .build::<_, _, bytes::Bytes>(h3_quic)
            .await
            .map_err(|error| format!("HTTP/3 setup failed: {error}"))?;

        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://{server_name}{path}"))
            .body(())
            .expect("CONNECT-UDP request");

        request
            .extensions_mut()
            .insert(h3::ext::Protocol::CONNECT_UDP);

        let mut connect_stream = send_request
            .send_request(request)
            .await
            .map_err(|error| format!("CONNECT-UDP request failed: {error}"))?;

        let stream_id = connect_stream.id();

        let response = connect_stream
            .recv_response()
            .await
            .map_err(|error| format!("CONNECT-UDP response failed: {error}"))?;

        if !response.status().is_success() {
            return Err(format!("CONNECT-UDP response was {}", response.status()));
        }

        let datagram_context = stream_id;
        let mut datagram_sender = h3_connection.get_datagram_sender(datagram_context);
        let mut datagram_reader = h3_connection.get_datagram_reader();

        let payload = if invalid_context {
            bytes::Bytes::from_static(b"\x01connect-udp-probe")
        } else {
            bytes::Bytes::from_static(b"\0connect-udp-probe")
        };

        datagram_sender
            .send_datagram(payload)
            .map_err(|error| format!("CONNECT-UDP datagram send failed: {error}"))?;

        if invalid_context {
            return match connect_stream.recv_data().await {
                Err(_error) => Ok(Vec::new()),
                Ok(_) => Err("invalid CONNECT-UDP context was accepted".to_owned()),
            };
        }

        let datagram = datagram_reader
            .read_datagram()
            .await
            .map_err(|error| format!("CONNECT-UDP datagram receive failed: {error}"))?;

        if datagram.stream_id() != stream_id {
            return Err("CONNECT-UDP datagram context changed".to_owned());
        }

        connect_stream
            .finish()
            .await
            .map_err(|error| format!("CONNECT-UDP session close failed: {error}"))?;

        let payload = datagram.into_payload();

        if payload.first() != Some(&0) {
            return Err("CONNECT-UDP inner context changed".to_owned());
        }

        Ok(payload.slice(1..).to_vec())
    }
}

fn encode_test_capsule(kind: u64, payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encode_test_varint(kind, &mut encoded);

    encode_test_varint(
        u64::try_from(payload.len()).expect("capsule payload length fits"),
        &mut encoded,
    );

    encoded.extend_from_slice(payload);
    encoded
}

fn decode_test_capsules(mut encoded: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let mut capsules = Vec::new();

    while !encoded.is_empty() {
        let Some((kind, kind_len)) = decode_test_varint(encoded) else {
            return Err("truncated Capsule Protocol type".to_owned());
        };

        let Some((length, length_len)) = decode_test_varint(&encoded[kind_len..]) else {
            return Err("truncated Capsule Protocol length".to_owned());
        };

        let length = usize::try_from(length).map_err(|_| "Capsule Protocol length is too large")?;
        let start = kind_len + length_len;

        let end = start
            .checked_add(length)
            .ok_or("Capsule Protocol length overflows")?;

        if end > encoded.len() {
            return Err("truncated Capsule Protocol payload".to_owned());
        }

        capsules.push((kind, encoded[start..end].to_vec()));
        encoded = &encoded[end..];
    }

    Ok(capsules)
}

fn encode_test_varint(value: u64, output: &mut Vec<u8>) {
    match value {
        0..=63 => output.push(u8::try_from(value).expect("bounded test varint")),

        64..=16_383 => {
            let value = u16::try_from(value | 0x4000).expect("bounded test varint");
            output.extend_from_slice(&value.to_be_bytes());
        }

        16_384..=1_073_741_823 => {
            let value = u32::try_from(value | 0x8000_0000).expect("bounded test varint");
            output.extend_from_slice(&value.to_be_bytes());
        }

        _ => {
            let value = value | 0xC000_0000_0000_0000;
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn decode_test_varint(encoded: &[u8]) -> Option<(u64, usize)> {
    let first = encoded.first().copied()?;
    let length = 1usize << (first >> 6);

    if encoded.len() < length {
        return None;
    }

    let mut value = u64::from(first & 0x3F);

    for byte in &encoded[1..length] {
        value = (value << 8) | u64::from(*byte);
    }

    Some((value, length))
}
