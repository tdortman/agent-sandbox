use super::{
    h3::{Http3Origin, Http3OriginSettings},
    origins::{TlsAlpn, TlsOrigin, harness_tls_alpn, read_http_response, start_tls_origin},
    *,
};

/// Origin selection for one harness.
struct OriginOptions {
    ip: IpAddr,
    origin_port: u16,
    tls: bool,
    tls_alpn: TlsAlpn,
    keep_alive: bool,
    http3: Option<Http3OriginOptions>,
    certificate: PathBuf,
    private_key: PathBuf,
    root: PathBuf,
}

struct Http3OriginOptions {
    alt_svc: bool,
    reject_sessions: bool,
    refuse_sessions: bool,
    drop_first_session: bool,
}

/// The origins a harness can start; only the modes the harness asked for
/// are populated.
struct HarnessOrigins {
    tcp: TcpOrigin,
    tls: Option<TlsOrigin>,
    h3: Option<Http3Origin>,
}

async fn start_harness_origin(options: OriginOptions) -> HarnessOrigins {
    if let Some(http3) = options.http3.as_ref() {
        let gate = options.root.join("gate");
        let alt_svc_file = http3.alt_svc.then(|| options.root.join("alt-svc"));

        let origin = Http3Origin::start_with_settings(
            options.ip,
            0,
            &options.certificate,
            &options.private_key,
            &options.root,
            Http3OriginSettings {
                gate: Some(&gate),
                alt_svc_file: alt_svc_file.as_deref(),
                reject_sessions: http3.reject_sessions,
                refuse_sessions: http3.refuse_sessions,
                drop_first_session: http3.drop_first_session,
            },
        )
        .await;

        return HarnessOrigins {
            tcp: TcpOrigin::start(options.ip, 0, b"unused").await,
            tls: None,
            h3: Some(origin),
        };
    }

    if options.tls {
        let origin_address = SocketAddr::new(options.ip, options.origin_port);

        let (origin, tls_origin) = start_tls_origin(
            origin_address,
            &options.certificate,
            &options.private_key,
            options.tls_alpn,
        )
        .await;

        return HarnessOrigins {
            tcp: origin,
            tls: Some(tls_origin),
            h3: None,
        };
    }

    let origin = if options.keep_alive {
        TcpOrigin::start_keep_alive(options.ip, options.origin_port, b"origin-response").await
    } else {
        TcpOrigin::start(options.ip, options.origin_port, b"origin-response").await
    };

    HarnessOrigins {
        tcp: origin,
        tls: None,
        h3: None,
    }
}

/// Extra HTTP/3 options for one harness.
#[derive(Default)]
struct Http3Options {
    /// Let the proxy bind an ephemeral alternative port and report it back;
    /// the origin then advertises the reported port.
    alt_svc: bool,
    test_ech_dns: Option<SocketAddr>,
    reject_sessions: bool,
    refuse_sessions: bool,
    drop_first_session: bool,
}

#[derive(Default)]
struct HarnessOptions {
    tls: bool,
    advertise_http11_alpn: bool,
    keep_alive: bool,
    http10_origin: bool,
    claim_errors: bool,
    http3: Option<Http3Options>,
}

fn spawn_harness_proxy(mut command: Command, proxy_log: &Path, ready: &Path) -> Child {
    command
        .env("AGENT_SANDBOX_PROXY_SESSION_READY", ready)
        .env("INVOCATION_ID", "0123456789abcdef0123456789abcdef")
        .stdout(Stdio::from(
            std::fs::File::create(proxy_log).expect("create proxy log"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(proxy_log).expect("create proxy log"),
        ))
        .spawn()
        .expect("start proxy")
}

fn write_harness_ca(root: &TempDir) -> (PathBuf, PathBuf) {
    let ca = generate_simple_self_signed(vec!["localhost".to_owned()]).expect("generate CA");
    let ca_cert = root.path().join("ca.pem");
    let ca_key = root.path().join("ca-key.pem");
    std::fs::write(&ca_cert, ca.cert.pem()).expect("write CA certificate");
    std::fs::write(&ca_key, ca.signing_key.serialize_pem()).expect("write CA key");
    (ca_cert, ca_key)
}

fn start_harness_policy(root: &TempDir, claim_errors: bool) -> FakePolicy {
    if claim_errors {
        FakePolicy::start_claim_error(root.path())
    } else {
        FakePolicy::start(root.path())
    }
}

pub struct TransparentHarness {
    pub proxy_address: SocketAddr,
    pub origin: TcpOrigin,
    pub udp_origin: UdpOrigin,
    pub policy: FakePolicy,
    pub h3_origin: Option<Http3Origin>,

    /// Address of the alternative endpoint the proxy intercepts, when the
    /// harness started one.
    pub h3_alt_address: Option<SocketAddr>,

    pub proxy_log: PathBuf,
    tls_origin: Option<TlsOrigin>,
    root: TempDir,
    proxy: Child,
}

impl TransparentHarness {
    pub async fn start(ip: IpAddr, origin_port: u16) -> Self {
        Self::start_inner(ip, origin_port, HarnessOptions::default()).await
    }

    pub async fn start_keep_alive(ip: IpAddr, origin_port: u16) -> Self {
        Self::start_inner(ip, origin_port, HarnessOptions {
            keep_alive: true,
            ..HarnessOptions::default()
        })
        .await
    }

    pub async fn start_tls(ip: IpAddr) -> Self {
        Self::start_inner(ip, 0, HarnessOptions {
            tls: true,
            advertise_http11_alpn: true,
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start a TLS harness whose origin does not advertise ALPN.
    pub async fn start_tls_without_alpn(ip: IpAddr) -> Self {
        Self::start_inner(ip, 0, HarnessOptions {
            tls: true,
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start a plain harness whose origin is an explicit HTTP/1.0 upstream.
    pub async fn start_with_http10_origin(ip: IpAddr, origin_port: u16) -> Self {
        Self::start_inner(ip, origin_port, HarnessOptions {
            http10_origin: true,
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start a harness whose policy service rejects every flow claim.
    pub async fn start_claim_error(ip: IpAddr, origin_port: u16) -> Self {
        Self::start_inner(ip, origin_port, HarnessOptions {
            claim_errors: true,
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start a harness with the HTTP/3 backend enabled and an HTTP/3 origin.
    pub async fn start_http3(ip: IpAddr) -> Self {
        Self::start_inner(ip, 0, HarnessOptions {
            http3: Some(Http3Options::default()),
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start an HTTP/3 harness whose origin omits session settings.
    pub async fn start_http3_rejecting_sessions(ip: IpAddr) -> Self {
        let http3_options = Http3Options {
            reject_sessions: true,
            ..Http3Options::default()
        };

        Self::start_inner(ip, 0, HarnessOptions {
            http3: Some(http3_options),
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start an HTTP/3 harness whose origin refuses approved sessions.
    pub async fn start_http3_refusing_sessions(ip: IpAddr) -> Self {
        let http3_options = Http3Options {
            refuse_sessions: true,
            ..Http3Options::default()
        };

        Self::start_inner(ip, 0, HarnessOptions {
            http3: Some(http3_options),
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start an HTTP/3 harness whose first approved session closes early.
    pub async fn start_http3_reconnecting_sessions(ip: IpAddr) -> Self {
        let http3_options = Http3Options {
            drop_first_session: true,
            ..Http3Options::default()
        };

        Self::start_inner(ip, 0, HarnessOptions {
            http3: Some(http3_options),
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start an HTTP/3 harness whose origin advertises one alternative
    /// endpoint, which the proxy also intercepts.
    pub async fn start_http3_with_alt(ip: IpAddr) -> Self {
        let http3_options = Http3Options {
            alt_svc: true,
            ..Http3Options::default()
        };

        Self::start_inner(ip, 0, HarnessOptions {
            http3: Some(http3_options),
            ..HarnessOptions::default()
        })
        .await
    }

    /// Start an HTTP/3 harness whose upstream ECH lookups use `dns`.
    pub async fn start_http3_with_ech_dns(ip: IpAddr, dns: SocketAddr) -> Self {
        let http3_options = Http3Options {
            test_ech_dns: Some(dns),
            ..Http3Options::default()
        };

        Self::start_inner(ip, 0, HarnessOptions {
            http3: Some(http3_options),
            ..HarnessOptions::default()
        })
        .await
    }

    async fn start_inner(ip: IpAddr, origin_port: u16, options: HarnessOptions) -> Self {
        let HarnessOptions {
            tls,
            advertise_http11_alpn,
            keep_alive,
            http10_origin,
            claim_errors,
            http3,
        } = options;
        let root = tempfile::tempdir().expect("temporary harness directory");
        let policy = start_harness_policy(&root, claim_errors);
        let (ca_cert, ca_key) = write_harness_ca(&root);

        let origins = start_harness_origin(OriginOptions {
            ip,
            origin_port,
            tls,
            tls_alpn: harness_tls_alpn(advertise_http11_alpn),
            keep_alive,
            http3: http3.as_ref().map(|http3| Http3OriginOptions {
                alt_svc: http3.alt_svc,
                reject_sessions: http3.reject_sessions,
                refuse_sessions: http3.refuse_sessions,
                drop_first_session: http3.drop_first_session,
            }),
            certificate: ca_cert.clone(),
            private_key: ca_key.clone(),
            root: root.path().to_owned(),
        })
        .await;

        let origin = origins.tcp;
        let tls_origin = origins.tls;
        let h3_origin = origins.h3;
        let udp_origin = UdpOrigin::start(ip).await;
        let ready = root.path().join("ready");
        let state = root.path().join("ech");
        let bound_ports_path = root.path().join("bound-ports");

        let destination = h3_origin
            .as_ref()
            .map_or(origin.address, |origin| origin.address);

        let mut proxy_command = Command::new(env!("CARGO_BIN_EXE_agent-sandbox-proxy"));

        // The proxy binds port 0 and writes its actual ports back; handing a
        // pre-chosen port to the child would race other tests' ephemeral
        // binds between the reservation being released and the child binding.
        proxy_command.args([
            "--policy-socket",
            policy.socket.to_str().expect("policy socket path"),
            "--ca-certificate",
            ca_cert.to_str().expect("CA path"),
            "--ca-private-key",
            ca_key.to_str().expect("CA key path"),
            "--ech-state-dir",
            state.to_str().expect("ECH state path"),
            "--listen-port",
            "0",
            "--write-bound-ports",
            bound_ports_path.to_str().expect("bound ports path"),
            "--test-destination",
            &destination.to_string(),
        ]);

        if tls {
            proxy_command.arg("--test-tls");
        }

        if http10_origin {
            proxy_command.args([
                "--http10-upstream-origin",
                &format!("http://localhost:{}", origin.address.port()),
            ]);
        }

        if tls_origin.is_some() {
            proxy_command.env("SSL_CERT_FILE", &ca_cert);
        }

        if let Some(http3) = http3.as_ref() {
            proxy_command
                .args(["--enable-http3-backend", "--http3-listen-port"])
                .arg("0");

            if http3.alt_svc {
                proxy_command.args(["--http3-alt-port", "0"]);
            }

            if let Some(dns) = http3.test_ech_dns {
                proxy_command.args(["--test-ech-dns", &dns.to_string()]);
            }

            proxy_command.env("SSL_CERT_FILE", &ca_cert);
        }

        let proxy_log = root.path().join("proxy.log");
        let proxy = spawn_harness_proxy(proxy_command, &proxy_log, &ready);
        wait_for_path(&ready).await;

        let (proxy_address, h3_alt_address) =
            resolve_harness_addresses(&root, ip, &read_bound_ports(&bound_ports_path));

        Self {
            proxy_address,
            origin,
            udp_origin,
            policy,
            h3_origin,
            h3_alt_address,
            proxy_log,
            tls_origin,
            root,
            proxy,
        }
    }

    pub async fn request(&self, path: &str) -> Vec<u8> {
        let mut stream = TcpStream::connect(self.proxy_address)
            .await
            .expect("connect proxy");

        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            self.origin.address.port()
        );

        stream
            .write_all(request.as_bytes())
            .await
            .expect("write client request");

        let mut response = Vec::new();

        stream
            .read_to_end(&mut response)
            .await
            .expect("read client response");

        response
    }

    pub async fn pooled_requests(&self) -> (Vec<u8>, Vec<u8>) {
        let mut stream = TcpStream::connect(self.proxy_address)
            .await
            .expect("connect proxy");

        let host = format!("localhost:{}", self.origin.address.port());
        let first_request = format!("GET /pool-first HTTP/1.1\r\nHost: {host}\r\n\r\n");

        stream
            .write_all(first_request.as_bytes())
            .await
            .expect("write first pooled request");

        let first_response = read_http_response(&mut stream).await;
        let second_request = format!("GET /pool-second HTTP/1.1\r\nHost: {host}\r\n\r\n");

        stream
            .write_all(second_request.as_bytes())
            .await
            .expect("write second pooled request");

        let second_response = read_http_response(&mut stream).await;
        (first_response, second_response)
    }

    pub async fn websocket_request(&self) -> Vec<u8> {
        let mut stream = TcpStream::connect(self.proxy_address)
            .await
            .expect("connect proxy");

        let request = format!(
            "GET /websocket HTTP/1.1\r\nHost: localhost:{}\r\nUpgrade: websocket\r\nConnection: \
             Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: \
             13\r\n\r\n",
            self.origin.address.port()
        );

        stream
            .write_all(request.as_bytes())
            .await
            .expect("write websocket request");

        let mut response = Vec::new();

        while !response.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];

            stream
                .read_exact(&mut byte)
                .await
                .expect("read websocket response");

            response.push(byte[0]);
        }

        stream
            .write_all(b"ping")
            .await
            .expect("write websocket payload");

        let mut payload = [0; 4];

        stream
            .read_exact(&mut payload)
            .await
            .expect("read websocket payload");

        response.extend_from_slice(&payload);
        response
    }

    pub async fn http10_request(&self, path: &str) -> Vec<u8> {
        let mut stream = TcpStream::connect(self.proxy_address)
            .await
            .expect("connect proxy");

        let request = format!("GET {path} HTTP/1.0\r\nConnection: close\r\n\r\n");

        stream
            .write_all(request.as_bytes())
            .await
            .expect("write HTTP/1.0 request");

        let mut response = Vec::new();

        stream
            .read_to_end(&mut response)
            .await
            .expect("read HTTP/1.0 response");

        response
    }

    pub async fn streaming_request(&self, path: &str) -> (Vec<u8>, Vec<u8>) {
        let mut stream = TcpStream::connect(self.proxy_address)
            .await
            .expect("connect proxy");

        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            self.origin.address.port()
        );

        stream
            .write_all(request.as_bytes())
            .await
            .expect("write client request");

        let mut first = Vec::new();

        while !first.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];

            stream
                .read_exact(&mut byte)
                .await
                .expect("read response header");

            first.push(byte[0]);
        }

        let mut first_body = [0; 7];

        stream
            .read_exact(&mut first_body)
            .await
            .expect("read first response body chunk");

        first.extend_from_slice(&first_body);
        self.origin.stream_gate.notify_one();
        let mut rest = Vec::new();

        stream
            .read_to_end(&mut rest)
            .await
            .expect("read remaining response");

        (first, rest)
    }

    pub async fn abort_streaming_request(&self, path: &str) {
        let mut stream = TcpStream::connect(self.proxy_address)
            .await
            .expect("connect proxy");

        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            self.origin.address.port()
        );

        stream
            .write_all(request.as_bytes())
            .await
            .expect("write client request");

        let mut headers = Vec::new();

        while !headers.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];

            stream
                .read_exact(&mut byte)
                .await
                .expect("read response headers");

            headers.push(byte[0]);
        }

        let mut first_body = [0; 7];

        stream
            .read_exact(&mut first_body)
            .await
            .expect("read first response body chunk");

        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };

        setsockopt(&stream.as_fd(), Linger, &linger).expect("set reset linger");
        drop(stream);
        self.origin.stream_gate.notify_one();
    }

    /// Send raw bytes over TLS to the proxy and return the client output.
    ///
    /// `servername` selects the TLS SNI value, which the proxy treats as the
    /// verified TLS identity for authority resolution.
    pub fn tls_raw_request(&self, request: &str, servername: Option<&str>) -> Vec<u8> {
        let ip = self.proxy_address.ip().to_string();

        let endpoint = if self.proxy_address.is_ipv6() {
            format!("[{ip}]:{}", self.proxy_address.port())
        } else {
            format!("{ip}:{}", self.proxy_address.port())
        };

        let mut command = Command::new("openssl");

        command.args([
            "s_client",
            "-quiet",
            "-connect",
            &endpoint,
            "-CAfile",
            self.root.path().join("ca.pem").to_str().expect("CA path"),
        ]);

        if let Some(servername) = servername {
            command.args(["-servername", servername]);
        }

        let mut client = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start TLS client");

        client
            .stdin
            .take()
            .expect("TLS client stdin")
            .write_all(request.as_bytes())
            .expect("write TLS request");

        client
            .wait_with_output()
            .expect("read TLS client response")
            .stdout
    }

    pub fn tls_request(&self, path: &str) -> Vec<u8> {
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            self.origin.address.port()
        );

        self.tls_raw_request(&request, None)
    }

    /// Send a hostless HTTP/1.0 request over TLS with SNI.
    pub fn tls_http10_request(&self, path: &str) -> Vec<u8> {
        self.tls_raw_request(&format!("GET {path} HTTP/1.0\r\n\r\n"), Some("localhost"))
    }

    pub fn policy_events(&self) -> Arc<Mutex<PolicyEvents>> {
        self.policy.events.clone()
    }

    /// Send one HTTP/3 GET request through the proxy.
    pub async fn http3_request(&self, path: &str) -> Result<Http3Response, String> {
        self.http3_request_to(self.proxy_address, path).await
    }

    /// Send one HTTP/3 GET request to an explicit proxy endpoint.
    pub async fn http3_request_to(
        &self,
        address: SocketAddr,
        path: &str,
    ) -> Result<Http3Response, String> {
        let client = Http3Client::new(&self.root.path().join("ca.pem"));
        client.request(address, "localhost", path).await
    }

    /// Send one HTTP/3 GET request whose ECH offer uses the proxy's keys.
    pub async fn http3_ech_request(&self, path: &str) -> Result<Http3Response, String> {
        let config_list = std::fs::read(self.ech_state_dir().join("ech-config-list"))
            .map_err(|error| format!("read proxy ECH configuration: {error}"))?;

        let client = Http3Client::with_ech(&self.ca_file(), &config_list);
        client.request(self.proxy_address, "localhost", path).await
    }

    /// Directory holding the proxy's ECH key material and configuration.
    #[must_use]
    pub fn ech_state_dir(&self) -> PathBuf {
        self.root.path().join("ech")
    }

    /// Path of the harness CA certificate.
    #[must_use]
    pub fn ca_file(&self) -> PathBuf {
        self.root.path().join("ca.pem")
    }

    /// The HTTP/3 origin started with this harness.
    #[must_use]
    pub const fn h3_origin(&self) -> &Http3Origin {
        self.h3_origin.as_ref().expect("HTTP/3 origin")
    }

    /// Path of the streaming gate file for the HTTP/3 origin.
    #[must_use]
    pub fn h3_stream_gate(&self) -> PathBuf {
        self.root.path().join("gate")
    }
}

impl Drop for TransparentHarness {
    fn drop(&mut self) {
        let _ = self.proxy.kill();
        let _ = self.proxy.wait();
        let _ = self.tls_origin.take();
    }
}

async fn wait_for_path(path: &Path) {
    timeout(Duration::from_secs(5), async {
        while !path.exists() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("proxy readiness");
}

/// The ports the proxy bound, reported through its `--write-bound-ports`
/// file after every listener is up.
struct BoundProxyPorts {
    tcp: u16,
    http3_main: Option<u16>,
    http3_alts: Vec<u16>,
}

/// Derive the client-facing addresses from the proxy's reported ports and
/// publish the alternative port to the origin's advertisement file.
fn resolve_harness_addresses(
    root: &TempDir,
    ip: IpAddr,
    bound_ports: &BoundProxyPorts,
) -> (SocketAddr, Option<SocketAddr>) {
    let proxy_address = SocketAddr::new(ip, bound_ports.http3_main.unwrap_or(bound_ports.tcp));

    let h3_alt_address = bound_ports
        .http3_alts
        .first()
        .copied()
        .map(|port| SocketAddr::new(ip, port));

    if let Some(alt_port) = bound_ports.http3_alts.first() {
        std::fs::write(root.path().join("alt-svc"), alt_port.to_string())
            .expect("write origin alt-svc port");
    }

    (proxy_address, h3_alt_address)
}

fn read_bound_ports(path: &Path) -> BoundProxyPorts {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read bound proxy ports from {}: {error}", path.display()));

    let mut ports = BoundProxyPorts {
        tcp: 0,
        http3_main: None,
        http3_alts: Vec::new(),
    };

    for line in content.lines() {
        let Some((key, value)) = line.split_once(' ') else {
            panic!("malformed bound proxy port line: {line:?}");
        };

        let port: u16 = value
            .parse()
            .unwrap_or_else(|error| panic!("malformed bound proxy port {value:?}: {error}"));

        match key {
            "tcp" => ports.tcp = port,
            "http3" if ports.http3_main.is_none() => ports.http3_main = Some(port),
            "http3" => ports.http3_alts.push(port),
            other => panic!("unknown bound proxy port key: {other:?}"),
        }
    }

    assert_ne!(
        ports.tcp,
        0,
        "bound proxy ports file {} has no tcp entry",
        path.display()
    );

    ports
}

pub const fn loopback(version: IpVersion) -> IpAddr {
    match version {
        IpVersion::V4 => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpVersion::V6 => IpAddr::V6(Ipv6Addr::LOCALHOST),
    }
}

#[derive(Clone, Copy)]
pub enum IpVersion {
    V4,
    V6,
}
