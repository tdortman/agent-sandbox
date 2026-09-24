{
  config,
  lib,
  pkgs,
  inputs,
  ...
}:
let
  inherit (agentSandboxLib) dbusRuleJson httpRuleJson packageHasPolicy;
  agentSandboxLib = import ./lib.nix {
    inherit lib;
    inherit (flake) jail-nix;
  };
  cPortMatch =
    ports:
    if ports == [ ] then
      "0"
    else
      lib.concatMapStringsSep " || " (port: "port == ${toString port}") ports;
  cfg = config.agent-sandbox.network;
  flake = import ../../../lib/consumer.nix { inherit inputs pkgs; };
  hostNatPkg = mkNetnsLauncher {
    name = "agent-sandbox-host-nat";

    runtimeInputs = [
      pkgs.iproute2
      pkgs.nftables
      pkgs.procps # sysctl
    ];

    script = hostNatScript;
  };
  hostNatScript = pkgs.replaceVars ./netns/host-nat.sh {
    inherit loopbackHandoffIp6;
    # Host services then see a loopback peer and reply over loopback, so a
    # wildcard-bound UDP server's reply source matches the conntrack entry.
    hostLoopbackInputRule = lib.escapeShellArg ''iifname "${runtime.network.vethHost}" ip saddr ${runtime.network.netnsIp} ip daddr 127.0.0.1 ct status dnat snat to 127.0.0.1'';

    hostLoopbackOutputRule = lib.escapeShellArg (
      loopbackProtocolRules (
        protocol: ports:
        "ip daddr 127.0.0.2 ${protocol} dport { ${portSet ports} } dnat to ${runtime.network.netnsIp}"
      )
    );

    hostLoopbackOutputRule6 = lib.escapeShellArg (
      loopbackProtocolRules (
        protocol: ports:
        "ip6 daddr ${loopbackHandoffIp6} ${protocol} dport { ${portSet ports} } dnat to ${runtime.network.netnsIp6}"
      )
    );

    hostLoopbackPostroutingRule = lib.escapeShellArg (
      loopbackProtocolRules (
        protocol: ports:
        "ip saddr 127.0.0.0/8 ip daddr ${runtime.network.netnsIp} ${protocol} dport { ${portSet ports} } snat to ${runtime.hostIp}"
      )
    );

    hostLoopbackPostroutingRule6 = lib.escapeShellArg (
      loopbackProtocolRules (
        protocol: ports:
        "ip6 daddr ${runtime.network.netnsIp6} ${protocol} dport { ${portSet ports} } snat to ${runtime.hostIp6}"
      )
    );

    # Every sandbox handoff port except the veth DNS forwarder lands on host
    # localhost; network policy gates each destination inside the sandbox.
    hostLoopbackPreroutingRule = lib.escapeShellArg ''iifname "${runtime.network.vethHost}" ip saddr ${runtime.network.netnsIp} ip daddr ${runtime.hostIp} meta l4proto { tcp, udp } th dport != 53 dnat to 127.0.0.1'';
    hostLoopbackPreroutingRule6 = lib.escapeShellArg "";
    vethHost = runtime.network.vethHost;
  };
  http3UdpPorts = [
    (toString runtime.httpProxy.http3.udpPort)
  ]
  ++ map toString runtime.httpProxy.http3.altUdpPorts;
  http3UdpPortsComma = lib.concatStringsSep "," http3UdpPorts;
  http3UdpPortsSpace = lib.concatStringsSep " " http3UdpPorts;
  loopbackBpfObject =
    pkgs.runCommand "agent-sandbox-loopback-bpf.o"
      {
        nativeBuildInputs = [
          pkgs.libbpf
          pkgs.linuxHeaders
          pkgs.llvmPackages.clang-unwrapped
        ];
      }
      ''
        ${pkgs.llvmPackages.clang-unwrapped}/bin/clang -O2 -g -target bpf \
          -DTCP_PORT_MATCH='(${cPortMatch loopbackTcpPorts})' \
          -DUDP_PORT_MATCH='(${cPortMatch loopbackUdpPorts})' \
          -I${pkgs.libbpf}/include \
          -I${pkgs.linuxHeaders}/include \
          -c ${./loopback/redirect.bpf.c} \
          -o "$out"
      '';
  loopbackBpfPkg = mkNetnsLauncher {
    name = "agent-sandbox-loopback-bpf";

    runtimeInputs = [
      pkgs.bpftools
      pkgs.coreutils
      pkgs.iproute2
    ];

    script = loopbackBpfScript;
  };
  loopbackBpfScript = pkgs.replaceVars ./loopback/bpf.sh {
    inherit (runtime) hostIp6;
    inherit (runtime.network) netnsIp6;
    bpfObject = loopbackBpfObject;
    helperBin = "${loopbackHelperPkg}/bin/agent-sandbox-netns-helper";
    netnsName = runtime.network.netnsName;
  };
  loopbackHandoffIp6 = "::2";
  loopbackHelperPkg = pkgs.stdenv.mkDerivation {
    pname = "agent-sandbox-netns-helper";
    version = "1";
    src = ./loopback/netns-helper.c;

    buildPhase = ''
      runHook preBuild
      $CC -O2 "$src" -o agent-sandbox-netns-helper
      runHook postBuild
    '';

    dontUnpack = true;

    installPhase = ''
      runHook preInstall
      install -Dm755 agent-sandbox-netns-helper "$out/bin/agent-sandbox-netns-helper"
      runHook postInstall
    '';
  };
  loopbackPolicyRules = lib.concatMap (
    port:
    map (host: { inherit host port; }) [
      "127.0.0.1"
      "::1"
      runtime.network.netnsIp6
    ]
  ) loopbackPorts;
  loopbackPorts = lib.unique (loopbackTcpPorts ++ loopbackUdpPorts);
  loopbackProtocolRules =
    rule:
    lib.concatStringsSep "\n" (
      lib.optional (loopbackTcpPorts != [ ]) (rule "tcp" loopbackTcpPorts)
      ++ lib.optional (loopbackUdpPorts != [ ]) (rule "udp" loopbackUdpPorts)
    );
  loopbackTcpPorts = lib.unique cfg.loopback.tcpPorts;
  loopbackUdpPorts = lib.unique cfg.loopback.udpPorts;
  mkNetnsLauncher =
    {
      name,
      runtimeInputs,
      script,
    }:
    pkgs.writeShellApplication {
      inherit name runtimeInputs;

      text = ''
        exec ${pkgs.bash}/bin/bash ${script} "$@"
      '';
    };
  netnsDownPkg = mkNetnsLauncher {
    name = "agent-sandbox-netns-down";
    runtimeInputs = [ pkgs.iproute2 ];
    script = netnsDownScript;
  };
  netnsDownScript = pkgs.replaceVars ./netns/down.sh {
    inherit loopbackHandoffIp6;
    netnsName = runtime.network.netnsName;
    vethHost = runtime.network.vethHost;
  };
  netnsUpPkg = mkNetnsLauncher {
    name = "agent-sandbox-netns-up";

    runtimeInputs = [
      hostNatPkg
      pkgs.coreutils
      pkgs.iproute2
      pkgs.nftables
      pkgs.procps # sysctl
      pkgs.util-linux # unshare
    ];

    script = netnsUpScript;
  };
  netnsUpScript = pkgs.replaceVars ./netns/up.sh {
    inherit (runtime) hostIp hostIp6;
    inherit loopbackHandoffIp6 nftRules;
    hostIp6Cidr = "${runtime.hostIp6}/${toString runtime.network.netnsIp6Prefix}";
    hostIpCidr = "${runtime.hostIp}/30";
    hostNatBin = "${hostNatPkg}/bin/agent-sandbox-host-nat";
    netnsIp = runtime.network.netnsIp;
    netnsIp6Cidr = "${runtime.network.netnsIp6}/${toString runtime.network.netnsIp6Prefix}";
    netnsName = runtime.network.netnsName;

    proxyUidElement = lib.optionalString cfg.httpProxy.enable ''
      ip netns exec "$NETNS" nft add element inet agent_sandbox proxy_uid { $(id -u "${proxyUser}") }
    '';

    vethHost = runtime.network.vethHost;
    vethNetns = runtime.network.vethNetns;
  };
  # These daemons do not execute approved host commands, so they can be
  # confined without changing the policy daemon's executor namespace.
  networkDaemonHardening = networkHardening // {
    NoNewPrivileges = true;
    ReadWritePaths = [ "/run/agent-sandbox" ];
  };
  # These daemons do not execute approved host commands, so they can be
  # confined without changing the policy daemon's executor namespace.
  networkHardening = {
    LockPersonality = true;
    PrivateTmp = true;
    ProtectControlGroups = true;
    ProtectHome = true;
    ProtectSystem = "strict";

    RestrictAddressFamilies = [
      "AF_UNIX"
      "AF_NETLINK"
      "AF_INET"
      "AF_INET6"
    ];

    RestrictSUIDSGID = true;
  };
  # The namespace creator must publish its /run/netns bind mount to PID 1.
  # Mount/filesystem isolation here would leave only an empty path behind when
  # the oneshot exits, so keep only restrictions that do not create a private
  # mount namespace.
  networkNamespaceSetupHardening = {
    inherit (networkHardening)
      LockPersonality
      RestrictAddressFamilies
      RestrictSUIDSGID
      ;
  };
  # Setup units retain their existing root capabilities for netlink/nftables
  # operations, but do not need host home directories or a shared /tmp.
  networkSetupHardening = networkHardening // {
    ReadWritePaths = [
      "/run/agent-sandbox"
      "/run/netns"
      "/var/lib/agent-sandbox"
    ];
  };
  nfqLauncher = pkgs.writeShellScript "agent-sandbox-nfq-with-owner" ''
    set -eu
    proxy_args=()
    ${lib.optionalString verdictGateEnabled ''
      if proxy_uid=$(${pkgs.coreutils}/bin/id -u ${lib.escapeShellArg proxyUser} 2>/dev/null); then
        proxy_args=(--proxy-uid "$proxy_uid")
      else
        echo "agent-sandbox verdict gate: cannot resolve proxy uid; verdict cache stays off" >&2
      fi
    ''}
    pins=/run/agent-sandbox/owner-hints
    ${pkgs.coreutils}/bin/mkdir -p "$pins"
    # The service's private mount namespace owns these fresh pins. The query
    # process owns every observer link, so all detach together when it exits.
    if ${pkgs.util-linux}/bin/mount -t bpf bpf "$pins"; then
      ${pkgs.coreutils}/bin/mkdir -p "$pins/maps"
      if ${pkgs.bpftools}/bin/bpftool prog loadall ${ownerHintBpfObject} "$pins" pinmaps "$pins/maps"; then
        exec ${sandboxPkg}/bin/agent-sandbox-nfq --owner-hints "$pins" "$@" ''${proxy_args[@]}
      fi
    fi
    echo "kernel ownership hints unavailable; continuing with iterator" >&2
    exec ${sandboxPkg}/bin/agent-sandbox-nfq "$@" ''${proxy_args[@]}
  '';
  nfqReadyPath = "/run/agent-sandbox/nfq-ready";
  # The DNS forwarder runs on the host and listens on the veth gateway. It
  # forwards raw DNS queries to the upstream resolver (configured via
  # `agent-sandbox.network.dnsForwardTarget`) and writes IP->hostname mappings
  # to a shared cache file before responding.
  #
  # DNS responses must NOT be queued to NFQUEUE. NFQUEUE is single-threaded
  # and blocks during policy checks (up to approval_timeout). If DNS
  # responses were queued on the output hook, they would stall behind any
  # pending policy check, breaking name resolution for every new hostname.
  #
  # There is no allow fast-path for NFQUEUE-owned traffic. In proxy mode,
  # NFQUEUE handles the transparently proxied service ports and new UDP
  # flows; direct TCP destinations are gated by seccomp user notification
  # and then accepted by the kernel route. Denied destinations get a short
  # reject-set entry only so client calls fail quickly instead of retrying
  # until TCP timeout. Established/related conntrack entries, DNS traffic
  # to the forwarder, and transient reject entries bypass NFQUEUE.
  nftRules = ''
    table inet agent_sandbox {
      # Transient reject sets for denied destinations.
      # NFQ adds these on deny verdicts (dynamic, auto-expire).
      set reject_v4 {
        type ipv4_addr . inet_service;
        flags dynamic, timeout;
        size 65535;
        policy performance;
        timeout 10s;
      }
      set reject_v6 {
        type ipv6_addr . inet_service;
        flags dynamic, timeout;
        size 65535;
        policy performance;
        timeout 10s;
      }
      # The transparent proxy runs inside the netns. Its own sockets are
      # exempt from the UDP queue below; the netns up script populates this
      # set with the proxy uid at runtime.
      set proxy_uid {
        type uid;
        size 1;
      }

      # Host localhost flows leave through the loopback handoff address. Judge
      # them here, before the handoff DNAT rewrites them to the veth gateway:
      # nft nat chains all run at the kernel's fixed NAT hook priority (-100),
      # whatever their own priority.
      chain handoff {
        type filter hook output priority -110; policy accept;
        ct state established,related accept
        ip daddr 127.0.0.2 ip daddr . tcp dport @reject_v4 reject with tcp reset
        ip daddr 127.0.0.2 ip daddr . udp dport @reject_v4 reject
        ip6 daddr ${loopbackHandoffIp6} ip6 daddr . tcp dport @reject_v6 reject with tcp reset
        ip6 daddr ${loopbackHandoffIp6} ip6 daddr . udp dport @reject_v6 reject with icmpv6 type port-unreachable
        ip daddr 127.0.0.2 tcp flags & (syn | ack) == syn queue num ${toString runtime.queueNumber}
        ip daddr 127.0.0.2 meta l4proto udp queue num ${toString runtime.queueNumber}
        ip6 daddr ${loopbackHandoffIp6} tcp flags & (syn | ack) == syn queue num ${toString runtime.queueNumber}
        ip6 daddr ${loopbackHandoffIp6} meta l4proto udp queue num ${toString runtime.queueNumber}
      }

      chain output {
        type filter hook output priority 0; policy drop;
        ct state established,related accept
        # Handoff flows were judged by the handoff chain before their DNAT.
        ct status dnat ip daddr ${runtime.hostIp} accept
        ct status dnat ip6 daddr ${runtime.hostIp6} accept
        # DNS traffic to the forwarder bypasses NFQUEUE
        ip daddr ${runtime.hostIp} udp dport 53 accept
        ip daddr ${runtime.hostIp} tcp dport 53 accept
        ip6 daddr ${runtime.hostIp6} udp dport 53 accept
        ip6 daddr ${runtime.hostIp6} tcp dport 53 accept
        # NDP only: neighbor and router discovery for the veth gateway.
        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
        # Reject denied destinations from transient reject sets. UDP flows
        # claimed for the transparent proxy carry its mark and skip these:
        # the proxy enforces their policy per request, and a denied direct
        # flow must not poison a later proxy flow to the same destination.
        # TCP stays unconditional: ambiguous owners fail fast here, and no
        # legitimate proxy TCP flow can be listed.
        ip daddr . tcp dport @reject_v4 reject with tcp reset
        ip daddr . udp dport @reject_v4 meta mark != ${proxyMark} reject
        ip6 daddr . tcp dport @reject_v6 reject with tcp reset
        ip6 daddr . udp dport @reject_v6 meta mark != ${proxyMark} reject with icmpv6 type port-unreachable
        # Encrypted DNS transports have no policy-controlled resolver path.
        tcp dport 853 reject with tcp reset
        ${lib.optionalString (
          cfg.httpProxy.enable && cfg.httpProxy.http3.enable
        ) "udp dport 853 reject\n"}
        ${lib.optionalString (!cfg.httpProxy.http3.enable) "udp dport { 443, 853 } reject\n"}
        ${lib.optionalString (!cfg.httpProxy.enable)
          "    ip protocol tcp tcp flags & (syn | ack) == syn queue num ${toString runtime.queueNumber}\n    ip protocol udp queue num ${toString runtime.queueNumber}\n    meta nfproto ipv6 meta l4proto tcp tcp flags & (syn | ack) == syn queue num ${toString runtime.queueNumber}\n    meta nfproto ipv6 meta l4proto udp queue num ${toString runtime.queueNumber}\n"
        }
        ${lib.optionalString cfg.httpProxy.enable ''
          # The proxy's own upstream sockets must not be queued back for
          # policy; without this its HTTP/3 backend flows would be
          # registered as intercepted proxy flows.
          meta skuid @proxy_uid accept
          # Direct TCP ports were approved by seccomp user notification;
          # keep them on the kernel route. New UDP flows are queued for a
          # transport check (one deduped prompt per host:port), then
          # established flows pass via the conntrack rule above.
          ip protocol tcp accept
          ip protocol udp ct state new,untracked queue num ${toString runtime.queueNumber}
          meta nfproto ipv6 meta l4proto tcp accept
          meta nfproto ipv6 meta l4proto udp ct state new,untracked queue num ${toString runtime.queueNumber}
        ''}
      }
    }
    # Handoff DNAT only: the packet filter judges these flows in the
    # agent_sandbox handoff chain first.
    table ip agent_sandbox_loopback {
      chain output {
        type nat hook output priority dstnat; policy accept;
        ip daddr 127.0.0.2 meta l4proto { tcp, udp } dnat to ${runtime.hostIp}
      }
      chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 127.0.0.0/8 ip daddr ${runtime.hostIp} meta l4proto { tcp, udp } snat to ${runtime.network.netnsIp}
      }
      chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        ${loopbackProtocolRules (
          protocol: ports:
          ''iifname "${runtime.network.vethNetns}" ip saddr ${runtime.hostIp} ip daddr ${runtime.network.netnsIp} ${protocol} dport { ${portSet ports} } dnat to 127.0.0.1''
        )}
      }
    }
    table ip6 agent_sandbox_loopback {
      chain output {
        type nat hook output priority dstnat; policy accept;
        ${loopbackProtocolRules (
          protocol: ports:
          "ip6 daddr ${loopbackHandoffIp6} ${protocol} dport { ${portSet ports} } dnat to ${runtime.hostIp6}"
        )}
      }
      chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ${loopbackProtocolRules (
          protocol: ports:
          "ip6 daddr ${runtime.hostIp6} ${protocol} dport { ${portSet ports} } snat to ${runtime.network.netnsIp6}"
        )}
      }
    }
  '';
  # Inside the jail we cannot use nss-resolve (no /run/systemd/resolve). Plain DNS only.
  nsswitchConfText = ''
    hosts: files dns
    networks: files
  '';
  ownerBpfObject = pkgs.runCommand "agent-sandbox-owner-bpf.o" { } ''
    ${pkgs.llvmPackages.clang-unwrapped}/bin/clang -O2 -g -target bpf \
      -I${pkgs.libbpf}/include \
      -I${pkgs.linuxHeaders}/include \
      -c ${./owner}/resolve.bpf.c -o "$out"
  '';
  ownerHintBpfObject = pkgs.runCommand "agent-sandbox-owner-hint-bpf.o" { } ''
    ${pkgs.llvmPackages.clang-unwrapped}/bin/clang -O2 -g -target bpf -mcpu=v4 \
      -I${pkgs.libbpf}/include \
      -I${pkgs.linuxHeaders}/include \
      -c ${./owner}/hint.bpf.c -o "$out"
  '';
  packageEffectiveName =
    value:
    if value.name != null then
      value.name
    else if value.binary != null then
      value.binary
    else
      lib.baseNameOf (lib.getExe value.package);
  policyEnabled =
    cfg.enable
    || rootCfg.policy.dbus.enable
    || rootCfg.sudoPolicy == "approve"
    || rootCfg.gates.filesystem.enable
    || rootCfg.policy.filesystem.declarativeAllow != [ ]
    || rootCfg.policy.filesystem.declarativeDeny != [ ]
    || rootCfg.policy.resources.declarativeAllow != [ ]
    || rootCfg.policy.resources.declarativeDeny != [ ]
    || rootCfg.policy.sudo.declarativeAllow != [ ]
    || rootCfg.policy.sudo.declarativeDeny != [ ]
    || lib.any packageHasPolicy rootCfg.packages;
  portSet = ports: lib.concatStringsSep ", " (map toString ports);
  proxyBundlePath = "/run/agent-sandbox/proxy-ca-bundle.pem";
  proxyCaCertificate = cfg.httpProxy.caCertificateFile;
  proxyCaPrivateKey = cfg.httpProxy.caPrivateKeyFile;
  proxyCidrsPath = "/etc/agent-sandbox/proxy-upstream-cidrs.json";
  proxyFirewallPkg = pkgs.writeShellApplication {
    name = "agent-sandbox-proxy-firewall";

    runtimeInputs = [
      pkgs.coreutils
      pkgs.jq
      pkgs.nftables
    ];

    text = builtins.readFile ./proxy-firewall.sh;
  };
  proxyGroup = "agent-sandbox-proxy";
  proxyGroupLookupPkg = pkgs.writeShellApplication {
    name = "agent-sandbox-proxy-group-gid";

    runtimeInputs = [
      pkgs.coreutils
      pkgs.getent
      pkgs.glibc.bin
    ];

    text = builtins.readFile ./proxy-group-gid.sh;
  };
  proxyInitPkg = pkgs.writeShellApplication {
    name = "agent-sandbox-proxy-init";

    runtimeInputs = [
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.openssl
    ];

    text = builtins.readFile ./proxy-init.sh;
  };
  proxyLaunchPkg = pkgs.writeShellApplication {
    name = "agent-sandbox-proxy-launch";
    runtimeInputs = [ pkgs.coreutils ];

    text = ''
      set -euo pipefail
      exec ${
        lib.escapeShellArgs (
          [
            "${sandboxPkg}/bin/agent-sandbox-proxy"
            "--policy-socket"
            runtime.httpProxy.socketPath
            "--ca-certificate"
            "${proxyStateDir}/proxy-ca-cert.pem"
            "--ca-private-key"
            "${proxyStateDir}/proxy-ca.key"
            "--ech-state-dir"
            proxyStateDir
            "--listen-port"
            "18080"
          ]
          ++ lib.concatMap (url: [
            "--websocket-http11-url"
            url
          ]) runtime.httpProxy.websocketHttp11Urls
          ++ lib.concatMap (origin: [
            "--http10-upstream-origin"
            origin
          ]) runtime.httpProxy.http10UpstreamOrigins
          ++ lib.concatMap (origin: [
            "--h2c-upstream-origin"
            origin
          ]) runtime.httpProxy.h2cUpstreamOrigins
          ++ lib.optionals (runtime.httpProxy.upstreamClientIdentitiesFile != null) [
            "--upstream-client-identities"
            runtime.httpProxy.upstreamClientIdentitiesFile
          ]
          ++ lib.optionals runtime.httpProxy.http3.enable [
            "--enable-http3-backend"
            "--http3-upstream-handshake-timeout-ms"
            (toString runtime.httpProxy.http3.upstreamHandshakeTimeoutMs)
            "--http3-listen-port"
            (toString runtime.httpProxy.http3.udpPort)
          ]
          ++ lib.concatMap (port: [
            "--http3-alt-port"
            (toString port)
          ]) runtime.httpProxy.http3.altUdpPorts
        )
      }
    '';
  };
  # Packet mark claiming a flow for the transparent proxy. Shared with
  # proxy-tproxy-route.sh (its $mark argument); both sides must agree.
  proxyMark = "51820";
  proxyPolicyLauncher = pkgs.writeShellApplication {
    name = "agent-sandbox-policy-launch";
    runtimeInputs = [ proxyGroupLookupPkg ];

    text = ''
      set -euo pipefail
      proxy_gid="''${AGENT_SANDBOX_PROXY_GID_OVERRIDE:-}"
      if [[ -z "$proxy_gid" ]]; then
        proxy_gid="$(${proxyGroupLookupPkg}/bin/agent-sandbox-proxy-group-gid ${lib.escapeShellArg proxyGroup})"
      fi
      [[ "$proxy_gid" =~ ^[1-9][0-9]*$ ]] || {
        echo "agent-sandbox policy: proxy group ID is invalid" >&2
        exit 1
      }
      exec ${sandboxPkg}/bin/agent-sandbox-policyd "$@" --proxy-gid "$proxy_gid"
    '';
  };
  proxyReadyPath = "${proxyStateDir}/proxy-ready";
  proxyStateDir = "/var/lib/agent-sandbox/proxy";
  proxyTproxyRoutePkg = pkgs.writeShellApplication {
    name = "agent-sandbox-proxy-tproxy-route";

    runtimeInputs = [
      pkgs.coreutils
      pkgs.iproute2
      pkgs.nftables
      pkgs.systemd
    ];

    text = builtins.readFile ./proxy-tproxy-route.sh;
  };
  proxyUser = "agent-sandbox-proxy";
  readinessMarkerPkg = pkgs.writeShellApplication {
    name = "agent-sandbox-readiness-marker";
    runtimeInputs = [ pkgs.coreutils ];
    text = builtins.readFile ./readiness-marker.sh;
  };
  # forwards raw DNS queries to the configured upstream resolver and writes
  # IP->hostname mappings to a shared cache for NFQUEUE prompts.
  resolvConfText = ''
    nameserver ${runtime.hostIp}
    options edns0 trust-ad
  '';
  rootCfg = config.agent-sandbox;
  runtime = agentSandboxLib.mkRuntime { inherit rootCfg; };
  sandboxPkg = flake.package "agent-sandbox";
  verdictBpfObject =
    pkgs.runCommand "agent-sandbox-verdict-gate-bpf.o"
      {
        nativeBuildInputs = [
          pkgs.libbpf
          pkgs.linuxHeaders
          pkgs.llvmPackages.clang-unwrapped
        ];
      }
      ''
        ${pkgs.llvmPackages.clang-unwrapped}/bin/clang -O2 -g -target bpf \
          -I${pkgs.libbpf}/include \
          -I${pkgs.linuxHeaders}/include \
          -c ${./policy/gate.bpf.c} \
          -o "$out"
      '';
  verdictBpfScript = pkgs.replaceVars ./policy/bpf.sh {
    inherit verdictMapDir;
    bpfObject = verdictBpfObject;
  };
  verdictGateBpfPkg = mkNetnsLauncher {
    name = "agent-sandbox-verdict-gate-bpf";

    runtimeInputs = [
      pkgs.bpftools
      pkgs.coreutils
    ];

    script = verdictBpfScript;
  };
  verdictGateEnabled = cfg.verdictGate.enable;
  verdictMapDir = "/sys/fs/bpf/agent-sandbox-verdict";
in
{
  config = lib.mkIf policyEnabled (
    lib.mkMerge [
      {
        environment.etc."agent-sandbox/policy.json".text = builtins.toJSON (
          {
            network = {
              direct = {
                allow = map (r: { inherit (r) host port; }) (cfg.declarativeAllow ++ loopbackPolicyRules);
                deny = map (r: { inherit (r) host port; }) cfg.declarativeDeny;
              };

              http = {
                allow = map httpRuleJson cfg.httpProxy.declarativeAllow;
                deny = map httpRuleJson cfg.httpProxy.declarativeDeny;
              };
            };

            sudo = {
              allow = map (r: { inherit (r) argv; }) rootCfg.policy.sudo.declarativeAllow;
              deny = map (r: { inherit (r) argv; }) rootCfg.policy.sudo.declarativeDeny;
            };
          }
          // lib.optionalAttrs rootCfg.policy.dbus.enable {
            dbus = {
              allow = map dbusRuleJson rootCfg.policy.dbus.declarativeAllow;
              deny = map dbusRuleJson rootCfg.policy.dbus.declarativeDeny;
            };
          }
          //
            lib.optionalAttrs
              (
                config.agent-sandbox.gates.filesystem.enable
                || rootCfg.policy.filesystem.declarativeAllow != [ ]
                || rootCfg.policy.filesystem.declarativeDeny != [ ]
              )
              {
                filesystem = {
                  allow = [
                    {
                      access = "all";
                      path = "/nix/store";
                    }
                    {
                      # The wrapper's own session context, read once per
                      # sandboxed command. Read-only: nothing inside the
                      # sandbox may rewrite the context it is judged by.
                      access = "read";
                      path = "/run/agent-sandbox/session-context.json";
                    }
                  ]
                  ++ map (r: { inherit (r) access path; }) rootCfg.policy.filesystem.declarativeAllow;

                  deny = [
                    {
                      access = "all";
                      path = "~/.config/agent-sandbox";
                    }
                    {
                      access = "all";
                      path = "./.agent-sandbox";
                    }
                  ]
                  ++ map (r: { inherit (r) access path; }) rootCfg.policy.filesystem.declarativeDeny;
                };
              }
          //
            lib.optionalAttrs
              (
                rootCfg.policy.resources.declarativeAllow != [ ] || rootCfg.policy.resources.declarativeDeny != [ ]
              )
              {
                resources = {
                  allow = map (r: { inherit (r) access kind path; }) rootCfg.policy.resources.declarativeAllow;
                  deny = map (r: { inherit (r) access kind path; }) rootCfg.policy.resources.declarativeDeny;
                };
              }
        );

        networking.dhcpcd.denyInterfaces = lib.optional cfg.enable runtime.network.vethHost;

        systemd.services.agent-sandbox-policy = {
          description = "Policy daemon for agent-sandbox";
          before = lib.optionals cfg.enable [ "agent-sandbox-nfq.service" ];

          after =
            lib.optionals cfg.enable [
              "agent-sandbox-dns.service"
              "agent-sandbox-netns.service"
            ]
            ++ [ "network.target" ];

          requires = lib.optionals cfg.enable [
            "agent-sandbox-dns.service"
            "agent-sandbox-netns.service"
          ];

          wantedBy = [ "multi-user.target" ];

          serviceConfig = {
            Type = "simple";

            ExecStart = lib.escapeShellArgs (
              [
                (
                  if runtime.httpProxy.enable then
                    "${proxyPolicyLauncher}/bin/agent-sandbox-policy-launch"
                  else
                    "${sandboxPkg}/bin/agent-sandbox-policyd"
                )
                "--socket"
                runtime.policySocket
                "--sandbox-socket"
                runtime.sandboxPolicySocket
                "--declarative"
                "/etc/agent-sandbox/policy.json"
                "--export-json"
                runtime.exportedJson
                "--approval-timeout"
                (toString runtime.approvalTimeout)
              ]
              ++ lib.concatMap (value: [
                "--package-declarative"
                "${packageEffectiveName value}=/etc/agent-sandbox/packages/${packageEffectiveName value}.json"
              ]) (lib.filter packageHasPolicy rootCfg.packages)
              ++ lib.optionals (!runtime.interactiveApproval) [
                "--no-interactive-approval"
              ]
              ++ lib.optionals (runtime.autoSpawnPolicyUi && runtime.uiBackend != "none") [
                "--ui-spawn-cmd"
                "${sandboxPkg}/bin/agent-sandbox-ui"
              ]
              ++ lib.optionals runtime.httpProxy.enable [
                "--proxy-socket"
                runtime.httpProxy.socketPath
              ]
              ++ lib.optionals (runtime.exportedNix != "") [
                "--export-nix"
                runtime.exportedNix
              ]
              ++ lib.optionals config.agent-sandbox.gates.filesystem.enable [
                "--fs-monitor-cmd"
                "${sandboxPkg}/bin/agent-sandbox-fsmon"
              ]
              ++
                lib.optionals
                  (
                    (config.agent-sandbox.gates.syscalls.enable && config.agent-sandbox.network.enable)
                    || config.agent-sandbox.gates.resources.enable
                    || config.agent-sandbox.gates.filesystem.enable
                  )
                  [
                    "--syscall-broker-cmd"
                    "${sandboxPkg}/bin/agent-sandbox-syscall-broker"
                  ]
            );

            ExecStopPost = "+${sandboxPkg}/bin/agent-sandbox-policyd --cleanup-cgroup-freeze";
            Restart = "on-failure";
            RuntimeDirectory = "agent-sandbox";
            RuntimeDirectoryPreserve = "yes";
            StateDirectory = "agent-sandbox";
          };

          environment = {
            AGENT_SANDBOX_DNS_CACHE = "/run/agent-sandbox/dns-cache.json";
            AGENT_SANDBOX_LOGINCTL = "${pkgs.systemd}/bin/loginctl";
            AGENT_SANDBOX_NOTIFY_SEND = "${pkgs.libnotify}/bin/notify-send";
            AGENT_SANDBOX_RUNUSER = "${pkgs.util-linux}/bin/runuser";
            AGENT_SANDBOX_UI_BACKEND = runtime.uiBackend;
          }
          // lib.optionalAttrs (runtime.httpProxy.enable && runtime.httpProxy.gid != null) {
            AGENT_SANDBOX_PROXY_GID_OVERRIDE = toString runtime.httpProxy.gid;
          }
          // lib.optionalAttrs (runtime.uiBackend == "zenity") {
            AGENT_SANDBOX_ZENITY = "${pkgs.zenity}/bin/zenity";
          };

        };
      }

      (lib.mkIf cfg.enable {
        boot = {
          kernel.sysctl = {
            "net.ipv4.conf.all.rp_filter" = 0;
            "net.ipv4.conf.default.rp_filter" = 0;
            "net.ipv4.ip_forward" = 1;
            "net.ipv6.conf.all.forwarding" = 1;
          };

          kernelModules = lib.optionals cfg.httpProxy.enable [
            "nf_tproxy_ipv4"
            "nf_tproxy_ipv6"
          ];
        };

        environment.etc = {
          "agent-sandbox/nsswitch.conf".text = nsswitchConfText;
          "agent-sandbox/resolv.conf".text = resolvConfText;
        }
        // lib.optionalAttrs cfg.httpProxy.enable {
          "agent-sandbox/proxy-upstream-cidrs.json" = {
            mode = "0644";
            text = builtins.toJSON cfg.httpProxy.upstreamAllowCidrs;
          };
        };

        # Runtime nft INPUT accepts are not enough when the host firewall has its own
        # later input chains. Open bridge ports declaratively on the veth interface.
        networking.firewall = {
          extraCommands = lib.mkIf (!config.networking.nftables.enable) ''
            iptables -A nixos-fw -i ${runtime.network.vethHost} -d 127.0.0.1 -m conntrack --ctstate DNAT -j nixos-fw-accept
          '';

          # Sandbox flows DNATed to host localhost may use any port.
          extraInputRules = lib.mkIf config.networking.nftables.enable ''
            iifname "${runtime.network.vethHost}" ip daddr 127.0.0.1 ct status dnat accept
          '';

          interfaces.${runtime.network.vethHost} = {
            allowedTCPPorts = lib.mkAfter ([ 53 ] ++ loopbackTcpPorts);
            allowedUDPPorts = lib.mkAfter ([ 53 ] ++ loopbackUdpPorts);
          };
        };

        security.wrappers.agent-sandbox-enter = {
          # setns(CLONE_NEWNET) needs CAP_SYS_ADMIN; CAP_NET_ADMIN alone is insufficient.
          capabilities = "cap_sys_admin,cap_net_admin+ep";
          group = "root";
          owner = "root";
          setgid = false;
          setuid = false;
          source = "${sandboxPkg}/bin/agent-sandbox-enter";
        };

        systemd.services = {
          agent-sandbox-dns = {
            description = "DNS forwarder for agent-sandbox (forwards raw DNS and records IP→hostname cache)";

            before = [
              "agent-sandbox-nfq.service"
              "agent-sandbox-policy.service"
            ];

            after = [
              "agent-sandbox-netns.service"
              "network.target"
              "systemd-resolved.service"
            ]
            ++ lib.optional cfg.httpProxy.enable "agent-sandbox-proxy-init.service";

            requires = [
              "agent-sandbox-netns.service"
            ]
            ++ lib.optional cfg.httpProxy.enable "agent-sandbox-proxy-init.service";

            wantedBy = [ "multi-user.target" ];

            serviceConfig = networkDaemonHardening // {
              Type = "simple";

              ExecStart = lib.escapeShellArgs (
                [
                  "${sandboxPkg}/bin/agent-sandbox-dns-forwarder"
                  "--listen-host"
                  runtime.hostIp
                  "--listen-port"
                  "53"
                  "--forward-target"
                  runtime.dnsForwardTarget
                  "--cache-path"
                  "/run/agent-sandbox/dns-cache.json"
                  "--push-socket"
                  "/run/agent-sandbox/dns-push.sock"
                ]
                ++ lib.optionals cfg.httpProxy.enable [
                  "--cache-client-ip"
                  runtime.network.netnsIp
                  "--ech-config-path"
                  "${proxyStateDir}/ech-config-list"
                ]
                ++ lib.optional cfg.httpProxy.enable "--suppress-https-svcb"
              );

              KillMode = "control-group";
              LimitNOFILE = 2048;
              MemoryMax = "256M";
              Restart = "on-failure";
              RuntimeDirectory = "agent-sandbox";
              RuntimeDirectoryPreserve = "yes";
              TasksMax = 512;
            };

            bindsTo = [ "agent-sandbox-netns.service" ];
          };

          agent-sandbox-netns = {
            before = [
              "agent-sandbox-dns.service"
              "agent-sandbox-nfq.service"
              "agent-sandbox-policy.service"
            ];

            after = [ "network-pre.target" ];
            wantedBy = [ "multi-user.target" ];

            serviceConfig = networkNamespaceSetupHardening // {
              Type = "oneshot";
              ExecStart = "${netnsUpPkg}/bin/agent-sandbox-netns-up";
              ExecStop = "${netnsDownPkg}/bin/agent-sandbox-netns-down";
              RemainAfterExit = true;
            };
          };

          agent-sandbox-nfq = {
            description = "Transport-layer policy enforcer inside agent-sandbox netns";

            after = [
              "agent-sandbox-dns.service"
              "agent-sandbox-netns.service"
              "agent-sandbox-policy.service"
            ];

            requires = [
              "agent-sandbox-dns.service"
              "agent-sandbox-netns.service"
              "agent-sandbox-policy.service"
            ];

            wantedBy = [ "multi-user.target" ];

            serviceConfig = networkDaemonHardening // {
              Type = "simple";

              ExecStart = lib.escapeShellArgs (
                [
                  (toString nfqLauncher)
                  "--owner-iterator"
                  (toString ownerBpfObject)
                  "--queue"
                  (toString runtime.queueNumber)
                  "--policy-socket"
                  runtime.sandboxPolicySocket
                  "--policy-timeout"
                  (toString runtime.policyTimeout)
                  "--nft-binary"
                  "${pkgs.nftables}/bin/nft"
                  "--dns-server-ip"
                  runtime.hostIp
                  "--push-socket"
                  "/run/agent-sandbox/dns-push.sock"
                ]
                ++ lib.optionals verdictGateEnabled [
                  "--verdict-map"
                  verdictMapDir
                ]
                ++ lib.optionals cfg.httpProxy.enable [
                  "--proxy-mode"
                  "--ready-file"
                  nfqReadyPath
                ]
                ++ lib.optionals (cfg.httpProxy.enable && cfg.httpProxy.http3.enable) [
                  "--udp-proxy-ports"
                  http3UdpPortsComma
                ]
              );

              ExecStartPre = lib.optionals cfg.httpProxy.enable [
                "${readinessMarkerPkg}/bin/agent-sandbox-readiness-marker ${nfqReadyPath}"
              ];

              ExecStopPost = lib.optionals cfg.httpProxy.enable [
                "${readinessMarkerPkg}/bin/agent-sandbox-readiness-marker ${nfqReadyPath}"
              ];

              NetworkNamespacePath = "/run/netns/${runtime.network.netnsName}";
              RuntimeDirectory = "agent-sandbox";
              RuntimeDirectoryPreserve = "yes";
            };

            environment.AGENT_SANDBOX_DNS_CACHE = "/run/agent-sandbox/dns-cache.json";
          };
        }
        // lib.optionalAttrs cfg.httpProxy.enable {
          agent-sandbox-proxy = {
            description = "Fail-closed transparent HTTP interceptor";
            before = [ "agent-sandbox-proxy-route.service" ];

            after = [
              "agent-sandbox-dns.service"
              "agent-sandbox-netns.service"
              "agent-sandbox-policy.service"
              "agent-sandbox-proxy-firewall.service"
              "agent-sandbox-proxy-init.service"
            ];

            wants = [ "agent-sandbox-proxy-route.service" ];

            requires = [
              "agent-sandbox-dns.service"
              "agent-sandbox-netns.service"
              "agent-sandbox-policy.service"
              "agent-sandbox-proxy-firewall.service"
              "agent-sandbox-proxy-init.service"
            ];

            wantedBy = [ "multi-user.target" ];

            serviceConfig = networkDaemonHardening // {
              Type = "simple";

              AmbientCapabilities = [
                "CAP_NET_ADMIN"
              ]
              ++ lib.optional cfg.httpProxy.http3.enable "CAP_NET_BIND_SERVICE";

              BindReadOnlyPaths = [ "/etc/agent-sandbox/resolv.conf:/etc/resolv.conf" ];

              CapabilityBoundingSet = [
                "CAP_NET_ADMIN"
              ]
              ++ lib.optional cfg.httpProxy.http3.enable "CAP_NET_BIND_SERVICE";

              ExecStart = "${proxyLaunchPkg}/bin/agent-sandbox-proxy-launch";

              ExecStartPre = [
                "+${readinessMarkerPkg}/bin/agent-sandbox-readiness-marker ${proxyReadyPath}"
              ];

              ExecStopPost = [
                "+${readinessMarkerPkg}/bin/agent-sandbox-readiness-marker ${proxyReadyPath}"
              ];

              Group = proxyGroup;
              NetworkNamespacePath = "/run/netns/${runtime.network.netnsName}";

              ReadOnlyPaths = [
                proxyBundlePath
                "/run/agent-sandbox"
              ];

              ReadWritePaths = [ proxyStateDir ];
              Restart = "always";
              RestartSec = 1;
              RuntimeDirectory = "agent-sandbox";
              RuntimeDirectoryMode = "0755";
              RuntimeDirectoryPreserve = "yes";
              User = proxyUser;
            };

            environment = {
              AGENT_SANDBOX_PROXY_SESSION_READY = proxyReadyPath;
              AGENT_SANDBOX_PROXY_SOCKET = runtime.httpProxy.socketPath;
              CURL_CA_BUNDLE = proxyBundlePath;
              REQUESTS_CA_BUNDLE = proxyBundlePath;
              SSL_CERT_FILE = proxyBundlePath;
            };

          };

          agent-sandbox-proxy-firewall = {
            description = "Restrictive egress firewall for agent-sandbox transparent proxy";
            before = [ "agent-sandbox-proxy.service" ];

            after = [
              "agent-sandbox-netns.service"
              "agent-sandbox-proxy-init.service"
              "network.target"
            ];

            requires = [
              "agent-sandbox-netns.service"
              "agent-sandbox-proxy-init.service"
            ];

            wantedBy = [ "multi-user.target" ];
            partOf = [ "agent-sandbox-proxy.service" ];

            serviceConfig = networkSetupHardening // {
              Type = "oneshot";

              ExecStart = lib.escapeShellArgs (
                [
                  "${proxyFirewallPkg}/bin/agent-sandbox-proxy-firewall"
                  proxyUser
                  proxyGroup
                  runtime.hostIp
                  proxyCidrsPath
                  "agent_sandbox_proxy"
                ]
                ++ [
                  (if runtime.httpProxy.http3.enable then http3UdpPortsComma else "0")
                ]
              );

              ExecStopPost = lib.escapeShellArgs (
                [
                  "${proxyFirewallPkg}/bin/agent-sandbox-proxy-firewall"
                  proxyUser
                  proxyGroup
                  runtime.hostIp
                  proxyCidrsPath
                  "agent_sandbox_proxy"
                ]
                ++ [
                  (if runtime.httpProxy.http3.enable then http3UdpPortsComma else "0")
                ]
                ++ [ "cleanup" ]
              );

              NetworkNamespacePath = "/run/netns/${runtime.network.netnsName}";
              RemainAfterExit = true;
            };
          };

          agent-sandbox-proxy-init = {
            description = "Initialize agent-sandbox interception CA";

            before = [
              "agent-sandbox-proxy-firewall.service"
              "agent-sandbox-proxy.service"
            ];

            after = [
              "agent-sandbox-netns.service"
              "network-pre.target"
            ];

            requires = [ "agent-sandbox-netns.service" ];
            wantedBy = [ "multi-user.target" ];

            serviceConfig = networkSetupHardening // {
              Type = "oneshot";

              ExecStart = lib.escapeShellArgs [
                "${proxyInitPkg}/bin/agent-sandbox-proxy-init"
                proxyStateDir
                proxyBundlePath
                "/etc/ssl/certs/ca-bundle.crt"
                "${sandboxPkg}/bin/agent-sandbox-proxy"
              ];

              ExecStartPost = "${pkgs.coreutils}/bin/chown -R ${proxyUser}:${proxyGroup} ${proxyStateDir}";

              LoadCredential =
                lib.optionals (proxyCaCertificate != null) [
                  "proxy-ca-cert:${proxyCaCertificate}"
                ]
                ++ lib.optionals (proxyCaPrivateKey != null) [
                  "proxy-ca-key:${proxyCaPrivateKey}"
                ];

              RemainAfterExit = true;
              RuntimeDirectory = "agent-sandbox";
              RuntimeDirectoryPreserve = "yes";
              StateDirectory = "agent-sandbox/proxy";
              StateDirectoryMode = "0700";
            };
          };

          agent-sandbox-proxy-route = {
            description = "Install fail-closed TPROXY routes for the proxy generation";

            after = [
              "agent-sandbox-proxy-firewall.service"
              "agent-sandbox-proxy.service"
            ];

            requires = [
              "agent-sandbox-proxy-firewall.service"
              "agent-sandbox-proxy.service"
            ];

            wantedBy = [ "multi-user.target" ];
            partOf = [ "agent-sandbox-proxy.service" ];

            serviceConfig = networkSetupHardening // {
              Type = "oneshot";

              ExecStart = lib.escapeShellArgs (
                [
                  "${proxyTproxyRoutePkg}/bin/agent-sandbox-proxy-tproxy-route"
                  "18080"
                  "51820"
                  "51820"
                  "agent_sandbox_proxy_tproxy"
                  (toString runtime.queueNumber)
                  proxyUser
                  "agent-sandbox-proxy.service"
                  "agent-sandbox-nfq.service"
                  proxyReadyPath
                  nfqReadyPath
                ]
                ++ lib.optionals runtime.httpProxy.http3.enable [
                  http3UdpPortsSpace
                ]
              );

              ExecStopPost = lib.escapeShellArgs (
                [
                  "${proxyTproxyRoutePkg}/bin/agent-sandbox-proxy-tproxy-route"
                  "18080"
                  "51820"
                  "51820"
                  "agent_sandbox_proxy_tproxy"
                  (toString runtime.queueNumber)
                  proxyUser
                  "agent-sandbox-proxy.service"
                  "agent-sandbox-nfq.service"
                  proxyReadyPath
                  nfqReadyPath
                ]
                ++ [
                  (lib.optionalString runtime.httpProxy.http3.enable http3UdpPortsSpace)
                  "cleanup"
                ]
              );

              NetworkNamespacePath = "/run/netns/${runtime.network.netnsName}";
              RemainAfterExit = true;
              Restart = "on-failure";
              RestartSec = 1;
              SuccessExitStatus = [ "143" ];
            };

            bindsTo = [ "agent-sandbox-proxy.service" ];
          };
        };

        users = {
          groups.${proxyGroup} = lib.mkIf cfg.httpProxy.enable { };

          users.${proxyUser} = lib.mkIf cfg.httpProxy.enable {
            createHome = false;
            description = "agent-sandbox transparent HTTP proxy";
            group = proxyGroup;
            home = "/var/empty";
            isSystemUser = true;
          };
        };
      })

      (lib.mkIf cfg.enable {
        systemd.services.agent-sandbox-loopback = {
          description = "Share localhost with the agent-sandbox network namespace";
          before = [ "multi-user.target" ];
          after = [ "agent-sandbox-netns.service" ];
          requires = [ "agent-sandbox-netns.service" ];
          wantedBy = [ "multi-user.target" ];

          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${loopbackBpfPkg}/bin/agent-sandbox-loopback-bpf";
            ExecStop = "${loopbackBpfPkg}/bin/agent-sandbox-loopback-bpf cleanup";
            RemainAfterExit = true;
          };
        };
      })

      (lib.mkIf (cfg.enable && verdictGateEnabled) {
        systemd.services.agent-sandbox-verdict-gate = {
          description = "Fail denied sandbox destinations in the kernel from the published verdict map";

          before = [
            "agent-sandbox-nfq.service"
            "multi-user.target"
          ];

          after = [ "agent-sandbox-netns.service" ];
          requires = [ "agent-sandbox-netns.service" ];
          wantedBy = [ "multi-user.target" ];

          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${verdictGateBpfPkg}/bin/agent-sandbox-verdict-gate-bpf";
            ExecStop = "${verdictGateBpfPkg}/bin/agent-sandbox-verdict-gate-bpf cleanup";
            RemainAfterExit = true;
          };
        };
      })
    ]
  );
}
