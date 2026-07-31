{
  config,
  lib,
  pkgs,
  inputs,
  ...
}:
let
  agentSandboxLib = import ./lib.nix {
    inherit lib;
    inherit (flake) jail-nix;
  };
  cfg = config.agent-sandbox.network;
  dbusRuleJson =
    rule:
    {
      target = {
        inherit (rule.target)
          bus
          destination
          interface
          member
          signature
          ;

        fd_metadata = map (fd: {
          inherit (fd) kind;
          read_only = fd.readOnly;
        }) rule.target.fdMetadata;

        message_kind = rule.target.messageKind;
        object_path = rule.target.objectPath;
      };
    }
    // lib.optionalAttrs (rule.comment != null) {
      inherit (rule) comment;
    };
  dnsTargetHost =
    let
      parts = lib.splitString ":" runtime.dnsForwardTarget;
    in
    if builtins.length parts > 1 then builtins.elemAt parts 0 else runtime.dnsForwardTarget;
  flake = import ../../../lib/consumer.nix { inherit inputs pkgs; };
  hostNatPkg = mkNetnsLauncher {
    name = "agent-sandbox-host-nat";

    runtimeInputs = [
      pkgs.nftables
      pkgs.procps # sysctl
    ];

    script = hostNatScript;
  };
  hostNatScript = pkgs.replaceVars ./netns/host-nat.sh {
    inherit dnsTargetHost;
    vethHost = runtime.network.vethHost;
  };
  httpRuleJson =
    rule:
    assert lib.assertMsg
      (
        (rule.methods != null && builtins.length rule.methods > 0 && !rule.allMethods)
        || (rule.allMethods && (rule.methods == null || builtins.length rule.methods == 0))
      )
      "agent-sandbox HTTP rule at ${rule.url} must set exactly one of a non-empty methods list or allMethods = true (allMethods cannot be combined with methods)";
    {
      inherit (rule) url;
      methods = if rule.allMethods then [ ] else rule.methods;
    }
    // lib.optionalAttrs (rule.comment != null) {
      inherit (rule) comment;
    };
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
    ];

    script = netnsUpScript;
  };
  netnsUpScript = pkgs.replaceVars ./netns/up.sh {
    inherit (runtime) hostIp hostIp6;
    inherit nftRules;
    hostIp6Cidr = "${runtime.hostIp6}/${toString runtime.network.netnsIp6Prefix}";
    hostIpCidr = "${runtime.hostIp}/30";
    hostNatBin = "${hostNatPkg}/bin/agent-sandbox-host-nat";
    netnsIp = runtime.network.netnsIp;
    netnsIp6Cidr = "${runtime.network.netnsIp6}/${toString runtime.network.netnsIp6Prefix}";
    netnsName = runtime.network.netnsName;
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
  # NFQUEUE handles only the transparently proxied service ports; direct
  # destinations are gated by seccomp user notification and then accepted by
  # the kernel route. Denied destinations get a short reject-set entry only
  # so client calls fail quickly instead of retrying until TCP timeout.
  # Established/related conntrack entries, DNS traffic to the forwarder, and
  # transient reject entries bypass NFQUEUE.
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

      chain output {
        type filter hook output priority 0; policy drop;
        ct state established,related accept
        # DNS traffic to the forwarder bypasses NFQUEUE
        ip daddr ${runtime.hostIp} udp dport 53 accept
        ip daddr ${runtime.hostIp} tcp dport 53 accept
        ip6 daddr ${runtime.hostIp6} udp dport 53 accept
        ip6 daddr ${runtime.hostIp6} tcp dport 53 accept
        # NDP only: neighbor and router discovery for the veth gateway.
        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
        # Reject denied destinations from transient reject sets
        ip daddr . tcp dport @reject_v4 reject with tcp reset
        ip daddr . udp dport @reject_v4 reject
        ip6 daddr . tcp dport @reject_v6 reject with tcp reset
        ip6 daddr . udp dport @reject_v6 reject with icmpv6 type port-unreachable
        # Encrypted DNS transports have no policy-controlled resolver path.
        tcp dport 853 reject with tcp reset
        ${lib.optionalString (
          cfg.httpProxy.enable && cfg.httpProxy.http3.enable
        ) "udp dport 853 reject\n"}
        ${lib.optionalString (!cfg.httpProxy.http3.enable) "udp dport { 443, 853 } reject\n"}
        ${lib.optionalString (!cfg.httpProxy.enable)
          "    ip protocol tcp tcp flags & (syn | ack) == syn queue num ${toString runtime.queueNumber}\n    ip protocol udp queue num ${toString runtime.queueNumber}\n    meta nfproto ipv6 meta l4proto tcp tcp flags & (syn | ack) == syn queue num ${toString runtime.queueNumber}\n    meta nfproto ipv6 meta l4proto udp queue num ${toString runtime.queueNumber}\n"
        }
        ${lib.optionalString cfg.httpProxy.enable "    # Direct ports were approved by seccomp user notification; keep them on the kernel route.\n    ip protocol tcp accept\n    ip protocol udp accept\n    meta nfproto ipv6 meta l4proto tcp accept\n    meta nfproto ipv6 meta l4proto udp accept\n"}
      }
    }
  '';
  # Inside the jail we cannot use nss-resolve (no /run/systemd/resolve). Plain DNS only.
  nsswitchConfText = ''
    hosts: files dns
    networks: files
  '';
  policyEnabled =
    cfg.enable
    || rootCfg.policy.dbus.enable
    || rootCfg.sudoPolicy == "approve"
    || rootCfg.gates.filesystem.enable;
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
          ++ lib.optionals runtime.httpProxy.http3.enable [
            "--http3"
            "--http3-listen-port"
            (toString runtime.httpProxy.http3.udpPort)
          ]
        )
      }
    '';
  };
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

in
lib.mkIf policyEnabled (
  lib.mkMerge [
    {
      environment.etc."agent-sandbox/declarative.json".text = builtins.toJSON (
        {
          network = {
            direct = {
              allow = map (r: { inherit (r) host port; }) cfg.declarativeAllow;
              deny = map (r: { inherit (r) host port; }) cfg.declarativeDeny;
            };

            http = {
              allow = map httpRuleJson cfg.httpProxy.declarativeAllow;
              deny = map httpRuleJson cfg.httpProxy.declarativeDeny;
            };
          };

          sudo = {
            allow = [ ];
            deny = [ ];
          };
        }
        // lib.optionalAttrs rootCfg.policy.dbus.enable {
          dbus = {
            allow = map dbusRuleJson rootCfg.policy.dbus.declarativeAllow;
            deny = map dbusRuleJson rootCfg.policy.dbus.declarativeDeny;
          };
        }
        // lib.optionalAttrs config.agent-sandbox.gates.filesystem.enable {
          filesystem = {
            allow = [
              {
                access = "all";
                path = "/nix/store";
              }
            ];

            deny = [ ];
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
              "/etc/agent-sandbox/declarative.json"
              "--export-json"
              runtime.exportedJson
              "--approval-timeout"
              (toString runtime.approvalTimeout)
            ]
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
      networking.firewall.interfaces.${runtime.network.vethHost} = {
        allowedTCPPorts = lib.mkAfter [ 53 ];
        allowedUDPPorts = lib.mkAfter [ 53 ];
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
            Restart = "on-failure";
            RuntimeDirectory = "agent-sandbox";
            RuntimeDirectoryPreserve = "yes";
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
                "${sandboxPkg}/bin/agent-sandbox-nfq"
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
              ++ lib.optionals cfg.httpProxy.enable [
                "--proxy-mode"
                "--ready-file"
                nfqReadyPath
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
              ++ [ (toString (if runtime.httpProxy.http3.enable then runtime.httpProxy.http3.udpPort else 0)) ]
              ++ [ "apply" ]
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
              ++ [ (toString (if runtime.httpProxy.http3.enable then runtime.httpProxy.http3.udpPort else 0)) ]
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
                (toString runtime.httpProxy.http3.udpPort)
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
              ++ lib.optionals runtime.httpProxy.http3.enable [
                (toString runtime.httpProxy.http3.udpPort)
              ]
              ++ [
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
  ]
)
