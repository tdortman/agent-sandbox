{
  config,
  lib,
  pkgs,
  inputs,
  ...
}:
let
  flake = import ../../../lib/consumer.nix { inherit inputs pkgs; };

  rootCfg = config.agent-sandbox;
  cfg = config.agent-sandbox.network;
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
        object_path = rule.target.objectPath;
        message_kind = rule.target.messageKind;
        fd_metadata = map (fd: {
          inherit (fd) kind;
          read_only = fd.readOnly;
        }) rule.target.fdMetadata;
      };
    }
    // lib.optionalAttrs (rule.comment != null) {
      inherit (rule) comment;
    };

  policyEnabled =
    cfg.enable
    || rootCfg.policy.dbus.enable
    || rootCfg.sudoPolicy == "approve"
    || rootCfg.gates.filesystem.enable;
  sandboxPkg = flake.package "agent-sandbox";
  agentSandboxLib = import ./lib.nix {
    inherit lib;
    inherit (flake) jail-nix;
  };
  runtime = agentSandboxLib.mkRuntime { inherit rootCfg; };
  dnsTargetHost =
    let
      parts = lib.splitString ":" runtime.dnsForwardTarget;
    in
    if builtins.length parts > 1 then builtins.elemAt parts 0 else runtime.dnsForwardTarget;
  # forwards raw DNS queries to the configured upstream resolver and writes
  # IP->hostname mappings to a shared cache for NFQUEUE prompts.
  resolvConfText = ''
    nameserver ${runtime.hostIp}
    options edns0 trust-ad
  '';

  # Inside the jail we cannot use nss-resolve (no /run/systemd/resolve). Plain DNS only.
  nsswitchConfText = ''
    hosts: files dns
    networks: files
  '';

  # These daemons do not execute approved host commands, so they can be
  # confined without changing the policy daemon's executor namespace.
  networkHardening = {
    PrivateTmp = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    ProtectControlGroups = true;
    RestrictAddressFamilies = [
      "AF_UNIX"
      "AF_NETLINK"
      "AF_INET"
      "AF_INET6"
    ];
  };

  # These daemons do not execute approved host commands, so they can be
  # confined without changing the policy daemon's executor namespace.
  networkDaemonHardening = networkHardening // {
    NoNewPrivileges = true;
    ReadWritePaths = [ "/run/agent-sandbox" ];
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

  # The namespace creator must publish its /run/netns bind mount to PID 1.
  # Mount/filesystem isolation here would leave only an empty path behind when
  # the oneshot exits, so keep only restrictions that do not create a private
  # mount namespace.
  networkNamespaceSetupHardening = {
    inherit (networkHardening)
      RestrictSUIDSGID
      LockPersonality
      RestrictAddressFamilies
      ;
  };

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
        ${lib.optionalString cfg.httpProxy.enable "    fib daddr type != local tcp dport { 80, 443, 8008, 8080, 8443 } oifname != \"${proxyInterface}\" reject\n    fib daddr type != local udp dport 443 oifname != \"${proxyInterface}\" reject\n"}
        type filter hook output priority 0; policy drop;
        ct state established,related accept
        # DNS traffic to the forwarder bypasses NFQUEUE
        ip daddr ${runtime.hostIp} udp dport 53 accept
        ip daddr ${runtime.hostIp} tcp dport 53 accept
        ip6 daddr ${runtime.hostIp6} udp dport 53 accept
        ip6 daddr ${runtime.hostIp6} tcp dport 53 accept
        # Kernel-generated WireGuard handshakes have no socket owner; bypass NFQUEUE only in proxy mode.
        ${lib.optionalString cfg.httpProxy.enable "    ip daddr ${cfg.httpProxy.proxyHostIp} udp dport ${toString cfg.httpProxy.wireguardPort} accept\n"}
        # NDP only: neighbor and router discovery for the veth gateway.
        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
        # Reject denied destinations from transient reject sets
        ip daddr . tcp dport @reject_v4 reject with tcp reset
        ip daddr . udp dport @reject_v4 reject
        ip6 daddr . tcp dport @reject_v6 reject with tcp reset
        ip6 daddr . udp dport @reject_v6 reject with icmpv6 type port-unreachable
        # In proxy mode, only transparently proxied service ports go through
        # NFQUEUE. Other network destinations remain gated by seccomp user
        # notification, which keeps the originating process blocked while an
        # approval is pending.
        ${lib.optionalString cfg.httpProxy.enable "    ip protocol tcp tcp dport { 80, 443, 8008, 8080, 8443 } tcp flags & (syn | ack) == syn queue num ${toString runtime.queueNumber}\n    ip protocol udp udp dport 443 queue num ${toString runtime.queueNumber}\n    meta nfproto ipv6 meta l4proto tcp tcp dport { 80, 443, 8008, 8080, 8443 } tcp flags & (syn | ack) == syn queue num ${toString runtime.queueNumber}\n    meta nfproto ipv6 meta l4proto udp udp dport 443 queue num ${toString runtime.queueNumber}\n"}
        ${lib.optionalString (!cfg.httpProxy.enable)
          "    ip protocol tcp tcp flags & (syn | ack) == syn queue num ${toString runtime.queueNumber}\n    ip protocol udp queue num ${toString runtime.queueNumber}\n    meta nfproto ipv6 meta l4proto tcp tcp flags & (syn | ack) == syn queue num ${toString runtime.queueNumber}\n    meta nfproto ipv6 meta l4proto udp queue num ${toString runtime.queueNumber}\n"
        }
        ${lib.optionalString cfg.httpProxy.enable "    # Direct ports were approved by seccomp user notification; keep them on the kernel route.\n    ip protocol tcp accept\n    ip protocol udp accept\n    meta nfproto ipv6 meta l4proto tcp accept\n    meta nfproto ipv6 meta l4proto udp accept\n"}
      }
    }
  '';

  hostNatScript = pkgs.replaceVars ./netns/host-nat.sh {
    vethHost = runtime.network.vethHost;
    inherit dnsTargetHost;
  };

  mkNetnsLauncher =
    {
      name,
      script,
      runtimeInputs,
    }:
    pkgs.writeShellApplication {
      inherit name runtimeInputs;
      text = ''
        exec ${pkgs.bash}/bin/bash ${script} "$@"
      '';
    };
  hostNatPkg = mkNetnsLauncher {
    name = "agent-sandbox-host-nat";
    script = hostNatScript;
    runtimeInputs = [
      pkgs.nftables
      pkgs.procps # sysctl
    ];
  };

  netnsUpScript = pkgs.replaceVars ./netns/up.sh {
    netnsName = runtime.network.netnsName;
    vethHost = runtime.network.vethHost;
    vethNetns = runtime.network.vethNetns;
    netnsIp = runtime.network.netnsIp;
    inherit (runtime) hostIp hostIp6;
    hostIpCidr = "${runtime.hostIp}/30";
    hostIp6Cidr = "${runtime.hostIp6}/${toString runtime.network.netnsIp6Prefix}";
    netnsIp6Cidr = "${runtime.network.netnsIp6}/${toString runtime.network.netnsIp6Prefix}";
    inherit nftRules;
    hostNatBin = "${hostNatPkg}/bin/agent-sandbox-host-nat";
  };

  netnsUpPkg = mkNetnsLauncher {
    name = "agent-sandbox-netns-up";
    script = netnsUpScript;
    runtimeInputs = [
      pkgs.coreutils
      pkgs.iproute2
      pkgs.nftables
      hostNatPkg
    ];
  };

  netnsDownScript = pkgs.replaceVars ./netns/down.sh {
    netnsName = runtime.network.netnsName;
    vethHost = runtime.network.vethHost;
  };
  netnsDownPkg = mkNetnsLauncher {
    name = "agent-sandbox-netns-down";
    script = netnsDownScript;
    runtimeInputs = [ pkgs.iproute2 ];
  };
  proxyStateDir = "/var/lib/agent-sandbox/proxy";
  proxyBundlePath = "/run/agent-sandbox/mitmproxy-ca-bundle.pem";
  proxyReadyPath = "${proxyStateDir}/proxy-ready";
  nfqReadyPath = "/run/agent-sandbox/nfq-ready";
  proxyInterface = "asbx-proxy";
  proxyCidrsPath = "/etc/agent-sandbox/proxy-upstream-cidrs.json";
  proxyUser = "agent-sandbox-proxy";
  proxyGroup = "agent-sandbox-proxy";
  proxyCaCertificate = cfg.httpProxy.caCertificateFile;
  proxyCaPrivateKey = cfg.httpProxy.caPrivateKeyFile;
  proxyGroupLookupPkg = pkgs.writeShellApplication {
    name = "agent-sandbox-proxy-group-gid";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.glibc.bin
      pkgs.getent
    ];
    text = builtins.readFile ./proxy-group-gid.sh;
  };
  proxyInitPkg = pkgs.writeShellApplication {
    name = "agent-sandbox-proxy-init";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.jq
      pkgs.openssl
      pkgs.wireguard-tools
    ];
    text = builtins.readFile ./proxy-init.sh;
  };
  proxyFirewallPkg = pkgs.writeShellApplication {
    name = "agent-sandbox-proxy-firewall";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.jq
      pkgs.nftables
    ];
    text = builtins.readFile ./proxy-firewall.sh;
  };
  proxyRoutePkg = pkgs.writeShellApplication {
    name = "agent-sandbox-proxy-route";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.iproute2
      pkgs.gawk
      pkgs.jq
      pkgs.systemd
      pkgs.wireguard-tools
    ];
    text = builtins.readFile ./proxy-route.sh;
  };
  readinessMarkerPkg = pkgs.writeShellApplication {
    name = "agent-sandbox-readiness-marker";
    runtimeInputs = [ pkgs.coreutils ];
    text = builtins.readFile ./readiness-marker.sh;
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
  proxyLaunchPkg = pkgs.writeShellApplication {
    name = "agent-sandbox-proxy-launch";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      set -euo pipefail
      proxy_gid="$(id -g ${proxyGroup})"
      [[ "$proxy_gid" =~ ^[1-9][0-9]*$ ]] || {
        echo "agent-sandbox proxy: invalid proxy group ID" >&2
        exit 1
      }
      export AGENT_SANDBOX_PROXY_GID="$proxy_gid"
      exec ${sandboxPkg}/bin/agent-sandbox-mitmdump "$@"
    '';
  };

in
lib.mkIf policyEnabled (
  lib.mkMerge [
    {
      networking.dhcpcd.denyInterfaces = lib.optional cfg.enable runtime.network.vethHost;
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
                path = "/nix/store";
                access = "all";
              }
            ];
            deny = [ ];
          };
        }
      );

      systemd.services.agent-sandbox-policy = {
        description = "Policy daemon for agent-sandbox";
        wantedBy = [ "multi-user.target" ];
        requires = lib.optionals cfg.enable [
          "agent-sandbox-netns.service"
          "agent-sandbox-dns.service"
        ];
        after =
          lib.optionals cfg.enable [
            "agent-sandbox-netns.service"
            "agent-sandbox-dns.service"
          ]
          ++ [ "network.target" ];
        before = lib.optionals cfg.enable [ "agent-sandbox-nfq.service" ];
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
          StateDirectory = "agent-sandbox";
          RuntimeDirectory = "agent-sandbox";
          RuntimeDirectoryPreserve = "yes";
          Restart = "on-failure";
          ExecStopPost = "+${sandboxPkg}/bin/agent-sandbox-policyd --cleanup-cgroup-freeze";
        };
        environment = {
          AGENT_SANDBOX_RUNUSER = "${pkgs.util-linux}/bin/runuser";
          AGENT_SANDBOX_LOGINCTL = "${pkgs.systemd}/bin/loginctl";
          AGENT_SANDBOX_NOTIFY_SEND = "${pkgs.libnotify}/bin/notify-send";
          AGENT_SANDBOX_UI_BACKEND = runtime.uiBackend;
          AGENT_SANDBOX_DNS_CACHE = "/run/agent-sandbox/dns-cache.json";
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
      boot.kernel.sysctl = {
        "net.ipv4.ip_forward" = 1;
        "net.ipv4.conf.all.rp_filter" = 0;
        "net.ipv4.conf.default.rp_filter" = 0;
        "net.ipv6.conf.all.forwarding" = 1;
      };

      # Runtime nft INPUT accepts are not enough when the host firewall has its own
      # later input chains. Open bridge ports declaratively on the veth interface.
      networking.firewall.interfaces.${runtime.network.vethHost} = {
        allowedTCPPorts = lib.mkAfter [ 53 ];
        allowedUDPPorts = lib.mkAfter [ 53 ];
      };

      environment.etc = {
        "agent-sandbox/resolv.conf".text = resolvConfText;
        "agent-sandbox/nsswitch.conf".text = nsswitchConfText;
      }
      // lib.optionalAttrs cfg.httpProxy.enable {
        "agent-sandbox/proxy-upstream-cidrs.json".text = builtins.toJSON cfg.httpProxy.upstreamAllowCidrs;
        "agent-sandbox/proxy-upstream-cidrs.json".mode = "0644";
      };

      security.wrappers.agent-sandbox-enter = {
        source = "${sandboxPkg}/bin/agent-sandbox-enter";
        # setns(CLONE_NEWNET) needs CAP_SYS_ADMIN; CAP_NET_ADMIN alone is insufficient.
        capabilities = "cap_sys_admin,cap_net_admin+ep";
        owner = "root";
        group = "root";
        setuid = false;
        setgid = false;
      };
      users.groups.${proxyGroup} = lib.mkIf cfg.httpProxy.enable { };
      users.users.${proxyUser} = lib.mkIf cfg.httpProxy.enable {
        isSystemUser = true;
        group = proxyGroup;
        home = "/var/empty";
        createHome = false;
        description = "agent-sandbox transparent HTTP proxy";
      };

      systemd.services = {
        agent-sandbox-netns = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network-pre.target" ];
          before = [
            "agent-sandbox-dns.service"
            "agent-sandbox-policy.service"
            "agent-sandbox-nfq.service"
          ];
          serviceConfig = networkNamespaceSetupHardening // {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = "${netnsUpPkg}/bin/agent-sandbox-netns-up";
            ExecStop = "${netnsDownPkg}/bin/agent-sandbox-netns-down";
          };
        };

        agent-sandbox-dns = {
          description = "DNS forwarder for agent-sandbox (forwards raw DNS and records IP→hostname cache)";
          bindsTo = [ "agent-sandbox-netns.service" ];
          wantedBy = [ "multi-user.target" ];
          after = [
            "agent-sandbox-netns.service"
            "network.target"
            "systemd-resolved.service"
          ];
          before = [
            "agent-sandbox-policy.service"
            "agent-sandbox-nfq.service"
          ];
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
              ]
            );
            Restart = "on-failure";
            KillMode = "control-group";
            RuntimeDirectory = "agent-sandbox";
            RuntimeDirectoryPreserve = "yes";
          };
        };

        agent-sandbox-nfq = {
          description = "Transport-layer policy enforcer inside agent-sandbox netns";
          wantedBy = [ "multi-user.target" ];
          requires = [
            "agent-sandbox-policy.service"
            "agent-sandbox-netns.service"
            "agent-sandbox-dns.service"
          ];
          after = [
            "agent-sandbox-policy.service"
            "agent-sandbox-netns.service"
            "agent-sandbox-dns.service"
          ];
          serviceConfig = networkDaemonHardening // {
            Type = "simple";
            NetworkNamespacePath = "/run/netns/${runtime.network.netnsName}";
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
            RuntimeDirectory = "agent-sandbox";
            RuntimeDirectoryPreserve = "yes";
            ExecStartPre = lib.optionals cfg.httpProxy.enable [
              "${readinessMarkerPkg}/bin/agent-sandbox-readiness-marker ${nfqReadyPath}"
            ];
            ExecStopPost = lib.optionals cfg.httpProxy.enable [
              "${readinessMarkerPkg}/bin/agent-sandbox-readiness-marker ${nfqReadyPath}"
            ];
          };
          environment = {
            AGENT_SANDBOX_DNS_CACHE = "/run/agent-sandbox/dns-cache.json";
          };
        };
      }
      // lib.optionalAttrs cfg.httpProxy.enable {
        agent-sandbox-proxy-init = {
          requires = [ "agent-sandbox-netns.service" ];
          after = [
            "agent-sandbox-netns.service"
            "network-pre.target"
          ];
          description = "Initialize agent-sandbox interception CA and WireGuard credentials";
          wantedBy = [ "multi-user.target" ];
          before = [
            "agent-sandbox-proxy-firewall.service"
            "agent-sandbox-proxy.service"
          ];
          serviceConfig = networkSetupHardening // {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = lib.escapeShellArgs [
              "${proxyInitPkg}/bin/agent-sandbox-proxy-init"
              proxyStateDir
              proxyBundlePath
              "/etc/ssl/certs/ca-bundle.crt"
            ];
            ExecStartPost = "${pkgs.coreutils}/bin/chown -R ${proxyUser}:${proxyGroup} ${proxyStateDir}";
            StateDirectory = "agent-sandbox/proxy";
            StateDirectoryMode = "0700";
            RuntimeDirectory = "agent-sandbox";
            RuntimeDirectoryPreserve = "yes";
            LoadCredential =
              lib.optionals (proxyCaCertificate != null) [
                "mitmproxy-ca-cert:${proxyCaCertificate}"
              ]
              ++ lib.optionals (proxyCaPrivateKey != null) [
                "mitmproxy-ca-key:${proxyCaPrivateKey}"
              ];
          };
        };

        agent-sandbox-proxy-firewall = {
          description = "Restrictive egress firewall for agent-sandbox transparent proxy";
          wantedBy = [ "multi-user.target" ];
          requires = [ "agent-sandbox-proxy-init.service" ];
          partOf = [ "agent-sandbox-proxy.service" ];
          after = [
            "agent-sandbox-proxy-init.service"
            "network.target"
          ];
          before = [ "agent-sandbox-proxy.service" ];
          serviceConfig = networkSetupHardening // {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = lib.escapeShellArgs [
              "${proxyFirewallPkg}/bin/agent-sandbox-proxy-firewall"
              proxyUser
              proxyGroup
              cfg.httpProxy.proxyHostIp
              runtime.hostIp
              (toString cfg.httpProxy.wireguardPort)
              proxyCidrsPath
              "agent_sandbox_proxy"
            ];
            ExecStopPost = lib.escapeShellArgs [
              "${proxyFirewallPkg}/bin/agent-sandbox-proxy-firewall"
              proxyUser
              proxyGroup
              cfg.httpProxy.proxyHostIp
              runtime.hostIp
              (toString cfg.httpProxy.wireguardPort)
              proxyCidrsPath
              "agent_sandbox_proxy"
              "cleanup"
            ];
          };
        };

        agent-sandbox-proxy = {
          description = "Fail-closed mitmproxy WireGuard HTTP interceptor";
          wantedBy = [ "multi-user.target" ];
          requires = [
            "agent-sandbox-proxy-init.service"
            "agent-sandbox-proxy-firewall.service"
            "agent-sandbox-policy.service"
            "agent-sandbox-netns.service"
            "agent-sandbox-dns.service"
          ];
          after = [
            "agent-sandbox-proxy-init.service"
            "agent-sandbox-proxy-firewall.service"
            "agent-sandbox-policy.service"
            "agent-sandbox-netns.service"
            "agent-sandbox-dns.service"
          ];
          before = [ "agent-sandbox-proxy-route.service" ];
          wants = [ "agent-sandbox-proxy-route.service" ];
          serviceConfig = networkDaemonHardening // {
            Type = "simple";
            User = proxyUser;
            Group = proxyGroup;
            ExecStartPre = [
              "+${readinessMarkerPkg}/bin/agent-sandbox-readiness-marker ${proxyReadyPath}"
            ];
            ExecStart = lib.escapeShellArgs [
              "${proxyLaunchPkg}/bin/agent-sandbox-proxy-launch"
              "--mode"
              "wireguard@${toString cfg.httpProxy.wireguardPort}"
              "--set"
              "confdir=${proxyStateDir}"
            ];
            ExecStopPost = [
              "+${readinessMarkerPkg}/bin/agent-sandbox-readiness-marker ${proxyReadyPath}"
            ];
            Restart = "always";
            RestartSec = 1;
            RuntimeDirectory = "agent-sandbox";
            RuntimeDirectoryMode = "0755";
            RuntimeDirectoryPreserve = "yes";
            ReadWritePaths = [ proxyStateDir ];
            ReadOnlyPaths = [
              proxyBundlePath
              "/run/agent-sandbox"
            ];
            BindReadOnlyPaths = [ "/etc/agent-sandbox/resolv.conf:/etc/resolv.conf" ];
          };
          environment = {
            SSL_CERT_FILE = proxyBundlePath;
            REQUESTS_CA_BUNDLE = proxyBundlePath;
            CURL_CA_BUNDLE = proxyBundlePath;
            AGENT_SANDBOX_PROXY_SOCKET = runtime.httpProxy.socketPath;
            AGENT_SANDBOX_PROXY_SESSION_READY = proxyReadyPath;
          };
        };

        agent-sandbox-proxy-route = {
          description = "Install fail-closed per-port WireGuard routes for the proxy generation";
          wantedBy = [ "multi-user.target" ];
          requires = [
            "agent-sandbox-proxy.service"
            "agent-sandbox-proxy-firewall.service"
          ];
          bindsTo = [ "agent-sandbox-proxy.service" ];
          after = [
            "agent-sandbox-proxy.service"
            "agent-sandbox-proxy-firewall.service"
          ];
          partOf = [ "agent-sandbox-proxy.service" ];
          serviceConfig = networkSetupHardening // {
            Type = "oneshot";
            NetworkNamespacePath = "/run/netns/${runtime.network.netnsName}";
            RemainAfterExit = true;
            ExecStart = lib.escapeShellArgs [
              "${proxyRoutePkg}/bin/agent-sandbox-proxy-route"
              proxyInterface
              "10.0.0.1"
              cfg.httpProxy.proxyHostIp
              (toString cfg.httpProxy.wireguardPort)
              "${proxyStateDir}/wireguard.conf"
              "agent-sandbox-proxy.service"
              "agent-sandbox-nfq.service"
              proxyReadyPath
              nfqReadyPath
              runtime.hostIp
            ];
            ExecStopPost = lib.escapeShellArgs [
              "${proxyRoutePkg}/bin/agent-sandbox-proxy-route"
              proxyInterface
              "10.0.0.1"
              cfg.httpProxy.proxyHostIp
              (toString cfg.httpProxy.wireguardPort)
              "${proxyStateDir}/wireguard.conf"
              "agent-sandbox-proxy.service"
              "agent-sandbox-nfq.service"
              proxyReadyPath
              nfqReadyPath
              runtime.hostIp
              "cleanup"
            ];
            # The switch transaction may stop the proxy while this helper is
            # waiting for readiness; its termination trap still performs cleanup.
            SuccessExitStatus = [ "143" ];
            Restart = "on-failure";
            RestartSec = 1;
          };
        };
      };
    })
  ]
)
