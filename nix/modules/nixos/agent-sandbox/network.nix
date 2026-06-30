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
  policyEnabled = cfg.enable || rootCfg.sudoPolicy == "approve" || rootCfg.gates.filesystem.enable;
  sandboxPkg = flake.package "agent-sandbox";
  policyPkg = sandboxPkg;
  enterBin = sandboxPkg;
  dnsTargetHost =
    let
      parts = lib.splitString ":" cfg.dnsForwardTarget;
    in
    if builtins.length parts > 1 then builtins.elemAt parts 0 else cfg.dnsForwardTarget;

  # Sandboxes query the veth gateway for DNS. The forwarder transparently
  # forwards raw DNS queries to the configured upstream resolver and writes
  # IP->hostname mappings to a shared cache for NFQUEUE prompts.
  resolvConfText = ''
    nameserver ${cfg.hostIp}
    options edns0 trust-ad
  '';

  # Inside the jail we cannot use nss-resolve (no /run/systemd/resolve). Plain DNS only.
  nsswitchConfText = ''
    hosts: files dns
    networks: files
  '';

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
  # There is no allow fast-path. NFQUEUE handles policy-bound TCP SYN and
  # UDP packets. Denied destinations get a short reject-set entry only so
  # client calls fail quickly instead of retrying until TCP timeout.
  # Established/related conntrack entries, DNS traffic to the forwarder,
  # and transient reject entries bypass NFQUEUE.
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
        ip daddr ${cfg.hostIp} udp dport 53 accept
        ip daddr ${cfg.hostIp} tcp dport 53 accept
        ip6 daddr ${cfg.hostIp6} udp dport 53 accept
        ip6 daddr ${cfg.hostIp6} tcp dport 53 accept
        # ICMPv6 is required for NDP (neighbor discovery). Without it,
        # IPv6 packets cannot reach the host veth gateway.
        ip6 nexthdr icmpv6 accept
        # Reject denied destinations from transient reject sets
        ip daddr . tcp dport @reject_v4 reject with tcp reset
        ip daddr . udp dport @reject_v4 reject
        ip6 daddr . tcp dport @reject_v6 reject with tcp reset
        ip6 daddr . udp dport @reject_v6 reject with icmpv6 type port-unreachable
        # Queue TCP SYN and UDP for policy enforcement
        ip protocol tcp tcp flags & (syn | ack) == syn queue num ${toString cfg.queueNumber}
        ip protocol udp queue num ${toString cfg.queueNumber}
        meta nfproto ipv6 meta l4proto tcp tcp flags & (syn | ack) == syn queue num ${toString cfg.queueNumber}
        meta nfproto ipv6 meta l4proto udp queue num ${toString cfg.queueNumber}
      }
    }
  '';

  hostNatPkg = pkgs.writeShellApplication {
    name = "agent-sandbox-host-nat";
    runtimeInputs = [
      pkgs.nftables
      pkgs.procps # sysctl
    ];
    text =
      builtins.replaceStrings
        [
          "@vethHost@"
          "@dnsTargetHost@"
        ]
        [
          cfg.vethHost
          dnsTargetHost
        ]
        (builtins.readFile ./netns/host-nat.sh);
  };

  netnsUpPkg = pkgs.writeShellApplication {
    name = "agent-sandbox-netns-up";
    runtimeInputs = [
      pkgs.iproute2
      pkgs.nftables
      hostNatPkg
    ];
    text =
      builtins.replaceStrings
        [
          "@netnsName@"
          "@vethHost@"
          "@vethNetns@"
          "@netnsIp@"
          "@hostIp@"
          "@hostIpCidr@"
          "@hostIp6@"
          "@hostIp6Cidr@"
          "@netnsIp6Cidr@"
          "@nftRules@"
          "@hostNatBin@"
        ]
        [
          cfg.netnsName
          cfg.vethHost
          cfg.vethNetns
          cfg.netnsIp
          cfg.hostIp
          "${cfg.hostIp}/30"
          cfg.hostIp6
          "${cfg.hostIp6}/${toString cfg.netnsIp6Prefix}"
          "${cfg.netnsIp6}/${toString cfg.netnsIp6Prefix}"
          nftRules
          "${hostNatPkg}/bin/agent-sandbox-host-nat"
        ]
        (builtins.readFile ./netns/up.sh);
  };

  netnsDownPkg = pkgs.writeShellApplication {
    name = "agent-sandbox-netns-down";
    runtimeInputs = [ pkgs.iproute2 ];
    text =
      builtins.replaceStrings
        [
          "@netnsName@"
          "@vethHost@"
        ]
        [
          cfg.netnsName
          cfg.vethHost
        ]
        (builtins.readFile ./netns/down.sh);
  };

in
lib.mkIf policyEnabled (
  lib.mkMerge [
    {
      environment.etc."agent-sandbox/declarative.json".text = builtins.toJSON (
        {
          network = {
            allow = map (r: { inherit (r) host port; }) cfg.declarativeAllow;
            deny = map (r: { inherit (r) host port; }) cfg.declarativeDeny;
          };
          sudo = {
            allow = [ ];
            deny = [ ];
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
              "${policyPkg}/bin/agent-sandbox-policyd"
              "--socket"
              config.agent-sandbox.policy.socketPath
              "--sandbox-socket"
              config.agent-sandbox.policy.sandboxSocketPath
              "--declarative"
              "/etc/agent-sandbox/declarative.json"
              "--export-json"
              config.agent-sandbox.policy.exportedJson
              "--approval-timeout"
              (toString config.agent-sandbox.policy.approvalTimeout)
            ]
            ++ lib.optionals (!config.agent-sandbox.policy.interactiveApproval) [
              "--no-interactive-approval"
            ]
            ++
              lib.optionals
                (config.agent-sandbox.policy.autoSpawnPolicyUi && config.agent-sandbox.policy.uiBackend != "none")
                [
                  "--ui-spawn-cmd"
                  "${policyPkg}/bin/agent-sandbox-ui"
                ]
            ++ lib.optionals (config.agent-sandbox.policy.exportedNix != "") [
              "--export-nix"
              config.agent-sandbox.policy.exportedNix
            ]
            ++ lib.optionals config.agent-sandbox.gates.filesystem.enable [
              "--fs-monitor-cmd"
              "${policyPkg}/bin/agent-sandbox-fsmon"
            ]
            ++
              lib.optionals
                (
                  (config.agent-sandbox.gates.syscalls.enable && config.agent-sandbox.network.enable)
                  || config.agent-sandbox.gates.resources.enable
                )
                [
                  "--syscall-broker-cmd"
                  "${policyPkg}/bin/agent-sandbox-syscall-broker"
                ]
          );
          StateDirectory = "agent-sandbox";
          RuntimeDirectory = "agent-sandbox";
          Restart = "on-failure";
        };
        path = [
          pkgs.util-linux
          pkgs.systemd
          pkgs.libnotify
        ]
        ++ lib.optionals (config.agent-sandbox.policy.uiBackend == "zenity") [
          pkgs.zenity
        ];
        environment = {
          AGENT_SANDBOX_RUNUSER = "${pkgs.util-linux}/bin/runuser";
          AGENT_SANDBOX_LOGINCTL = "${pkgs.systemd}/bin/loginctl";
          AGENT_SANDBOX_NOTIFY_SEND = "${pkgs.libnotify}/bin/notify-send";
          AGENT_SANDBOX_UI_BACKEND = config.agent-sandbox.policy.uiBackend;
          AGENT_SANDBOX_DNS_CACHE = "/run/agent-sandbox/dns-cache.json";
        }
        // lib.optionalAttrs (config.agent-sandbox.policy.uiBackend == "zenity") {
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
      networking.firewall.interfaces.${cfg.vethHost} = {
        allowedTCPPorts = lib.mkAfter [ 53 ];
        allowedUDPPorts = lib.mkAfter [ 53 ];
      };

      environment.etc."agent-sandbox/resolv.conf".text = resolvConfText;
      environment.etc."agent-sandbox/nsswitch.conf".text = nsswitchConfText;

      security.wrappers.agent-sandbox-enter = {
        source = "${enterBin}/bin/agent-sandbox-enter";
        # setns(CLONE_NEWNET) needs CAP_SYS_ADMIN; CAP_NET_ADMIN alone is insufficient.
        capabilities = "cap_sys_admin,cap_net_admin+ep";
        owner = "root";
        group = "root";
        setuid = false;
        setgid = false;
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
          serviceConfig = {
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
          serviceConfig = {
            Type = "simple";
            ExecStart = lib.escapeShellArgs [
              "${policyPkg}/bin/agent-sandbox-dns-forwarder"
              "--listen-host"
              cfg.hostIp
              "--listen-port"
              "53"
              "--forward-target"
              cfg.dnsForwardTarget
              "--cache-path"
              "/run/agent-sandbox/dns-cache.json"
              "--push-socket"
              "/run/agent-sandbox/dns-push.sock"
            ];
            Restart = "on-failure";
            KillMode = "control-group";
            RuntimeDirectory = "agent-sandbox";
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
          serviceConfig = {
            Type = "simple";
            NetworkNamespacePath = "/run/netns/${cfg.netnsName}";
            ExecStart = lib.escapeShellArgs [
              "${policyPkg}/bin/agent-sandbox-nfq"
              "--queue"
              (toString cfg.queueNumber)
              "--policy-socket"
              config.agent-sandbox.policy.sandboxSocketPath
              "--policy-timeout"
              (toString (lib.max cfg.policyTimeout config.agent-sandbox.policy.approvalTimeout))
              "--nft-binary"
              "${pkgs.nftables}/bin/nft"
              "--dns-server-ip"
              cfg.hostIp
              "--push-socket"
              "/run/agent-sandbox/dns-push.sock"
            ];
            RuntimeDirectory = "agent-sandbox";
          };
          environment = {
            AGENT_SANDBOX_DNS_CACHE = "/run/agent-sandbox/dns-cache.json";
          };
        };
      };
    })
  ]
)
