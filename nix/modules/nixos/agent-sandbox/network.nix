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
  policyEnabled = cfg.enable || rootCfg.sudoPolicy == "approve";
  sandboxPkg = flake.package "agent-sandbox";
  policyPkg = sandboxPkg;
  enterBin = sandboxPkg;
  proxy = cfg.proxyAddress;
  proxyParts = lib.splitString ":" proxy;
  proxyHost = builtins.elemAt proxyParts 0;
  proxyPort = builtins.elemAt proxyParts 1;

  dnsTargetHost =
    let
      parts = lib.splitString ":" cfg.dnsForwardTarget;
    in
    if builtins.length parts > 1 then builtins.elemAt parts 0 else cfg.dnsForwardTarget;

  # Sandboxes cannot reach 127.0.0.53 (host stub). They query the veth gateway;
  # agent-sandbox-dns-proxy forwards to dnsForwardTarget (systemd-resolved on NixOS).
  resolvConfText = ''
    nameserver ${cfg.hostIp}
    options edns0 trust-ad
  '';

  # Inside the jail we cannot use nss-resolve (no /run/systemd/resolve). Plain DNS only.
  nsswitchConfText = ''
    hosts: files dns
    networks: files
  '';

  # agent-sandbox-proxy runs as root in the netns; exclude root from DNAT and allow egress.
  nftRules = ''
    table inet agent_sandbox {
      ${lib.optionalString cfg.transparentRedirect ''
        chain prerouting {
          type nat hook output priority -100; policy accept;
          tcp dport { 80, 443 } ip daddr != ${proxyHost} meta skuid != 0 dnat ip to ${proxyHost}:${proxyPort}
        }
      ''}
      chain output {
        type filter hook output priority 0; policy drop;
        ct state established,related accept
        meta skuid 0 accept
        ip daddr ${proxyHost} tcp dport ${proxyPort} accept
        ip daddr 127.0.0.0/8 accept
        ip daddr ${cfg.hostIp} tcp dport 53 accept
        ip daddr ${cfg.hostIp} udp dport 53 accept
        udp dport 443 drop
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
      environment.etc."agent-sandbox/declarative.json".text = builtins.toJSON {
        network = {
          allow = map (r: { inherit (r) host port; }) cfg.declarativeAllow;
          deny = map (r: { inherit (r) host port; }) cfg.declarativeDeny;
        };
        sudo = {
          allow = [ ];
          deny = [ ];
        };
      };

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
        before = lib.optionals cfg.enable [ "agent-sandbox-proxy.service" ];
        serviceConfig = {
          Type = "simple";
          ExecStart = lib.escapeShellArgs (
            [
              "${policyPkg}/bin/agent-sandbox-policyd"
              "--socket"
              config.agent-sandbox.policy.socketPath
            ]
            ++ lib.optionals cfg.enable [
              "--sandbox-netns"
              "/run/netns/${cfg.netnsName}"
            ]
            ++ [
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
            ++ lib.optionals config.agent-sandbox.policy.autoSpawnPolicyUi [
              "--ui-spawn-cmd"
              "${policyPkg}/bin/agent-sandbox-ui"
            ]
            ++ lib.optionals (config.agent-sandbox.policy.exportedNix != "") [
              "--export-nix"
              config.agent-sandbox.policy.exportedNix
            ]
          );
          StateDirectory = "agent-sandbox";
          Restart = "on-failure";
        };
        path = [
          pkgs.util-linux
          pkgs.systemd
          pkgs.libnotify
        ];
        environment = {
          AGENT_SANDBOX_RUNUSER = "${pkgs.util-linux}/bin/runuser";
          AGENT_SANDBOX_LOGINCTL = "${pkgs.systemd}/bin/loginctl";
          AGENT_SANDBOX_NOTIFY_SEND = "${pkgs.libnotify}/bin/notify-send";
          AGENT_SANDBOX_KDIALOG = "${pkgs.kdePackages.kdialog}/bin/kdialog";
          AGENT_SANDBOX_DNS_CACHE = "/run/agent-sandbox/dns-cache.json";
        };
      };
    }

    (lib.mkIf cfg.enable {
      boot.kernel.sysctl = {
        "net.ipv4.ip_forward" = 1;
        "net.ipv4.conf.all.rp_filter" = 0;
        "net.ipv4.conf.default.rp_filter" = 0;
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
            "agent-sandbox-proxy.service"
          ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = "${netnsUpPkg}/bin/agent-sandbox-netns-up";
            ExecStop = "${netnsDownPkg}/bin/agent-sandbox-netns-down";
          };
        };

        agent-sandbox-dns = {
          description = "DNS proxy for agent-sandbox (records A/AAAA → hostname cache)";
          bindsTo = [ "agent-sandbox-netns.service" ];
          wantedBy = [ "multi-user.target" ];
          after = [
            "agent-sandbox-netns.service"
            "network.target"
            "systemd-resolved.service"
          ];
          before = [
            "agent-sandbox-policy.service"
            "agent-sandbox-proxy.service"
          ];
          serviceConfig = {
            Type = "simple";
            ExecStart = lib.escapeShellArgs [
              "${policyPkg}/bin/agent-sandbox-dns-proxy"
              "--listen-host"
              cfg.hostIp
              "--listen-port"
              "53"
              "--upstream"
              cfg.dnsForwardTarget
              "--cache-path"
              "/run/agent-sandbox/dns-cache.json"
            ];
            Restart = "on-failure";
            KillMode = "control-group";
          };
        };

        agent-sandbox-proxy = {
          description = "Policy proxy inside agent-sandbox netns";
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
              "${policyPkg}/bin/agent-sandbox-proxy"
              "--listen-host"
              proxyHost
              "--listen-port"
              proxyPort
              "--policy-socket"
              config.agent-sandbox.policy.socketPath
              "--policy-timeout"
              (toString (lib.max cfg.policyTimeout config.agent-sandbox.policy.approvalTimeout))
            ];
            Environment = "AGENT_SANDBOX_DNS_CACHE=/run/agent-sandbox/dns-cache.json";
            Restart = "on-failure";
          };
        };
      };
    })
  ]
)
