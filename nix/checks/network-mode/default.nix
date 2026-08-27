# Build-time regression guard for syscall broker network mode wiring.
#
# The broker fails closed when neither --network-mode nor
# AGENT_SANDBOX_NETWORK_MODE is present. Verify that both the static jail
# and dynamic-FS wrappers receive the derived mode for proxy-disabled and
# proxy-enabled runtimes.
{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  agentSandboxLib = import ../../modules/nixos/agent-sandbox/lib.nix {
    inherit lib;
    inherit (inputs) jail-nix;
  };
  declarativeHttpContract =
    assert
      validPolicyJson.network.direct == {
        allow = [ ];
        deny = [ ];
      };
    assert
      validPolicyJson.network.http.allow == [
        {
          comment = "API access";
          methods = [ ];
          url = "https://api.example.com/v1";
        }
      ];
    assert
      validPolicyJson.network.http.deny == [
        {
          methods = [ "POST" ];
          url = "https://api.example.com/v1/private";
        }
      ];
    assert !(lib.all (assertion: assertion.assertion) invalidProxySystem.config.assertions);
    assert
      !(builtins.tryEval invalidModeSystem.config.environment.etc."agent-sandbox/policy.json".text)
      .success;
    assert
      !(builtins.tryEval invalidMethodSystem.config.environment.etc."agent-sandbox/policy.json".text)
      .success;
    assert
      !(builtins.tryEval invalidFragmentSystem.config.environment.etc."agent-sandbox/policy.json".text)
      .success;

    assert
      !(builtins.tryEval invalidPortSystem.config.environment.etc."agent-sandbox/policy.json".text)
      .success;
    assert
      validPortJson.network.http.allow == [
        {
          methods = [ ];
          url = "https://api.example.com:65535/v1";
        }
      ];
    assert
      validPaddedPortJson.network.http.allow == [
        {
          methods = [ ];
          url = "https://api.example.com:080/v1";
        }
      ];
    assert
      (builtins.tryEval validFullGlobSystem.config.environment.etc."agent-sandbox/policy.json".text)
      .success;
    assert
      (builtins.tryEval validIpv6System.config.environment.etc."agent-sandbox/policy.json".text).success;
    assert
      !(builtins.tryEval invalidZeroPortSystem.config.environment.etc."agent-sandbox/policy.json".text)
      .success;
    true;
  dynamicDirect = mkWrapper {
    dynamic = true;
    proxy = false;
  };
  dynamicProxy = mkWrapper {
    dynamic = true;
    proxy = true;
  };
  echStateOrdering =
    let
      dnsService = validPortSystem.config.systemd.services."agent-sandbox-dns";
      initService = validPortSystem.config.systemd.services."agent-sandbox-proxy-init";
    in
    assert lib.elem "agent-sandbox-proxy-init.service" dnsService.after;
    assert lib.elem "agent-sandbox-proxy-init.service" dnsService.requires;
    assert lib.hasInfix "--init-ech-state-only" proxyInitSource;
    assert lib.hasInfix "agent-sandbox-proxy" (toString initService.serviceConfig.ExecStart);
    true;
  invalidFragmentSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy = {
      enable = true;

      declarativeAllow = [
        {
          allMethods = true;
          url = "https://api.example.com/v1#private";
        }
      ];
    };
  };
  invalidMethodSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy = {
      enable = true;

      declarativeAllow = [
        {
          methods = [ (builtins.concatStringsSep "" (builtins.genList (_: "A") 65)) ];
          url = "https://api.example.com/v1";
        }
      ];
    };
  };
  invalidModeSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy = {
      enable = true;

      declarativeAllow = [
        {
          methods = [ ];
          url = "https://api.example.com/v1";
        }
      ];
    };
  };
  invalidPortSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy = {
      enable = true;

      declarativeAllow = [
        {
          allMethods = true;
          url = "https://api.example.com:99999/v1";
        }
      ];
    };
  };
  invalidProxySystem = mkNixosSystem {
    agent-sandbox.network.httpProxy.declarativeAllow = [
      {
        allMethods = true;
        url = "https://api.example.com/v1";
      }
    ];
  };
  invalidZeroPortSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy = {
      enable = true;

      declarativeAllow = [
        {
          allMethods = true;
          url = "https://api.example.com:0/v1";
        }
      ];
    };
  };
  loopbackContract =
    let
      firewall = loopbackSystem.config.networking.firewall.interfaces.asbx-host;
      policy = builtins.fromJSON loopbackSystem.config.environment.etc."agent-sandbox/policy.json".text;
    in
    assert
      policy.network.direct.allow == [
        {
          host = "127.0.0.1";
          port = 24680;
        }
        {
          host = "169.254.100.1";
          port = 24680;
        }
        {
          host = "::1";
          port = 24680;
        }
        {
          host = "fd00:dead:beef::1";
          port = 24680;
        }
        {
          host = "fd00:dead:beef::2";
          port = 24680;
        }
        {
          host = "127.0.0.1";
          port = 24682;
        }
        {
          host = "169.254.100.1";
          port = 24682;
        }
        {
          host = "::1";
          port = 24682;
        }
        {
          host = "fd00:dead:beef::1";
          port = 24682;
        }
        {
          host = "fd00:dead:beef::2";
          port = 24682;
        }
      ];
    assert lib.elem 24680 firewall.allowedTCPPorts;
    assert lib.elem 24682 firewall.allowedUDPPorts;
    true;
  loopbackSystem = mkNixosSystem {
    agent-sandbox.network.loopback = {
      tcpPorts = [ 24680 ];
      udpPorts = [ 24682 ];
    };
  };
  mkNixosSystem =
    extraModule:
    inputs.nixpkgs.lib.nixosSystem {
      modules = [
        ../../modules/nixos/agent-sandbox
        {
          agent-sandbox = {
            enable = true;
            network.enable = true;
          };

          nixpkgs.pkgs = pkgs;
          system.stateVersion = "26.11";
        }
        extraModule
      ];

      specialArgs = { inherit inputs; };
      system = pkgs.stdenv.hostPlatform.system;
    };
  mkWrapper =
    {
      dynamic,
      proxy,
    }:
    agentSandboxLib.mkWrapPackage pkgs {
      package = pkgs.hello;
      binary = "hello";
      fsArmPkg = if dynamic then pkgs.hello else null;
      runtime = runtime proxy;
      syscallArmPkg = pkgs.hello;
    };
  networkModuleSource = builtins.toFile "agent-sandbox-network.nix" (
    builtins.readFile ../../modules/nixos/agent-sandbox/network.nix
  );
  networkWrapper = agentSandboxLib.mkWrapPackage pkgs {
    package = pkgs.hello;
    binary = "hello";
    fsArmPkg = pkgs.hello;

    network = {
      netnsEnter = "/run/test/netns-enter";
      netnsName = "agent-sandbox";
    };

    syscallArmPkg = pkgs.hello;
  };
  policyWrapper = agentSandboxLib.mkWrapPackage pkgs {
    package = pkgs.hello;
    binary = "hello";
    fsArmPkg = pkgs.hello;

    network = {
      netnsEnter = "/run/test/netns-enter";
      netnsName = "agent-sandbox";
    };

    packageName = "hello";
    policyContext = true;
    policyPkg = pkgs.hello;
    policySocket = "/run/test/policy.sock";
    sandboxPolicySocket = "/run/test/sandbox-policy.sock";
  };
  proxyFirewallSource = builtins.toFile "agent-sandbox-proxy-firewall.sh" (
    builtins.readFile ../../modules/nixos/agent-sandbox/proxy-firewall.sh
  );
  proxyGroupLookupCheck = pkgs.writeShellApplication {
    name = "proxy-group-lookup-regression";

    runtimeInputs = [
      pkgs.coreutils
      pkgs.getent
      pkgs.glibc.bin
    ];

    text = builtins.readFile ../../modules/nixos/agent-sandbox/proxy-group-gid.sh;
  };
  proxyInitSource = builtins.readFile ../../modules/nixos/agent-sandbox/proxy-init.sh;
  proxyTproxyRouteSource = builtins.toFile "agent-sandbox-proxy-tproxy-route.sh" (
    builtins.readFile ../../modules/nixos/agent-sandbox/proxy-tproxy-route.sh
  );
  runtime = proxy: {
    hostIp = "169.254.100.1";
    httpProxy.enable = proxy;
    network = { };
    policyContext = false;
  };
  script = wrapper: ''
    $(
      _script=$(readlink -f ${wrapper}/bin/hello)
      while
        _next=$(
          sed -n \
            -e 's#^[[:space:]]*exec \(/nix/store/[^ ]*/bin/sandboxed-[^ ]*\) "\$@"#\1#p' \
            -e 's#.*-- \(/nix/store/[^ ]*/bin/sandboxed-[^ ]*\) .*#\1#p' \
            "$_script" | head -n 1
        ) && test -n "$_next"
      do
        _script=$(readlink -f "$_next")
      done
      printf '%s' "$_script"
    )
  '';
  staticDirect = mkWrapper {
    dynamic = false;
    proxy = false;
  };
  staticPolicyWrapper = agentSandboxLib.mkWrapPackage pkgs {
    package = pkgs.hello;
    binary = "hello";
    packageName = "hello";
    policyContext = true;
    policyPkg = pkgs.hello;
    policySocket = "/run/test/policy.sock";
    sandboxPolicySocket = "/run/test/sandbox-policy.sock";
  };
  staticProxy = mkWrapper {
    dynamic = false;
    proxy = true;
  };
  validFullGlobSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy = {
      enable = true;

      declarativeAllow = [
        {
          allMethods = true;
          url = "https://[ab].example.com/{one,two}/file?.txt";
        }
      ];
    };
  };
  validIpv6System = mkNixosSystem {
    agent-sandbox.network.httpProxy = {
      enable = true;

      declarativeAllow = [
        {
          allMethods = true;
          url = "https://[::1]/v1";
        }
      ];
    };
  };
  validPaddedPortJson =
    builtins.fromJSON
      validPaddedPortSystem.config.environment.etc."agent-sandbox/policy.json".text;
  validPaddedPortSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy = {
      enable = true;

      declarativeAllow = [
        {
          allMethods = true;
          url = "https://api.example.com:080/v1";
        }
      ];
    };
  };
  validPolicyJson =
    builtins.fromJSON
      validPolicySystem.config.environment.etc."agent-sandbox/policy.json".text;
  validPolicySystem = mkNixosSystem {
    agent-sandbox.network.httpProxy = {
      enable = true;

      declarativeAllow = [
        {
          allMethods = true;
          comment = "API access";
          url = "https://api.example.com/v1";
        }
      ];

      declarativeDeny = [
        {
          methods = [ "POST" ];
          url = "https://api.example.com/v1/private";
        }
      ];
    };
  };
  validPortJson =
    builtins.fromJSON
      validPortSystem.config.environment.etc."agent-sandbox/policy.json".text;
  validPortSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy = {
      enable = true;

      declarativeAllow = [
        {
          allMethods = true;
          url = "https://api.example.com:65535/v1";
        }
      ];
    };
  };
in
pkgs.runCommand "network-mode-wrapper-regression" { } ''
  fail() { echo "FAIL: $*" >&2; exit 1; }
  test "${if declarativeHttpContract then "ok" else "failed"}" = ok
  test "${if echStateOrdering then "ok" else "failed"}" = ok
  test "${if loopbackContract then "ok" else "failed"}" = ok


  static_direct=${script staticDirect}
  static_proxy=${script staticProxy}
  dynamic_direct=${script dynamicDirect}
  dynamic_proxy=${script dynamicProxy}
  policy_wrapper=${script policyWrapper}
  static_policy_wrapper=${script staticPolicyWrapper}
  if grep -E -q -- '"(ssl_insecure|upstream_cert)=[^"]*"' ${networkModuleSource}; then
    fail "proxy service must not override wrapper-owned TLS options"
  fi
  grep -F -q -- 'tcp dport { $ports } counter meta mark set $mark queue num $queue_number' ${proxyTproxyRouteSource} \
    || fail "TPROXY route must queue TCP service ports for policy attribution"
  grep -F -q -- 'tcp dport { $ports } counter tproxy to :$listen_port meta mark set $mark' ${proxyTproxyRouteSource} \
    || fail "TPROXY route must redirect transparent TCP flows"
  grep -F -q -- 'echo "udp dport $(udp_set) meta mark set $mark"' ${proxyTproxyRouteSource} \
    || fail "TPROXY route must mark configured UDP flows"
  grep -F -q -- 'udp_reject="udp dport { 853, $(udp_elements) } reject"' ${proxyTproxyRouteSource} \
    || fail "TPROXY fail-closed UDP reject must flatten configured proxy ports"
  grep -F -q -- '++ [ "cleanup" ]' ${networkModuleSource} \
    || fail "proxy firewall service must remove its rules on stop"
  grep -F -q -- 'meta skuid $proxy_uid return' ${proxyTproxyRouteSource} \
    || fail "TPROXY route must exclude proxy-owned output"
  grep -F -q -- 'ct status dnat return' ${proxyTproxyRouteSource} \
    || fail "TPROXY route must preserve earlier loopback DNAT"
  grep -F -q -- 'ip route replace local 0.0.0.0/0 dev lo table "$route_table"' ${proxyTproxyRouteSource} \
    || fail "TPROXY route must preserve the UDP local route table"
  if grep -F -q -- 'oifname "lo" accept' ${proxyFirewallSource}; then
    fail "proxy firewall must not allow unrestricted loopback egress"
  fi
  grep -F -q -- 'fib daddr type local reject' ${proxyFirewallSource} \
    || fail "proxy firewall must reject host-local destinations"
  grep -F -q -- 'ip daddr != {' ${proxyFirewallSource} \
    || fail "proxy firewall must allow public IPv4 upstream destinations"
  grep -F -q -- 'ip6 daddr != {' ${proxyFirewallSource} \
    || fail "proxy firewall must allow public IPv6 upstream destinations"
  grep -F -q -- '# Direct TCP ports were approved by seccomp user notification' ${networkModuleSource} \
    || fail "proxy mode must accept seccomp-approved direct TCP traffic"


  grep -F -q -- '--setenv AGENT_SANDBOX_NETWORK_MODE direct' "$static_direct" \
    || fail "static direct wrapper does not set direct network mode"
  grep -F -q -- '--setenv AGENT_SANDBOX_NETWORK_MODE proxy' "$static_proxy" \
    || fail "static proxy wrapper does not set proxy network mode"
  grep -F -q -- 'RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_NETWORK_MODE direct)' "$dynamic_direct" \
    || fail "dynamic direct wrapper does not set direct network mode"
  grep -F -q -- 'RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_NETWORK_MODE proxy)' "$dynamic_proxy" \
    || fail "dynamic proxy wrapper does not set proxy network mode"
  for wrapper in "$static_policy_wrapper" "$policy_wrapper"; do
    grep -F -q -- 'if [[ -n "''${_agent_sandbox_session_id:-}" && -S /run/test/policy.sock ]]; then' "$wrapper" \
      || fail "wrapper must gate registration on the visible host policy socket"
    registration_block=$(sed -n '/if \[\[ -n .*_agent_sandbox_session_id/,/^ *fi$/p' "$wrapper")
    registration_trace=$(AGENT_SANDBOX_SESSION_ID=outer-session bash -x -c "_agent_sandbox_session_id=outer-session; $registration_block" 2>&1)
    if grep -F -q -- 'agent-sandbox-approve' <<<"$registration_trace"; then
      fail "nested wrapper attempted host-side sandbox registration"
    fi
  done
  grep -F -q -- '--setenv AGENT_SANDBOX_UDP_PROXY_PORTS 443' "$static_direct" \
    || fail "static direct wrapper does not set the default HTTP/3 UDP proxy ports"
  grep -F -q -- '--setenv AGENT_SANDBOX_UDP_PROXY_PORTS 443' "$static_proxy" \
    || fail "static proxy wrapper does not set the default HTTP/3 UDP proxy ports"
  grep -F -q -- 'RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_UDP_PROXY_PORTS 443)' "$dynamic_direct" \
    || fail "dynamic direct wrapper does not set the default HTTP/3 UDP proxy ports"
  grep -F -q -- 'RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_UDP_PROXY_PORTS 443)' "$dynamic_proxy" \
    || fail "dynamic proxy wrapper does not set the default HTTP/3 UDP proxy ports"
  grep -F -q -- '--setenv AGENT_SANDBOX_DNS_ENDPOINT 169.254.100.1:53' "$static_direct" \
    || fail "static direct wrapper does not set the configured DNS endpoint"
  grep -F -q -- '--setenv AGENT_SANDBOX_DNS_ENDPOINT 169.254.100.1:53' "$static_proxy" \
    || fail "static proxy wrapper does not set the configured DNS endpoint"
  grep -F -q -- 'RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_DNS_ENDPOINT 169.254.100.1:53)' "$dynamic_direct" \
    || fail "dynamic direct wrapper does not set the configured DNS endpoint"
  grep -F -q -- 'RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_DNS_ENDPOINT 169.254.100.1:53)' "$dynamic_proxy" \
    || fail "dynamic proxy wrapper does not set the configured DNS endpoint"
  if grep -F -q -- '/var/lib/agent-sandbox-proxy' "$static_proxy"; then
    fail "static proxy wrapper must not mount an absent proxy state path"
  fi
  if grep -F -q -- '/var/lib/agent-sandbox/proxy' "$static_proxy"; then
    fail "static proxy wrapper must not mount host proxy state"
  fi
  grep -F -q -- 'RUNTIME_ARGS+=(--tmpfs /var/lib/agent-sandbox/proxy)' "$dynamic_proxy" \
    || fail "dynamic proxy wrapper does not mask proxy state"
  for wrapper in "$static_proxy" "$dynamic_proxy"; do
    if grep -F -q -- '/etc/ssl/certs/ca-bundle.crt' "$wrapper"; then
      fail "proxy wrapper must not bind or reference the symlinked system CA path"
    fi
  done
  grep -F -q -- '--ro-bind-try /run/agent-sandbox/proxy-ca-bundle.pem /run/agent-sandbox/proxy-ca-bundle.pem' "$static_proxy" \
    || fail "static proxy wrapper does not mount the CA bundle at its non-symlink path"
  grep -F -q -- '--setenv SSL_CERT_FILE /run/agent-sandbox/proxy-ca-bundle.pem' "$static_proxy" \
    || fail "static proxy wrapper does not use the mounted CA bundle"
  grep -F -q -- '--setenv REQUESTS_CA_BUNDLE /run/agent-sandbox/proxy-ca-bundle.pem' "$static_proxy" \
    || fail "static proxy wrapper does not set REQUESTS_CA_BUNDLE to the mounted CA bundle"
  grep -F -q -- '--setenv CURL_CA_BUNDLE /run/agent-sandbox/proxy-ca-bundle.pem' "$static_proxy" \
    || fail "static proxy wrapper does not set CURL_CA_BUNDLE to the mounted CA bundle"
  grep -F -q -- '--setenv NODE_EXTRA_CA_CERTS /run/agent-sandbox/proxy-ca-bundle.pem' "$static_proxy" \
    || fail "static proxy wrapper does not set NODE_EXTRA_CA_CERTS to the mounted CA bundle"
  grep -F -q -- 'RUNTIME_ARGS+=(--ro-bind /run/agent-sandbox/proxy-ca-bundle.pem /run/agent-sandbox/proxy-ca-bundle.pem)' "$dynamic_proxy" \
    || fail "dynamic proxy wrapper does not mount the CA bundle at its non-symlink path"
  grep -F -q -- 'RUNTIME_ARGS+=(--setenv SSL_CERT_FILE /run/agent-sandbox/proxy-ca-bundle.pem)' "$dynamic_proxy" \
    || fail "dynamic proxy wrapper does not use the mounted CA bundle"
  grep -F -q -- 'RUNTIME_ARGS+=(--setenv REQUESTS_CA_BUNDLE /run/agent-sandbox/proxy-ca-bundle.pem)' "$dynamic_proxy" \
    || fail "dynamic proxy wrapper does not set REQUESTS_CA_BUNDLE to the mounted CA bundle"
  grep -F -q -- 'RUNTIME_ARGS+=(--setenv CURL_CA_BUNDLE /run/agent-sandbox/proxy-ca-bundle.pem)' "$dynamic_proxy" \
    || fail "dynamic proxy wrapper does not set CURL_CA_BUNDLE to the mounted CA bundle"
  grep -F -q -- 'RUNTIME_ARGS+=(--setenv NODE_EXTRA_CA_CERTS /run/agent-sandbox/proxy-ca-bundle.pem)' "$dynamic_proxy" \
    || fail "dynamic proxy wrapper does not set NODE_EXTRA_CA_CERTS to the mounted CA bundle"
  ${proxyGroupLookupCheck}/bin/proxy-group-lookup-regression nixbld \
    || fail "single proxy-group lookup was rejected"


  netns_launcher=$(cat ${
    validPolicySystem.config.systemd.services."agent-sandbox-netns".serviceConfig.ExecStart
  })
  netns_up_path=$(sed -n 's#.*exec /nix/store/[^ ]*/bin/bash \(/nix/store/[^ ]*\.sh\).*#\1#p' <<< "$netns_launcher")
  netns_up=$(cat "$netns_up_path")
  grep -F -q -- 'set proxy_uid {' <<< "$netns_up" \
    || fail "netns rules must declare the proxy uid set"
  grep -F -q -- 'meta skuid @proxy_uid accept' <<< "$netns_up" \
    || fail "proxy-mode netns rules must exempt the proxy uid from the UDP queue"
  grep -F -q -- 'ip protocol udp ct state new,untracked queue num' <<< "$netns_up" \
    || fail "proxy-mode netns rules must queue new UDP flows for transport checks"
  grep -F -q -- 'meta nfproto ipv6 meta l4proto udp ct state new,untracked queue num' <<< "$netns_up" \
    || fail "proxy-mode netns rules must queue new IPv6 UDP flows"
  grep -F -q -- 'nft add element inet agent_sandbox proxy_uid' <<< "$netns_up" \
    || fail "netns up script must populate the proxy uid set at runtime"

  loopback_netns_launcher=$(cat ${
    loopbackSystem.config.systemd.services."agent-sandbox-netns".serviceConfig.ExecStart
  })
  loopback_up_path=$(sed -n 's#.*exec /nix/store/[^ ]*/bin/bash \(/nix/store/[^ ]*\.sh\).*#\1#p' <<< "$loopback_netns_launcher")
  loopback_up=$(cat "$loopback_up_path")
  grep -F -q -- 'ip daddr 127.0.0.2 tcp dport { 24680 } dnat to 169.254.100.1' <<< "$loopback_up" \
    || fail "sandbox handoff address must DNAT configured TCP ports"
  grep -F -q -- 'ip daddr 127.0.0.2 udp dport { 24682 } dnat to 169.254.100.1' <<< "$loopback_up" \
    || fail "sandbox handoff address must DNAT configured UDP ports"
  grep -F -q -- 'ip saddr 169.254.100.1 ip daddr 169.254.100.2 tcp dport { 24680 } dnat to 127.0.0.1' <<< "$loopback_up" \
    || fail "host TCP traffic must DNAT to sandbox localhost"
  grep -F -q -- 'ip saddr 169.254.100.1 ip daddr 169.254.100.2 udp dport { 24682 } dnat to 127.0.0.1' <<< "$loopback_up" \
    || fail "host UDP traffic must DNAT to sandbox localhost"
  grep -F -q -- 'net.ipv4.conf.$NS_IF.route_localnet=1' <<< "$loopback_up" \
    || fail "sandbox veth must accept routed loopback destinations"
  grep -F -q -- 'ip6 daddr ::2 tcp dport { 24680 } dnat to fd00:dead:beef::1' <<< "$loopback_up" \
    || fail "sandbox IPv6 handoff address must DNAT configured TCP ports"
  grep -F -q -- 'ip6 daddr ::2 udp dport { 24682 } dnat to fd00:dead:beef::1' <<< "$loopback_up" \
    || fail "sandbox IPv6 handoff address must DNAT configured UDP ports"
  if grep -F -q -- 'ip6 daddr fd00:dead:beef::2 tcp dport { 24680 } dnat to ::1' <<< "$loopback_up"; then
    fail "IPv6 handoff packets must keep their routable destination for socket lookup"
  fi
  grep -F -q -- 'ip -6 route replace local ::2/128 dev lo' <<< "$loopback_up" \
    || fail "sandbox must route its IPv6 handoff address locally"

  host_nat_launcher=$(grep -o '/nix/store/[^" ]*/bin/agent-sandbox-host-nat' <<< "$loopback_up" | head -n1)
  host_nat_path=$(sed -n 's#.*exec /nix/store/[^ ]*/bin/bash \(/nix/store/[^ ]*\.sh\).*#\1#p' "$host_nat_launcher")
  host_nat=$(cat "$host_nat_path")
  grep -F -q -- 'iifname "asbx-host" ip saddr 169.254.100.2 ip daddr 169.254.100.1 tcp dport { 24680 } dnat to 127.0.0.1' <<< "$host_nat" \
    || fail "host veth must DNAT configured TCP ports to host localhost"
  grep -F -q -- 'iifname "asbx-host" ip saddr 169.254.100.2 ip daddr 169.254.100.1 udp dport { 24682 } dnat to 127.0.0.1' <<< "$host_nat" \
    || fail "host veth must DNAT configured UDP ports to host localhost"
  grep -F -q -- 'ip daddr 127.0.0.2 tcp dport { 24680 } dnat to 169.254.100.2' <<< "$host_nat" \
    || fail "host handoff address must DNAT configured TCP ports"
  if grep -F -q -- 'ip6 daddr fd00:dead:beef::1 tcp dport { 24680 } dnat to ::1' <<< "$host_nat"; then
    fail "IPv6 handoff packets must keep their routable destination for socket lookup"
  fi
  grep -F -q -- 'ip6 daddr ::2 tcp dport { 24680 } dnat to fd00:dead:beef::2' <<< "$host_nat" \
    || fail "host IPv6 handoff address must DNAT configured TCP ports"
  grep -F -q -- 'ip -6 route replace local "''${LOOPBACK_HANDOFF_IP6}/128" dev lo' <<< "$host_nat" \
    || fail "host must route its IPv6 handoff address locally"
  grep -F -q -- 'ENABLE_LOOPBACK="1"' <<< "$host_nat" \
    || fail "host veth must enable routed loopback destinations"

  loopback_bpf_launcher=${loopbackSystem.config.systemd.services.agent-sandbox-loopback.serviceConfig.ExecStart}
  loopback_bpf=$(cat "$(sed -n 's#.*exec /nix/store/[^ ]*/bin/bash \(/nix/store/[^ ]*\.sh\).*#\1#p' "$loopback_bpf_launcher")")
  grep -F -q -- 'value hex "''${host_endpoint[@]}"' <<< "$loopback_bpf" \
    || fail "shared localhost must pass host endpoint bytes as separate arguments"
  grep -F -q -- 'value hex "''${sandbox_endpoint[@]}"' <<< "$loopback_bpf" \
    || fail "shared localhost must pass sandbox endpoint bytes as separate arguments"
  grep -F -q -- 'bpftool cgroup attach "$cgroup" cgroup_inet4_connect' <<< "$loopback_bpf" \
    || fail "shared localhost must attach its connect hook"
  grep -F -q -- 'bpftool cgroup attach "$cgroup" cgroup_udp4_sendmsg' <<< "$loopback_bpf" \
    || fail "shared localhost must attach its UDP send hook"
  grep -F -q -- 'bpftool cgroup attach "$cgroup" cgroup_inet6_connect' <<< "$loopback_bpf" \
    || fail "shared localhost must attach its IPv6 connect hook"
  grep -F -q -- 'bpftool cgroup attach "$cgroup" cgroup_udp6_sendmsg' <<< "$loopback_bpf" \
    || fail "shared localhost must attach its IPv6 UDP send hook"
  grep -F -q -- 'bpftool cgroup attach "$cgroup" cgroup_inet6_bind' <<< "$loopback_bpf" \
    || fail "shared localhost must attach its IPv6 bind hook"
  grep -F -q -- 'bpftool cgroup attach "$cgroup" cgroup_inet6_getsockname' <<< "$loopback_bpf" \
    || fail "shared localhost must restore IPv6 localhost from getsockname"
  # A nested launch (a sandboxed agent spawning another inside the sandbox
  # network namespace) must not re-enter netns via the capability wrapper:
  # NoNewPrivileges suppresses its file capabilities and it aborts with
  # "failed to inherit capabilities" before its Rust setns body runs. The
  # netns launcher compares the current namespace with the target and execs
  # the inner directly when they already match, keeping the privileged enter
  # path only for a genuinely different namespace.
  netns_launcher=$(readlink -f ${networkWrapper}/bin/hello)
  grep -F -q -- 'stat -c %i /run/netns/agent-sandbox' "$netns_launcher" \
    || fail "netns launcher must read the target netns inode"
  grep -F -q -- 'readlink /proc/self/ns/net' "$netns_launcher" \
    || fail "netns launcher must read the current netns"
  grep -F -q -- '== "net:[$_asbx_target]"' "$netns_launcher" \
    || fail "netns launcher must compare current and target namespace identity"
  grep -E -q -- 'exec /nix/store/.*-sandboxed-hello/bin/sandboxed-hello "\$@"' "$netns_launcher" \
    || fail "netns launcher must bypass the wrapper and exec the inner directly when already in the namespace"
  grep -E -q -- 'exec /run/test/netns-enter agent-sandbox /nix/store/.*-sandboxed-hello/bin/sandboxed-hello "\$@"' "$netns_launcher" \
    || fail "netns launcher must keep the privileged enter path for a different namespace plus NoNewPrivileges"
  grep -F -q -- 'NoNewPrivileges detected; joining namespace via systemd user service' "$netns_launcher" \
    || fail "netns launcher must advertise the systemd user service escape when NoNewPrivileges is set from a different namespace"
  grep -F -q -- 'systemd-run' "$netns_launcher" \
    || fail "netns launcher must escape NoNewPrivileges through a systemd user transient service"
  grep -F -q -- '--user --quiet --collect --pipe --wait --service-type=exec --expand-environment=no' "$netns_launcher" \
    || fail "netns launcher must run the enter wrapper through a foreground, non-scope systemd service without expanding arguments"
  grep -F -q -- '--setenv "PATH=$PATH"' "$netns_launcher" \
    || fail "netns launcher must forward PATH into the systemd service"
  grep -F -q -- '--working-directory "$PWD"' "$netns_launcher" \
    || fail "netns launcher must forward the working directory into the systemd service"
  grep -F -q -- '_asbx_sd_status=0' "$netns_launcher" \
    || fail "netns launcher must initialise the systemd service status before the guarded call"
  grep -E -q -- '^[[:space:]]*if .*systemd-run' "$netns_launcher" \
    || fail "netns launcher must guard the systemd-run call against errexit before capturing its status"
  grep -F -q -- '_asbx_sd_status=$?' "$netns_launcher" \
    || fail "netns launcher must capture the systemd service exit status on failure"
  grep -F -q -- 'exit "$_asbx_sd_status"' "$netns_launcher" \
    || fail "netns launcher must propagate the systemd service exit status"
  grep -F -q -- 'the launching process set NoNewPrivileges and the systemd user service fallback failed' "$netns_launcher" \
    || fail "netns launcher must surface an actionable diagnostic when the systemd user service escape is unavailable"
  echo "PASS: direct and proxy network modes are wired"
  touch "$out"
''
