# Build-time regression guard for syscall broker network mode wiring.
#
# The broker fails closed when neither --network-mode nor
# AGENT_SANDBOX_NETWORK_MODE is present. Verify that both the static jail
# and dynamic-FS wrappers receive the derived mode for proxy-disabled and
# proxy-enabled runtimes.
{
  pkgs,
  lib,
  inputs,
  ...
}:
let
  agentSandboxLib = import ../../modules/nixos/agent-sandbox/lib.nix {
    inherit lib;
    inherit (inputs) jail-nix;
  };

  networkModuleSource = builtins.toFile "agent-sandbox-network.nix" (
    builtins.readFile ../../modules/nixos/agent-sandbox/network.nix
  );
  proxyRouteSource = builtins.toFile "agent-sandbox-proxy-route.sh" (
    builtins.readFile ../../modules/nixos/agent-sandbox/proxy-route.sh
  );
  proxyFirewallSource = builtins.toFile "agent-sandbox-proxy-firewall.sh" (
    builtins.readFile ../../modules/nixos/agent-sandbox/proxy-firewall.sh
  );
  runtime = proxy: {
    policyContext = false;
    network = { };
    hostIp = "169.254.100.1";
    httpProxy.enable = proxy;
  };

  mkWrapper =
    {
      proxy,
      dynamic,
    }:
    agentSandboxLib.mkWrapPackage pkgs {
      package = pkgs.hello;
      binary = "hello";
      runtime = runtime proxy;
      syscallArmPkg = pkgs.hello;
      fsArmPkg = if dynamic then pkgs.hello else null;
    };

  staticDirect = mkWrapper {
    proxy = false;
    dynamic = false;
  };
  staticProxy = mkWrapper {
    proxy = true;
    dynamic = false;
  };
  dynamicDirect = mkWrapper {
    proxy = false;
    dynamic = true;
  };
  dynamicProxy = mkWrapper {
    proxy = true;
    dynamic = true;
  };
  proxyGroupLookupCheck = pkgs.writeShellApplication {
    name = "proxy-group-lookup-regression";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.glibc.bin
      pkgs.getent
    ];
    text = builtins.readFile ../../modules/nixos/agent-sandbox/proxy-group-gid.sh;
  };
  mkNixosSystem =
    extraModule:
    inputs.nixpkgs.lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      specialArgs = { inherit inputs; };
      modules = [
        ../../modules/nixos/agent-sandbox
        {
          nixpkgs.pkgs = pkgs;
          agent-sandbox.enable = true;
          agent-sandbox.network.enable = true;
          system.stateVersion = "26.11";
        }
        extraModule
      ];
    };

  validPolicySystem = mkNixosSystem {
    agent-sandbox.network.httpProxy = {
      enable = true;
      declarativeAllow = [
        {
          url = "https://api.example.com/v1";
          allMethods = true;
          comment = "API access";
        }
      ];
      declarativeDeny = [
        {
          url = "https://api.example.com/v1/private";
          methods = [ "POST" ];
        }
      ];
    };
  };
  validPolicyJson =
    builtins.fromJSON
      validPolicySystem.config.environment.etc."agent-sandbox/declarative.json".text;
  validPortSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy.enable = true;
    agent-sandbox.network.httpProxy.declarativeAllow = [
      {
        url = "https://api.example.com:65535/v1";
        allMethods = true;
      }
    ];
  };
  validPortJson =
    builtins.fromJSON
      validPortSystem.config.environment.etc."agent-sandbox/declarative.json".text;

  invalidProxySystem = mkNixosSystem {
    agent-sandbox.network.httpProxy.declarativeAllow = [
      {
        url = "https://api.example.com/v1";
        allMethods = true;
      }
    ];
  };
  invalidModeSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy.enable = true;
    agent-sandbox.network.httpProxy.declarativeAllow = [
      {
        url = "https://api.example.com/v1";
        methods = [ ];
      }
    ];
  };
  invalidMethodSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy.enable = true;
    agent-sandbox.network.httpProxy.declarativeAllow = [
      {
        url = "https://api.example.com/v1";
        methods = [ (builtins.concatStringsSep "" (builtins.genList (_: "A") 65)) ];
      }
    ];
  };
  invalidFragmentSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy.enable = true;
    agent-sandbox.network.httpProxy.declarativeAllow = [
      {
        url = "https://api.example.com/v1#private";
        allMethods = true;
      }
    ];
  };
  invalidPortSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy.enable = true;
    agent-sandbox.network.httpProxy.declarativeAllow = [
      {
        url = "https://api.example.com:99999/v1";
        allMethods = true;
      }
    ];
  };
  validPaddedPortSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy.enable = true;
    agent-sandbox.network.httpProxy.declarativeAllow = [
      {
        url = "https://api.example.com:080/v1";
        allMethods = true;
      }
    ];
  };
  validPaddedPortJson =
    builtins.fromJSON
      validPaddedPortSystem.config.environment.etc."agent-sandbox/declarative.json".text;
  validIpv6System = mkNixosSystem {
    agent-sandbox.network.httpProxy.enable = true;
    agent-sandbox.network.httpProxy.declarativeAllow = [
      {
        url = "https://[::1]/v1";
        allMethods = true;
      }
    ];
  };
  validFullGlobSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy.enable = true;
    agent-sandbox.network.httpProxy.declarativeAllow = [
      {
        url = "https://[ab].example.com/{one,two}/file?.txt";
        allMethods = true;
      }
    ];
  };
  invalidZeroPortSystem = mkNixosSystem {
    agent-sandbox.network.httpProxy.enable = true;
    agent-sandbox.network.httpProxy.declarativeAllow = [
      {
        url = "https://api.example.com:0/v1";
        allMethods = true;
      }
    ];
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
          url = "https://api.example.com/v1";
          methods = [ ];
          comment = "API access";
        }
      ];
    assert
      validPolicyJson.network.http.deny == [
        {
          url = "https://api.example.com/v1/private";
          methods = [ "POST" ];
        }
      ];
    assert !(lib.all (assertion: assertion.assertion) invalidProxySystem.config.assertions);
    assert
      !(builtins.tryEval invalidModeSystem.config.environment.etc."agent-sandbox/declarative.json".text)
      .success;
    assert
      !(builtins.tryEval invalidMethodSystem.config.environment.etc."agent-sandbox/declarative.json".text)
      .success;
    assert
      !(builtins.tryEval
        invalidFragmentSystem.config.environment.etc."agent-sandbox/declarative.json".text
      ).success;

    assert
      !(builtins.tryEval invalidPortSystem.config.environment.etc."agent-sandbox/declarative.json".text)
      .success;
    assert
      validPortJson.network.http.allow == [
        {
          url = "https://api.example.com:65535/v1";
          methods = [ ];
        }
      ];
    assert
      validPaddedPortJson.network.http.allow == [
        {
          url = "https://api.example.com:080/v1";
          methods = [ ];
        }
      ];
    assert
      (builtins.tryEval validFullGlobSystem.config.environment.etc."agent-sandbox/declarative.json".text)
      .success;
    assert
      (builtins.tryEval validIpv6System.config.environment.etc."agent-sandbox/declarative.json".text)
      .success;
    assert
      !(builtins.tryEval
        invalidZeroPortSystem.config.environment.etc."agent-sandbox/declarative.json".text
      ).success;
    true;

  script = wrapper: ''
    $(
      _script=$(readlink -f ${wrapper}/bin/hello)
      while _next=$(sed -n 's#.*-- \(/nix/store/[^ ]*/bin/sandboxed-[^ ]*\) .*#\1#p' "$_script") && test -n "$_next"; do
        _script=$(readlink -f "$_next")
      done
      printf '%s' "$_script"
    )
  '';
in
pkgs.runCommand "network-mode-wrapper-regression" { } ''
  fail() { echo "FAIL: $*" >&2; exit 1; }
  test "${if declarativeHttpContract then "ok" else "failed"}" = ok


  static_direct=${script staticDirect}
  static_proxy=${script staticProxy}
  dynamic_direct=${script dynamicDirect}
  dynamic_proxy=${script dynamicProxy}
  if grep -E -q -- '"(ssl_insecure|upstream_cert)=[^"]*"' ${networkModuleSource}; then
    fail "proxy service must not override wrapper-owned TLS options"
  fi
  if grep -F -q -- 'client_key_tmp="/dev/null"' ${proxyRouteSource}; then
    fail "proxy route must not delete /dev/null during key cleanup"
  fi
  grep -F -q -- 'ip route replace default dev "$interface" table "$ROUTE_TABLE"' ${proxyRouteSource} \
    || fail "proxy route must install a selective IPv4 HTTP(S) route table"
  grep -F -q -- 'ip -6 route replace default dev "$interface" table "$ROUTE_TABLE"' ${proxyRouteSource} \
    || fail "proxy route must install a selective IPv6 HTTP(S) route table"
  grep -F -q -- '"tcp 80" "tcp 443" "tcp 8008" "tcp 8080" "tcp 8443" "udp 443"' ${proxyRouteSource} \
    || fail "proxy route must select the supported HTTP(S) service ports"
  grep -F -q -- 'proxy_ports add 4' ${proxyRouteSource} \
    || fail "proxy route must install IPv4 service-port rules"
  grep -F -q -- 'proxy_ports add 6' ${proxyRouteSource} \
    || fail "proxy route must install IPv6 service-port rules"
  grep -F -q -- 'ip route replace blackhole default table "$ROUTE_TABLE"' ${proxyRouteSource} \
    || fail "proxy route cleanup must leave IPv4 HTTP(S) fail-closed"
  grep -F -q -- 'ip -6 route replace blackhole default table "$ROUTE_TABLE"' ${proxyRouteSource} \
    || fail "proxy route cleanup must leave IPv6 HTTP(S) fail-closed"
  if grep -F -q -- 'oifname "lo" accept' ${proxyFirewallSource}; then
    fail "proxy firewall must not allow unrestricted loopback egress"
  fi
  grep -F -q -- 'fib daddr type local reject' ${proxyFirewallSource} \
    || fail "proxy firewall must reject host-local destinations"
  grep -F -q -- 'ip daddr != {' ${proxyFirewallSource} \
    || fail "proxy firewall must allow public IPv4 upstream destinations"
  grep -F -q -- 'ip6 daddr != {' ${proxyFirewallSource} \
    || fail "proxy firewall must allow public IPv6 upstream destinations"
  grep -F -q -- 'proxy_host_ip="$3"' ${proxyFirewallSource} \
    || fail "proxy firewall must keep WireGuard endpoint separate"
  grep -F -q -- 'dns_server_ip="$4"' ${proxyFirewallSource} \
    || fail "proxy firewall must receive a distinct DNS server"
  grep -F -q -- '"$dns_server_ip"' ${proxyFirewallSource} \
    || fail "proxy firewall must allow DNS only to its configured server"
  grep -F -q -- '"$proxy_host_ip" "$wireguard_port"' ${proxyFirewallSource} \
    || fail "proxy firewall must scope WireGuard to its configured endpoint"
  grep -F -q -- 'BindReadOnlyPaths = [ "/etc/agent-sandbox/resolv.conf:/etc/resolv.conf" ];' ${networkModuleSource} \
    || fail "proxy service must use the sandbox resolver configuration"
  # The WireGuard endpoint bypass must be guarded by proxy enablement: proxy mode
  # needs the kernel-generated handshake, while direct mode must keep all UDP queued.
  # The exact expression proves proxy mode emits the endpoint rule and direct mode
  # emits an empty string through optionalString's false branch.
  grep -F -q -- 'lib.optionalString cfg.httpProxy.enable "    ip daddr ''${cfg.httpProxy.proxyHostIp} udp dport ''${toString cfg.httpProxy.wireguardPort} accept\n"' ${networkModuleSource} \
    || fail "nft rules do not guard the configured proxy WireGuard endpoint"
  test "$(grep -F -c -- 'ip daddr ''${cfg.httpProxy.proxyHostIp} udp dport ''${toString cfg.httpProxy.wireguardPort} accept' ${networkModuleSource})" -eq 1 \
    || fail "nft rules contain an unexpected number of WireGuard endpoint exceptions"
  grep -F -q -- 'fib daddr type != local tcp dport' ${networkModuleSource} \
    || fail "proxy mode must fail closed for public HTTP(S) off WireGuard"
  grep -F -q -- 'fib daddr type != local udp dport 443' ${networkModuleSource} \
    || fail "proxy mode must fail closed for public UDP/443 off WireGuard"
  grep -F -q -- 'ip protocol tcp tcp dport { 80, 443, 8008, 8080, 8443 } tcp flags' ${networkModuleSource} \
    || fail "proxy mode must queue only transparent TCP service ports"
  grep -F -q -- 'ip protocol udp udp dport 443 queue' ${networkModuleSource} \
    || fail "proxy mode must queue only transparent UDP/443 traffic"
  grep -F -q -- 'lib.optionalString cfg.httpProxy.enable "    # Direct ports were approved by seccomp user notification' ${networkModuleSource} \
    || fail "proxy mode must accept seccomp-approved direct traffic"


  grep -F -q -- '--setenv AGENT_SANDBOX_NETWORK_MODE direct' "$static_direct" \
    || fail "static direct wrapper does not set direct network mode"
  grep -F -q -- '--setenv AGENT_SANDBOX_NETWORK_MODE proxy' "$static_proxy" \
    || fail "static proxy wrapper does not set proxy network mode"
  grep -F -q -- 'RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_NETWORK_MODE direct)' "$dynamic_direct" \
    || fail "dynamic direct wrapper does not set direct network mode"
  grep -F -q -- 'RUNTIME_ARGS+=(--setenv AGENT_SANDBOX_NETWORK_MODE proxy)' "$dynamic_proxy" \
    || fail "dynamic proxy wrapper does not set proxy network mode"
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
  grep -F -q -- '--ro-bind-try /run/agent-sandbox/mitmproxy-ca-bundle.pem /run/agent-sandbox/mitmproxy-ca-bundle.pem' "$static_proxy" \
    || fail "static proxy wrapper does not mount the CA bundle at its non-symlink path"
  grep -F -q -- '--setenv SSL_CERT_FILE /run/agent-sandbox/mitmproxy-ca-bundle.pem' "$static_proxy" \
    || fail "static proxy wrapper does not use the mounted CA bundle"
  grep -F -q -- '--setenv REQUESTS_CA_BUNDLE /run/agent-sandbox/mitmproxy-ca-bundle.pem' "$static_proxy" \
    || fail "static proxy wrapper does not set REQUESTS_CA_BUNDLE to the mounted CA bundle"
  grep -F -q -- '--setenv CURL_CA_BUNDLE /run/agent-sandbox/mitmproxy-ca-bundle.pem' "$static_proxy" \
    || fail "static proxy wrapper does not set CURL_CA_BUNDLE to the mounted CA bundle"
  grep -F -q -- 'RUNTIME_ARGS+=(--ro-bind /run/agent-sandbox/mitmproxy-ca-bundle.pem /run/agent-sandbox/mitmproxy-ca-bundle.pem)' "$dynamic_proxy" \
    || fail "dynamic proxy wrapper does not mount the CA bundle at its non-symlink path"
  grep -F -q -- 'RUNTIME_ARGS+=(--setenv SSL_CERT_FILE /run/agent-sandbox/mitmproxy-ca-bundle.pem)' "$dynamic_proxy" \
    || fail "dynamic proxy wrapper does not use the mounted CA bundle"
  grep -F -q -- 'RUNTIME_ARGS+=(--setenv REQUESTS_CA_BUNDLE /run/agent-sandbox/mitmproxy-ca-bundle.pem)' "$dynamic_proxy" \
    || fail "dynamic proxy wrapper does not set REQUESTS_CA_BUNDLE to the mounted CA bundle"
  grep -F -q -- 'RUNTIME_ARGS+=(--setenv CURL_CA_BUNDLE /run/agent-sandbox/mitmproxy-ca-bundle.pem)' "$dynamic_proxy" \
    || fail "dynamic proxy wrapper does not set CURL_CA_BUNDLE to the mounted CA bundle"
  ${proxyGroupLookupCheck}/bin/proxy-group-lookup-regression nixbld \
    || fail "single proxy-group lookup was rejected"


  echo "PASS: direct and proxy network modes are wired"
  touch "$out"
''
