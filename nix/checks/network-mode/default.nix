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
      while _next=$(sed -n 's#.*-- \(/nix/store/[^ ]*/bin/sandboxed-[^ ]*\) .*#\1#p' "$_script") && test -n "$_next"; do
        _script=$(readlink -f "$_next")
      done
      printf '%s' "$_script"
    )
  '';
  staticDirect = mkWrapper {
    dynamic = false;
    proxy = false;
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
      validPaddedPortSystem.config.environment.etc."agent-sandbox/declarative.json".text;
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
      validPolicySystem.config.environment.etc."agent-sandbox/declarative.json".text;
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
      validPortSystem.config.environment.etc."agent-sandbox/declarative.json".text;
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


  static_direct=${script staticDirect}
  static_proxy=${script staticProxy}
  dynamic_direct=${script dynamicDirect}
  dynamic_proxy=${script dynamicProxy}
  if grep -E -q -- '"(ssl_insecure|upstream_cert)=[^"]*"' ${networkModuleSource}; then
    fail "proxy service must not override wrapper-owned TLS options"
  fi
  grep -F -q -- 'tcp dport { $ports } counter meta mark set $mark queue num $queue_number' ${proxyTproxyRouteSource} \
    || fail "TPROXY route must queue TCP service ports for policy attribution"
  grep -F -q -- 'tcp dport { $ports } counter tproxy to :$listen_port meta mark set $mark' ${proxyTproxyRouteSource} \
    || fail "TPROXY route must redirect transparent TCP flows"
  if grep -F -q -- 'oifname "lo" accept' ${proxyFirewallSource}; then
    fail "proxy firewall must not allow unrestricted loopback egress"
  fi
  grep -F -q -- 'fib daddr type local reject' ${proxyFirewallSource} \
    || fail "proxy firewall must reject host-local destinations"
  grep -F -q -- 'ip daddr != {' ${proxyFirewallSource} \
    || fail "proxy firewall must allow public IPv4 upstream destinations"
  grep -F -q -- 'ip6 daddr != {' ${proxyFirewallSource} \
    || fail "proxy firewall must allow public IPv6 upstream destinations"
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


  echo "PASS: direct and proxy network modes are wired"
  touch "$out"
''
