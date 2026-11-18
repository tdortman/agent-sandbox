{
  lib,
  pkgs,
  inputs,
  ...
}:
let
  inherit (e2e)
    baseNode
    commonExtraPkgs
    dbusPolicy
    installPolicy
    mkBash
    module
    ;
  # The sandboxed OAuth client's redirect listener: serves one request on
  # sandbox loopback, records its path, and exits.
  callbackServer = pkgs.writeText "callback-server.py" ''
    import http.server
    import sys

    port, page = int(sys.argv[1]), sys.argv[2].encode()


    class Callback(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            with open("/tmp/callback", "w") as callback:
                callback.write(self.path + "\n")
            self.send_response(200)
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)


    with http.server.HTTPServer(("127.0.0.1", port), Callback) as server:
        print("ready", flush=True)
        server.handle_request()
  '';
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };
  # Stands in for xdg-desktop-portal plus the host browser: OpenURI follows the
  # OAuth redirect from the host network namespace, as a browser would after
  # sign-in, and records the callback page.
  fakePortal = pkgs.writeText "fake-portal.py" ''
    import asyncio
    import urllib.parse
    import urllib.request

    from dbus_next.aio import MessageBus
    from dbus_next.service import ServiceInterface, method

    RESULT = "/tmp/fake-portal-result"


    def browse(uri):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(uri).query)
        redirect = query["redirect_uri"][0] + "?code=e2e-code&state=e2e-state"
        try:
            with urllib.request.urlopen(redirect, timeout=10) as response:
                body = response.read().decode()
        except Exception as error:
            body = f"error: {error}"
        with open(RESULT, "w") as result:
            result.write(body)


    class OpenURI(ServiceInterface):
        def __init__(self):
            super().__init__("org.freedesktop.portal.OpenURI")

        @method()
        def OpenURI(self, parent_window: "s", uri: "s", options: "a{sv}") -> "o":
            asyncio.get_running_loop().run_in_executor(None, browse, uri)
            return "/org/freedesktop/portal/desktop/request/1_1/e2e"


    async def main():
        bus = await MessageBus().connect()
        bus.export("/org/freedesktop/portal/desktop", OpenURI())
        await bus.request_name("org.freedesktop.portal.Desktop")
        await asyncio.get_running_loop().create_future()


    asyncio.run(main())
  '';
in
pkgs.testers.runNixOSTest (_: {
  name = "e2e-oauth-bridge";
  node.specialArgs = { inherit inputs; };

  nodes.oauth =
    _:
    lib.recursiveUpdate baseNode (
      lib.recursiveUpdate (installPolicy dbusPolicy) {
        imports = [ module ];

        agent-sandbox = {
          enable = true;

          gates = {
            filesystem.enable = true;
            resources.enable = true;
          };

          network.enable = true;

          packages = [
            (mkBash "sandbox-oauth-bash" {
              extraPkgs = commonExtraPkgs ++ [ pkgs.python3 ];
            })
          ];

          policy = {
            dbus = {
              enable = true;

              declarativeAllow = [
                {
                  comment = "browser launch through the desktop portal";

                  target = {
                    bus = "session";
                    destination = "org.freedesktop.portal.Desktop";
                    interface = "org.freedesktop.portal.OpenURI";
                    member = "OpenURI";
                    messageKind = "method_call";
                    objectPath = "/org/freedesktop/portal/desktop";
                    signature = "(ssa{sv})";
                  };
                }
              ];

              socketDirectory = "/var/lib/agent-sandbox-test/dbus-runtime";
              upstreamAddress = "unix:path=/run/user/1000/bus";
            };

            interactiveApproval = false;
            uiBackend = "none";
          };
        };

        services.dbus.enable = true;

        systemd.user.services.fake-portal = {
          wantedBy = [ "default.target" ];

          serviceConfig.ExecStart = "${
            pkgs.python3.withPackages (python: [ python.dbus-next ])
          }/bin/python3 ${fakePortal}";
        };
      }
    );

  testScript = ''
    import json
    import shlex
    import urllib.parse

    port = 18200
    session_env = (
        "env",
        "XDG_RUNTIME_DIR=/run/user/1000",
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
    )

    def as_sandbox_user(*args):
        return shlex.join(["runuser", "-u", "sandbox", "--", *session_env, *args])

    def authorize_url(port):
        return "https://auth.test/authorize?client_id=e2e&redirect_uri=" + urllib.parse.quote(
            f"http://127.0.0.1:{port}/callback", safe=""
        )

    start_all()
    oauth.wait_for_unit("multi-user.target")
    oauth.wait_for_unit("agent-sandbox-netns.service")
    oauth.wait_for_unit("agent-sandbox-policy.service")
    oauth.wait_until_succeeds(
        as_sandbox_user("dbus-send", "--session", "--print-reply", "--dest=org.freedesktop.DBus",
                        "/org/freedesktop/DBus", "org.freedesktop.DBus.ListNames")
        + " | grep -q org.freedesktop.portal.Desktop",
        timeout=60,
    )

    # Without a bridge the host cannot reach a listener on sandbox loopback.
    oauth.fail(f"curl --silent --max-time 2 http://127.0.0.1:{port}/")

    # An OAuth client in the sandbox listens for its redirect on sandbox
    # loopback and opens the authorization URL the way agents do: xdg-open,
    # or a browser library honouring $BROWSER. The fake portal follows the
    # redirect from the host network namespace, as the host browser would.
    def sign_in(port, opener):
        page = f"callback-ok-{port}"
        authorize = shlex.quote(authorize_url(port))
        script = f"""
        set -eu
        python3 ${callbackServer} {port} {page} &
        listener=$!
        sleep 0.5
        {opener} {authorize}
        timeout 20 sh -c "while kill -0 $listener 2>/dev/null; do sleep 0.1; done"
        grep -qx '/callback?code=e2e-code&state=e2e-state' /tmp/callback
        """
        oauth.succeed("rm -f /tmp/fake-portal-result")
        oauth.fail(f"curl --silent --max-time 2 http://127.0.0.1:{port}/")
        oauth.succeed(as_sandbox_user("sandbox-oauth-bash", "-c", script), timeout=60)
        result = oauth.wait_until_succeeds("cat /tmp/fake-portal-result", timeout=15)
        assert result == page, f"browser saw {result!r}"

        # Once the client stops listening, the next connection closes the
        # bridge instead of looping back through the sandbox's host-loopback
        # fallback.
        oauth.fail(f"curl --silent --max-time 5 http://127.0.0.1:{port}/")
        oauth.wait_until_fails(f"ss -ltnH 'sport = :{port}' | grep -q .", timeout=10)

    sign_in(18200, "xdg-open")
    sign_in(18201, "python3 -c 'import sys, webbrowser; assert webbrowser.open(sys.argv[1])'")

    # The terminal is outside the sandbox and knows the PID of the clicked
    # pane's foreground job. The client only prints the URL.
    url = authorize_url(18202)
    page = "callback-ok-18202"
    client_log = "/run/user/1000/terminal-oauth.log"
    project = "/home/user/sandbox-cwd"
    policy = f"{project}/.agent-sandbox/policy.json"
    deny = json.dumps({"dbus": {"deny": [{"target": {
        "bus": "session",
        "destination": "org.freedesktop.portal.Desktop",
        "object_path": "/org/freedesktop/portal/desktop",
        "interface": "org.freedesktop.portal.OpenURI",
        "member": "OpenURI",
        "message_kind": "method_call",
        "signature": "(ssa{sv})",
    }}]}})
    oauth.succeed("rm -f /tmp/fake-portal-result")
    oauth.succeed(as_sandbox_user("mkdir", "-p", f"{project}/.agent-sandbox"))
    oauth.succeed(as_sandbox_user("sh", "-c", f"printf %s {shlex.quote(deny)} >{policy}"))
    client = f"printf '%s\\n' {shlex.quote(url)}; exec python3 ${callbackServer} 18202 {page}"
    oauth.succeed(as_sandbox_user("sh", "-c", f"""
        cd {project}
        sandbox-oauth-bash -c {shlex.quote(client)} \
            >{client_log} 2>&1 &
        echo $! >/run/user/1000/terminal-oauth.pid
    """))
    oauth.wait_until_succeeds(f"grep -qx ready {client_log}", timeout=15)
    oauth.fail("curl --silent --max-time 2 http://127.0.0.1:18202/")
    pid = oauth.succeed("cat /run/user/1000/terminal-oauth.pid").strip()
    opener = as_sandbox_user("agent-sandbox-dbus-proxy", "open")
    for args in [f"1 {shlex.quote(url)}", f"{pid} https://example.com"]:
        status, output = oauth.execute(f"{opener} {args}")
        assert status == 3, f"expected normal link handling, got {status}: {output}"
    open_link = f"{opener} {pid} {shlex.quote(url)}"
    status, output = oauth.execute(f"{open_link} 2>&1")
    assert status == 1 and "AccessDenied" in output, f"expected policy denial, got {status}: {output}"
    oauth.fail("test -e /tmp/fake-portal-result")
    oauth.fail("curl --silent --max-time 2 http://127.0.0.1:18202/")
    oauth.succeed(as_sandbox_user("rm", policy))
    oauth.wait_until_succeeds(open_link, timeout=10)
    assert oauth.wait_until_succeeds("cat /tmp/fake-portal-result", timeout=15) == page
    oauth.succeed(f"grep -Fq 'GET /callback?code=e2e-code&state=e2e-state HTTP/' {client_log}")

    oauth.succeed("journalctl -u agent-sandbox-policy.service --no-pager | grep -q 'bridging host loopback port'")
  '';
})
