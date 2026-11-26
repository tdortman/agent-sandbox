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
    mkPolicy
    module
    ;
  e2e = import ../e2e/common.nix {
    inherit inputs lib pkgs;
  };
  pythonDbus = pkgs.python3.withPackages (ps: [ ps.dbus-fast ]);
  secretClient = pkgs.writeScriptBin "secret-client" ''
    #!${pythonDbus}/bin/python
    import asyncio
    import json
    import sys

    from dbus_fast import BusType, Message, MessageType, Variant
    from dbus_fast.aio import MessageBus

    SECRETS_DEST = "org.freedesktop.secrets"
    SERVICE_PATH = "/org/freedesktop/secrets"


    class DbusCallError(Exception):
        def __init__(self, error_name, body):
            super().__init__(f"{error_name}: {body}")
            self.error_name = error_name
            self.body = body


    def parse_attrs(pairs):
        out = {}
        for pair in pairs:
            key, value = pair.split("=", 1)
            out[key] = value
        return out


    async def call_or_raise(bus, msg):
        reply = await bus.call(msg)
        if reply.message_type == MessageType.ERROR:
            raise DbusCallError(reply.error_name, reply.body)
        return reply


    async def open_session(bus):
        reply = await call_or_raise(
            bus,
            Message(
                destination=SECRETS_DEST,
                path=SERVICE_PATH,
                interface="org.freedesktop.Secret.Service",
                member="OpenSession",
                signature="sv",
                body=["plain", Variant("s", "")],
            ),
        )
        return reply.body[1]


    async def close_session(bus, session_path):
        await call_or_raise(
            bus,
            Message(
                destination=SECRETS_DEST,
                path=session_path,
                interface="org.freedesktop.Secret.Session",
                member="Close",
            ),
        )


    async def run_command(bus, args):
        cmd = args[0]

        if cmd == "create":
            collection_path = args[1]
            label = args[2]
            secret_text = args[3]
            replace = args[4].lower() == "true"
            attrs = parse_attrs(args[5:])
            session = await open_session(bus)
            try:
                props = {
                    "org.freedesktop.Secret.Item.Label": Variant("s", label),
                    "org.freedesktop.Secret.Item.Attributes": Variant("a{ss}", attrs),
                }
                secret_struct = [session, b"", secret_text.encode("utf-8"), "text/plain"]
                reply = await call_or_raise(
                    bus,
                    Message(
                        destination=SECRETS_DEST,
                        path=collection_path,
                        interface="org.freedesktop.Secret.Collection",
                        member="CreateItem",
                        signature="a{sv}(oayays)b",
                        body=[props, secret_struct, replace],
                    ),
                )
                return reply.body[0]
            finally:
                await close_session(bus, session)

        if cmd == "search":
            attrs = parse_attrs(args[1:])
            reply = await call_or_raise(
                bus,
                Message(
                    destination=SECRETS_DEST,
                    path=SERVICE_PATH,
                    interface="org.freedesktop.Secret.Service",
                    member="SearchItems",
                    signature="a{ss}",
                    body=[attrs],
                ),
            )
            return json.dumps(reply.body[0])

        if cmd == "collection-items":
            collection_path = args[1]
            reply = await call_or_raise(
                bus,
                Message(
                    destination=SECRETS_DEST,
                    path=collection_path,
                    interface="org.freedesktop.DBus.Properties",
                    member="Get",
                    signature="ss",
                    body=["org.freedesktop.Secret.Collection", "Items"],
                ),
            )
            return json.dumps(reply.body[0].value)

        if cmd == "get-secret":
            item_path = args[1]
            session = await open_session(bus)
            try:
                reply = await call_or_raise(
                    bus,
                    Message(
                        destination=SECRETS_DEST,
                        path=item_path,
                        interface="org.freedesktop.Secret.Item",
                        member="GetSecret",
                        signature="o",
                        body=[session],
                    ),
                )
                return bytes(reply.body[0][2]).decode("utf-8")
            finally:
                await close_session(bus, session)

        if cmd == "set-secret":
            item_path = args[1]
            secret_text = args[2]
            session = await open_session(bus)
            try:
                secret_struct = [session, b"", secret_text.encode("utf-8"), "text/plain"]
                await call_or_raise(
                    bus,
                    Message(
                        destination=SECRETS_DEST,
                        path=item_path,
                        interface="org.freedesktop.Secret.Item",
                        member="SetSecret",
                        signature="(oayays)",
                        body=[secret_struct],
                    ),
                )
                return "ok"
            finally:
                await close_session(bus, session)

        if cmd == "set-label":
            item_path = args[1]
            label = args[2]
            await call_or_raise(
                bus,
                Message(
                    destination=SECRETS_DEST,
                    path=item_path,
                    interface="org.freedesktop.DBus.Properties",
                    member="Set",
                    signature="ssv",
                    body=["org.freedesktop.Secret.Item", "Label", Variant("s", label)],
                ),
            )
            return "ok"

        if cmd == "delete":
            item_path = args[1]
            await call_or_raise(
                bus,
                Message(
                    destination=SECRETS_DEST,
                    path=item_path,
                    interface="org.freedesktop.Secret.Item",
                    member="Delete",
                ),
            )
            return "ok"

        if cmd == "get-attrs":
            item_path = args[1]
            reply = await call_or_raise(
                bus,
                Message(
                    destination=SECRETS_DEST,
                    path=item_path,
                    interface="org.freedesktop.DBus.Properties",
                    member="Get",
                    signature="ss",
                    body=["org.freedesktop.Secret.Item", "Attributes"],
                ),
            )
            return json.dumps(reply.body[0].value, sort_keys=True)

        raise RuntimeError(f"unknown subcommand: {cmd}")


    async def main():
        args = sys.argv[1:]
        bus = await MessageBus(bus_type=BusType.SESSION).connect()
        try:
            if args[0] == "expect-error":
                expected_error = args[1]
                try:
                    result = await run_command(bus, args[2:])
                except DbusCallError as exc:
                    if exc.error_name != expected_error:
                        print(
                            f"expected D-Bus error {expected_error}, got {exc.error_name}: {exc.body}",
                            file=sys.stderr,
                        )
                        sys.exit(1)
                    print(exc.error_name)
                    return
                print(
                    f"expected D-Bus error {expected_error}, but call succeeded with: {result}",
                    file=sys.stderr,
                )
                sys.exit(1)

            print(await run_command(bus, args))
        finally:
            bus.disconnect()


    asyncio.run(main())
  '';
  secretServicePeer = pkgs.writeText "agent-sandbox-vm-secrets-peer.py" ''
    import asyncio
    import json
    import os
    import pathlib
    import signal
    import sys

    from dbus_fast import BusType, DBusError, PropertyAccess, Variant
    from dbus_fast.aio import MessageBus
    from dbus_fast.service import ServiceInterface, dbus_property, method

    SECRETS_NAME = "org.freedesktop.secrets"
    SERVICE_PATH = "/org/freedesktop/secrets"
    SESSION_PATH = "/org/freedesktop/secrets/session/s1"
    COLL_NAME = "kdewallet"
    COLL_PATH = f"/org/freedesktop/secrets/collection/{COLL_NAME}"
    DEFAULT_ALIAS_PATH = "/org/freedesktop/secrets/aliases/default"
    STATE_PATH = pathlib.Path(sys.argv[1])


    class SecretStore:
        def __init__(self, bus, state_path):
            self.bus = bus
            self.state_path = state_path
            self.next_id = 1
            self.items = {}
            self.item_order = []
            self.exported = {}
            self._load_or_seed()

        def _load_or_seed(self):
            if self.state_path.exists():
                data = json.loads(self.state_path.read_text(encoding="utf-8"))
                # Simulate KWallet / oo7-daemon sequential integer renumbering on
                # every daemon restart so object paths never stay constant.
                self.next_id = max(int(data.get("next_id", 1)), 10) + 100
                for entry in data.get("items", []):
                    self._add_item_record(
                        entry["label"],
                        dict(entry["attributes"]),
                        entry["value"],
                        entry.get("content_type", "text/plain"),
                    )
            else:
                self._add_item_record(
                    "Host GitHub Token",
                    {"service": "shared-gh", "Uuid": "host-uuid-shared"},
                    "host-shared-gh-token",
                    "text/plain",
                )
                self._add_item_record(
                    "Host Private Vault",
                    {"service": "private-vault"},
                    "host-private-vault-token",
                    "text/plain",
                )
                self._add_item_record(
                    "Host Shadow Original",
                    {"service": "shadow-me"},
                    "host-shadow-original",
                    "text/plain",
                )
                self._add_item_record(
                    "Host Disposable",
                    {"service": "disposable"},
                    "host-disposable",
                    "text/plain",
                )
            self._save()

        def _save(self):
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "next_id": self.next_id,
                "items": [self.items[p] for p in self.item_order if p in self.items],
            }
            tmp = self.state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(self.state_path)

        def _add_item_record(self, label, attributes, value, content_type):
            item_id = self.next_id
            self.next_id += 1
            path = f"{COLL_PATH}/{item_id}"
            record = {
                "label": label,
                "attributes": attributes,
                "value": value,
                "content_type": content_type,
            }
            self.items[path] = record
            self.item_order.append(path)
            iface = ItemInterface(self, path)
            self.exported[path] = iface
            self.bus.export(path, iface)
            return path

        def ordered_paths(self):
            # Deliberately return untagged host items BEFORE package-tagged
            # items so dbus-proxy must reorder package secrets first.
            host_paths = []
            pkg_paths = []
            for path in self.item_order:
                if path not in self.items:
                    continue
                if "agent-sandbox:package" in self.items[path]["attributes"]:
                    pkg_paths.append(path)
                else:
                    host_paths.append(path)
            return host_paths + pkg_paths

        def search(self, query):
            matched = []
            for path in self.ordered_paths():
                attrs = self.items[path]["attributes"]
                if all(attrs.get(k) == v for k, v in query.items()):
                    matched.append(path)
            return matched

        def create_item(self, properties, secret, replace):
            label_var = properties.get("org.freedesktop.Secret.Item.Label")
            attrs_var = properties.get("org.freedesktop.Secret.Item.Attributes")
            label = str(label_var.value) if label_var is not None else ""
            attrs = dict(attrs_var.value) if attrs_var is not None else {}
            value = bytes(secret[2]).decode("utf-8")
            content_type = str(secret[3])

            matched_path = None
            if replace and attrs:
                # KWallet / gnome-keyring subset matching: an existing item
                # matches iff every incoming attribute exists with equal value.
                for path in self.ordered_paths():
                    existing = self.items[path]["attributes"]
                    if all(existing.get(k) == v for k, v in attrs.items()):
                        matched_path = path
                        break

            if matched_path is not None:
                entry = self.items[matched_path]
                entry["label"] = label
                entry["attributes"] = attrs
                entry["value"] = value
                entry["content_type"] = content_type
                self._save()
                return matched_path

            path = self._add_item_record(label, attrs, value, content_type)
            self._save()
            return path

        def delete_item(self, path):
            if path not in self.items:
                raise DBusError("org.freedesktop.Secret.Error.NoSuchObject", f"no item {path}")
            del self.items[path]
            self.item_order = [p for p in self.item_order if p != path]
            iface = self.exported.pop(path, None)
            if iface is not None:
                self.bus.unexport(path, iface)
            self._save()


    class SessionInterface(ServiceInterface):
        def __init__(self):
            super().__init__("org.freedesktop.Secret.Session")

        @method()
        def Close(self):
            return


    class ServiceInterfaceImpl(ServiceInterface):
        def __init__(self, store):
            super().__init__("org.freedesktop.Secret.Service")
            self.store = store

        @method()
        def OpenSession(self, algorithm: "s", input_val: "v") -> "vo":
            return [Variant("s", ""), SESSION_PATH]

        @method()
        def ReadAlias(self, name: "s") -> "o":
            if name == "default":
                return COLL_PATH
            return "/"

        @method()
        def SearchItems(self, attributes: "a{ss}") -> "aoao":
            return [self.store.search(attributes), []]

        @method()
        def GetSecrets(self, items: "ao", session: "o") -> "a{o(oayays)}":
            out = {}
            for path in items:
                if path in self.store.items:
                    entry = self.store.items[path]
                    out[path] = [
                        session,
                        b"",
                        entry["value"].encode("utf-8"),
                        entry["content_type"],
                    ]
            return out

        @method()
        def Unlock(self, objects: "ao") -> "aoo":
            return [objects, "/"]

        @dbus_property(access=PropertyAccess.READ)
        def Collections(self) -> "ao":
            return [COLL_PATH]


    class CollectionInterface(ServiceInterface):
        def __init__(self, store):
            super().__init__("org.freedesktop.Secret.Collection")
            self.store = store

        @method()
        def SearchItems(self, attributes: "a{ss}") -> "ao":
            return self.store.search(attributes)

        @method()
        def CreateItem(self, properties: "a{sv}", secret: "(oayays)", replace: "b") -> "oo":
            path = self.store.create_item(properties, secret, replace)
            return [path, "/"]

        @dbus_property(access=PropertyAccess.READ)
        def Items(self) -> "ao":
            return self.store.ordered_paths()

        @dbus_property(access=PropertyAccess.READWRITE)
        def Label(self) -> "s":
            return COLL_NAME

        @Label.setter
        def Label(self, value: "s"):
            return

        @dbus_property(access=PropertyAccess.READ)
        def Locked(self) -> "b":
            return False


    class ItemInterface(ServiceInterface):
        def __init__(self, store, path):
            super().__init__("org.freedesktop.Secret.Item")
            self.store = store
            self.path = path

        def _entry(self):
            entry = self.store.items.get(self.path)
            if entry is None:
                raise DBusError(
                    "org.freedesktop.Secret.Error.NoSuchObject",
                    f"no item {self.path}",
                )
            return entry

        @method()
        def GetSecret(self, session: "o") -> "(oayays)":
            entry = self._entry()
            return [
                session,
                b"",
                entry["value"].encode("utf-8"),
                entry["content_type"],
            ]

        @method()
        def SetSecret(self, secret: "(oayays)"):
            entry = self._entry()
            entry["value"] = bytes(secret[2]).decode("utf-8")
            entry["content_type"] = str(secret[3])
            self.store._save()

        @method()
        def Delete(self) -> "o":
            self.store.delete_item(self.path)
            return "/"

        @dbus_property(access=PropertyAccess.READWRITE)
        def Attributes(self) -> "a{ss}":
            return dict(self._entry()["attributes"])

        @Attributes.setter
        def Attributes(self, value: "a{ss}"):
            entry = self._entry()
            entry["attributes"] = dict(value)
            self.store._save()

        @dbus_property(access=PropertyAccess.READWRITE)
        def Label(self) -> "s":
            return self._entry()["label"]

        @Label.setter
        def Label(self, value: "s"):
            entry = self._entry()
            entry["label"] = str(value)
            self.store._save()

        @dbus_property(access=PropertyAccess.READ)
        def Locked(self) -> "b":
            return False


    async def main():
        bus_sock = "/run/user/1000/bus"
        for _ in range(100):
            if os.path.exists(bus_sock):
                break
            await asyncio.sleep(0.1)

        bus = await MessageBus(bus_type=BusType.SESSION).connect()
        store = SecretStore(bus, STATE_PATH)
        bus.export(SERVICE_PATH, ServiceInterfaceImpl(store))
        bus.export(SESSION_PATH, SessionInterface())
        bus.export(COLL_PATH, CollectionInterface(store))
        bus.export(DEFAULT_ALIAS_PATH, CollectionInterface(store))
        await bus.request_name(SECRETS_NAME)

        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        await stop.wait()
        bus.disconnect()


    asyncio.run(main())
  '';
  # Keeps the relay socket directory reachable and nscd lookups denied, so
  # the D-Bus call under test is the only prompt.
  rememberedPolicy = mkPolicy "dbus-remembered" {
    dbus = ''
      {
        "allow": [
          {
            "target": {
              "bus": "session",
              "destination": ":*",
              "object_path": "/org/freedesktop/DBus",
              "interface": "org.freedesktop.DBus",
              "member": "NameAcquired",
              "message_kind": "signal",
              "signature": "s",
              "fd_metadata": []
            },
            "comment": "global"
          }
        ],
        "deny": []
      }
    '';

    filesystem = ''
      {
        "allow": [
          { "path": "/etc/passwd", "access": "read" },
          { "path": "/etc/group", "access": "read" }
        ],
        "deny": []
      }
    '';

    resources = ''
      {
        "allow": [
          { "kind": "unix_socket", "path": "/var/lib/agent-sandbox-test/dbus-runtime", "access": "connect" },
          { "kind": "unix_socket", "path": "/var/lib/agent-sandbox-test/dbus-runtime", "access": "send" }
        ],
        "deny": [
          { "kind": "unix_socket", "path": "/var/run/nscd/socket", "access": "connect" }
        ]
      }
    '';
  };
in
rec {
  dbusNode =
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

          packages = [
            (mkBash "sandbox-dbus-bash" {
              extraPkgs = commonExtraPkgs;
            })

            (mkBash "sandbox-secrets-alpha" {
              extraPkgs = commonExtraPkgs ++ [ secretClient ];

              policy.secrets.allow = [
                {
                  access = "all";
                  collection = "default";
                  comment = "alpha own partition";
                  partition = "own_package";
                }
                {
                  access = "read";
                  attributes.service = "shared-gh";
                  collection = "default";
                  comment = "alpha durable host read";
                  partition = "host";
                }
              ];
            })

            (mkBash "sandbox-secrets-beta" {
              extraPkgs = commonExtraPkgs ++ [ secretClient ];

              policy.secrets.allow = [
                {
                  access = "all";
                  collection = "default";
                  comment = "beta own partition";
                  partition = "own_package";
                }
              ];
            })
          ];

          policy = {
            dbus = {
              enable = true;

              declarativeAllow =
                map
                  (bus: {
                    comment = "VM module serialization allow";

                    target = {
                      inherit bus;
                      destination = "org.freedesktop.DBus";
                      interface = "org.freedesktop.DBus";
                      member = "ListNames";
                      messageKind = "method_call";
                      objectPath = "/org/freedesktop/DBus";
                      signature = "";
                    };
                  })
                  [
                    "session"
                    "system"
                  ];

              declarativeDeny =
                map
                  (bus: {
                    comment = "VM module serialization deny";

                    target = {
                      inherit bus;
                      destination = "org.freedesktop.DBus";
                      interface = "org.freedesktop.DBus";
                      member = "GetId";
                      messageKind = "method_call";
                      objectPath = "/org/freedesktop/DBus";
                      signature = "";
                    };
                  })
                  [
                    "session"
                    "system"
                  ];

              socketDirectory = "/var/lib/agent-sandbox-test/dbus-runtime";
              upstreamAddress = "unix:path=/run/user/1000/bus";
            };

            interactiveApproval = false;
            uiBackend = "none";
          };
        };

        services.dbus.enable = true;

        systemd.services.agent-sandbox-vm-secrets-peer = {
          description = "Mock freedesktop Secret Service peer for VM e2e test";

          after = [
            "dbus.service"
            "user@1000.service"
          ];

          wants = [ "user@1000.service" ];
          wantedBy = [ "multi-user.target" ];

          serviceConfig = {
            ExecStart = lib.escapeShellArgs [
              "${pythonDbus}/bin/python"
              secretServicePeer
              "/var/lib/agent-sandbox-secrets-peer/state.json"
            ];

            Group = "users";
            Restart = "on-failure";
            StateDirectory = "agent-sandbox-secrets-peer";
            User = "sandbox";
          };

          environment = {
            DBUS_SESSION_BUS_ADDRESS = "unix:path=/run/user/1000/bus";
            XDG_RUNTIME_DIR = "/run/user/1000";
          };
        };
      }
    );

  # Interactive approval with no D-Bus rules: every call prompts until a
  # verdict is cached or a rule is remembered.
  rememberedNode =
    _:
    lib.recursiveUpdate baseNode (
      lib.recursiveUpdate (installPolicy rememberedPolicy) {
        imports = [ module ];

        agent-sandbox = {
          enable = true;

          gates = {
            filesystem.enable = true;
            resources.enable = true;
          };

          packages = [
            (mkBash "sandbox-dbus-remembered-bash" {
              extraPkgs = commonExtraPkgs;
            })
          ];

          policy = {
            dbus = {
              enable = true;
              socketDirectory = "/var/lib/agent-sandbox-test/dbus-runtime";
              upstreamAddress = "unix:path=/run/user/1000/bus";
            };

            uiBackend = "none";
          };
        };

        services.dbus.enable = true;
      }
    );

  preamble = ''
    import shlex

    def command(*args):
        return shlex.join(str(arg) for arg in args)

    def sandbox_command(node, args, *, wrapper=(), expect_success=True):
        line = command("runuser", "-u", "sandbox", "--", *wrapper, *args)
        check = node.succeed if expect_success else node.fail
        return check(line, timeout=60)

    def sandbox_shell(node, package, script, *, wrapper=(), cwd=None, env=(), expect_success=True):
        argv = [*env, package, "-c", script]
        if cwd is not None:
            argv = ["sh", "-c", f"cd {shlex.quote(cwd)} && exec {shlex.join(argv)}"]
        return sandbox_command(
            node,
            argv,
            wrapper=wrapper,
            expect_success=expect_success,
        )

    session_wrapper = (
        "env",
        "XDG_RUNTIME_DIR=/run/user/1000",
        "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
    )
  '';

  relayScript = ''
    # D-Bus relay: the configured upstream overrides a bad caller address,
    # both buses enforce capability policy, and raw host socket access is denied.
    dbus.wait_for_unit("agent-sandbox-policy.service")
    sandbox_shell(
        dbus,
        "sandbox-dbus-bash",
        "dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames | grep -q array",
        wrapper=("env", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/missing-bus"),
    )
    sandbox_shell(
        dbus,
        "sandbox-dbus-bash",
        "dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.Introspectable.Introspect | grep -q org.freedesktop.DBus",
        wrapper=session_wrapper,
    )
    sandbox_shell(
        dbus,
        "sandbox-dbus-bash",
        "! dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.GetId",
        wrapper=("env", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"),
    )
    sandbox_shell(
        dbus,
        "sandbox-dbus-bash",
        "dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.RequestName string:com.example.Sandbox uint32:0",
        wrapper=session_wrapper,
        expect_success=False,
    )
    sandbox_shell(
        dbus,
        "sandbox-dbus-bash",
        "dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.AddMatch \"string:type='signal',sender='org.freedesktop.portal.Desktop',interface='org.freedesktop.portal.Request',member='Response'\"",
        wrapper=session_wrapper,
    )
    for rule in ["type='signal'", "type='signal',interface='org.example.Interface',eavesdrop='true'"]:
        sandbox_shell(
            dbus,
            "sandbox-dbus-bash",
            f"dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.AddMatch {shlex.quote('string:' + rule)} 2>&1 | grep -q org.freedesktop.DBus.Error.AccessDenied",
            wrapper=session_wrapper,
        )
    sandbox_shell(
        dbus,
        "sandbox-dbus-bash",
        "! timeout 2 socat - UNIX-CONNECT:/run/dbus/system_bus_socket",
        wrapper=("env", "XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"),
    )

    sandbox_shell(
        dbus,
        "sandbox-dbus-bash",
        "dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ListNames | grep -q array",
        wrapper=session_wrapper,
    )
    sandbox_shell(
        dbus,
        "sandbox-dbus-bash",
        "dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.GetId 2>&1 | grep -q org.freedesktop.DBus.Error.AccessDenied",
        wrapper=session_wrapper,
    )
  '';

  secretsHelpers = ''
    import json

    def wait_for_secrets_owner():
        dbus.wait_until_succeeds(
            command(
                "runuser",
                "-u",
                "sandbox",
                "--",
                *session_wrapper,
                "dbus-send",
                "--session",
                "--print-reply",
                "--dest=org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus.GetNameOwner",
                "string:org.freedesktop.secrets",
            ),
            timeout=30,
        )

    def host_secret_client(*args):
        return sandbox_command(
            dbus,
            ["${secretClient}/bin/secret-client", *args],
            wrapper=session_wrapper,
        ).strip()

    def pkg_secret_client(package, *args):
        return sandbox_shell(
            dbus,
            package,
            command("secret-client", *args),
            wrapper=session_wrapper,
        ).strip()

    dbus.wait_for_unit("agent-sandbox-vm-secrets-peer.service")
    wait_for_secrets_owner()
  '';

  secretsIsolationScript = ''
    # 1. Own-package store/retrieve and strict cross-package isolation.
    alpha_item = pkg_secret_client(
        "sandbox-secrets-alpha",
        "create",
        "/org/freedesktop/secrets/aliases/default",
        "Alpha API Token",
        "alpha-only-secret",
        "false",
        "service=alpha-api",
    )
    assert alpha_item.startswith("/org/freedesktop/secrets/collection/kdewallet/"), alpha_item

    alpha_search = json.loads(
        pkg_secret_client("sandbox-secrets-alpha", "search", "service=alpha-api")
    )
    assert alpha_search == [alpha_item], f"expected alpha to find own item, got {alpha_search}"
    assert (
        pkg_secret_client("sandbox-secrets-alpha", "get-secret", alpha_item)
        == "alpha-only-secret"
    )

    # Second package cannot discover alpha's item via SearchItems or Collection.Items.
    beta_search = json.loads(
        pkg_secret_client("sandbox-secrets-beta", "search", "service=alpha-api")
    )
    assert beta_search == [], f"beta must not discover alpha's secret: {beta_search}"
    beta_coll_items = json.loads(
        pkg_secret_client(
            "sandbox-secrets-beta",
            "collection-items",
            "/org/freedesktop/secrets/collection/kdewallet",
        )
    )
    assert alpha_item not in beta_coll_items, f"alpha item leaked into beta Collection.Items: {beta_coll_items}"

    # Second package cannot directly read, modify, relabel, or delete alpha's item.
    pkg_secret_client(
        "sandbox-secrets-beta",
        "expect-error",
        "org.freedesktop.DBus.Error.AccessDenied",
        "get-secret",
        alpha_item,
    )
    pkg_secret_client(
        "sandbox-secrets-beta",
        "expect-error",
        "org.freedesktop.DBus.Error.AccessDenied",
        "set-secret",
        alpha_item,
        "beta-hijack",
    )
    pkg_secret_client(
        "sandbox-secrets-beta",
        "expect-error",
        "org.freedesktop.DBus.Error.AccessDenied",
        "set-label",
        alpha_item,
        "Hijacked Label",
    )
    pkg_secret_client(
        "sandbox-secrets-beta",
        "expect-error",
        "org.freedesktop.DBus.Error.AccessDenied",
        "delete",
        alpha_item,
    )
    assert (
        pkg_secret_client("sandbox-secrets-alpha", "get-secret", alpha_item)
        == "alpha-only-secret"
    )

    # 2. Package-first shadowing: CreateItem(..., replace=true) with identical
    #    client attributes to an existing host secret leaves the host secret
    #    untouched and SearchItems orders the package secret ahead of the host secret.
    host_shadow_paths = json.loads(host_secret_client("search", "service=shadow-me"))
    assert len(host_shadow_paths) == 1, host_shadow_paths
    host_shadow_path = host_shadow_paths[0]
    assert host_secret_client("get-secret", host_shadow_path) == "host-shadow-original"

    alpha_shadow_path = pkg_secret_client(
        "sandbox-secrets-alpha",
        "create",
        "/org/freedesktop/secrets/aliases/default",
        "Alpha Shadow Secret",
        "alpha-shadow-value",
        "true",
        "service=shadow-me",
    )
    assert alpha_shadow_path != host_shadow_path, "CreateItem(replace=true) must not overwrite host item"
    assert host_secret_client("get-secret", host_shadow_path) == "host-shadow-original"
    host_shadow_attrs = json.loads(host_secret_client("get-attrs", host_shadow_path))
    assert "agent-sandbox:package" not in host_shadow_attrs, host_shadow_attrs

    alpha_shadow_search = json.loads(
        pkg_secret_client("sandbox-secrets-alpha", "search", "service=shadow-me")
    )
    assert alpha_shadow_search == [
        alpha_shadow_path,
        host_shadow_path,
    ], f"expected package secret ahead of host secret, got {alpha_shadow_search}"
    assert (
        pkg_secret_client("sandbox-secrets-alpha", "get-secret", alpha_shadow_search[0])
        == "alpha-shadow-value"
    )
  '';

  secretsDurableScript = ''
    alpha_item = pkg_secret_client(
        "sandbox-secrets-alpha",
        "create",
        "/org/freedesktop/secrets/aliases/default",
        "Alpha API Token",
        "alpha-only-secret",
        "false",
        "service=alpha-api",
    )

    # 3. Durable host secret access across deletions and service restarts that
    #    renumber sequential integer item object paths.
    shared_v1 = json.loads(
        pkg_secret_client("sandbox-secrets-alpha", "search", "service=shared-gh")
    )
    assert len(shared_v1) == 1, shared_v1
    assert (
        pkg_secret_client("sandbox-secrets-alpha", "get-secret", shared_v1[0])
        == "host-shared-gh-token"
    )

    # Unapproved host secret is denied for alpha, and shared-gh is denied for beta.
    private_v1 = json.loads(
        pkg_secret_client("sandbox-secrets-alpha", "search", "service=private-vault")
    )
    assert len(private_v1) == 1, private_v1
    pkg_secret_client(
        "sandbox-secrets-alpha",
        "expect-error",
        "org.freedesktop.DBus.Error.AccessDenied",
        "get-secret",
        private_v1[0],
    )
    pkg_secret_client(
        "sandbox-secrets-beta",
        "expect-error",
        "org.freedesktop.DBus.Error.AccessDenied",
        "get-secret",
        shared_v1[0],
    )

    # Delete a host item on the host bus and restart the Secret Service peer so
    # every surviving item receives a new sequential numeric object path and the
    # daemon acquires a new unique bus name.
    disposable = json.loads(host_secret_client("search", "service=disposable"))
    assert len(disposable) == 1, disposable
    host_secret_client("delete", disposable[0])

    dbus.succeed("systemctl restart agent-sandbox-vm-secrets-peer.service")
    dbus.wait_for_unit("agent-sandbox-vm-secrets-peer.service")
    wait_for_secrets_owner()

    shared_v2 = json.loads(
        pkg_secret_client("sandbox-secrets-alpha", "search", "service=shared-gh")
    )
    assert len(shared_v2) == 1, shared_v2
    assert (
        shared_v2[0] != shared_v1[0]
    ), f"expected numeric item path to renumber across restart: {shared_v1[0]} == {shared_v2[0]}"
    assert (
        pkg_secret_client("sandbox-secrets-alpha", "get-secret", shared_v2[0])
        == "host-shared-gh-token"
    )

    # Unapproved host secret remains denied after renumbering.
    private_v2 = json.loads(
        pkg_secret_client("sandbox-secrets-alpha", "search", "service=private-vault")
    )
    assert len(private_v2) == 1 and private_v2[0] != private_v1[0], (private_v1, private_v2)
    pkg_secret_client(
        "sandbox-secrets-alpha",
        "expect-error",
        "org.freedesktop.DBus.Error.AccessDenied",
        "get-secret",
        private_v2[0],
    )

    # Alpha's own package secret survives renumbering and remains hidden from beta.
    alpha_v2 = json.loads(
        pkg_secret_client("sandbox-secrets-alpha", "search", "service=alpha-api")
    )
    assert len(alpha_v2) == 1 and alpha_v2[0] != alpha_item, (alpha_item, alpha_v2)
    assert (
        pkg_secret_client("sandbox-secrets-alpha", "get-secret", alpha_v2[0])
        == "alpha-only-secret"
    )
    assert (
        json.loads(pkg_secret_client("sandbox-secrets-beta", "search", "service=alpha-api"))
        == []
    )
    pkg_secret_client(
        "sandbox-secrets-beta",
        "expect-error",
        "org.freedesktop.DBus.Error.AccessDenied",
        "get-secret",
        alpha_v2[0],
    )
  '';

  rememberedScript = ''
    # A call answered from the cached verdict or from a remembered rule
    # leaves the sandbox running. The approved first call freezes the scope
    # while it pends; the repeat must not add to the scope's frozen time.
    remembered.wait_for_unit("agent-sandbox-policy.service")
    remembered.wait_until_succeeds("test -S /run/user/1000/bus")

    pending_cmd = "runuser -u sandbox -- agent-sandbox-approve pending"

    def frozen_usec(scope_path):
        return int(
            remembered.succeed(
                f"awk '$1 == \"frozen_usec\" {{print $2}}' /sys/fs/cgroup{scope_path}/cgroup.stat.local"
            ).strip()
        )

    def repeated_call(tag, member, pause, scope):
        call = (
            "dbus-send --session --print-reply --dest=org.freedesktop.DBus "
            f"/org/freedesktop/DBus org.freedesktop.DBus.{member} >/dev/null"
        )
        script = (
            f": marker-{tag}; {call} && echo first-done && sleep {pause} && {call} && echo second-done; "
            "exec sleep 3600"
        )
        out = f"/tmp/{tag}.out"
        inner = f"cd /home/user && {shlex.join(['sandbox-dbus-remembered-bash', '-c', script])}"
        detached = (
            "nohup runuser -u sandbox -- env XDG_RUNTIME_DIR=/run/user/1000 "
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "
            f"sh -c {shlex.quote(inner)} </dev/null >{out} 2>&1 &"
        )
        remembered.succeed(command("sh", "-c", detached))
        try:
            remembered.wait_until_succeeds(f"{pending_cmd} | grep -F -q {member}", timeout=60)
        except Exception:
            print(remembered.execute(f"{pending_cmd}; echo ---; cat {out}; echo ---; ps aux | grep -E 'dbus-send|marker'")[1])
            raise
        pending_id = remembered.succeed(f"{pending_cmd} | grep -F {member} | head -1 | cut -f1").strip()
        remembered.succeed(
            command("runuser", "-u", "sandbox", "--", "agent-sandbox-approve", "approve", pending_id, scope)
        )

        # The scope's frozen time right after the approved call returns; the
        # sandbox waits `pause` before repeating the call.
        scope_path = remembered.succeed(
            f"until grep -q first-done {out}; do sleep 0.02; done; "
            f"for pid in $(pgrep -f marker-{tag}); do awk -F: '$1 == 0 {{print $3}}' /proc/$pid/cgroup; done "
            "2>/dev/null | grep agent-sandbox | head -1",
            timeout=60,
        ).strip()
        assert scope_path, "sandbox scope not found"
        before = frozen_usec(scope_path)
        assert before > 0, f"approved call never froze {scope_path}"

        remembered.wait_until_succeeds(f"grep -q second-done {out}", timeout=60)
        after = frozen_usec(scope_path)
        assert after == before, f"repeat froze {scope_path}: {before} -> {after}"
        remembered.succeed("pkill -f '^sleep 3600$'")

    # Approved once: the repeat inside the verdict cache's two-second window
    # is answered from the cache.
    repeated_call("cache-once", "ListNames", "0.5", "once")

    # Approved at project_package scope: the repeat, after the cache window,
    # is answered by the remembered rule.
    repeated_call("rule-remembered", "ListActivatableNames", "3", "project_package")
  '';

  # Boots only `node`; `script` runs after the shared helpers.
  mkCheck =
    {
      name,
      node,
      script,
    }:
    pkgs.testers.runNixOSTest (_: {
      name = "e2e-transport-dbus-${name}";
      node.specialArgs = { inherit inputs; };
      nodes.${node} =
        {
          dbus = dbusNode;
          remembered = rememberedNode;
        }
        .${node};

      testScript = ''
        start_all()
        ${node}.wait_for_unit("multi-user.target")
      ''
      + preamble
      + script;
    });
}
