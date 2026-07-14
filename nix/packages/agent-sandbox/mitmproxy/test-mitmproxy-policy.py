"""Focused smoke test for dedicated session and short-lived RPC sockets."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import tempfile
import types
from pathlib import Path


def _load_addon():
    mitmproxy = types.ModuleType("mitmproxy")
    mitmproxy.http = types.SimpleNamespace()
    mitmproxy.tcp = types.SimpleNamespace()
    mitmproxy.udp = types.SimpleNamespace()
    mitmproxy.http.HTTPFlow = object
    mitmproxy.tcp.TCPFlow = object
    mitmproxy.udp.UDPFlow = object
    mitmproxy.ctx = types.SimpleNamespace(master=None)
    connection = types.ModuleType("mitmproxy.connection")
    connection.Connection = object
    flow = types.ModuleType("mitmproxy.flow")
    flow.Flow = object
    sys.modules.update({
        "mitmproxy": mitmproxy,
        "mitmproxy.connection": connection,
        "mitmproxy.flow": flow,
    })
    spec = importlib.util.spec_from_file_location(
        "agent_sandbox_mitmproxy_policy",
        Path(__file__).with_name("mitmproxy-policy.py"),
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    assert spec.name not in sys.modules
    spec.loader.exec_module(module)
    return module


async def main() -> None:
    addon_module = _load_addon()
    token = "a" * 64
    attribution = "b" * 64
    request_id = "01900000-0000-7000-8000-000000000001"
    connection_id = "01900000-0000-4000-8000-000000000002"
    http_body = addon_module._decode_reply(
        {
            "kind": "http_check",
            "reply": {
                "ok": True,
                "allowed": True,
                "source": "allow",
                "request": {"method": "GET", "url": "https://example.com/"},
            },
        }
    )
    assert http_body.ok and http_body.allowed
    network_body = addon_module._decode_reply(
        {"kind": "network_flow", "reply": {"ok": True, "allowed": True, "source": "allow"}}
    )
    assert network_body.ok and network_body.allowed
    assert addon_module._decode_reply({"kind": "canceled", "reply": {"ok": True}}) is True
    try:
        addon_module._decode_reply({"kind": "error", "reply": {"ok": False, "error": "denied"}})
    except addon_module.WireError:
        pass
    else:
        raise AssertionError("error body must fail closed")
    seen: list[dict[str, object]] = []
    assert addon_module._authority_host_port("https", "example.com:8443") == (
        "example.com",
        8443,
    )
    assert addon_module._authority_host_port("https", "[::1]:8443") == ("::1", 8443)

    assert not addon_module._opaque_tls_transport("udp", 443)
    assert addon_module._opaque_tls_transport("tcp", 443)
    assert addon_module._opaque_tls_transport("tcp", 8443)

    retry_addon = addon_module.PolicyAddon()
    ready_directory = tempfile.TemporaryDirectory()
    ready_path = Path(ready_directory.name) / "session-ready"
    invocation_id = "c" * 32
    retry_addon.invocation_id = invocation_id
    retry_addon.session_ready_path = str(ready_path)
    attempts = 0
    session_reader = asyncio.StreamReader()

    class SessionWriter:
        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    async def flaky_open() -> object:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise addon_module.WireError("socket not ready")
        return session_reader, SessionWriter(), addon_module.ProxySessionToken(token)

    retry_addon._open_session = flaky_open
    await retry_addon.running()
    assert (await retry_addon._ensure_session()).value == token
    assert attempts == 2
    assert ready_path.read_text(encoding="ascii") == f"{invocation_id}\n"
    assert list(ready_path.parent.glob("session-ready.tmp.*")) == []
    session_reader.feed_eof()
    await retry_addon.done()
    assert not ready_path.exists()
    ready_directory.cleanup()

    fast_seen = asyncio.Event()
    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        active: set[asyncio.Task[None]] = set()
        

        async def respond(request: dict[str, object]) -> None:
            seen.append(request)
            op = request["op"]
            if op == "open_proxy_session":
                reply: object = {"ok": True, "proxy_session": token}
            elif op == "claim_network_flow":
                assert request["connection_id"] == connection_id
                reply = {"ok": True, "attribution_token": attribution}
            elif op == "check_http":
                request_data = request["request"]
                assert isinstance(request_data, dict)
                url = request_data["url"]
                if isinstance(url, str) and url.endswith("/fast"):
                    fast_seen.set()
                if isinstance(url, str) and url.endswith("/slow"):
                    await fast_seen.wait()
                reply = {
                    "request_id": request["request_id"],
                    "reply": {
                        "kind": "http_check",
                        "reply": {
                            "ok": True,
                            "allowed": True,
                            "source": "allow",
                            "request": request_data,
                        },
                    },
                }
            elif op == "release_network_flow":
                reply = {"ok": True}
            else:
                raise AssertionError(op)
            writer.write(json.dumps(reply).encode() + b"\n")
            await writer.drain()

        try:
            while line := await reader.readline():
                task = asyncio.create_task(respond(json.loads(line)))
                active.add(task)
                task.add_done_callback(active.discard)
            if active:
                await asyncio.gather(*active)
        finally:
            writer.close()
            await writer.wait_closed()

    with tempfile.TemporaryDirectory() as directory:
        socket = str(Path(directory) / "proxy.sock")
        server = await asyncio.start_unix_server(serve, socket)
        addon = addon_module.PolicyAddon()
        addon.socket_path = socket
        addon.rpc_timeout = 2
        session = await addon._ensure_session()
        assert session.value == token
        state = addon_module.ConnectionState(
            addon_module.NetworkFlowKey("tcp", "10.0.0.2", 40000, "93.184.216.34", 443),
            addon_module.ProxyConnectionId(connection_id),
            addon_module.AttributionToken(attribution),
        )
        claim = await addon._rpc({
            "op": "claim_network_flow",
            "proxy_session": session.value,
            "flow": state.key.encode(),
            "connection_id": state.connection_id.encode(),
        })
        assert claim.value == attribution
        check = await addon._rpc({
            "op": "check_http",
            "proxy_session": session.value,
            "request_id": request_id,
            "attribution_token": attribution,
            "request": {"method": "GET", "url": "https://example.com/"},
        })
        assert check.ok and check.allowed

        async def check_url(url: str, check_id: str) -> object:
            return await addon._rpc(
                {
                    "op": "check_http",
                    "proxy_session": session.value,
                    "request_id": check_id,
                    "attribution_token": attribution,
                    "request": {"method": "GET", "url": url},
                }
            )
        slow, fast = await asyncio.gather(
            check_url("https://example.com/slow", "01900000-0000-7000-8000-000000000003"),
            check_url("https://example.com/fast", "01900000-0000-7000-8000-000000000004"),
        )
        assert slow.request.path == "/slow"
        assert fast.request.path == "/fast"
        await addon._rpc({
            "op": "release_network_flow",
            "proxy_session": session.value,
            "attribution_token": attribution,
        })
        await addon.done()
        server.close()
        await server.wait_closed()

    check_seen = asyncio.Event()
    cancel_seen = asyncio.Event()
    async def cancel_serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while line := await reader.readline():
                request = json.loads(line)
                if request["op"] == "open_proxy_session":
                    writer.write(
                        json.dumps({"ok": True, "proxy_session": token}).encode() + b"\n"
                    )
                    await writer.drain()
                elif request["op"] == "check_http":
                    check_seen.set()
                    continue
                elif request["op"] == "cancel_check":
                    cancel_seen.set()
                    reply = {
                        "request_id": request["request_id"],
                        "reply": {"kind": "canceled", "reply": {"ok": True}},
                    }
                    writer.write(json.dumps(reply).encode() + b"\n")
                    await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    with tempfile.TemporaryDirectory() as directory:
        socket = str(Path(directory) / "cancel.sock")
        server = await asyncio.start_unix_server(cancel_serve, socket)
        addon = addon_module.PolicyAddon()
        addon.socket_path = socket
        session = await addon._ensure_session()
        flow = types.SimpleNamespace(live=True, kill=lambda: None)
        pending = asyncio.create_task(
            addon._checked_rpc(
                flow,
                {
                    "op": "check_http",
                    "proxy_session": session.value,
                    "request_id": request_id,
                    "attribution_token": attribution,
                    "request": {"method": "GET", "url": "https://example.com/"},
                },
                addon_module.ProxyRequestId.decode(request_id),
            )
        )
        await asyncio.wait_for(check_seen.wait(), 2)
        pending.cancel()
        try:
            await pending
        except asyncio.CancelledError:
            pass
        await asyncio.wait_for(cancel_seen.wait(), 2)
        await addon.done()
        server.close()
        await server.wait_closed()

    operations = [request["op"] for request in seen]
    assert operations[:3] == [
        "open_proxy_session",
        "claim_network_flow",
        "check_http",
    ]
    assert operations.count("check_http") == 3
    assert operations[-1] == "release_network_flow"


if __name__ == "__main__":
    asyncio.run(main())
