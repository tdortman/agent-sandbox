"""Fail-closed mitmproxy policy bridge for agent-sandbox.

The addon deliberately has no policy logic of its own. Every decision is made by
policyd over the dedicated proxy Unix socket. The socket is opened afresh for
each request so an interrupted RPC cannot poison a later request.
"""


import asyncio
import ipaddress
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any

from mitmproxy import ctx, http, tcp, udp
from mitmproxy.connection import Connection
from mitmproxy.flow import Flow


SOCKET_ENV = "AGENT_SANDBOX_PROXY_SOCKET"
SESSION_READY_ENV = "AGENT_SANDBOX_PROXY_SESSION_READY"
INVOCATION_ID_ENV = "INVOCATION_ID"
DEFAULT_SOCKET = "/run/agent-sandbox/proxy-policy.sock"
MAX_ACTIVE_CHECKS = 256
MAX_PENDING_BYTES = 256 * 1024
DEFAULT_RPC_TIMEOUT = 305.0


class WireError(ValueError):
    """The peer sent a malformed or unexpected wire value."""


def _exact(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise WireError(f"invalid {name} envelope")
    return value


def _optional_exact(
    value: Any, required: set[str], optional: set[str], name: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WireError(f"invalid {name} envelope")
    keys = set(value)
    if not required <= keys or not keys <= required | optional:
        raise WireError(f"invalid {name} envelope")
    return value


def _bool(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise WireError(f"invalid {name}")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise WireError(f"invalid {name}")
    return value


def _token(value: Any, name: str) -> str:
    value = _text(value, name)
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise WireError(f"invalid {name}")
    return value


def _uuid(value: Any, name: str, version: int) -> str:
    value = _text(value, name)
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise WireError(f"invalid {name}") from error
    if (
        str(parsed) != value
        or parsed.version != version
        or parsed.variant != uuid.RFC_4122
    ):
        raise WireError(f"invalid {name}")
    return value


@dataclass(frozen=True, slots=True)
class ProxySessionToken:
    value: str

    @classmethod
    def decode(cls, value: Any) -> "ProxySessionToken":
        return cls(_token(value, "proxy_session"))

    def encode(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class AttributionToken:
    value: str

    @classmethod
    def decode(cls, value: Any) -> "AttributionToken":
        return cls(_token(value, "attribution_token"))

    def encode(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ProxyRequestId:
    value: str

    @classmethod
    def new(cls) -> "ProxyRequestId":
        return (
            cls(str(uuid.uuid7())) if hasattr(uuid, "uuid7") else cls._new_v7_fallback()
        )

    @classmethod
    def _new_v7_fallback(cls) -> "ProxyRequestId":
        # RFC 9562 UUIDv7 uses the Unix millisecond timestamp and random bits.
        timestamp = (time.time_ns() // 1_000_000) & ((1 << 48) - 1)
        random_bits = int.from_bytes(os.urandom(10), "big")
        raw = (timestamp << 80) | (0x7 << 76) | ((random_bits & ((1 << 12) - 1)) << 64)
        raw |= 0x8000000000000000 | (random_bits & ((1 << 62) - 1))
        return cls(str(uuid.UUID(int=raw)))

    @classmethod
    def decode(cls, value: Any) -> "ProxyRequestId":
        return cls(_uuid(value, "request_id", 7))

    def encode(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ProxyConnectionId:
    value: str

    @classmethod
    def new(cls) -> "ProxyConnectionId":
        return cls(str(uuid.uuid4()))

    def encode(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class NetworkFlowKey:
    protocol: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int

    @classmethod
    def from_flow(cls, flow: Flow, protocol: str) -> "NetworkFlowKey":
        if protocol not in ("tcp", "udp"):
            raise WireError("invalid transport protocol")
        source = _socket_address(flow.client_conn, "peername")
        destination = _socket_address(flow.server_conn, "address")
        return cls(protocol, source[0], source[1], destination[0], destination[1])

    def encode(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
        }


def _socket_address(connection: Connection, field: str) -> tuple[str, int]:
    address = getattr(connection, field, None)
    if not isinstance(address, tuple) or len(address) < 2:
        raise WireError("missing socket address")
    host, port = address[0], address[1]
    if not isinstance(host, str) or not isinstance(port, int) or isinstance(port, bool):
        raise WireError("invalid socket address")
    try:
        host = str(ipaddress.ip_address(host.split("%", 1)[0]))
    except ValueError as error:
        raise WireError("socket address is not an IP literal") from error
    if not 1 <= port <= 65535:
        raise WireError("invalid socket port")
    return host, port


@dataclass(frozen=True, slots=True)
class HttpRequest:
    method: str
    scheme: str
    authority: str
    path: str

    @classmethod
    def from_flow(cls, flow: http.HTTPFlow) -> "HttpRequest":
        raw_method = flow.request.data.method
        raw_path = flow.request.data.path
        if not isinstance(raw_method, bytes) or not isinstance(raw_path, bytes):
            raise WireError("invalid HTTP request fields")
        try:
            method = raw_method.decode("ascii")
            path = raw_path.decode("ascii")
        except UnicodeDecodeError as error:
            raise WireError("HTTP method/path is not ASCII") from error
        authority = flow.request.host_header
        if not isinstance(authority, str) or not authority:
            raise WireError("missing HTTP authority")
        transport = flow.client_conn.transport_protocol
        scheme = (
            "https"
            if transport == "udp"
            or flow.client_conn.tls
            or flow.client_conn.tls_established
            else "http"
        )
        if path == "":
            path = "/"
        if path == "*":
            path_for_wire = "*"
        else:
            path_for_wire = path
        return cls(method, scheme, authority, path_for_wire)

    def encode(self) -> dict[str, str]:
        if self.path == "*":
            url = f"{self.scheme}://{self.authority} *"
        else:
            url = f"{self.scheme}://{self.authority}{self.path}"
        return {"method": self.method, "url": url}

    @classmethod
    def decode(cls, value: Any) -> "HttpRequest":
        value = _exact(value, {"method", "url"}, "HTTP request")
        method = _text(value["method"], "HTTP method")
        raw_url = _text(value["url"], "HTTP URL")
        if "://" not in raw_url:
            raise WireError("invalid HTTP URL")
        scheme, remainder = raw_url.split("://", 1)
        if remainder.endswith(" *"):
            authority = remainder[:-2]
            path = "*"
        else:
            slash = remainder.find("/")
            if slash < 1:
                raise WireError("invalid HTTP URL authority")
            authority, path = remainder[:slash], remainder[slash:]
        if (
            scheme not in ("http", "https")
            or not authority
            or (path != "*" and not path.startswith("/"))
        ):
            raise WireError("invalid HTTP URL")
        if "?" in raw_url or "#" in raw_url:
            raise WireError("HTTP URL contains query or fragment")
        if path == "*" and method != "OPTIONS":
            raise WireError("asterisk target requires OPTIONS")
        return cls(method, scheme, authority, path)


@dataclass(frozen=True, slots=True)
class ConnectionState:
    key: NetworkFlowKey
    connection_id: ProxyConnectionId
    attribution_token: AttributionToken


@dataclass(frozen=True, slots=True)
class HttpCheckReply:
    ok: bool
    allowed: bool
    request: HttpRequest | None

    @classmethod
    def decode(cls, value: Any) -> "HttpCheckReply":
        value = _optional_exact(
            value, {"ok", "allowed", "source"}, {"error", "request"}, "HTTP reply"
        )
        _text(value["source"], "HTTP reply source")
        if "error" in value:
            _text(value["error"], "HTTP reply error")
        request = (
            None if "request" not in value else HttpRequest.decode(value["request"])
        )
        return cls(
            _bool(value["ok"], "HTTP reply ok"),
            _bool(value["allowed"], "HTTP reply allowed"),
            request,
        )


@dataclass(frozen=True, slots=True)
class NetworkCheckReply:
    ok: bool
    allowed: bool

    @classmethod
    def decode(cls, value: Any) -> "NetworkCheckReply":
        value = _optional_exact(
            value, {"ok", "allowed", "source"}, {"error"}, "network reply"
        )
        _text(value["source"], "network reply source")
        if "error" in value:
            _text(value["error"], "network reply error")
        return cls(
            _bool(value["ok"], "network reply ok"),
            _bool(value["allowed"], "network reply allowed"),
        )


def _opaque_tls_transport(protocol: str, port: int) -> bool:
    return protocol == "tcp" and port in (443, 8443)

class PolicyAddon:
    """A fail-closed, typed adapter between live flows and policyd."""

    def __init__(self) -> None:
        self.socket_path = os.environ.get(SOCKET_ENV, DEFAULT_SOCKET)
        self.rpc_timeout = _positive_float(
            os.environ.get("AGENT_SANDBOX_PROXY_TIMEOUT"), DEFAULT_RPC_TIMEOUT
        )
        self.session_ready_path = os.environ.get(SESSION_READY_ENV)
        self.invocation_id = os.environ.get(INVOCATION_ID_ENV)
        self._session: ProxySessionToken | None = None
        self._session_reader: asyncio.StreamReader | None = None
        self._session_writer: asyncio.StreamWriter | None = None
        self._session_watch_task: asyncio.Task[Any] | None = None
        self._session_lock = asyncio.Lock()
        self._active_checks = 0
        self._pending_bytes: dict[str, int] = {}
        self._flow_keys: dict[str, NetworkFlowKey] = {}
        self._flows: dict[str, Flow] = {}
        self._claims: dict[NetworkFlowKey, ConnectionState] = {}
        self._claim_refs: dict[NetworkFlowKey, int] = {}
        self._tasks: set[asyncio.Task[Any]] = set()

    def load(self, loader: Any) -> None:
        loader.add_option(
            "agent_sandbox_policy_timeout",
            int,
            max(1, int(self.rpc_timeout)),
            "Maximum seconds for one agent-sandbox policy decision.",
        )

    async def running(self) -> None:
        for attempt in range(3):
            try:
                await self._ensure_session()
                return
            except asyncio.CancelledError:
                raise
            except Exception:
                if attempt == 2:
                    master = getattr(ctx, "master", None)
                    if master is not None:
                        master.shutdown()
                    return
                await asyncio.sleep(0.25)

    async def requestheaders(self, flow: http.HTTPFlow) -> None:
        if not flow.live:
            self._kill(flow)
            return
        if self._blocked_http_method(flow):
            self._kill(flow)
            return
        try:
            request = HttpRequest.from_flow(flow)
            state = await self._claim(
                flow, "tcp" if flow.client_conn.transport_protocol == "tcp" else "udp"
            )
            if state is None:
                return
            request_id = ProxyRequestId.new()
            reply = await self._checked_rpc(
                flow,
                {
                    "op": "check_http",
                    "proxy_session": self._session_value(),
                    "request_id": request_id.encode(),
                    "attribution_token": state.attribution_token.encode(),
                    "request": request.encode(),
                },
                request_id,
            )
            if (
                not isinstance(reply, HttpCheckReply)
                or not reply.ok
                or not reply.allowed
                or reply.request is None
            ):
                self._kill(flow)
                await self._release_flow(flow)
                return
            if not flow.live:
                self._kill(flow)
                await self._release_flow(flow)
                return
            self._rewrite_upstream(flow, reply.request)
        except asyncio.CancelledError:
            self._kill(flow)
            await self._release_flow(flow)
            raise
        except BaseException:
            self._kill(flow)
            await self._release_flow(flow)

    def request(self, flow: http.HTTPFlow) -> None:
        content = flow.request.content
        if isinstance(content, bytes) and not self._account_bytes(flow, len(content)):
            self._kill(flow)
            self._schedule_release(flow)

    async def response(self, flow: http.HTTPFlow) -> None:
        await self._release_flow(flow)

    async def error(self, flow: Flow) -> None:
        await self._release_flow(flow)

    async def tcp_start(self, flow: tcp.TCPFlow) -> None:
        await self._transport_start(flow, "tcp")

    async def udp_start(self, flow: udp.UDPFlow) -> None:
        await self._transport_start(flow, "udp")

    def tcp_message(self, flow: tcp.TCPFlow) -> None:
        self._transport_message(flow)

    def udp_message(self, flow: udp.UDPFlow) -> None:
        self._transport_message(flow)

    async def tcp_end(self, flow: tcp.TCPFlow) -> None:
        await self._release_flow(flow)

    async def tcp_error(self, flow: tcp.TCPFlow) -> None:
        await self._release_flow(flow)

    async def udp_end(self, flow: udp.UDPFlow) -> None:
        await self._release_flow(flow)

    async def udp_error(self, flow: udp.UDPFlow) -> None:
        await self._release_flow(flow)

    async def done(self) -> None:
        for task in tuple(self._tasks):
            task.cancel()
        self._tasks.clear()
        self._clear_session_ready()
        watcher = self._session_watch_task
        if watcher is not None and watcher is not asyncio.current_task():
            watcher.cancel()
            try:
                await watcher
            except BaseException:
                pass
        self._session_watch_task = None
        writer = self._session_writer
        self._session = None
        self._session_reader = None
        self._session_writer = None
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except BaseException:
                pass

    async def _transport_start(self, flow: Flow, protocol: str) -> None:
        if not flow.live:
            self._kill(flow)
            return
        try:
            state = await self._claim(flow, protocol)
            if state is None:
                return
            # Opaque TCP/TLS on 443 cannot be attributed to an HTTP request;
            # UDP/443 remains eligible for the HTTP/3 transport check.
            if _opaque_tls_transport(protocol, state.key.destination_port):
                self._kill(flow)
                await self._release_flow(flow)
                return
            request_id = ProxyRequestId.new()
            reply = await self._checked_rpc(
                flow,
                {
                    "op": "check_network_flow",
                    "proxy_session": self._session_value(),
                    "request_id": request_id.encode(),
                    "attribution_token": state.attribution_token.encode(),
                },
                request_id,
            )
            if (
                not isinstance(reply, NetworkCheckReply)
                or not reply.ok
                or not reply.allowed
                or not flow.live
            ):
                self._kill(flow)
                await self._release_flow(flow)
        except asyncio.CancelledError:
            self._kill(flow)
            await self._release_flow(flow)
            raise
        except BaseException:
            self._kill(flow)
            await self._release_flow(flow)

    def _transport_message(self, flow: Flow) -> None:
        messages = getattr(flow, "messages", ())
        if not messages:
            return
        content = getattr(messages[-1], "content", None)
        if isinstance(content, bytes) and not self._account_bytes(flow, len(content)):
            self._kill(flow)
            self._schedule_release(flow)

    async def _ensure_session(self) -> ProxySessionToken:
        if self._session is not None:
            return self._session

        async with self._session_lock:
            if self._session is not None:
                return self._session
            reader, writer, reply = await asyncio.wait_for(
                self._open_session(), self.rpc_timeout
            )
            watcher: asyncio.Task[Any] | None = None
            try:
                self._session = reply
                self._session_reader = reader
                self._session_writer = writer
                watcher = asyncio.create_task(
                    self._watch_session(reader), name="agent-sandbox proxy session"
                )
                self._session_watch_task = watcher
                self._set_session_ready()
                return reply
            except BaseException:
                self._clear_session_ready()
                if watcher is not None:
                    watcher.cancel()
                    try:
                        await watcher
                    except BaseException:
                        pass
                self._session_watch_task = None
                self._session = None
                self._session_reader = None
                self._session_writer = None
                writer.close()
                try:
                    await writer.wait_closed()
                except BaseException:
                    pass
                raise

    async def _open_session(
        self,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, ProxySessionToken]:
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            writer.write(b'{"op":"open_proxy_session"}\n')
            await writer.drain()
            reply = await self._read_rpc_reply(reader)
            if not isinstance(reply, ProxySessionToken):
                raise WireError("invalid proxy session reply")
            return reader, writer, reply
        except BaseException:
            writer.close()
            try:
                await writer.wait_closed()
            except BaseException:
                pass
            raise

    def _set_session_ready(self) -> None:
        if self.session_ready_path is None:
            return
        invocation_id = self.invocation_id
        if (
            invocation_id is None
            or len(invocation_id) != 32
            or any(character not in "0123456789abcdef" for character in invocation_id)
        ):
            raise WireError("invalid systemd invocation ID")
        temporary = f"{self.session_ready_path}.tmp.{os.getpid()}"
        try:
            with open(temporary, "w", encoding="ascii") as marker:
                marker.write(f"{invocation_id}\n")
            os.chmod(temporary, 0o644)
            os.replace(temporary, self.session_ready_path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _clear_session_ready(self) -> None:
        if self.session_ready_path is None:
            return
        try:
            os.unlink(self.session_ready_path)
        except OSError:
            pass

    async def _watch_session(self, reader: asyncio.StreamReader) -> None:
        try:
            while await reader.read(4096):
                pass
        except asyncio.CancelledError:
            return
        except BaseException:
            pass
        if reader is not self._session_reader:
            return
        self._clear_session_ready()
        self._session = None
        self._session_reader = None
        self._session_writer = None
        self._claims.clear()
        self._claim_refs.clear()
        self._flow_keys.clear()
        self._pending_bytes.clear()
        for flow in tuple(self._flows.values()):
            self._kill(flow)
        self._flows.clear()
        master = getattr(ctx, "master", None)
        if master is not None:
            master.shutdown()

    def _session_value(self) -> str:
        if self._session is None:
            raise WireError("proxy session unavailable")
        return self._session.encode()

    async def _claim(self, flow: Flow, protocol: str) -> ConnectionState | None:
        flow_id = flow.id
        if not flow.live:
            self._flows.pop(flow_id, None)
            self._kill(flow)
            return None
        self._flows[flow_id] = flow
        existing_key = self._flow_keys.get(flow_id)
        if existing_key is not None:
            return self._claims[existing_key]
        try:
            key = NetworkFlowKey.from_flow(flow, protocol)
            await self._ensure_session()
            state = self._claims.get(key)
            if state is not None:
                self._flow_keys[flow_id] = key
                self._claim_refs[key] = self._claim_refs.get(key, 0) + 1
                return state
            if not self._acquire_permit(flow):
                self._flows.pop(flow_id, None)
                return None
            connection_id = ProxyConnectionId.new()
            try:
                reply = await self._rpc(
                    {
                        "op": "claim_network_flow",
                        "proxy_session": self._session_value(),
                        "flow": key.encode(),
                        "connection_id": connection_id.encode(),
                    }
                )
            finally:
                self._release_permit()
            if not isinstance(reply, AttributionToken):
                raise WireError("invalid flow claim reply")
            state = ConnectionState(key, connection_id, reply)
            self._claims[key] = state
            self._claim_refs[key] = 1
            self._flow_keys[flow_id] = key
            return state
        except BaseException:
            self._flows.pop(flow_id, None)
            self._kill(flow)
            return None

    async def _release_flow(self, flow: Flow) -> None:
        self._flows.pop(flow.id, None)
        key = self._flow_keys.pop(flow.id, None)
        self._pending_bytes.pop(flow.id, None)
        if key is None:
            return
        refs = self._claim_refs.get(key, 0) - 1
        if refs > 0:
            self._claim_refs[key] = refs
            return
        self._claim_refs.pop(key, None)
        state = self._claims.pop(key, None)
        if state is None or self._session is None:
            return
        try:
            await self._rpc(
                {
                    "op": "release_network_flow",
                    "proxy_session": self._session_value(),
                    "attribution_token": state.attribution_token.encode(),
                }
            )
        except BaseException:
            pass

    async def _checked_rpc(
        self, flow: Flow, payload: dict[str, Any], request_id: ProxyRequestId
    ) -> Any:
        if not self._acquire_permit(flow):
            return None
        try:
            return await self._rpc(payload)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            self._kill(flow)
            await self._cancel_check(request_id)
            raise
        except BaseException:
            self._kill(flow)
            return None
        finally:
            self._release_permit()

    async def _cancel_check(self, request_id: ProxyRequestId) -> None:
        if self._session is None:
            return
        try:
            await asyncio.shield(
                asyncio.wait_for(
                    self._rpc(
                        {
                            "op": "cancel_check",
                            "proxy_session": self._session_value(),
                            "request_id": request_id.encode(),
                        }
                    ),
                    self.rpc_timeout,
                )
            )
        except BaseException:
            pass

    async def _rpc(self, payload: dict[str, Any]) -> Any:
        async def transaction() -> Any:
            reader, writer = await asyncio.open_unix_connection(self.socket_path)
            try:
                writer.write(
                    json.dumps(
                        payload, separators=(",", ":"), ensure_ascii=True
                    ).encode("ascii")
                    + b"\n"
                )
                await writer.drain()
                return await self._read_rpc_reply(reader)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except BaseException:
                    pass

        return await asyncio.wait_for(transaction(), self.rpc_timeout)

    async def _read_rpc_reply(self, reader: asyncio.StreamReader) -> Any:
        line = await reader.readline()
        if not line or len(line) > 128 * 1024 or not line.endswith(b"\n"):
            raise WireError("invalid policyd response framing")
        try:
            value = json.loads(line[:-1])
        except (TypeError, ValueError) as error:
            raise WireError("invalid policyd response JSON") from error
        return _decode_reply(value)

    def _acquire_permit(self, flow: Flow) -> bool:
        if self._active_checks >= MAX_ACTIVE_CHECKS or not flow.live:
            self._kill(flow)
            return False
        self._active_checks += 1
        return True

    def _release_permit(self) -> None:
        self._active_checks = max(0, self._active_checks - 1)

    def _account_bytes(self, flow: Flow, size: int) -> bool:
        if size < 0:
            return False
        total = self._pending_bytes.get(flow.id, 0) + size
        self._pending_bytes[flow.id] = total
        return total <= MAX_PENDING_BYTES

    def _rewrite_upstream(self, flow: http.HTTPFlow, request: HttpRequest) -> None:
        host, port = _authority_host_port(request.scheme, request.authority)
        if flow.server_conn.connected or flow.server_conn.state.value != 0:
            raise WireError("upstream connection already open")
        flow.request.host = host
        flow.request.port = port
        flow.server_conn.address = (host, port)

    @staticmethod
    def _blocked_http_method(flow: http.HTTPFlow) -> bool:
        raw_method = flow.request.data.method
        if not isinstance(raw_method, bytes):
            return True
        try:
            method = raw_method.decode("ascii").upper()
        except UnicodeDecodeError:
            return True
        if method in {"CONNECT", "MASQUE", "WEBTRANSPORT"}:
            return True
        for name in ("protocol", ":protocol", "upgrade"):
            value = flow.request.headers.get(name)
            if isinstance(value, str) and value.lower() == "webtransport":
                return True
        return False

    def _kill(self, flow: Flow) -> None:
        try:
            if flow.live:
                flow.kill()
        except BaseException:
            try:
                flow.live = False
            except BaseException:
                pass

    def _schedule_release(self, flow: Flow) -> None:
        task = asyncio.create_task(self._release_flow(flow))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)


def _authority_host_port(scheme: str, authority: str) -> tuple[str, int]:
    try:
        if authority.startswith("["):
            end = authority.find("]")
            if end < 0:
                raise ValueError
            host = authority[1:end]
            suffix = authority[end + 1 :]
            if suffix and not suffix.startswith(":"):
                raise ValueError
            port = int(suffix[1:]) if suffix else (443 if scheme == "https" else 80)
        elif authority.count(":") == 1:
            host, port_text = authority.rsplit(":", 1)
            port = int(port_text)
        elif ":" in authority:
            raise ValueError
        else:
            host = authority
            port = 443 if scheme == "https" else 80
        if not host or not 1 <= port <= 65535:
            raise ValueError
        return host, port
    except (TypeError, ValueError) as error:
        raise WireError("invalid HTTP authority") from error


def _positive_float(value: str | None, default: float) -> float:
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError:
        return default
    return parsed if parsed > 0 else default


def _decode_reply(value: Any) -> Any:
    if isinstance(value, dict) and set(value) == {"ok", "error"}:
        if _bool(value["ok"], "error reply ok"):
            raise WireError("successful error reply")
        _text(value["error"], "error reply")
        raise WireError("policyd rejected proxy operation")
    if isinstance(value, dict) and set(value) == {"ok", "proxy_session"}:
        if not _bool(value["ok"], "session reply ok"):
            raise WireError("proxy session rejected")
        return ProxySessionToken.decode(value["proxy_session"])
    if isinstance(value, dict) and set(value) == {"ok", "attribution_token"}:
        if not _bool(value["ok"], "claim reply ok"):
            raise WireError("flow claim rejected")
        return AttributionToken.decode(value["attribution_token"])
    if isinstance(value, dict) and set(value) == {"ok"}:
        if not _bool(value["ok"], "simple reply ok"):
            raise WireError("proxy operation rejected")
        return True
    if isinstance(value, dict) and set(value) == {"kind", "reply"}:
        kind = _text(value["kind"], "proxy reply kind")
        if kind == "http_check":
            return HttpCheckReply.decode(value["reply"])
        if kind == "network_flow":
            return NetworkCheckReply.decode(value["reply"])
        if kind == "canceled":
            return _decode_reply(value["reply"])
        if kind == "error":
            return _decode_reply(value["reply"])
        raise WireError("unknown proxy reply kind")
    if isinstance(value, dict) and {"request_id", "reply"} <= set(value):
        value = _exact(value, {"request_id", "reply"}, "proxy reply")
        ProxyRequestId.decode(value["request_id"])
        return _decode_reply(value["reply"])
    if isinstance(value, dict) and {"ok", "allowed", "source"} <= set(value):
        if "request" in value or "error" in value:
            return HttpCheckReply.decode(value)
        return NetworkCheckReply.decode(value)
    raise WireError("unknown policyd reply")


addons = [PolicyAddon()]
