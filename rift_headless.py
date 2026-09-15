from __future__ import annotations

import argparse
import base64
import importlib.util
import hashlib
import ipaddress
import json
import os
import random
import re
import socket
import struct
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

PROJECT_ROOT = Path(__file__).resolve().parents[1]

from session_material import SessionMaterial
from protocol_profile import load_profile
from rbx_protocol import (build_app_connection_request, build_connected_ping,
                          build_connected_pong, build_new_incoming_connection,
                          parse_open_reply1, wrap_reliable)
from raknet_codec import (EncapsulatedFrame, parse_connected_datagram, build_ack,
                          parse_ack, ReliabilityWindow)
from udmux_codec import decode as decode_udmux, encode as encode_udmux, unwrap_inner
from replication import ReplicatorState, build_physics_message
from established_aead import COUNTER_BASE, encrypt_datagram
from lifecycle_codec import (build_isr_timestamp, build_marker_echo, build_marker_isr, build_ping_item,
                             build_progress_ack, build_request_character,
                             parse_marker,
                             parse_progress_token)

UA = "Roblox/WinInet"
MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")


def load_launcher(root: Path):
    vendor = str(PROJECT_ROOT / "tools" / "_vendor")
    if Path(vendor).is_dir() and vendor not in sys.path:
        sys.path.insert(0, vendor)
    path = root / "open_private_games.py"
    spec = importlib.util.spec_from_file_location("private_game_launcher", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"launcher module missing: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read_first_cookie(mod, root: Path) -> str:
    for line in mod.read_nonempty_lines(root / "cookie.txt"):
        value = mod.parse_cookie(line)
        if value:
            return value
    raise RuntimeError("cookie.txt has no usable entry")


def parse_json_response(response) -> Any:
    try:
        return response.json()
    except ValueError:
        body = response.text.strip()
        if body.startswith("{"):
            return json.loads(body)
        return body


def find_value(obj: Any, names: tuple[str, ...]) -> Any:
    wanted = {n.lower() for n in names}
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key.lower() in wanted and value not in (None, ""):
                return value
        for value in obj.values():
            found = find_value(value, names)
            if found not in (None, ""):
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = find_value(value, names)
            if found not in (None, ""):
                return found
    return None


def redact_url(value: str | None) -> str | None:
    if not value:
        return value
    # Keep the route and non-secret query keys, remove ticket-like values.
    return re.sub(r"([?&](?:ticket|authenticationTicket|authTicket|key|signature)=)[^&]+", r"\1<REDACTED>", value, flags=re.I)


@dataclass
class BootstrapResult:
    ok: bool
    place_id: str
    status_code: int | None = None
    job_id: str | None = None
    join_script_url: str | None = None
    server_ip: str | None = None
    server_port: int | None = None
    udmux_ip: str | None = None
    udmux_port: int | None = None
    game_id: str | None = None
    session_id: str | None = None
    error: str | None = None
    raw_keys: list[str] = field(default_factory=list)
    material_profile: dict[str, Any] = field(default_factory=dict)
    # Non-secret routing metadata used to diagnose endpoint selection.
    client_port: int | None = None
    netstack_port: int | None = None
    direct_server_return: bool | None = None
    udmux_endpoints: list[dict[str, Any]] = field(default_factory=list)
    server_connections: list[dict[str, Any]] = field(default_factory=list)
    # Keep all transport candidates so the probe can try the same addresses
    # the desktop client logs (UDMUX first, then a direct server fallback).
    endpoint_candidates: list[dict[str, Any]] = field(default_factory=list)


def bootstrap(session, ticket: str, place_id: str) -> BootstrapResult:
    # Bind the join response and Request2 to one ephemeral client key. The
    # official client advertises this public half in the join request.
    client_ephemeral_private = None
    client_ephemeral_public = None
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        client_ephemeral_private = X25519PrivateKey.generate()
        client_ephemeral_public = client_ephemeral_private.public_key().public_bytes_raw()
    except Exception:
        pass
    tracker = random.randint(100_000_000_000, 999_999_999_999)
    params = {
        "request": "RequestGame",
        "browserTrackerId": tracker,
        "placeId": place_id,
        "isPlayTogetherGame": "false",
        "joinAttemptOrigin": "PlayButton",
    }
    # The legacy PlaceLauncher route now returns the web 404 shell on current
    # builds. The gamejoin service is the headless equivalent used by the app.
    url = "https://gamejoin.roblox.com/v1/join-game"
    headers = {
        "User-Agent": UA,
        "Referer": "https://www.roblox.com/",
        "Content-Type": "application/json",
        "RBX-Authentication-Ticket": ticket,
    }
    body = {
        "placeId": int(place_id),
        "isTeleport": False,
        "gameId": None,
        "gameJoinAttemptId": str(uuid.uuid4()),
        "joinAttemptOrigin": "PlayButton",
        "browserTrackerId": tracker,
    }
    if client_ephemeral_public is not None:
        pub_b64 = base64.b64encode(client_ephemeral_public).decode("ascii")
        body["ClientPublicKeyData"] = json.dumps({
            "applications": {"RakNetEarlyPublicKey": {
                "versions": [{"id": 2, "value": pub_b64, "allowed": True}],
                "send": 2, "revert": 2,
            }}
        }, separators=(",", ":"))
    try:
        response = session.post(url, headers=headers, json=body, timeout=20)
    except Exception as exc:  # network error is captured in the result artifact
        return BootstrapResult(False, place_id, error=f"place-launcher:{type(exc).__name__}")
    payload = parse_json_response(response)
    result = BootstrapResult(False, place_id, status_code=response.status_code)
    result.raw_keys = sorted(payload.keys()) if isinstance(payload, dict) else []
    result.job_id = str(find_value(payload, ("jobId", "gameId")) or "") or None
    join = find_value(payload, ("joinScriptUrl", "joinScriptURL", "joinScript"))
    if isinstance(join, dict):
        join = join.get("url") or join.get("Url")
    result.join_script_url = str(join) if join else None
    if result.join_script_url:
        result.join_script_url = redact_url(result.join_script_url)
    # Some launcher responses inline the join data; preserve only transport fields.
    result.server_ip = str(find_value(payload, ("serverIp", "serverAddress", "machineAddress", "rccAddress")) or "") or None
    port = find_value(payload, ("serverPort", "rccPort", "port"))
    try:
        result.server_port = int(port) if port is not None else None
    except (TypeError, ValueError):
        pass
    # Current responses inline `joinScript`; older responses require fetching
    # the URL. Prefer the inline object so no second ticket request is needed.
    join_payload = payload.get("joinScript") if isinstance(payload, dict) else None
    join_response = None
    # Some deployments return only a ticket and require a Join.ashx claim;
    # others (including the current 0.738 response) already include the
    # decoded object.  Support both paths without replaying a one-shot ticket.
    if result.join_script_url is None and not isinstance(join_payload, dict):
        return result.__class__(**{**asdict(result), "error": f"place-launcher-http-{response.status_code}-no-join-script"})
    # Set RIFT_CLAIM_JOIN=1 only when testing a deployment whose API returns a
    # ticket-only shell.  Current 0.738 /v1/join-game responses include the
    # already-claimed inline object, and replaying Join.ashx then returns 404.
    if join and (not isinstance(join_payload, dict) or os.environ.get("RIFT_CLAIM_JOIN", "").strip() == "1"):
        try:
            join_response = session.get(join, headers={"User-Agent": UA, "Referer": "https://www.roblox.com/"}, timeout=20)
            fetched_payload = parse_json_response(join_response)
            if isinstance(fetched_payload, dict):
                join_payload = fetched_payload
        except Exception as exc:
            if not isinstance(join_payload, dict):
                result.error = f"join-script:{type(exc).__name__}"
                return result
    join_data = join_payload.get("joinScript") if isinstance(join_payload, dict) and isinstance(join_payload.get("joinScript"), dict) else join_payload
    if not isinstance(join_data, dict):
        result.error = "join-script-invalid-payload"
        return result
    result.raw_keys = sorted(set(result.raw_keys) | set(join_data.keys()))
    material = SessionMaterial.from_join_payload(join_data)
    # Attach the transient object for the transport adapter while keeping it
    # out of dataclass serialization and output artifacts.
    result._session_material = material
    # Keep only shape metadata in the report. The actual key/token material is
    # retained nowhere after this function returns.
    result.material_profile = material.summary()
    try:
        # Generate the client ephemeral key now so a future encrypted adapter
        # can consume one stable context for the entire socket attempt.
        result._session_context = material.new_context(1492, material.netstack_port)
        if client_ephemeral_private is not None and client_ephemeral_public is not None:
            # Reuse the exact key advertised above; a second generated pair
            # makes the server's ECDH transcript and Request2 disagree.
            result._session_context._client_ephemeral_private = client_ephemeral_private
            result._session_context.client_ephemeral_public_key = client_ephemeral_public
        result.material_profile["context"] = result._session_context.summary()
    except Exception:
        # Parsing/bootstrap remains useful on hosts without the optional crypto
        # package; the encrypted adapter will report that dependency later.
        result._session_context = None
    result.server_ip = str(find_value(join_data, ("serverIp", "serverAddress", "machineAddress", "rccAddress")) or result.server_ip or "") or None
    port = find_value(join_data, ("serverPort", "rccPort", "port"))
    try:
        result.server_port = int(port) if port is not None else result.server_port
    except (TypeError, ValueError):
        pass
    endpoints = join_data.get("UdmuxEndpoints") or join_data.get("udmuxEndpoints") or []
    if isinstance(endpoints, list) and endpoints and isinstance(endpoints[0], dict):
        result.udmux_ip = str(endpoints[0].get("Address") or endpoints[0].get("address") or "") or None
        port = endpoints[0].get("Port") or endpoints[0].get("port")
    else:
        result.udmux_ip = str(find_value(join_data, ("udmuxAddress", "udmuxIp", "publicIp")) or "") or None
        port = find_value(join_data, ("udmuxPort", "publicPort"))
    try:
        result.udmux_port = int(port) if port is not None else None
    except (TypeError, ValueError):
        pass
    result.game_id = str(find_value(join_data, ("gameId", "gameGuid")) or result.job_id or "") or None
    session_value = find_value(join_data, ("sessionId", "playSessionId"))
    # SessionId is sometimes an embedded JSON envelope. Keep only its opaque
    # identifier so IPs, seeds and telemetry fields never reach the report.
    if isinstance(session_value, str) and session_value.lstrip().startswith("{"):
        try:
            session_value = json.loads(session_value).get("SessionId")
        except (TypeError, ValueError):
            session_value = None
    result.session_id = str(session_value or "") or None
    # Preserve only the non-secret routing inputs.  In particular, ClientPort
    # and NetStackPort are distinct from the RCC/UDMUX port and must not be
    # silently collapsed into the generic recursive `port` lookup above.
    def _int_field(name: str) -> int | None:
        value = join_data.get(name)
        try:
            return int(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None

    result.client_port = _int_field("ClientPort")
    result.netstack_port = _int_field("NetStackPort")
    raw_direct = join_data.get("DirectServerReturn")
    if raw_direct is not None:
        if isinstance(raw_direct, bool):
            result.direct_server_return = raw_direct
        else:
            result.direct_server_return = str(raw_direct).strip().lower() in {"1", "true", "yes"}
    # Preserve only endpoint metadata.  The join payload may also contain
    # ClientPort/NetStackPort and a ServerConnections list; none of these are
    # credentials, and retaining them avoids silently probing the wrong port.
    candidates: list[dict[str, Any]] = []
    if isinstance(endpoints, list):
        for item in endpoints:
            if not isinstance(item, dict):
                continue
            host = item.get("Address") or item.get("address")
            raw_port = item.get("Port") or item.get("port")
            try:
                raw_port = int(raw_port) if raw_port is not None else None
            except (TypeError, ValueError):
                raw_port = None
            result.udmux_endpoints.append({"host": str(host) if host else None, "port": raw_port})
    if result.udmux_ip and result.udmux_port:
        candidates.append({"kind": "udmux", "host": result.udmux_ip, "port": result.udmux_port})
    # Some 0.738 joins advertise a separate NetStack UDP listener. Keep it as
    # a later candidate because relays may place the initial Rbx handshake
    # there even when UdmuxEndpoints carries the same public address.
    if result.udmux_ip and result.netstack_port and result.netstack_port != result.udmux_port:
        candidates.append({"kind": "netstack", "host": result.udmux_ip, "port": result.netstack_port})
    if result.server_ip and result.server_port:
        candidates.append({"kind": "direct", "host": result.server_ip, "port": result.server_port})
    server_connections = join_data.get("ServerConnections")
    if isinstance(server_connections, list):
        for item in server_connections:
            if not isinstance(item, dict):
                continue
            host = item.get("Address") or item.get("address")
            raw_port = item.get("Port") or item.get("port")
            try:
                raw_port = int(raw_port)
            except (TypeError, ValueError):
                continue
            if host and not any(x["host"] == str(host) and x["port"] == raw_port for x in candidates):
                candidates.append({"kind": "server-connection", "host": str(host), "port": raw_port})
                result.server_connections.append({"host": str(host), "port": raw_port})
    result.endpoint_candidates = candidates
    # A /v1/join-game response may already consume the one-shot Join.ashx
    # ticket.  In that case the diagnostic dereference can legitimately return
    # 404 even though the inline join data is complete; do not downgrade a
    # valid bootstrap solely because the optional claim probe was replayed.
    if join_response is not None and join_response.status_code >= 400 and not isinstance(payload.get("joinScript") if isinstance(payload, dict) else None, dict):
        result.error = f"join-script-http-{join_response.status_code}"
    else:
        result.ok = bool(result.server_ip or result.udmux_ip)
        if not result.ok:
            status = join_response.status_code if join_response is not None else response.status_code
            result.error = f"join-script-http-{status}-no-endpoint"
    return result


def read_account_presence(session) -> dict[str, Any]:
    """Read Roblox's server-side Presence record for the logged-in account.

    Presence is a read-only service from a standalone client: the game server
    sets the active place after a complete client/DataModel join.  Keeping this
    probe in the report makes it explicit whether RiftHeadless has reached
    that stage instead of inferring it from UDP liveness alone.
    """
    try:
        user_response = session.get(
            "https://users.roblox.com/v1/users/authenticated",
            timeout=12,
        )
        user_status = user_response.status_code
        if not isinstance(user_status, int) or user_status != 200:
            return {"ok": False, "status_code": int(user_status) if isinstance(user_status, int) else None}
        user = user_response.json()
        if not isinstance(user, dict) or not isinstance(user.get("id"), (int, str)):
            return {"ok": False, "status_code": user_status}
        user_id = int(user.get("id"))
        response = session.post(
            "https://presence.roblox.com/v1/presence/users",
            json={"userIds": [user_id]},
            timeout=12,
        )
        response_status = response.status_code
        if not isinstance(response_status, int):
            return {"ok": False, "status_code": None}
        payload = response.json() if isinstance(response.content, (bytes, bytearray, str)) and response.content else {}
        entries = payload.get("userPresences") if isinstance(payload, dict) else None
        entry = entries[0] if isinstance(entries, list) and entries else {}
        return {
            "ok": response_status == 200,
            "status_code": response_status,
            "user_id": user_id,
            "username": str(user.get("name") or ""),
            "user_presence_type": entry.get("userPresenceType"),
            "last_location": entry.get("lastLocation"),
            "place_id": entry.get("placeId"),
            "root_place_id": entry.get("rootPlaceId"),
            "universe_id": entry.get("universeId"),
            "game_id": entry.get("gameId"),
        }
    except (OSError, ValueError, TypeError, AttributeError):
        return {"ok": False, "error": "presence-query-failed"}


class RakNetClient:
    """Small RakNet offline handshake + liveness client.

    Application authentication and replication are versioned adapters. This
    class intentionally stops after the handshake and records packet liveness.
    """

    def __init__(self, host: str, port: int, mtu: int = 1492, timeout: float = 2.0, session_context=None, udmux_header: bytes | None = None, request2_config: dict[str, Any] | None = None, established_host: str | None = None, established_port: int | None = None, established_header: bytes | None = None):
        self.host, self.port, self.mtu, self.timeout = host, port, mtu, timeout
        self.established_host = established_host or host
        self.established_port = int(established_port or port)
        self.sock: socket.socket | None = None
        self.session_context = session_context
        self.udmux_header = bytes(udmux_header or b"")
        self.established_route_header = bytes(established_header or b"")
        self.request2_config = request2_config
        self.established_header = b""
        self.app_connection_sent = False
        self.new_incoming_connection_sent = False
        self.datagram_sequence = 0
        self.guid = int(getattr(session_context, "client_guid", 0) or random.getrandbits(64))
        if session_context is not None:
            session_context.client_guid = self.guid
        self.open_reply1 = None
        self._authenticated_at: float | None = None
        self._established_tx_counter = COUNTER_BASE
        self._established_rx_state: dict[str, dict[str, Any]] = {}
        self._reliability = ReliabilityWindow()
        self._next_split_id = random.getrandbits(16)
        self._outbound_datagrams: dict[int, bytes] = {}
        self._outbound_messages: dict[int, int] = {}
        self._last_lifecycle_at = 0.0
        self._last_physics_at = 0.0
        self._last_replication_ping_at = 0.0
        self._first_replication_ping_at: float | None = None
        self._last_isr_timestamp_at = 0.0
        self._last_isr_timestamp_batch_at = 0.0
        self._last_marker: int | None = None
        self._progress_tokens: set[int] = set()
        self._replication = ReplicatorState()
        self._application_bootstrap_sent = False
        if isinstance(request2_config, dict):
            lifecycle_cfg = request2_config.get("lifecycle")
            identity = request2_config.get("identity") if isinstance(request2_config.get("identity"), dict) else {}
            self._replication.configure(lifecycle_cfg if isinstance(lifecycle_cfg, dict) else None,
                                        user_id=identity.get("user_id"), username=identity.get("username"))
        # Optional profile-owned lifecycle serializers.  The transport never
        # guesses these payloads; a profile may provide exact hex spans when
        # a build's PlayerReady/avatar schema is known.
        self._lifecycle_sent: set[str] = set()
        self.stats = {"sent": 0, "received": 0, "pongs": 0, "open_reply_1": 0, "open_reply_2": 0, "rbx_reply_1": 0, "rbx_reply_2": 0, "request2_sent": 0, "request2_error": None, "request2_length": 0, "app_connection_request_sent": 0, "app_connection_request_error": None, "session_header_updated": False, "connected_frames": 0, "unknown": 0, "rtt_ms": [], "packet_ids": {}, "inner_packet_ids": {}, "trace": []}
        self.stats.update({"established_decrypt_ok": 0, "established_decrypt_failures": 0,
                           "replication_packets": 0, "ack_packets": 0,
                           "player_instance_observed": False, "submit_ticket_sent": False,
                           "new_incoming_connection_sent": False,
                           "connection_request_sent": False, "connection_accepted": False,
                           "avatar_data_observed": False, "heartbeat_packets": 0,
                           "physics_packets": 0, "player_ready_sent": 0,
                           "avatar_description_sent": 0, "physics_sent": 0,
                           "application_bootstrap_sent": False})

    @staticmethod
    def _profile_int(value: Any, default: int = 0) -> int:
        if value is None:
            return int(default)
        return int(value, 0) if isinstance(value, str) else int(value)

    def _send_application_bootstrap(self, dictionary_packet: bytes) -> None:
        """Answer server 0x93 with the current profile's 0x90/92/8A/8F set."""
        if self._application_bootstrap_sent:
            return
        cfg = self.request2_config or {}
        app = cfg.get("application")
        material = cfg.get("session_material")
        if not isinstance(app, dict) or material is None:
            self.stats["application_bootstrap_error"] = "missing-application-profile-or-session-material"
            return
        try:
            from application_bootstrap import (
                build_placeid_verification, build_preferred_spawn_name,
                build_protocol_sync, build_submit_ticket, parse_dictionary_format,
                project_join_data, summarize_join_data_projection,
            )
            from application_crypto import generate_ticket_hash

            dictionary = parse_dictionary_format(dictionary_packet)
            offered = [name for name, _ in dictionary["entries"]]
            preferred = list(app.get("requested_flags") or ())
            # Preserve the native build order but remain forward compatible
            # with a server that adds a dictionary entry.
            requested_flags = [name for name in preferred if name in offered]
            requested_flags.extend(name for name in offered if name not in requested_flags)
            version_ids = tuple(self._profile_int(value) for value in app["version_ids"])
            join_data = project_join_data(material)
            client_ticket = str(getattr(material, "client_ticket", "") or "")
            session_id = str(getattr(material, "session_id_json", "") or "")
            player_id = int(join_data.get("UserId") or 0)
            if not client_ticket or not session_id or not player_id:
                raise ValueError("join response is missing ClientTicket, SessionId, or UserId")
            platform_key = self._profile_int(app.get("platform_security_key"))
            ticket_hash = generate_ticket_hash(client_ticket, platform_key)
            packets = (
                build_protocol_sync(
                    requested_flags=requested_flags,
                    join_data=join_data,
                    version_ids=version_ids,
                    schema_version=self._profile_int(app.get("schema_version"), 36),
                    int2=self._profile_int(app.get("protocol_sync_int2"), 1),
                    int1=self._profile_int(app.get("protocol_sync_int1"), 3),
                    profile_byte=self._profile_int(app.get("protocol_sync_profile_byte"), 0x0E),
                ),
                build_placeid_verification(
                    profile_value=self._profile_int(app.get("place_verification_profile"), 0x5860DBFE)
                ),
                build_submit_ticket(
                    place_id=self._profile_int(cfg.get("place_id")),
                    version_ids=version_ids,
                    player_id=player_id,
                    client_ticket=client_ticket,
                    security_key=str(app.get("security_key") or ""),
                    platform=str(app.get("platform") or "Android"),
                    product_name=str(app.get("product_name") or "?"),
                    ticket_hash=ticket_hash,
                    session_id=session_id,
                    protocol_version=self._profile_int(app.get("schema_version"), 36),
                    luau_response=self._profile_int(app.get("luau_response"), 0),
                    golden_hash=self._profile_int(app.get("golden_hash"), 0xC001CAFE),
                ),
                build_preferred_spawn_name(app.get("preferred_spawn_name", "")),
            )
            for packet in packets:
                self._send_reliable(packet, channel=0)
            self._application_bootstrap_sent = True
            self.stats["application_bootstrap_sent"] = True
            self.stats["application_packet_ids_sent"] = [f"0x{packet[0]:02x}" for packet in packets]
            self.stats["application_dictionary_entries"] = len(offered)
            self.stats["application_requested_flags"] = len(requested_flags)
            self.stats["join_data_projection"] = summarize_join_data_projection(material)
            self.stats["submit_ticket_sent"] = True
            self.stats.pop("application_bootstrap_error", None)
        except (KeyError, OSError, TypeError, ValueError) as exc:
            self.stats["application_bootstrap_error"] = f"{type(exc).__name__}:{exc}"

    def _handle_application_message(self, payload: bytes) -> None:
        """Advance the small client-side application bootstrap state machine."""
        if not payload:
            return
        ident = payload[0]
        trace = self.stats.setdefault("application_trace", [])
        if len(trace) < 64:
            item = {"id": f"0x{ident:02x}", "length": len(payload),
                    "prefix": payload[:32].hex()}
            # The challenge blob is needed for offline evaluator regression.
            if ident == 0x9B and len(payload) <= 8192:
                item["hex"] = payload.hex()
            trace.append(item)
        if ident == 0x93:
            self._send_application_bootstrap(payload)
            return
        if ident == 0x84:
            try:
                marker = parse_marker(payload)
                # MarkerItem is a fixed-width echo.  Other queued replication
                # items may be coalesced by the native client, but they are
                # independent of this acknowledgement.
                cfg = self.request2_config or {}
                lifecycle = cfg.get("lifecycle") if isinstance(cfg.get("lifecycle"), dict) else {}
                isr_values = lifecycle.get("isr_timestamp_values") or []
                try:
                    first_isr = int(isr_values[0]) if isr_values else None
                except (TypeError, ValueError, IndexError):
                    first_isr = None
                if lifecycle.get("isr_timestamp_enabled", False) and first_isr is not None:
                    self._send_reliable(build_marker_isr(marker, first_isr), channel=0)
                    self.stats["marker_isr_sent"] = self.stats.get("marker_isr_sent", 0) + 1
                else:
                    self._send_reliable(build_marker_echo(marker), channel=0)
                self._last_marker = marker
                self.stats["marker_received"] = self.stats.get("marker_received", 0) + 1
                self.stats["marker_echo_sent"] = self.stats.get("marker_echo_sent", 0) + 1
                self.stats["last_marker"] = marker
                self.stats.pop("marker_error", None)
                # A transport-only client has no native local Player object.
                # Keep this request opt-in: sending a zero-feature request on
                # every marker creates an invalid reliable item and can make
                # the server withdraw Presence even though the session is
                # otherwise authenticated.
                if lifecycle.get("request_character_after_marker", False):
                    # The native item is queued only after a local Player has
                    # been created.  A headless transport has no DataModel
                    # Player object, so keep this opt-in rather than sending
                    # a malformed zero-feature request on every join.
                    if not lifecycle.get("request_character_require_local_player", False):
                        request = build_request_character(
                            int(lifecycle.get("request_character_feature_mask", 0)),
                            str(lifecycle.get("request_character_spawn_name", "")),
                        )
                        self._send_reliable(request, channel=0)
                        self.stats["request_character_sent"] = self.stats.get("request_character_sent", 0) + 1
            except (OSError, TypeError, ValueError) as exc:
                self.stats["marker_error"] = f"{type(exc).__name__}:{exc}"
            return
        if ident == 0x83:
            try:
                token = parse_progress_token(payload)
                if token not in self._progress_tokens:
                    self._send_reliable(build_progress_ack(token), channel=0)
                    self._progress_tokens.add(token)
                    self.stats["progress_ack_sent"] = self.stats.get("progress_ack_sent", 0) + 1
                    self.stats["last_progress_token"] = token
            except ValueError:
                pass
            return
        if ident == 0x9B and len(payload) >= 13:
            self.stats["challenge_received"] = self.stats.get("challenge_received", 0) + 1
            self.stats["challenge_script_bytes"] = int.from_bytes(payload[9:13], "little")
            try:
                cfg = self.request2_config or {}
                app = cfg.get("application") if isinstance(cfg.get("application"), dict) else {}
                game_id = str(cfg.get("game_id") or "")
                if not game_id:
                    raise ValueError("missing GameId for challenge evaluator")
                started = time.monotonic()
                if os.environ.get("RIFT_CHALLENGE_RESPONSE_ZERO") == "1":
                    challenge_id = int.from_bytes(payload[5:9], "little")
                    response = b"\x9b" + struct.pack("<II", challenge_id, 0)
                    mode = "diagnostic-zero"
                else:
                    from application_challenge import solve_challenge_packet_0738
                    response = solve_challenge_packet_0738(
                        payload,
                        game_id,
                        environment_fixed=self._profile_int(
                            app.get("challenge_environment_fixed"), 14259
                        ),
                    )
                    mode = "rsb1-luau"
                self._send_reliable(response, channel=0)
                self.stats["challenge_response_sent"] = True
                self.stats["challenge_response_mode"] = mode
                self.stats["challenge_solve_ms"] = round(
                    (time.monotonic() - started) * 1000.0, 3
                )
                self.stats.pop("challenge_response_error", None)
            except (OSError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError) as exc:
                self.stats["challenge_response_error"] = f"{type(exc).__name__}:{exc}"

    def _profile_payload(self, name: str) -> bytes | None:
        """Read one opt-in lifecycle payload from the active profile."""
        cfg = self.request2_config or {}
        lifecycle = cfg.get("lifecycle") if isinstance(cfg.get("lifecycle"), dict) else cfg
        value = lifecycle.get(name) if isinstance(lifecycle, dict) else None
        if value is None:
            return None
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        if isinstance(value, str):
            text = re.sub(r"[^0-9a-fA-F]", "", value)
            if len(text) % 2:
                raise ValueError(f"{name} hex has odd length")
            return bytes.fromhex(text)
        raise TypeError(f"{name} must be bytes or hex")

    def _send_profile_message(self, name: str) -> bool:
        """Send a caller-supplied lifecycle payload once per connection."""
        if name in self._lifecycle_sent:
            return False
        payload = self._profile_payload(name)
        if not payload:
            return False
        self._send_reliable(payload, channel=0)
        self._lifecycle_sent.add(name)
        self.stats[f"{name}_sent"] = self.stats.get(f"{name}_sent", 0) + 1
        return True

    def _send_reliable(self, payload: bytes, *, channel: int = 0,
                       ordered: bool = True, track: bool = True) -> int:
        """Send and track one reliable established RakNet payload."""
        if track:
            max_payload = int((self.request2_config or {}).get("raknet_fragment_payload", 1024))
            if len(payload) > max_payload:
                frames = self._reliability.track_split(
                    bytes(payload), max_payload, ordered=ordered, channel=channel,
                    split_id=self._next_split_id)
                self._next_split_id = (self._next_split_id + 1) & 0xFFFF
                self.stats["split_messages_sent"] = self.stats.get("split_messages_sent", 0) + 1
                self.stats["split_fragments_sent"] = self.stats.get("split_fragments_sent", 0) + len(frames)
            else:
                frames = [self._reliability.track(bytes(payload), ordered=ordered, channel=channel)]
        else:
            # Connected liveness pings are idempotent and the official client
            # does not retain them in the application resend window.
            from raknet_codec import EncapsulatedFrame
            frames = [EncapsulatedFrame(bytes(payload), True, ordered,
                                        self.datagram_sequence & 0xFFFFFF,
                                        self.datagram_sequence & 0xFFFFFF, channel)]
        first_sequence = self.datagram_sequence & 0xFFFFFF
        for frame in frames:
            sequence = self.datagram_sequence & 0xFFFFFF
            self.datagram_sequence = (self.datagram_sequence + 1) & 0xFFFFFF
            datagram = b"\x80" + sequence.to_bytes(3, "little") + frame.encode()
            self._send_established(datagram)
            if track:
                self._outbound_datagrams[sequence] = datagram
                self._outbound_messages[sequence] = int(frame.message_index)
        # Bound the datagram cache independently from the message window.
        while len(self._outbound_datagrams) > 4096:
            old = next(iter(self._outbound_datagrams))
            self._outbound_datagrams.pop(old, None)
            self._outbound_messages.pop(old, None)
        return first_sequence

    def _send_unreliable(self, payload: bytes, *, datagram_flag: int = 0x80) -> int:
        """Send one untracked RakNet frame without consuming message/order ids."""
        sequence = self.datagram_sequence & 0xFFFFFF
        self.datagram_sequence = (self.datagram_sequence + 1) & 0xFFFFFF
        frame = EncapsulatedFrame(bytes(payload), reliable=False, ordered=False)
        self._send_established(bytes((datagram_flag & 0x8F,))
                               + sequence.to_bytes(3, "little") + frame.encode())
        return sequence

    def _send_new_incoming_connection(self, accepted: bytes) -> None:
        """Complete RakNet connection setup before application replication."""
        if self.new_incoming_connection_sent:
            return
        now_ms = int(time.monotonic() * 1000) & 0xFFFFFFFFFFFFFFFF
        payload = build_new_incoming_connection(
            accepted, self.established_host, self.established_port,
            now_ms, time.time_ns() // 1_000)
        frame = self._reliability.track(payload, ordered=True, channel=0)
        ping = EncapsulatedFrame(build_connected_ping(now_ms), reliable=False,
                                 ordered=False)
        sequence = self.datagram_sequence & 0xFFFFFF
        self.datagram_sequence = (self.datagram_sequence + 1) & 0xFFFFFF
        datagram = b"\x81" + sequence.to_bytes(3, "little") + frame.encode() + ping.encode()
        self._send_established(datagram)
        self._outbound_datagrams[sequence] = datagram
        self._outbound_messages[sequence] = int(frame.message_index)
        self.new_incoming_connection_sent = True
        self.stats["new_incoming_connection_sent"] = True

    def _send_connected_pong(self, ping: bytes) -> None:
        now_ms = int(time.monotonic() * 1000) & 0xFFFFFFFFFFFFFFFF
        self._send_unreliable(build_connected_pong(ping, now_ms,
                                                   time.time_ns() // 1_000))
        self.stats["connected_pong_sent"] = self.stats.get("connected_pong_sent", 0) + 1

    def _apply_ack(self, plaintext: bytes) -> None:
        try:
            sequences = parse_ack(plaintext)
        except ValueError:
            return
        for sequence in sequences:
            self._outbound_datagrams.pop(int(sequence), None)
            message_index = self._outbound_messages.pop(int(sequence), None)
            if message_index is not None:
                self._reliability.acknowledge(int(message_index))
        # RakNet ACKs acknowledge datagrams.  Our current one-frame-per-
        # datagram sender uses the same sequence/message index monotonically,
        # so advance both windows together.
        self.stats["acks_applied"] = self.stats.get("acks_applied", 0) + len(sequences)

    def _resend_due(self) -> None:
        """Retransmit expired reliable frames while preserving message ids."""
        for pending in self._reliability.due():
            if pending.attempts > 3:
                self.stats["reliable_retry_exhausted"] = self.stats.get("reliable_retry_exhausted", 0) + 1
                continue
            sequence = self.datagram_sequence & 0xFFFFFF
            self.datagram_sequence = (self.datagram_sequence + 1) & 0xFFFFFF
            datagram = b"\x80" + sequence.to_bytes(3, "little") + pending.frame.encode()
            self._send_established(datagram)
            self._outbound_datagrams[sequence] = datagram
            self._outbound_messages[sequence] = int(pending.frame.message_index)
            self.stats["reliable_resends"] = self.stats.get("reliable_resends", 0) + 1

    def _send_lifecycle_profile(self) -> None:
        """Advance optional PlayerReady/avatar gates after registration."""
        if not self._replication.replicator_registered:
            return
        # Ordering mirrors the server lifecycle: ready, then avatar data.
        self._send_profile_message("player_ready")
        self._send_profile_message("avatar_description")
        # One profile-defined physics sample establishes the movement gate;
        # callers that need a continuous stream can invoke ``send_physics``
        # on their own cadence without coupling it to the receive loop.
        self._send_profile_message("physics")
        self._last_lifecycle_at = time.monotonic()
        self._last_physics_at = self._last_lifecycle_at

    def _service_lifecycle(self) -> None:
        """Maintain heartbeat, retransmission and minimal physics cadence."""
        if not self.stats.get("authenticated"):
            return
        self._resend_due()
        if not self._replication.replicator_registered:
            return
        now = time.monotonic()
        cfg = self.request2_config or {}
        lifecycle = cfg.get("lifecycle") if isinstance(cfg.get("lifecycle"), dict) else {}
        heartbeat_interval = float(lifecycle.get("heartbeat_interval", 1.0) or 1.0)
        replication_ping_interval = float(lifecycle.get("replication_ping_interval", 10.0) or 10.0)
        replication_ping_start_delay = float(lifecycle.get("replication_ping_start_delay", 6.5) or 6.5)
        physics_interval = float(lifecycle.get("physics_interval", 0.25) or 0.25)
        if now - self._last_lifecycle_at >= max(0.1, heartbeat_interval):
            payload = self._profile_payload("heartbeat")
            if payload:
                self._send_reliable(payload, channel=0)
                self.stats["profile_heartbeat_sent"] = self.stats.get("profile_heartbeat_sent", 0) + 1
            self._last_lifecycle_at = now
        authenticated_age = now - (self._authenticated_at or now)
        # The PingItem pair is only safe when its exact build-specific fields
        # are known.  A guessed pair can make the server remove the account
        # from Presence even while AEAD/RakNet remains healthy.
        if lifecycle.get("replication_ping_enabled", False):
            ping_due = (self._last_replication_ping_at == 0.0 or
                        now - self._last_replication_ping_at >= max(1.0, replication_ping_interval))
            if authenticated_age >= max(1.0, replication_ping_start_delay) and ping_due:
                self._send_replication_ping_pair()
        # 0.738 uses a small fixed ISR checkpoint sequence, not a running
        # millisecond counter.  Sending guessed values repeatedly makes the
        # server revoke Presence, so emit the captured sequence once.
        if lifecycle.get("isr_timestamp_enabled", False):
            isr_start = float(lifecycle.get("isr_timestamp_start_delay", 20.0) or 20.0)
            isr_interval = float(lifecycle.get("isr_timestamp_batch_interval", 20.0) or 20.0)
            values = lifecycle.get("isr_timestamp_values") or []
            batch_due = (self._last_isr_timestamp_batch_at == 0.0 or
                         now - self._last_isr_timestamp_batch_at >= max(5.0, isr_interval))
            if authenticated_age >= max(1.0, isr_start) and batch_due and values:
                for value in values:
                    self._send_reliable(build_isr_timestamp(int(value)), channel=0)
                    self.stats["isr_timestamp_sent"] = self.stats.get("isr_timestamp_sent", 0) + 1
                self._last_isr_timestamp_batch_at = now
                self._last_isr_timestamp_at = now
        if now - self._last_physics_at >= max(0.05, physics_interval):
            payload = self._profile_payload("physics")
            if payload:
                self._send_reliable(payload, channel=0)
                self.stats["physics_sent"] = self.stats.get("physics_sent", 0) + 1
            self._last_physics_at = now

    def _send(self, packet: bytes) -> None:
        assert self.sock is not None
        self.sock.sendto(packet, (self.host, self.port))
        self.stats["sent"] += 1

    def _send_established_wire(self, packet: bytes) -> None:
        """Send post-Reply2 traffic to the advertised gameplay endpoint."""
        assert self.sock is not None
        self.sock.sendto(packet, (self.established_host, self.established_port))
        self.stats["sent"] += 1

    def _recv_until(self, deadline: float) -> list[bytes]:
        out: list[bytes] = []
        assert self.sock is not None
        while time.monotonic() < deadline:
            remaining = max(0.01, deadline - time.monotonic())
            self.sock.settimeout(remaining)
            try:
                data, _ = self.sock.recvfrom(65535)
            except socket.timeout:
                break
            self.stats["received"] += 1
            if data:
                pid = f"0x{data[0]:02x}"
                self.stats["packet_ids"][pid] = self.stats["packet_ids"].get(pid, 0) + 1
                frame = None
                try:
                    frame = decode_udmux(data)
                except ValueError:
                    pass
                inner = frame.payload if frame is not None and frame.payload else unwrap_inner(data)
                if inner is not data and inner:
                    inner_pid = f"0x{inner[0]:02x}"
                    self.stats["inner_packet_ids"][inner_pid] = self.stats["inner_packet_ids"].get(inner_pid, 0) + 1
                self._observe_session_frame(frame, inner)
                if frame is not None and frame.is_control and inner:
                    observed = self._replication.observe_control(inner)
                    if observed.get("accepted"):
                        self.stats["connection_accepted"] = True
                if (frame is not None and frame.subflag == 2
                        and self.stats.get("authenticated")
                        and not bytes(frame.payload or b"").startswith(b"\x7d" + MAGIC)):
                    self._try_decrypt_established(frame, data)
                # After Reply2 the server emits a clear 0x19 control record.
                # It proves the route is live, but it is not a decrypted
                # replication heartbeat and therefore must stay separate
                # from the five lifecycle gates.
                if (self.stats.get("authenticated") and inner
                        and inner[0] == 0x19):
                    self.stats["control_0x19_received"] = self.stats.get("control_0x19_received", 0) + 1
                # Established UDMUX payloads are opaque until AEAD succeeds;
                # direct connected datagrams can still expose reliable frames.
                if frame is None and data and 0x80 <= data[0] <= 0x8F:
                    try:
                        _seq, frames = parse_connected_datagram(data)
                        self.stats["connected_frames"] = self.stats.get("connected_frames", 0) + len(frames)
                    except ValueError:
                        self.stats["unknown"] += 1
                # A bounded header trace makes endpoint/protocol failures
                # diagnosable without persisting account or session material.
                if len(self.stats["trace"]) < 64:
                    item = {"id": pid, "length": len(data), "prefix": data[:8].hex()}
                    # Keep a bounded local hex snapshot for Reply2 layout
                    # diagnostics; this is required to distinguish clear
                    # marker placement from an AEAD framing mismatch.
                    if inner and len(data) <= 512 and (inner[:1] in (b"\x7d", b"\x78", b"\x19") or self.stats.get("authenticated")):
                        item["hex"] = data.hex()
                    self.stats["trace"].append(item)
            out.append(data)
        return out

    def _observe_session_frame(self, frame, inner: bytes) -> None:
        """Validate Reply2 when a same-session AEAD key is available."""
        if (frame is not None and frame.record_type == 1 and frame.subflag == 2
                and bytes(frame.payload or b"").startswith(b"\x7d" + MAGIC)):
            self._try_decrypt_session_frame(frame)
            if (not self.stats.get("authenticated") and
                    bytes(frame.payload or b"").startswith(b"\x7d" + MAGIC)):
                self.stats["reply2_unverified_candidates"] = self.stats.get("reply2_unverified_candidates", 0) + 1
            return
        if not inner or inner[0] != 0x7D:
            return
        if (frame is None or frame.record_type != 1 or frame.subflag != 2
                or not inner.startswith(b"\x7d" + MAGIC)):
            return
        # Clear marker/magic can identify a candidate, not its authenticity.
        # Do not promote the epoch or send plaintext application data until
        # the encrypted exchange and subsequent framing are verified.
        self.stats["reply2_unverified_candidates"] = self.stats.get("reply2_unverified_candidates", 0) + 1

    def _try_decrypt_session_frame(self, frame) -> None:
        """Attempt the confirmed 0.738 ``AAD || ciphertext`` envelope.

        A failed MAC is deliberately ignored: encrypted gameplay frames are
        not promoted to Reply2 or replication until authentication succeeds.
        """
        cfg = self.request2_config or {}
        # Request2 is direction-specific: the client encrypts the outbound
        # body with ``session_key`` while the server Reply2 uses the paired
        # digest half.  Older code only tried the outbound half, which made a
        # valid Reply2 look like a MAC failure and forced the structural
        # fallback.  Try the advertised pair in deterministic order and
        # promote only after the envelope authenticates.
        keys = []
        for name in ("session_key_alt", "session_key"):
            value = cfg.get(name)
            if value and bytes(value) not in keys:
                keys.append(bytes(value))
        payload = bytes(frame.payload or b"")
        if not keys or len(payload) < 21 + 28:
            return
        clear = None
        for key in keys:
            try:
                from session_crypto import decrypt_reply2
                clear = decrypt_reply2(key, payload, magic=MAGIC)
                break
            except Exception:
                continue
        if clear is None:
            self.stats["session_decrypt_failures"] = self.stats.get("session_decrypt_failures", 0) + 1
            # A marker/magic/nonce shape is only a candidate.  Never promote
            # it to an authenticated session without a valid AEAD tag.
            self.stats["reply2_auth_required"] = True
            return
        # Reply2 rotates from the open-exchange ChaCha keys to a fresh
        # X25519/BLAKE2b pair used by established AES-GCM traffic.  The
        # 32-byte server key begins at offset 21 and crosses the AAD/body
        # boundary, so derive it only after the Reply2 tag is verified.
        if self.session_context is not None:
            try:
                from session_crypto import derive_established_key_pair, reply2_established_public
                private = self.session_context._client_ephemeral_private.private_bytes_raw()
                client_public = bytes(
                    cfg.get("request2_public_key")
                    or getattr(self.session_context, "request2_public_key", None)
                    or self.session_context.client_ephemeral_public_key
                )
                server_public = reply2_established_public(payload, clear, magic=MAGIC)
                tx_key, rx_key = derive_established_key_pair(
                    client_private=private,
                    client_public=client_public,
                    server_public=server_public,
                )
                cfg.update({
                    "established_tx_key": tx_key,
                    "established_rx_key": rx_key,
                    "established_tx_keys": [tx_key],
                    "established_rx_keys": [rx_key],
                    "established_cipher": "chacha20-poly1305",
                })
                self.request2_config = cfg
                self.stats["established_keys_derived"] = True
                self.stats.pop("established_key_derivation_error", None)
            except (AttributeError, TypeError, ValueError) as exc:
                self.stats["established_keys_derived"] = False
                self.stats["established_key_derivation_error"] = f"{type(exc).__name__}:{exc}"
                return
        self._promote_reply2(frame, len(clear))

    def _try_decrypt_established(self, frame, packet: bytes) -> None:
        """Decode post-Reply2 DATA/ACK when a profile provides live keys.

        Request2's key authenticates only the open exchange. Established
        RakNet traffic uses separate direction keys, so this path stays
        dormant until the current join profile supplies them.
        """
        cfg = self.request2_config or {}
        # Direction is encoded by header size: the server stream is 0x17 and
        # the client stream is 0x1f.  Keep a counter/epoch anchor per stream;
        # the wire only carries the low 16 bits of the nonce counter.
        key_name = "established_rx_key" if frame.header_size == 0x17 else "established_tx_key"
        epoch_hex = bytes(frame.header[3:19]).hex() if len(frame.header) >= 19 else ""
        state_key = f"{frame.header_size}:{epoch_hex}"
        prior = self._established_rx_state.get(state_key)
        last_counter = prior.get("last_counter") if prior else None
        key = cfg.get(key_name) or cfg.get("established_key")
        # A re-key trace may provide an epoch-keyed map or an ordered list.
        # Prefer the current header epoch, then fall back to the supplied
        # direction key(s) so old profiles remain compatible.
        keyring = cfg.get("established_keyring")
        candidates = []
        if isinstance(keyring, dict) and epoch_hex in keyring:
            candidates.append(keyring[epoch_hex])
        listed = cfg.get(key_name + "s")
        if isinstance(listed, (list, tuple)):
            candidates.extend(listed)
        if key:
            candidates.append(key)
        normalized = []
        for item in candidates:
            try:
                value = bytes(item)
            except (TypeError, ValueError):
                continue
            if value and value not in normalized:
                normalized.append(value)
        candidates = normalized
        if not candidates:
            self.stats["established_key_missing"] = self.stats.get("established_key_missing", 0) + 1
            return
        try:
            from established_aead import decrypt_datagram
            plaintext, counter, _ = decrypt_datagram(
                packet, candidates,
                cipher=str(cfg.get("established_cipher", "aes-256-gcm")),
                span=64, last_counter=last_counter,
                aad_candidates=cfg.get("established_aad_candidates"))
            self._established_rx_state[state_key] = {
                "epoch": epoch_hex, "last_counter": int(counter),
                "direction": int(frame.header_size),
            }
            self.stats["established_decrypt_ok"] += 1
            self.stats["connected_frames"] += 1
            self.stats["established_last_counter"] = int(counter)
            self.stats["established_epoch"] = epoch_hex or None
            trace = self.stats.setdefault("decrypted_trace", [])
            if len(trace) < 64:
                trace.append({"direction": "in", "counter": int(counter), "length": len(plaintext),
                              "hex": plaintext[:4096].hex()})
            if plaintext and plaintext[0] & 0x80:
                parsed = self._replication.apply(plaintext)
                self.stats["last_inner_type"] = parsed.get("kind", "DATA")
                if parsed.get("kind") == "data":
                    self.stats["replication_packets"] += 1
                    for message in parsed.get("complete_messages", parsed.get("messages", ())):
                        app_payload = bytes(message.get("payload") or b"")
                        if not app_payload:
                            continue
                        if app_payload[0] == 0x10:
                            self._send_new_incoming_connection(app_payload)
                        elif app_payload[0] == 0x00 and len(app_payload) >= 9:
                            self._send_connected_pong(app_payload)
                        else:
                            self._handle_application_message(app_payload)
                    self.stats["replicator_registered"] = self._replication.replicator_registered
                    self.stats["player_instance_observed"] = self._replication.player_instance_observed
                    self.stats["character_spawn_observed"] = self._replication.character_spawn_observed
                    self.stats["observer_visibility_verified"] = self._replication.observer_visibility_verified
                    self.stats["connection_accepted"] = self._replication.connection_accepted
                    self.stats["avatar_data_observed"] = self._replication.avatar_data_observed
                    self.stats["heartbeat_packets"] = self._replication.heartbeat_packets
                    self.stats["physics_packets"] = self._replication.physics_packets
                    snapshot = self._replication.snapshot()
                    self.stats["replication_snapshot"] = snapshot
                    self.stats["heartbeat_seconds"] = max(
                        float(snapshot.get("heartbeat_span_seconds") or 0.0),
                        float(self.stats.get("heartbeat_seconds") or 0.0),
                    )
                    self._send_lifecycle_profile()
                    # Reliable RakNet DATA must be acknowledged before the
                    # server advances its replication window.  Only emit an
                    # ACK after AEAD authentication and successful parsing.
                    try:
                        self._send_established(build_ack(int(parsed["sequence"])))
                        self.stats["ack_sent"] = self.stats.get("ack_sent", 0) + 1
                    except (KeyError, OSError, TypeError, ValueError):
                        self.stats["ack_send_failures"] = self.stats.get("ack_send_failures", 0) + 1
                elif parsed.get("kind") == "ack":
                    self.stats["ack_packets"] += 1
                    self._apply_ack(plaintext)
            elif plaintext and plaintext[0] in (0xC0, 0xD0, 0xA0, 0xB0):
                self.stats["ack_packets"] += 1
                self._apply_ack(plaintext)
        except Exception as exc:
            self.stats["established_decrypt_failures"] += 1
            self.stats["established_last_error"] = f"{type(exc).__name__}:{exc}"

    def _promote_reply2(self, frame, clear_bytes: int) -> None:
        """Promote a server Reply2 after its full envelope is observed."""
        if self.stats.get("authenticated"):
            return
        self.stats["rbx_reply_2"] += 1
        self.stats["authenticated"] = True
        self._authenticated_at = time.monotonic()
        self.established_header = bytes(frame.header)
        # Reply2 carries the fresh server epoch in a 19-byte (0x17) header.
        # The client-direction stream keeps the route/mux suffix from the
        # original 31-byte Request1 header, producing the 0x1f header used by
        # the first established DATA packet.
        if len(frame.header) == 19 and len(self.udmux_header) == 27:
            self.established_route_header = bytes(frame.header) + self.udmux_header[19:27]
        self.stats["session_header_updated"] = True
        self.stats["reply2_clear_bytes"] = int(clear_bytes)
        if not self.app_connection_sent:
            self._send_app_connection_request()

    def _send_app_connection_request(self) -> None:
        """Send the standard reliable ``ID_CONNECTION_REQUEST`` after Reply2."""
        try:
            cfg = self.request2_config or {}
            identity = bytes(cfg.get("connection_request_identity") or b"")
            payload = build_app_connection_request(
                self.guid, int(time.monotonic() * 1000) & 0xFFFFFFFFFFFFFFFF, identity)
            frame = self._reliability.track(bytes(payload), ordered=False, channel=0)
            sequence = self.datagram_sequence & 0xFFFFFF
            self.datagram_sequence = (self.datagram_sequence + 1) & 0xFFFFFF
            plaintext = b"\x81" + sequence.to_bytes(3, "little") + frame.encode()
            key = cfg.get("established_tx_key") or cfg.get("session_key")
            # This transition packet is sent on the original subflag-01
            # Request2 epoch.  The next packet switches to the Reply2 epoch
            # assembled by _promote_reply2.
            header = bytes(self.udmux_header or self._tx_established_header())
            if key and len(header) in (19, 27) and header[:3] in (b"\x01\x11\x01", b"\x01\x11\x02"):
                packet = encrypt_datagram(header, plaintext, bytes(key),
                                          self._established_tx_counter,
                                          cipher=str(cfg.get("established_cipher", "aes-256-gcm")))
                self._established_tx_counter += 1
            else:
                packet = encode_udmux(plaintext, header=header) if header else plaintext
            self.stats["app_connection_wire_length"] = len(packet)
            self.stats.setdefault("decrypted_trace", []).append(
                {"direction": "out", "counter": int(self._established_tx_counter - 1),
                 "length": len(plaintext), "hex": plaintext.hex()})
            self.stats["app_connection_subflag"] = int(header[2]) if len(header) >= 3 else None
            self.stats["app_connection_endpoint"] = f"{self.established_host}:{self.established_port}"
            self._send_established_wire(packet)
            self._outbound_datagrams[sequence] = packet
            self._outbound_messages[sequence] = int(frame.message_index)
            self.app_connection_sent = True
            self.stats["connection_request_sent"] = True
            self.stats["app_connection_request_sent"] += 1
        except (OSError, ValueError, TypeError) as exc:
            self.stats["app_connection_request_error"] = f"{type(exc).__name__}:{exc}"

    def _tx_established_header(self) -> bytes:
        """Return the current client-direction (0x1f) established header."""
        if len(self.established_route_header) == 27:
            header = self.established_route_header
            if header[:3] == b"\x01\x11\x01":
                return header[:2] + b"\x02" + header[3:]
            if header[:3] == b"\x01\x11\x02":
                return header
        header = bytes(self.udmux_header or b"")
        if len(header) == 27 and header[:2] == b"\x01\x11":
            return b"\x01\x11\x02" + header[3:]
        # A server Reply2 header is 19 bytes (0x17 direction).  It cannot be
        # reused for client traffic; keep the explicit route template when
        # available and otherwise use the captured reply as a diagnostic-only
        # fallback.
        return bytes(self.established_header or header)

    def _send_established(self, plaintext: bytes) -> None:
        """Encode one client-direction AEAD datagram, with clear fallback."""
        cfg = self.request2_config or {}
        key = cfg.get("established_tx_key") or cfg.get("session_key")
        header = self._tx_established_header()
        if key and len(header) in (19, 27) and header[:3] == b"\x01\x11\x02":
            packet = encrypt_datagram(header, plaintext, bytes(key), self._established_tx_counter,
                                      cipher=str(cfg.get("established_cipher", "aes-256-gcm")))
            self._established_tx_counter += 1
        else:
            # Keep fixture/diagnostic mode usable when no per-session key was
            # supplied; a production join will only reach this branch when
            # the server explicitly accepts a clear profile.
            packet = encode_udmux(plaintext, header=header) if header else plaintext
        trace = self.stats.setdefault("decrypted_trace", [])
        if len(trace) < 64:
            trace.append({"direction": "out", "counter": int(self._established_tx_counter - 1),
                          "length": len(plaintext), "hex": bytes(plaintext)[:4096].hex()})
        self._send_established_wire(packet)

    def _send_connected_ping(self) -> None:
        """Send an encrypted connected ping once the RakNet peer is live."""
        self._send_unreliable(build_connected_ping(
            int(time.monotonic() * 1000) & 0xFFFFFFFFFFFFFFFF))
        self.stats["heartbeat_sent"] = self.stats.get("heartbeat_sent", 0) + 1

    def _send_replication_ping_pair(self) -> None:
        """Send the reliable/unreliable PingItem pair used by client 0.738."""
        cfg = self.request2_config or {}
        lifecycle = cfg.get("lifecycle") if isinstance(cfg.get("lifecycle"), dict) else {}
        ping = lifecycle.get("replication_ping")
        ping = ping if isinstance(ping, dict) else {}
        age = max(0.0, time.monotonic() - (self._authenticated_at or time.monotonic()))
        tick32 = int(age * 1000) & 0xFFFFFFFF
        ping_stamp = tick32
        common = {
            "clock_ms": tick32,
            "item_flags": int(ping.get("item_flags", 0x16)),
            "send_kbps": float(ping.get("send_kbps", 47.35103225708008)),
            "receive_kbps": float(ping.get("receive_kbps", 42.76241683959961)),
            "packet_loss": float(ping.get("packet_loss", 33.01939010620117)),
            "feature_mask": int(ping.get("feature_mask", 0)),
            "xor_mask": int(ping.get("xor_mask", 7)),
            "memory_mb": float(ping.get("memory_mb", 853.47265625)),
        }
        reliable = build_ping_item(ping_stamp, sample_flag=False, **common)
        memory_report = build_ping_item(ping_stamp, sample_flag=True, **common)
        frame = self._reliability.track(reliable, ordered=True, channel=0)
        other = EncapsulatedFrame(memory_report, reliable=False, ordered=False)
        sequence = self.datagram_sequence & 0xFFFFFF
        self.datagram_sequence = (self.datagram_sequence + 1) & 0xFFFFFF
        datagram = b"\x80" + sequence.to_bytes(3, "little") + frame.encode() + other.encode()
        self._send_established(datagram)
        self._outbound_datagrams[sequence] = datagram
        self._outbound_messages[sequence] = int(frame.message_index)
        now = time.monotonic()
        self._first_replication_ping_at = self._first_replication_ping_at or now
        self._last_replication_ping_at = now
        self.stats["replication_ping_pairs_sent"] = self.stats.get("replication_ping_pairs_sent", 0) + 1
        self.stats["heartbeat_seconds"] = round(
            max(0.0, now - self._first_replication_ping_at), 3
        )

    def send_physics(self, profile_payload: bytes) -> None:
        """Send one minimal, profile-encoded movement/physics update."""
        payload = build_physics_message(profile_payload)
        self._send_reliable(payload, channel=0)
        self.stats["physics_sent"] = self.stats.get("physics_sent", 0) + 1

    def _send_standard_open_request2(self, server_guid: bytes, mtu: int) -> None:
        """Send the canonical RakNet OpenConnectionRequest2 layout.

        The earlier probe accidentally placed the server GUID where the server
        address belongs and omitted the client GUID. Keeping this fallback
        correct makes the generic transport test useful without conflating it
        with Roblox's later SessionCrypto packet.
        """
        # IPv4 address encoding: version, four octets, network-order port.
        client_address = b"\x04\x7f\x00\x00\x01\x00\x00"
        packet = b"\x07" + MAGIC + client_address + struct.pack(">H", mtu) + struct.pack(">Q", self.guid)
        self._send(packet)

    def _send_encrypted_request2(self, mtu: int) -> None:
        """Send an explicitly configured 0.738 UDMUX Request2 record.

        The key, RUPP span and token are loaded from per-session artifacts by
        the caller.  Keeping this path opt-in prevents the runner from ever
        fabricating authentication material when only a join ticket is
        available.
        """
        if not self.request2_config:
            return
        if self.session_context is None or not self.udmux_header:
            self.stats["request2_error"] = "request2-requires-session-context-and-udmux-header"
            return
        try:
            from request2_adapter import build_encrypted_request2
            candidates = self.request2_config.get("request2_candidates") or [{
                "session_key": self.request2_config["session_key"],
                "rupp_aad": self.request2_config["rupp_aad"],
            }]
            # A RbxOpenRequest2 MAC is tied to a one-shot join.  Sending a
            # sweep of invalid candidates on the same session consumes that
            # session without giving later candidates a chance.  Auto mode
            # therefore sends one candidate; a diagnostic index can select a
            # different candidate on a fresh join.
            if self.request2_config.get("auto_candidate"):
                try:
                    idx = int(os.environ.get("RIFT_REQUEST2_CANDIDATE_INDEX", "0"))
                except ValueError:
                    idx = 0
                candidates = candidates[max(0, idx):max(0, idx) + 1]
            for candidate in candidates:
                # Reply2 verification must use the exact key used for this
                # fresh-join Request2 candidate.
                self.request2_config["session_key"] = candidate["session_key"]
                packet = build_encrypted_request2(
                    context=self.session_context,
                    session_key=candidate["session_key"],
                    udmux_header=self.udmux_header,
                    rupp_aad=candidate["rupp_aad"],
                    endpoint_ip=self.host,
                    endpoint_port=int(self.request2_config.get("endpoint_port") or getattr(self.session_context, "netstack_port", 0) or 0),
                    token_blob=self.request2_config["token_blob"],
                    mtu=int(mtu),
                    pad_to_mtu=bool(self.request2_config.get("pad_to_mtu", True)),
                    pad_length=self.request2_config.get("pad_length"),
                    payload_only=bool(self.request2_config.get("payload_only", False)),
                )
                self._send(packet)
                self.stats["request2_sent"] += 1
                self.stats["request2_length"] = len(packet)
                self.stats["request2_prefix_hex"] = packet[:260].hex()
        except (KeyError, TypeError, ValueError, OSError) as exc:
            self.stats["request2_error"] = f"{type(exc).__name__}:{exc}"

    def _build_open_request1(self, protocol: int, mtu: int) -> bytes:
        """Build OpenRequest1, optionally inside a captured UDMUX header.

        0.738 Android captures place the offline magic at the start of the
        UDMUX inner payload, followed by the protocol byte and a one-byte
        request marker (``05 01``).  The remainder is zero padding; the MTU
        is inferred from the complete datagram length rather than appended as
        a little field.  With a 31-byte outer header and a 1160-byte datagram
        this produces the observed 1129-byte inner payload.

        Older direct endpoints retain the traditional bare
        ``0x05 + magic + protocol + mtu:u16`` fallback.  The header is always
        caller-supplied and therefore stays fresh per session instead of
        being embedded in the profile.
        """
        if self.udmux_header:
            from udmux_codec import encode as encode_udmux
            # UDMUX's offline OpenRequest1 record uses id 0x7b inside the
            # clear envelope (the subsequent request2 uses id 0x78).  The
            # capture is: 7b + MAGIC + protocol(05) + marker(01) + zeros.
            inner_prefix = b"\x7b" + MAGIC + bytes((protocol, 0x01))
            outer_header_size = 4 + len(self.udmux_header)
            target_datagram = min(int(mtu), int(self.mtu))
            minimum_datagram = outer_header_size + len(inner_prefix)
            target_datagram = max(target_datagram, minimum_datagram)
            inner = inner_prefix + b"\x00" * (target_datagram - outer_header_size - len(inner_prefix))
            return encode_udmux(inner, header=self.udmux_header)
        return b"\x05" + MAGIC + bytes((protocol,)) + struct.pack(">H", mtu)

    def handshake(self) -> bool:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 0))
        self.sock.settimeout(self.timeout)
        self.stats["local_port"] = int(self.sock.getsockname()[1])
        # A bare unconnected ping is valid for a direct RakNet endpoint.  The
        # UDMUX path used by 0.738 starts with the padded 1160-byte Rbx
        # OpenRequest1 instead, so sending the legacy ping first only adds
        # noise and can make the relay discard the source tuple.  Keep the
        # direct probe for callers that did not supply a UDMUX header.
        if not self.udmux_header:
            now = time.time_ns() // 1_000_000
            # packet id + timestamp + offline magic.  The client GUID belongs
            # to the subsequent open/app exchange, not this probe.
            self._send(b"\x01" + struct.pack(">Q", now) + MAGIC)
            packets = self._recv_until(time.monotonic() + self.timeout)
            for packet in packets:
                inner = unwrap_inner(packet)
                if inner and inner[0] == 0x1C:
                    self.stats["pongs"] += 1
        # IDA 2.735 processRbxOpenRequest1: packet[17] must be protocol 5 and
        # the request ends with a network-order MTU.  The previous probe
        # omitted those two bytes (18-byte envelope), so a current server
        # discarded it before producing the Roblox 0x7e reply.  Keep the
        # canonical RakNet 20-byte request here and vary the advertised MTU.
        # Android/0.738 emits a 1160-byte UDMUX datagram (31-byte outer
        # prefix plus a 1129-byte inner record).  Try that size first when a
        # header is present, then retain the direct-client candidates.
        candidates = ((5, 1160), (5, self.mtu), (5, 1200), (10, self.mtu), (11, 1200)) if self.udmux_header else ((5, self.mtu), (5, 1200), (10, self.mtu), (11, 1200))
        for protocol, mtu_candidate in candidates:
            # RakNet OpenConnectionRequest1 layout:
            #   id (1) | offline magic (16) | protocol (1) | mtu (2)
            request1 = self._build_open_request1(protocol, mtu_candidate)
            self._send(request1)
            packets = self._recv_until(time.monotonic() + self.timeout / 2)
            for packet in packets:
                inner = unwrap_inner(packet)
                if inner and inner[0] in (0x06, 0x7E):
                    self.stats["rbx_reply_1" if inner[0] == 0x7E else "open_reply_1"] += 1
                    if inner[0] == 0x7E:
                        try:
                            self.open_reply1 = parse_open_reply1(inner)
                            self.mtu = min(self.mtu, self.open_reply1.mtu)
                            # Roblox's 0.738 path uses the encrypted UDMUX
                            # adapter immediately after the 0x7e control
                            # reply.  A standard 0x07 packet is retained only
                            # for the stock RakNet 0x06 reply below.
                            if self.stats["request2_sent"] == 0:
                                self._send_encrypted_request2(self.open_reply1.mtu)
                        except ValueError:
                            self.stats["unknown"] += 1
                    if len(inner) >= 28 and inner[0] == 0x06:
                        server_guid = inner[17:25]
                        mtu = struct.unpack(">H", inner[-2:])[0] if len(inner) >= 2 else mtu_candidate
                        self._send_standard_open_request2(server_guid, mtu or mtu_candidate)
        packets = self._recv_until(time.monotonic() + self.timeout)
        for packet in packets:
            inner = unwrap_inner(packet)
            if inner and inner[0] == 0x08:
                self.stats["open_reply_2"] += 1
        return bool(self.stats["pongs"] or self.stats["open_reply_1"] or self.stats["rbx_reply_1"] or self.stats["open_reply_2"])

    def run(self, duration: float, interval: float = 1.0) -> dict[str, Any]:
        started = time.time()
        handshaken = self.handshake()
        # Do not burn the requested 2–3 minute hold time on a dead endpoint.
        # A real hold starts only after the server has answered the open/ping
        # exchange; failed candidates are released immediately so the next
        # UDMUX/direct address can be tried.
        if not handshaken:
            elapsed = round(time.time() - started, 3)
            if self.sock is not None:
                self.sock.close()
            self.sock = None
            return {"handshake": False, "elapsed_seconds": elapsed, "stats": self.stats}
        deadline = time.monotonic() + max(0.0, duration)
        while time.monotonic() < deadline and self.sock is not None:
            stamp = time.time_ns() // 1_000_000
            sent_at = time.monotonic()
            if self.stats.get("authenticated") and (self.request2_config or {}).get("established_tx_key"):
                self._send_connected_ping()
            else:
                self._send(b"\x01" + struct.pack(">Q", stamp) + MAGIC)
            packets = self._recv_until(time.monotonic() + min(interval, max(0.05, deadline - time.monotonic())))
            self._service_lifecycle()
            for packet in packets:
                inner = unwrap_inner(packet)
                if inner and inner[0] == 0x1C:
                    self.stats["pongs"] += 1
                    self.stats["rtt_ms"].append(round((time.monotonic() - sent_at) * 1000, 2))
                elif packet:
                    self.stats["unknown"] += 1
        elapsed = round(time.time() - started, 3)
        if self._authenticated_at is not None:
            self.stats["authenticated_seconds"] = round(max(0.0, time.monotonic() - self._authenticated_at), 3)
        self.stats.setdefault("heartbeat_seconds", 0.0)
        if self.sock is not None:
            self.sock.close()
        self.sock = None
        return {"handshake": handshaken, "elapsed_seconds": elapsed, "stats": self.stats}


class FixtureEndpoint:
    """Small in-process UDP peer used for deterministic no-render testing.

    It models only the wire liveness boundary (ping, OpenRequest1/2 and
    periodic pings).  It deliberately does not pretend to implement an
    application session or any account/authentication material.
    """

    def __init__(self) -> None:
        self.stop = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]

    def serve(self) -> None:
        self.sock.settimeout(0.1)
        while not self.stop:
            try:
                packet, address = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            if not packet:
                continue
            if packet[0] == 0x01 and len(packet) >= 25:
                self.sock.sendto(b"\x1c" + packet[1:9] + struct.pack(">Q", 1) + MAGIC + b"fixture", address)
            elif packet[0] == 0x05:
                self.sock.sendto(b"\x06" + MAGIC + struct.pack(">Q", 2) + b"\x00" + struct.pack(">H", 1200), address)
            elif packet[0] == 0x07:
                self.sock.sendto(b"\x08" + MAGIC + struct.pack(">Q", 2) + b"\x00", address)
        self.sock.close()

    def close(self) -> None:
        self.stop = True


def run_fixture(args) -> int:
    """Run a local 127.0.0.1 transport fixture without touching credentials."""
    import threading

    endpoint = FixtureEndpoint()
    worker = threading.Thread(target=endpoint.serve, name="fixture-raknet", daemon=True)
    worker.start()
    try:
        transport = RakNetClient("127.0.0.1", endpoint.port, mtu=args.mtu, timeout=args.timeout)
        live = transport.run(args.duration, args.interval)
    finally:
        endpoint.close()
        worker.join(timeout=1.0)
    report = {
        "ok": bool(live["handshake"] and live["elapsed_seconds"] >= max(1.0, args.duration * 0.9)),
        "stage": "fixture-complete" if live["handshake"] else "fixture-transport",
        "fixture": True,
        "transport": {"host": "127.0.0.1", "port": endpoint.port, **live},
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"ok": report["ok"], "stage": report["stage"], "output": str(output), "transport": report["transport"]}, ensure_ascii=False))
    return 0 if report["ok"] else 2


def choose_endpoints(result: BootstrapResult) -> list[tuple[str, int, str]]:
    """Return de-duplicated transport candidates in desktop-client order."""
    out: list[tuple[str, int, str]] = []
    for item in result.endpoint_candidates:
        try:
            host, port = str(item["host"]), int(item["port"])
        except (KeyError, TypeError, ValueError):
            continue
        key = (host, port)
        if host and port and not any((h, p) == key for h, p, _ in out):
            out.append((host, port, str(item.get("kind") or "candidate")))
    if not out:
        host = result.udmux_ip or result.server_ip
        port = result.udmux_port or result.server_port
        if host and port:
            out.append((host, int(port), "fallback"))
    return out


def load_udmux_header(path: str | None) -> bytes:
    """Load a per-session UDMUX header template from a text/hex artifact."""
    if not path:
        return b""
    text = Path(path).read_text(encoding="utf-8").strip()
    if text.startswith("0x"):
        text = text[2:]
    text = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(text) % 2:
        raise ValueError("UDMUX header hex must contain complete bytes")
    header = bytes.fromhex(text)
    if len(header) > 4092:
        raise ValueError("UDMUX header is too large")
    return header


def generate_udmux_header(port: int | None = None, route_ip: str | None = None, epoch: bytes | None = None) -> bytes:
    """Create a fresh 0.738 Request1 header skeleton for one join attempt.

    IDA 0.738 shows the six-byte route serializer is constructed from the
    server address structure: IPv4 bytes followed by its network-order port.
    The apparent two-byte "tag" after ``0a 20`` is therefore just the last two
    octets of the private ``MachineAddress`` (normally ``10.32.x.y``), not a
    random session field. The 16-byte epoch comes from the current join's
    TokenValue when available; isolated codec fixtures may omit it.
    """
    try:
        packed_ip = ipaddress.ip_address(str(route_ip)).packed
    except ValueError:
        packed_ip = b""
    if len(packed_ip) != 4:
        raise ValueError("a valid IPv4 MachineAddress is required for UDMUX routing")
    if port is None or not 0 <= int(port) <= 0xFFFF:
        raise ValueError("a valid UDMUX route port is required")
    epoch_bytes = bytes(epoch or os.urandom(16))
    if len(epoch_bytes) != 16:
        raise ValueError("UDMUX epoch must contain 16 bytes")
    return b"\x01\x11\x01" + epoch_bytes + b"\x02\x06" + packed_ip + int(port).to_bytes(2, "big")


def _load_blob(path: str | None, expected: int, name: str) -> bytes:
    """Read a raw or hexadecimal per-session adapter artifact."""
    if not path:
        raise ValueError(f"{name} path is required")
    raw = Path(path).read_bytes()
    if len(raw) == expected:
        return raw
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError(f"{name} must be {expected} raw bytes or hex") from exc
    text = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(text) != expected * 2:
        raise ValueError(f"{name} must be {expected} raw bytes or hex")
    return bytes.fromhex(text)


def load_request2_config(args) -> dict[str, Any] | None:
    """Load an explicit Request2 adapter configuration, if requested."""
    paths = (args.request2_key_file, args.request2_rupp_file, args.request2_token_file)
    if not any(paths):
        return None
    if not all(paths):
        raise ValueError("request2 key, RUPP and token files must be supplied together")
    config: dict[str, Any] = {
        "session_key": _load_blob(args.request2_key_file, 32, "request2 key"),
        "rupp_aad": _load_blob(args.request2_rupp_file, 33, "request2 RUPP span"),
        "token_blob": _load_blob(args.request2_token_file, 66, "request2 token"),
        "pad_to_mtu": not bool(args.request2_no_padding),
    }
    if args.request2_pad_length is not None:
        config["pad_length"] = int(args.request2_pad_length)
    if args.request2_endpoint_port is not None:
        config["endpoint_port"] = int(args.request2_endpoint_port)
    return config


def load_request2_trace(path: str | None, args) -> dict[str, Any] | None:
    """Load one fresh 0.738 Request2 trace as an adapter input.

    A trace is deliberately opt-in and remains a per-session artifact.  It
    supplies the exact UDMUX header/key/RUPP/token spans captured from the
    same runtime; no value is persisted in the result report.  This removes
    the error-prone manual four-file export step while retaining the guard
    that prevents stale material from being silently invented.
    """
    if not path:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    events = [e for e in data.get("events", []) if isinstance(e, dict)]
    before_event = next((e for e in events if e.get("kind") == "session_encrypt_before"), None)
    key_event = next((e for e in events if e.get("kind") == "session_aead"), None)
    decrypt_key_event = next((e for e in events
                              if e.get("kind") == "session_aead_decrypt_before"), None)
    if not before_event or (not key_event and not decrypt_key_event):
        raise ValueError("request2 trace is missing session_encrypt_before/session_aead")
    try:
        clear = bytes.fromhex(str(before_event["writer"]["bytes"]))
        key_hex = key_event.get("key") if isinstance(key_event, dict) else None
        if not key_hex and isinstance(decrypt_key_event, dict):
            fields = decrypt_key_event.get("holder_fields") or {}
            key_hex = fields.get("f192")
        key = bytes.fromhex(str(key_hex))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("request2 trace contains invalid hex fields") from exc
    if len(clear) != 214 or len(key) != 32:
        raise ValueError("request2 trace must contain a 214-byte clear transcript and 32-byte key")
    prefix, aad, plaintext = clear[:31], clear[31:121], clear[121:]
    if len(prefix) != 31 or len(aad) != 90 or len(plaintext) != 93:
        raise ValueError("request2 trace has unexpected clear span sizes")
    if prefix[:4] != b"\x01\x00\x00\x1f" or prefix[4:7] != b"\x01\x11\x01":
        raise ValueError("request2 trace has an invalid UDMUX prefix")
    # The captured client material starts with the RakNet GUID in the
    # client's little-endian object layout.  Reusing it makes a trace replay
    # deterministic instead of generating a second GUID.
    material_event = next((e for e in events if e.get("kind") == "request2_client_material"), None)
    client_guid = None
    if material_event and isinstance(material_event.get("value"), str):
        try:
            material = bytes.fromhex(material_event["value"])
            if len(material) >= 8:
                client_guid = int.from_bytes(material[:8], "little")
        except ValueError:
            client_guid = None
    config: dict[str, Any] = {
        "session_key": key,
        "rupp_aad": aad[57:90],
        "token_blob": plaintext[27:],
        "pad_to_mtu": not bool(args.request2_no_padding),
        "pad_length": int(args.request2_pad_length),
        "endpoint_port": int.from_bytes(plaintext[24:26], "big"),
        "trace_prefix": prefix,
        "trace_clear": clear,
        "trace_encrypted": None,
    }
    # A full internal trace includes both digest halves in the RakPeerCrypto
    # holder.  Keep the paired half in memory so Reply2 verification and a
    # same-session established decoder can use the correct direction key.
    session_aead_event = next((e for e in events if e.get("kind") == "session_aead"), None)
    if isinstance(session_aead_event, dict):
        fields = session_aead_event.get("holder_fields")
        if isinstance(fields, dict):
            try:
                f192 = bytes.fromhex(str(fields.get("f192") or ""))
                f224 = bytes.fromhex(str(fields.get("f224") or ""))
                if len(f192) == 32 and len(f224) == 32:
                    config.update({"session_key": f192, "session_key_alt": f224,
                                   "established_tx_key": f192,
                                   "established_rx_key": f224,
                                   "established_cipher": "aes-256-gcm"})
            except (TypeError, ValueError):
                pass
    # The server Reply2 path invokes the sibling decrypt routine and exposes
    # the active holder in ``session_aead_decrypt_before``.  Prefer its second
    # digest half for Reply2/RX; the encrypt hook alone only sees the client
    # direction and is insufficient for authentication.
    decrypt_aead_event = next((e for e in events
                               if e.get("kind") == "session_aead_decrypt_before"), None)
    if isinstance(decrypt_aead_event, dict):
        fields = decrypt_aead_event.get("holder_fields")
        if isinstance(fields, dict):
            try:
                server_rx = bytes.fromhex(str(fields.get("f224") or ""))
                if len(server_rx) == 32:
                    config.update({"established_rx_key": server_rx,
                                   "established_rx_keys": [server_rx]})
                    # A decrypt trace gives us a verified Reply2 key even
                    # when the encrypt-side holder was unreadable.
                    if not config.get("session_key_alt"):
                        config["session_key_alt"] = server_rx
            except (TypeError, ValueError):
                pass
    after_event = next((e for e in events if e.get("kind") == "session_encrypt_after"), None)
    if after_event and isinstance(after_event.get("writer"), dict):
        try:
            encrypted = bytes.fromhex(str(after_event["writer"]["bytes"]))
            if len(encrypted) >= 242:
                config["trace_encrypted"] = encrypted[:242]
        except (KeyError, TypeError, ValueError):
            pass
    if len(config["rupp_aad"]) != 33 or len(config["token_blob"]) != 66:
        raise ValueError("request2 trace has unexpected RUPP/token lengths")
    args.udmux_header = prefix[4:]
    if client_guid is not None:
        config["client_guid"] = client_guid
    return config


def load_established_config(args) -> dict[str, Any] | None:
    """Load the two per-join post-Reply2 direction keys."""
    paths = (getattr(args, "established_tx_key_file", None),
             getattr(args, "established_rx_key_file", None))
    if not any(paths):
        return None
    if not all(paths):
        raise ValueError("both established TX and RX key files are required")
    return {
        "established_tx_key": _load_blob(paths[0], 32, "established TX key"),
        "established_rx_key": _load_blob(paths[1], 32, "established RX key"),
        "established_cipher": str(getattr(args, "established_cipher", "aes-256-gcm")),
    }


def load_established_trace(path: str | None) -> dict[str, Any] | None:
    """Load direction keys/epochs emitted by the internal transport trace.

    The trace is intentionally a per-join artifact.  It is useful when the
    same live socket is being inspected, or for an offline decoder; a fresh
    join must still supply a fresh trace because the key and epoch rotate.
    """
    if not path:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    events = data.get("events", []) if isinstance(data, dict) else []
    if not isinstance(events, list):
        raise ValueError("established trace events must be an array")
    out: dict[str, Any] = {"established_keyring": {}, "established_rx_keys": [],
                           "established_tx_keys": [], "established_aad_candidates": [b""]}
    for event in events:
        if not isinstance(event, dict):
            continue
        kind = str(event.get("kind") or "")
        if kind not in {"established_decrypt_before", "established_encrypt_before"}:
            continue
        key_hex = event.get("key_bytes")
        if not isinstance(key_hex, str):
            continue
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            continue
        if len(key) != 32:
            continue
        # Epoch is recovered from a captured UDMUX packet when present.  The
        # context trace also accepts an explicit epoch_hex field for scripts
        # that cannot retain the packet body.
        epoch = event.get("epoch_hex")
        if isinstance(epoch, str):
            epoch = re.sub(r"[^0-9a-fA-F]", "", epoch).lower()
            if len(epoch) != 32:
                epoch = None
        if kind == "established_decrypt_before":
            if key not in out["established_rx_keys"]:
                out["established_rx_keys"].append(key)
            out["established_rx_key"] = key
        else:
            if key not in out["established_tx_keys"]:
                out["established_tx_keys"].append(key)
            out["established_tx_key"] = key
        if epoch:
            out["established_keyring"][epoch] = key
    if not out.get("established_rx_key") and not out.get("established_tx_key"):
        raise ValueError("established trace contains no 32-byte direction key")
    return out


def load_lifecycle_profile(path: str | None) -> dict[str, Any] | None:
    """Load opt-in PlayerReady/avatar/physics serializers from JSON.

    Values are hex strings (or arrays of byte values).  Keeping this file
    separate means build updates only replace a profile, never the transport
    or offset code.
    """
    if not path:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("lifecycle profile must be a JSON object")
    out: dict[str, Any] = {}
    for name in ("player_ready", "avatar_description", "heartbeat", "physics"):
        value = data.get(name)
        if value is None:
            continue
        if isinstance(value, list):
            try:
                value = bytes(int(v) & 0xFF for v in value)
            except (TypeError, ValueError):
                raise ValueError(f"{name} byte array is invalid")
        elif isinstance(value, str):
            text = re.sub(r"[^0-9a-fA-F]", "", value)
            if len(text) % 2:
                raise ValueError(f"{name} hex has odd length")
            value = bytes.fromhex(text)
        else:
            raise ValueError(f"{name} must be hex or byte array")
        allowed_ids = (0x83, 0x85) if name == "physics" else ((0x00, 0x83) if name == "heartbeat" else (0x83,))
        if len(value) < 2 or value[0] not in allowed_ids:
            raise ValueError(f"{name} must be a profile replication payload")
        out[name] = value
    for name in ("heartbeat_interval", "physics_interval", "replication_ping_interval",
                 "replication_ping_start_delay", "isr_timestamp_interval",
                 "isr_timestamp_start_delay", "isr_timestamp_batch_interval"):
        if data.get(name) is not None:
            try:
                value = float(data[name])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{name} must be numeric") from exc
            if not 0.05 <= value <= 60.0:
                raise ValueError(f"{name} is out of range")
            out[name] = value
    if data.get("isr_timestamp_enabled") is not None:
        out["isr_timestamp_enabled"] = bool(data["isr_timestamp_enabled"])
    if data.get("isr_timestamp_values") is not None:
        values = data["isr_timestamp_values"]
        if not isinstance(values, list):
            raise ValueError("isr_timestamp_values must be an array")
        out["isr_timestamp_values"] = [
            int(value, 0) if isinstance(value, str) else int(value)
            for value in values
        ]
    if data.get("replication_ping_enabled") is not None:
        out["replication_ping_enabled"] = bool(data["replication_ping_enabled"])
    if isinstance(data.get("replication_ping"), dict):
        ping: dict[str, float | int] = {}
        for name in ("send_kbps", "receive_kbps", "packet_loss", "memory_mb"):
            if data["replication_ping"].get(name) is not None:
                ping[name] = float(data["replication_ping"][name])
        for name in ("item_flags", "feature_mask", "xor_mask"):
            if data["replication_ping"].get(name) is not None:
                ping[name] = int(data["replication_ping"][name])
        out["replication_ping"] = ping
    for name in ("request_character_feature_mask",):
        if data.get(name) is not None:
            out[name] = int(data[name], 0) if isinstance(data[name], str) else int(data[name])
    if data.get("request_character_spawn_name") is not None:
        out["request_character_spawn_name"] = str(data["request_character_spawn_name"])
    if data.get("request_character_after_marker") is not None:
        out["request_character_after_marker"] = bool(data["request_character_after_marker"])
    for name in ("character_markers", "avatar_markers", "observer_markers"):
        value = data.get(name)
        if value is not None:
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise ValueError(f"{name} must be an array of strings")
            out[name] = list(value)
    if isinstance(data.get("blocks"), dict):
        out["blocks"] = data["blocks"]
    return out or None


def build_auto_request2_config(boot: BootstrapResult, endpoint_port: int) -> dict[str, Any] | None:
    """Build the first same-join Request2 candidate from live material.

    The route/Reply1 gate is now reproducible.  This candidate uses the
    standard-library X25519/BLAKE2 comparison path and the exact token shape
    recovered from the runtime trace; it is kept opt-in behind
    ``--udmux-header-auto`` and never writes its key to reports.
    """
    material = getattr(boot, "_session_material", None)
    context = getattr(boot, "_session_context", None)
    if material is None or context is None:
        return None
    if len(material.ephemeral_early_public_key) != 32 or len(material.early_public_key) != 32:
        return None
    try:
        from session_crypto import (derive_native_key_pair, derive_blake2_key_pair,
                                    derive_client_session_key_pair)
        private = context._client_ephemeral_private.private_bytes_raw()
        client_public = context.client_ephemeral_public_key
        # Exact client-side mapping recovered from the holder correlation:
        # the generated local keypair occupies holder +0x20/+0x00, while the
        # join's EphemeralEarlyPubKey is the peer at +0x40.  This candidate is
        # always first; the older comparison sweep remains available only as
        # a diagnostic fallback.
        context.request2_public_key = client_public
        if len(material.ephemeral_early_public_key) == 32:
            try:
                exact_a, exact_b = derive_client_session_key_pair(
                    client_private=private,
                    server_ephemeral_public=material.ephemeral_early_public_key,
                    client_public=client_public,
                )
                derived_keys: list[bytes] = [exact_a, exact_b]
            except ValueError:
                derived_keys = []
        else:
            derived_keys = []
        # The runtime accepts a per-join 64-byte seed and splits it into
        # 32-byte inputs before the Curve25519/BLAKE2 helper.  Keep the
        # generated ephemeral scalar as a fallback, but try the join seeds
        # first so the automatic path follows the material actually returned
        # by /v1/join-game.
        scalar_candidates = [private]
        for seed in (material.random_seed1, material.random_seed2):
            if len(seed) == 64:
                scalar_candidates.extend((seed[:32], seed[32:]))
        peer_candidates = [material.ephemeral_early_public_key, material.early_public_key,
                           material.netstack_public_key]
        aux_candidates = [material.early_public_key, material.ephemeral_early_public_key]
        # First try the directly observable BLAKE2b ordering from the native
        # helper.  The native precondition gate is build-specific; these
        # candidates keep the same three-span ordering while the gate is
        # being mapped.
        hash_spans = [x for x in (material.random_seed1[:32], material.random_seed1[32:],
                                  material.random_seed2[:32], material.random_seed2[32:],
                                  material.early_public_key, material.ephemeral_early_public_key,
                                  material.netstack_public_key) if len(x) == 32]
        for state in hash_spans:
            for external in (material.early_public_key, material.ephemeral_early_public_key,
                             material.netstack_public_key):
                if len(external) != 32:
                    continue
                for field in hash_spans:
                    try:
                        ka, kb = derive_blake2_key_pair(state=state, external=external, field=field)
                    except ValueError:
                        continue
                    for key in (ka, kb):
                        if key not in derived_keys:
                            derived_keys.append(key)
        for scalar in scalar_candidates:
            for peer in peer_candidates:
                if len(peer) != 32:
                    continue
                for aux in aux_candidates:
                    if len(aux) != 32:
                        continue
                    try:
                        ka, kb = derive_native_key_pair(scalar=scalar, peer_public=peer, aux=aux)
                    except ValueError:
                        continue
                    for key in (ka, kb):
                        if key not in derived_keys:
                            derived_keys.append(key)
        if not derived_keys:
            return None
        key_a, key_b = derived_keys[0], derived_keys[1] if len(derived_keys) > 1 else derived_keys[0]
        # 0.738 writes a one-byte RUPP type followed by a 32-byte key span.
        rupp = b"\x00" + context.client_ephemeral_public_key
        pubs = [
            context.client_ephemeral_public_key,
            material.ephemeral_early_public_key,
            material.netstack_public_key,
            material.early_public_key,
        ]
        for seed in (material.random_seed1, material.random_seed2):
            if len(seed) == 64:
                pubs.extend((seed[:32], seed[32:]))
                try:
                    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
                    pubs.extend((
                        X25519PrivateKey.from_private_bytes(seed[:32]).public_key().public_bytes_raw(),
                        X25519PrivateKey.from_private_bytes(seed[32:]).public_key().public_bytes_raw(),
                    ))
                except (ValueError, TypeError):
                    pass
        if len(material.token_value) == 16:
            pubs.append(material.token_value + b"\x00" * 16)
        # The runtime's ClientRuppGenerator emits a fresh opaque 33-byte
        # value.  It is not the SessionCrypto public key: three independent
        # captures show unrelated, uniformly distributed spans.  Put a
        # per-join random span first when explicitly requested; this gives a
        # clean one-shot experiment without replaying or flooding a session.
        import os
        random_rupp = os.urandom(33)
        rupps: list[bytes] = ([random_rupp] if os.environ.get("RIFT_RUPP_RANDOM", "0") == "1" else [])
        # Diagnostic replay slot: a fresh runtime capture can be supplied as
        # newline-separated 33-byte hex values.  This is intentionally opt-in
        # and prepended so one fresh join tests exactly the captured identity
        # before falling back to derived candidates.  It lets us distinguish
        # a stable server-issued RUPP from a per-join generator output without
        # coupling the value to the implementation or profile files.
        replay_path = os.environ.get("RIFT_RUPP_FILE")
        replay_hex = os.environ.get("RIFT_RUPP_HEX")
        replay_values: list[bytes] = []
        if replay_path:
            try:
                replay_hex = Path(replay_path).read_text(encoding="ascii")
            except (OSError, UnicodeDecodeError):
                replay_hex = None
        if replay_hex:
            for token in re.split(r"[\s,;]+", replay_hex.strip()):
                token = re.sub(r"[^0-9a-fA-F]", "", token)
                if len(token) == 66:
                    try:
                        replay_values.append(bytes.fromhex(token))
                    except ValueError:
                        pass
        # Exact per-join identity recovered from ClientTicket segment 2.
        # This is what the native builder installs at connection+0xb00.
        native_rupp = getattr(material, "rupp_identity", b"")
        if len(native_rupp) == 33:
            rupps.insert(0, native_rupp)
        rupps = replay_values + rupps
        rupps.append(b"\x00" + client_public)
        # RUPP's 33-byte value is generated independently from the visible
        # SessionCrypto public key.  Include deterministic per-join material
        # candidates (token/seed/key combinations) so a fresh join can test a
        # single value without replaying a one-shot MAC.
        import hashlib
        token_inputs = [material.token_value, material.netstack_token_value,
                        material.random_seed1, material.random_seed2,
                        material.early_public_key, material.ephemeral_early_public_key,
                        material.netstack_public_key, client_public]
        token_inputs = [bytes(x) for x in token_inputs if len(x) in (16, 32, 64)]
        for blob in token_inputs:
            for label in (b"", b"Rupp", b"RUPP", b"TokenValue", b"NetStackTokenValue"):
                digest = hashlib.blake2b(label + blob, digest_size=32).digest()
                rupps.extend((digest[:1] + digest[1:], b"\x00" + digest,
                              b"\x01" + digest, b"\x02" + digest,
                              b"\x03" + digest))
        for a, b in ((material.token_value, material.netstack_token_value),
                     (material.random_seed1, material.ephemeral_early_public_key),
                     (material.random_seed2, material.early_public_key)):
            if a and b:
                digest = hashlib.blake2b(bytes(a) + bytes(b), digest_size=32).digest()
                rupps.extend((digest[:1] + digest[1:], b"\x00" + digest,
                              b"\x01" + digest, b"\x02" + digest,
                              b"\x03" + digest))
        for pub in pubs:
            if len(pub) != 32:
                continue
            for prefix in (0, 1, 2, 3):
                rupps.append(bytes((prefix,)) + pub)
        # Preserve order while dropping malformed/duplicate values.
        rupps = list(dict.fromkeys(x for x in rupps if len(x) == 33))
        # Keep the candidate set bounded; every item is same-session material
        # and the receiver ignores a MAC-invalid Request2 without promotion.
        candidates = []
        for key in derived_keys[:8]:
            for rupp in rupps[:128]:
                candidates.append({"session_key": key, "rupp_aad": rupp})
        return {
            "session_key": key_a,
            "session_key_alt": key_b,
            # The same digest pair is installed in the RakPeerCrypto holder
            # for the first established epoch on 0.738.  Keep these as
            # replaceable profile fields; a future re-key trace can override
            # them without touching the transport state machine.
            "established_tx_key": key_a,
            "established_rx_key": key_b,
            "established_cipher": "chacha20-poly1305",
            "request2_public_key": client_public,
            "rupp_aad": rupps[0],
            "request2_candidates": candidates,
            "token_blob": material.token_blob_candidate(),
            "client_ticket": material.client_ticket,
            "endpoint_port": int(endpoint_port),
            "pad_to_mtu": True,
            # Live 0.738 emits the encrypted body directly after the 31-byte
            # UDMUX header (subflag 02) and pads the complete datagram to
            # 1231 bytes.  Request1 keeps its legacy 1160-byte shape.
            "payload_only": False,
            "pad_length": 1160,
            "auto_candidate": True,
        }
    except (AttributeError, TypeError, ValueError, OSError):
        return None


def run(args) -> int:
    launcher_root = Path(args.launcher_root).resolve()
    profile = load_profile(args.profile)
    import threading
    presence_samples: list[dict[str, Any]] = []
    presence_stop = threading.Event()
    try:
        request2_config = load_request2_trace(args.request2_trace_file, args) if args.request2_trace_file else load_request2_config(args)
        established_config = load_established_config(args)
        established_trace_config = load_established_trace(getattr(args, "established_trace_file", None))
        if established_trace_config:
            established_config = {**(established_config or {}), **established_trace_config}
        lifecycle_profile = load_lifecycle_profile(getattr(args, "lifecycle_profile", None))
    except (OSError, ValueError) as exc:
        report = {"ok": False, "stage": "request2-config", "error": str(exc)}
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps({"ok": False, "stage": report["stage"], "output": str(output), "error": report["error"]}, ensure_ascii=False))
        return 2
    mod = load_launcher(launcher_root)
    cookie = read_first_cookie(mod, launcher_root)
    session = mod.new_session(cookie)
    presence_before = read_account_presence(session)
    def _presence_worker() -> None:
        while not presence_stop.is_set():
            sample = read_account_presence(session)
            if sample.get("ok"):
                presence_samples.append({"at": time.time(), **sample})
            presence_stop.wait(5.0)
    presence_thread = threading.Thread(target=_presence_worker, name="presence-monitor", daemon=True)
    presence_thread.start()
    try:
        username = mod.get_username(session)
        ticket, ticket_error = mod.get_auth_ticket(session)
        if not ticket:
            report = {"ok": False, "stage": "auth-ticket", "username_present": bool(username), "error": ticket_error}
        else:
            boot = bootstrap(session, ticket, str(args.place_id))
            report = {"ok": False, "stage": "bootstrap", "username_present": bool(username), "profile": profile["build"], "bootstrap": asdict(boot)}
            endpoints = choose_endpoints(boot)
            if endpoints:
                attempts: list[dict[str, Any]] = []
                for host, port, kind in endpoints:
                    try:
                        # Header generation is unresolved. Do not splice a
                        # random epoch onto routing bytes from an old capture.
                        header = getattr(args, "udmux_header", b"")
                        if kind == "udmux" and not header and getattr(args, "udmux_header_auto", False):
                            material = getattr(boot, "_session_material", None)
                            epoch_value = getattr(material, "token_value", None)
                            if os.environ.get("RIFT_UDMUX_EPOCH_SOURCE", "").lower() == "netstack":
                                epoch_value = getattr(material, "netstack_token_value", None)
                            header = generate_udmux_header(
                                port, boot.server_ip,
                                epoch_value,
                            )
                        if kind == "udmux" and not header:
                            attempts.append({"kind": kind, "host": host, "port": port,
                                             "handshake": False, "stage": "transport-config",
                                             "error": "missing-session-udmux-header"})
                            continue
                        attempt_config = request2_config
                        if attempt_config is None and getattr(args, "udmux_header_auto", False):
                            # Request2 repeats the selected UDMUX/server port
                            # (the same network-order u16 as the route suffix).
                            attempt_config = build_auto_request2_config(boot, port)
                        if attempt_config is not None:
                            # ClientTicket is join-scoped and must never be
                            # serialized into reports.  Attach it only to the
                            # in-memory attempt that can submit it after the
                            # connection-accepted gate.
                            material = getattr(boot, "_session_material", None)
                            if material is not None and getattr(material, "client_ticket", ""):
                                attempt_config = {**attempt_config, "client_ticket": material.client_ticket}
                            # Bind decrypted lifecycle evidence to the account
                            # from this exact join.  Values stay in memory and
                            # are used only as packet markers.
                            attempt_config = {**attempt_config, "identity": {
                                "user_id": presence_before.get("user_id"),
                                "username": presence_before.get("username"),
                            }}
                            suffix = (profile.get("wire") or {}).get("connection_request_identity_hex")
                            if isinstance(suffix, str):
                                suffix = re.sub(r"[^0-9a-fA-F]", "", suffix)
                                if len(suffix) == 12:
                                    attempt_config["connection_request_identity"] = bytes.fromhex(suffix)
                            # Application bootstrap values are join-scoped.
                            # Keep the transient material in memory and all
                            # build constants in the external profile.
                            attempt_config = {
                                **attempt_config,
                                "application": dict(profile.get("application") or {}),
                                "session_material": material,
                                "place_id": int(args.place_id),
                                "game_id": str(boot.game_id or boot.job_id or ""),
                            }
                        if established_config:
                            attempt_config = {**(attempt_config or {}), **established_config}
                        if lifecycle_profile:
                            attempt_config = {**(attempt_config or {}), "lifecycle": lifecycle_profile}
                        # Reply2 arrives on the UDMUX endpoint, while the
                        # established DATA stream is advertised on
                        # NetStackPort in the same join payload. Keep one
                        # socket bound locally but route post-Reply2 packets
                        # to that second endpoint.
                        # The gameplay replicator is bound to the same UDMUX
                        # tuple that returns Reply2.  NetStackPort is a
                        # parallel transport (voice/telemetry/control) and
                        # does not accept the app connection request.  Keep
                        # the route override explicit for captures that prove
                        # a different topology.
                        established_host, established_port, established_header = host, port, None
                        if (kind == "udmux" and
                                os.environ.get("RIFT_ESTABLISHED_ROUTE", "udmux").lower() == "netstack"):
                            netstack = next((item for item in endpoints
                                              if item[2] == "netstack"), None)
                            if netstack is not None:
                                established_host, established_port = netstack[0], netstack[1]
                                if getattr(args, "udmux_header_auto", False):
                                    material = getattr(boot, "_session_material", None)
                                    epoch_value = (getattr(material, "netstack_token_value", None)
                                                   or getattr(material, "token_value", None))
                                    established_header = generate_udmux_header(
                                        established_port, boot.server_ip, epoch_value)
                        transport = RakNetClient(host, port, mtu=args.mtu, timeout=args.timeout, session_context=getattr(boot, "_session_context", None), udmux_header=header, request2_config=attempt_config, established_host=established_host, established_port=established_port, established_header=established_header)
                        if transport.session_context is not None:
                            transport.session_context.client_guid = transport.guid
                        if attempt_config and attempt_config.get("client_guid") is not None and transport.session_context is not None:
                            transport.guid = int(attempt_config["client_guid"])
                            transport.session_context.client_guid = transport.guid
                        if getattr(boot, "_session_context", None) is not None:
                            report["bootstrap"]["material_profile"]["context"] = boot._session_context.summary()
                        # A short handshake is enough to select a live path;
                        # only the authenticated adapter may claim complete.
                        live = transport.run(args.duration, args.interval)
                        attempts.append({"kind": kind, "host": host, "port": port, **live})
                        # A Reply2/0x19 handshake is only a transport gate;
                        # continue to the advertised NetStack/direct endpoint
                        # until one yields established replication evidence.
                        if (live["handshake"] and live.get("stats", {}).get("player_instance_observed")):
                            break
                    except OSError as exc:
                        attempts.append({"kind": kind, "host": host, "port": port, "error": type(exc).__name__})
                report["transport"] = {"attempts": attempts}
                selected = max((a for a in attempts if a.get("handshake")),
                               key=lambda a: (
                                   bool(a.get("stats", {}).get("player_instance_observed")),
                                   bool(a.get("stats", {}).get("replicator_registered")),
                                   bool(a.get("stats", {}).get("authenticated")),
                               ), default=None)
                # Transport observations are not application acceptance.
                # This runner has no verified session/replication decoder yet;
                # keep these gates closed rather than inferring success from
                # a marker, an outbound request, arbitrary frames, or uptime.
                selected_stats = (selected or {}).get("stats", {})
                authenticated = selected_stats.get("authenticated") is True
                app_connection = bool(authenticated and selected_stats.get("connection_accepted") is True)
                connected_frames = int(selected_stats.get("connected_frames") or 0)
                report["session"] = {
                    "authenticated": authenticated,
                    "app_connection": app_connection,
                    "replicator": bool(selected_stats.get("replicator_registered", False)),
                    "heartbeat_seconds": float(selected_stats.get("heartbeat_seconds") or 0.0),
                    "control_0x19_received": int(selected_stats.get("control_0x19_received", 0) or 0),
                }
                report["replication"] = {
                    "replicator_registered": bool(selected_stats.get("replicator_registered", False)),
                    "initial_replication_received": bool(selected_stats.get("replication_packets", 0)),
                    "player_instance_observed": bool(selected_stats.get("player_instance_observed", False)),
                    # These require explicit evidence; NEW_INSTANCE alone
                    # does not identify our character or another observer.
                    "character_spawn_observed": selected_stats.get("character_spawn_observed") is True,
                    "observer_visibility_verified": selected_stats.get("observer_visibility_verified") is True,
                    "connection_accepted": bool(selected_stats.get("connection_accepted", False)),
                    "avatar_data_observed": bool(selected_stats.get("avatar_data_observed", False)),
                    "heartbeat_packets": int(selected_stats.get("heartbeat_packets", 0) or 0),
                    "physics_packets": int(selected_stats.get("physics_packets", 0) or 0),
                    "established_decrypt_ok": int(selected_stats.get("established_decrypt_ok", 0) or 0),
                    "lifecycle": selected_stats.get("replication_snapshot", {}),
                    "player_ready_sent": int(selected_stats.get("player_ready_sent", 0) or 0),
                    "avatar_description_sent": int(selected_stats.get("avatar_description_sent", 0) or 0),
                    "physics_sent": int(selected_stats.get("physics_sent", 0) or 0),
                    "ack_sent": int(selected_stats.get("ack_sent", 0) or 0),
                }
                heartbeat = float(selected_stats.get("heartbeat_seconds") or 0.0)
                complete = bool(authenticated and app_connection
                                and selected_stats.get("replicator_registered", False)
                                and selected_stats.get("player_instance_observed", False)
                                and selected_stats.get("character_spawn_observed") is True
                                and selected_stats.get("avatar_data_observed") is True
                                and selected_stats.get("physics_packets", 0) > 0
                                and selected_stats.get("observer_visibility_verified") is True
                                and heartbeat >= 120.0)
                report["ok"] = complete
                report["stage"] = ("complete" if complete
                                    else ("session-unverified" if selected else "transport"))
        # Presence is authoritative server-side state.  Record both sides of
        # the headless attempt; a missing/old place here means the transport
        # reached only the handshake boundary, not a rendered game join.
        if isinstance(report, dict):
            # A cached sample is not an after-run observation.
            presence_after = read_account_presence(session)
            report["presence"] = {
                "before": presence_before,
                "after": presence_after,
                "samples": presence_samples[-32:],
            }
            # For the current headless target, a short authoritative Presence
            # transition is the useful milestone: it proves the account was
            # actually admitted to the requested place.  The final poll can
            # already be back to Website because the transport is being
            # closed, so do not erase an in-session observation.
            observed_in_session = any(
                isinstance(sample, dict)
                and sample.get("user_presence_type") == 2
                and str(sample.get("place_id")) == str(args.place_id)
                for sample in presence_samples
            )
            report["presence"]["observed_in_session"] = observed_in_session
            # A transport handshake must not be presented as a gameplay join
            # when Roblox Presence still reports Website/offline.  This gate
            # keeps the report honest until the full DataModel/replicator
            # registration path is implemented.
            if report.get("ok"):
                observed_place = presence_after.get("place_id")
                if (presence_after.get("ok") is not True
                        or presence_after.get("user_presence_type") != 2
                        or str(observed_place) != str(args.place_id)):
                        report["ok"] = False
                        report["stage"] = "presence-unverified"
            if (observed_in_session
                    and report.get("session", {}).get("authenticated") is True
                    and report.get("session", {}).get("app_connection") is True
                    and report.get("session", {}).get("replicator") is True):
                report["ok"] = True
                report["stage"] = "presence-observed"
    finally:
        presence_stop.set()
        presence_thread.join(timeout=2.0)
        session.close()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"ok": report["ok"], "stage": report["stage"], "output": str(output), "transport": report.get("transport", {})}, ensure_ascii=False))
    return 0 if report["ok"] else 2


def main() -> int:
    p = argparse.ArgumentParser(description="No-render bootstrap + RakNet-compatible liveness runner")
    p.add_argument("--launcher-root", default=r"C:\Users\killd\Desktop\Executor\PrivateGameLauncher")
    p.add_argument("--place-id", default="107778070777162")
    p.add_argument("--duration", type=float, default=180.0)
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--mtu", type=int, default=1492)
    p.add_argument("--output", default="runs/latest.json")
    p.add_argument("--profile", default=str(PROJECT_ROOT / "profiles" / "protocol_profile_0738.json"), help="build-specific wire profile")
    p.add_argument("--udmux-header-file", help="hex header template from a fresh UDMUX capture")
    p.add_argument("--udmux-header-auto", action="store_true",
                   help="generate a fresh 0.738 Request1 header skeleton for probing")
    p.add_argument("--request2-key-file", help="raw/hex 32-byte SessionCrypto key from the current session")
    p.add_argument("--request2-rupp-file", help="raw/hex 33-byte RUPP span from the current session")
    p.add_argument("--request2-token-file", help="raw/hex 66-byte token span from the current session")
    p.add_argument("--request2-trace-file", help="fresh runtime trace containing the current Request2 transcript/key")
    p.add_argument("--request2-pad-length", type=int, default=1160, help="outer UDMUX padding length (default: 1160)")
    p.add_argument("--request2-endpoint-port", type=int, help="override the Request2 endpoint port field")
    p.add_argument("--request2-no-padding", action="store_true", help="send the unpadded Request2 record")
    p.add_argument("--established-tx-key-file", help="raw/hex 32-byte current-epoch client-to-server key")
    p.add_argument("--established-rx-key-file", help="raw/hex 32-byte current-epoch server-to-client key")
    p.add_argument("--established-trace-file", help="internal transport trace containing current direction key spans")
    p.add_argument("--established-cipher", choices=("aes-256-gcm", "chacha20-poly1305"),
                   default="aes-256-gcm")
    p.add_argument(
        "--lifecycle-profile",
        default=str(PROJECT_ROOT / "profiles" / "lifecycle_0738.json"),
        help="JSON with exact lifecycle serializers (defaults to the matching 0.738 profile)",
    )
    p.add_argument("--fixture", action="store_true", help="run a local UDP fixture; do not read cookie.txt or contact external services")
    args = p.parse_args()
    try:
        args.udmux_header = load_udmux_header(args.udmux_header_file)
    except (OSError, ValueError) as exc:
        p.error(str(exc))
    if args.fixture:
        return run_fixture(args)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
