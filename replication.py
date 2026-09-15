"""Small, build-profiled replication boundary for RiftHeadless.

The transport owns AEAD and reliability; this module only decodes the
decrypted RakNet DATA payload and records the minimum server-side lifecycle
signals needed by a headless client.  Unknown property values are preserved
as bytes instead of being guessed without the build's schema.
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Any

from raknet_codec import EncapsulatedFrame, SplitReassembler


ID_CONNECTION_REQUEST_ACCEPTED = 0x10
ID_NEW_INCOMING_CONNECTION = 0x13
ID_SUBMIT_TICKET = 0x8A
ID_DATA = 0x83
ID_CONNECTED_PING = 0x00
ID_PHYSICS = 0x85
ID_CONNECTION_REQUEST = 0x09
ID_CONNECTION_ATTEMPT_FAILED = 0x11
ID_DISCONNECTION_NOTIFICATION = 0x13

# Replication block ids observed in the 0.738 stream.  They are kept in one
# place so a profile update does not require changing the transport.
BLOCK_NEW_INSTANCE = 0x02
BLOCK_PLAYER_READY = 0x03
BLOCK_AVATAR = 0x04
BLOCK_HEARTBEAT = 0x05
BLOCK_PHYSICS = 0x06


def _as_marker(value: Any) -> bytes:
    """Normalize one profile marker (text or hexadecimal) to bytes."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if not isinstance(value, str):
        raise ValueError("marker must be text or hex")
    text = value.strip()
    if text.startswith("hex:"):
        text = text[4:]
        text = "".join(ch for ch in text if ch in "0123456789abcdefABCDEF")
        if len(text) % 2:
            raise ValueError("hex marker has odd length")
        return bytes.fromhex(text)
    return text.encode("utf-8")


def encode_string(value: str | bytes) -> bytes:
    """Encode a profile string as a bounded little-endian length span."""
    raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    if len(raw) > 0xFFFF:
        raise ValueError("string span too large")
    return struct.pack("<H", len(raw)) + raw


def build_data_message(block_type: int, body: bytes = b"") -> bytes:
    """Build one opaque replication DATA message.

    The block body is deliberately caller supplied.  This gives each build
    profile a stable serializer boundary while preserving unknown fields.
    """
    if not 0 <= int(block_type) <= 0xFF:
        raise ValueError("block type out of range")
    return bytes((ID_DATA, int(block_type))) + bytes(body)


def build_player_ready(player_id: int, *, character: str = "") -> bytes:
    """Serialize the minimal PlayerReady profile message."""
    if not 0 <= int(player_id) <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("player id out of range")
    return build_data_message(BLOCK_PLAYER_READY,
                              struct.pack("<Q", int(player_id)) + encode_string(character))


def build_avatar_description(description: bytes | str) -> bytes:
    """Serialize an avatar-description span without interpreting its schema."""
    return build_data_message(BLOCK_AVATAR, encode_string(description))


def build_heartbeat(timestamp_ms: int) -> bytes:
    """Serialize the profile heartbeat block used by a lifecycle adapter."""
    if not 0 <= int(timestamp_ms) <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("timestamp out of range")
    return build_data_message(BLOCK_HEARTBEAT, struct.pack("<Q", int(timestamp_ms)))


def build_submit_ticket(client_ticket: bytes | str, security_token: bytes = b"") -> bytes:
    """Serialize the explicit Roblox ``ID_SUBMIT_TICKET`` payload.

    Current servers carry two length-prefixed byte spans.  The values are
    supplied by the join response/session profile; this function never
    derives or invents a token.  Lengths are little-endian BitStream fields.
    """
    ticket = client_ticket.encode("utf-8") if isinstance(client_ticket, str) else bytes(client_ticket)
    token = bytes(security_token)
    if len(ticket) > 0xFFFF or len(token) > 0xFFFF:
        raise ValueError("ticket/token too large")
    return bytes((ID_SUBMIT_TICKET,)) + struct.pack("<H", len(ticket)) + ticket + struct.pack("<H", len(token)) + token


def build_connected_ping(timestamp_ms: int) -> bytes:
    """Build RakNet's connected liveness message (ID_CONNECTED_PING)."""
    if not 0 <= int(timestamp_ms) <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("timestamp out of range")
    return bytes((ID_CONNECTED_PING,)) + struct.pack("<Q", int(timestamp_ms))


def build_physics_message(payload: bytes) -> bytes:
    """Wrap a profile-encoded physics body as ``ID_PHYSICS``.

    The 0.738 body schema is sent separately by the server, so callers pass
    the build-specific body bytes rather than relying on an invented CFrame
    layout.  This keeps the movement hook ready without corrupting the stream.
    """
    body = bytes(payload)
    if len(body) > 0xFFFF:
        raise ValueError("physics payload too large")
    return bytes((ID_PHYSICS,)) + body


def _u24le(data: bytes, offset: int) -> int:
    if offset + 3 > len(data):
        raise ValueError("truncated u24")
    return int.from_bytes(data[offset:offset + 3], "little")


def parse_datagram(plaintext: bytes) -> dict[str, Any]:
    """Parse one decrypted RakNet DATA/ACK datagram."""
    data = bytes(plaintext)
    if not data:
        raise ValueError("empty RakNet datagram")
    flags = data[0]
    if flags & 0x40:
        return {"flags": flags, "kind": "ack", "messages": []}
    if not flags & 0x80 or len(data) < 4:
        raise ValueError(f"unsupported RakNet flags 0x{flags:02x}")
    sequence = _u24le(data, 1)
    offset = 4
    messages: list[dict[str, Any]] = []
    while offset < len(data):
        frame = EncapsulatedFrame.decode(data[offset:])
        consumed = frame.wire_size
        if consumed <= 0 or offset + consumed > len(data):
            raise ValueError("truncated encapsulated frame")
        item: dict[str, Any] = {
            "payload": frame.payload,
            "reliable": frame.reliable,
            "ordered": frame.ordered,
            "message_index": frame.message_index,
            "order_index": frame.order_index,
            "order_channel": frame.order_channel,
            "reliability_mode": frame.reliability_mode,
            "split_count": frame.split_count,
            "split_id": frame.split_id,
            "split_index": frame.split_index,
        }
        if frame.payload:
            item["id"] = frame.payload[0]
            if frame.payload[0] == ID_DATA and len(frame.payload) > 1:
                item["block_type"] = frame.payload[1]
        messages.append(item)
        offset += consumed
    return {"flags": flags, "kind": "data", "sequence": sequence, "messages": messages}


def parse_ack(plaintext: bytes) -> dict[str, Any]:
    """Parse RakNet ACK/NACK ranges into individual sequence numbers.

    Roblox uses the compact ``0xc0 | count:u16be | records`` form.  A record
    begins with ``0`` for a single sequence and ``1`` for an inclusive range,
    both followed by little-endian 24-bit values.  Unknown trailing bytes are
    rejected rather than being treated as an acknowledgement, which keeps the
    reliability window from advancing on malformed input.
    """
    data = bytes(plaintext)
    if len(data) < 4 or data[0] not in (0xC0, 0xD0, 0xA0, 0xB0):
        raise ValueError("not an ACK/NACK datagram")
    count = int.from_bytes(data[1:3], "big")
    offset = 3
    sequences: list[int] = []
    for _ in range(count):
        if offset >= len(data):
            raise ValueError("truncated ACK record")
        is_single = data[offset]
        offset += 1
        if offset + 3 > len(data):
            raise ValueError("truncated ACK sequence")
        first = int.from_bytes(data[offset:offset + 3], "little")
        offset += 3
        last = first
        if not is_single:
            if offset + 3 > len(data):
                raise ValueError("truncated ACK range")
            last = int.from_bytes(data[offset:offset + 3], "little")
            offset += 3
            if last < first or last - first > 0xFFFFFF:
                raise ValueError("invalid ACK range")
        # Bound expansion so a corrupt range cannot allocate unbounded memory.
        if len(sequences) + (last - first + 1) > 0x10000:
            raise ValueError("ACK range is too large")
        sequences.extend(range(first, last + 1))
    if data[0] in (0xD0, 0xB0) and len(data) - offset == 6:
        offset += 6
    if offset != len(data):
        raise ValueError("unexpected ACK trailing bytes")
    return {"flags": data[0], "kind": "ack", "sequences": sequences}


@dataclass(slots=True)
class ReplicatorState:
    """Lifecycle and bounded evidence collected from decrypted packets."""

    connection_accepted: bool = False
    replicator_registered: bool = False
    player_instance_observed: bool = False
    avatar_data_observed: bool = False
    heartbeat_packets: int = 0
    physics_packets: int = 0
    # These two fields are intentionally separate from the generic
    # ``player_instance_observed`` flag.  A NEW_INSTANCE block can describe a
    # service object, so character/observer gates only open when the payload
    # carries an identity or an explicit profile marker.
    character_spawn_observed: bool = False
    observer_visibility_verified: bool = False
    player_ready_observed: bool = False
    identity_user_id: int | None = None
    identity_name: str | None = None
    character_markers: tuple[bytes, ...] = field(default_factory=tuple)
    avatar_markers: tuple[bytes, ...] = field(default_factory=tuple)
    observer_markers: tuple[bytes, ...] = field(default_factory=tuple)
    block_map: dict[str, tuple[int, ...]] = field(default_factory=dict)
    block_counts: dict[int, int] = field(default_factory=dict)
    application_ids: dict[int, int] = field(default_factory=dict)
    bootstrap_observed: bool = False
    schema_observed: bool = False
    split_messages_completed: int = 0
    first_data_at: float | None = None
    last_data_at: float | None = None
    first_heartbeat_at: float | None = None
    last_heartbeat_at: float | None = None
    last_sequence: int | None = None
    last_referent: int | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    _split_reassembler: SplitReassembler = field(default_factory=SplitReassembler,
                                                   repr=False)

    def configure(self, profile: dict[str, Any] | None = None, *,
                  user_id: int | None = None, username: str | None = None) -> None:
        """Apply optional build/profile hints without changing wire parsing.

        Profiles may provide marker strings and block ids under ``replication``
        (or directly at the top level).  Unknown keys are ignored so a newer
        profile can be used with an older parser.  Identity values are only
        used for matching bytes already present in a decrypted packet.
        """
        if user_id is not None:
            try:
                self.identity_user_id = int(user_id)
            except (TypeError, ValueError):
                self.identity_user_id = None
        if username:
            self.identity_name = str(username)
        cfg = profile.get("replication", profile) if isinstance(profile, dict) else {}
        if not isinstance(cfg, dict):
            return
        for name in ("character_markers", "avatar_markers", "observer_markers"):
            values = cfg.get(name)
            if values is None:
                continue
            if isinstance(values, (str, bytes, bytearray)):
                values = [values]
            try:
                setattr(self, name, tuple(_as_marker(item) for item in values))
            except (TypeError, ValueError):
                continue
        blocks = cfg.get("blocks")
        if isinstance(blocks, dict):
            for name, values in blocks.items():
                if isinstance(values, int):
                    values = [values]
                if isinstance(values, (list, tuple)):
                    try:
                        parsed = tuple(int(item) & 0xFF for item in values)
                    except (TypeError, ValueError):
                        continue
                    if parsed:
                        self.block_map[str(name)] = parsed

    def observe_control(self, payload: bytes) -> dict[str, Any]:
        """Consume a clear/inner control payload (accepted/disconnect)."""
        data = bytes(payload)
        ident = data[0] if data else None
        if ident in (ID_CONNECTION_REQUEST_ACCEPTED, ID_NEW_INCOMING_CONNECTION):
            self.connection_accepted = True
        return {"kind": "control", "id": ident, "accepted": self.connection_accepted}

    def _contains_identity(self, payload: bytes) -> bool:
        if self.identity_user_id is None:
            return False
        value = int(self.identity_user_id)
        candidates = {value.to_bytes(8, "little"), value.to_bytes(8, "big"),
                      (value & 0xFFFFFFFF).to_bytes(4, "little"),
                      (value & 0xFFFFFFFF).to_bytes(4, "big")}
        return any(candidate in payload for candidate in candidates)

    @staticmethod
    def _contains_markers(payload: bytes, markers: tuple[bytes, ...]) -> bool:
        return any(marker and marker in payload for marker in markers)

    def _apply_block(self, block: int, payload: bytes) -> None:
        now = time.monotonic()
        if block == BLOCK_NEW_INSTANCE:
            self.player_instance_observed = True
            explicit_character = self._contains_markers(payload, self.character_markers)
            if self.identity_name:
                explicit_character = explicit_character or self.identity_name.encode("utf-8") in payload
            # A matching account id is stronger than a generic instance name.
            self.character_spawn_observed = explicit_character or self._contains_identity(payload)
        elif block == BLOCK_PLAYER_READY:
            self.player_ready_observed = True
            self.character_spawn_observed = self.character_spawn_observed or self._contains_identity(payload)
        elif block == BLOCK_AVATAR:
            self.avatar_data_observed = True
        elif block == BLOCK_HEARTBEAT:
            self.heartbeat_packets += 1
            self.first_heartbeat_at = self.first_heartbeat_at or now
            self.last_heartbeat_at = now
        elif block == BLOCK_PHYSICS:
            self.physics_packets += 1
        if self._contains_markers(payload, self.avatar_markers):
            self.avatar_data_observed = True
        if self._contains_markers(payload, self.observer_markers):
            self.observer_visibility_verified = True
        if self._contains_identity(payload) and block not in (BLOCK_NEW_INSTANCE, BLOCK_PLAYER_READY):
            # A later property/appearance block referencing the local user is
            # valid character evidence even when the instance arrived first.
            self.character_spawn_observed = True

    def apply(self, plaintext: bytes) -> dict[str, Any]:
        parsed = parse_datagram(plaintext)
        if parsed["kind"] != "data":
            return parsed
        self.last_sequence = parsed.get("sequence")
        complete_messages: list[dict[str, Any]] = []
        for msg in parsed["messages"]:
            raw_frame = EncapsulatedFrame(
                bytes(msg["payload"]), bool(msg["reliable"]), bool(msg["ordered"]),
                int(msg["message_index"]), int(msg["order_index"]),
                int(msg["order_channel"]),
                split_count=int(msg.get("split_count") or 0),
                split_id=int(msg.get("split_id") or 0),
                split_index=int(msg.get("split_index") or 0),
                reliability_mode=msg.get("reliability_mode"))
            complete = self._split_reassembler.push(raw_frame)
            if complete is None:
                continue
            if raw_frame.split:
                self.split_messages_completed += 1
            payload = bytes(complete.payload)
            if not payload:
                continue
            complete_messages.append({
                **msg,
                "payload": payload,
                "id": payload[0],
                "split_count": 0,
                "reassembled": bool(raw_frame.split),
            })
            now = time.monotonic()
            ident = payload[0]
            self.application_ids[ident] = self.application_ids.get(ident, 0) + 1
            if ident in (ID_CONNECTION_REQUEST_ACCEPTED, ID_NEW_INCOMING_CONNECTION):
                self.connection_accepted = True
            if ident == 0x93:
                self.bootstrap_observed = True
            if ident == 0x97:
                self.schema_observed = True
            if ident == ID_PHYSICS:
                self.physics_packets += 1
            if ident != ID_DATA or len(payload) < 2:
                continue
            self.replicator_registered = True
            block = payload[1]
            self.block_counts[block] = self.block_counts.get(block, 0) + 1
            # A monotonic timestamp is useful for diagnosing a stalled
            # lifecycle without persisting any account/session material.
            self.first_data_at = self.first_data_at or now
            self.last_data_at = now
            self._apply_block(block, payload)
            # Profile aliases override the built-in ids while retaining the
            # built-in behavior for fields not mentioned by a profile.
            if block in self.block_map.get("character", ()):
                self.character_spawn_observed = True
            if block in self.block_map.get("avatar", ()):
                self.avatar_data_observed = True
            if block in self.block_map.get("observer", ()):
                self.observer_visibility_verified = True
            if block in self.block_map.get("heartbeat", ()) and block != BLOCK_HEARTBEAT:
                self.heartbeat_packets += 1
                self.first_heartbeat_at = self.first_heartbeat_at or now
                self.last_heartbeat_at = now
            if block in self.block_map.get("physics", ()) and block != BLOCK_PHYSICS:
                self.physics_packets += 1
            # Length-prefixed strings are enough to identify avatar/schema
            # data while retaining opaque values for later profile decoding.
            for i in range(2, len(payload) - 1):
                n = payload[i]
                if 1 <= n <= 64 and i + 1 + n <= len(payload):
                    chunk = payload[i + 1:i + 1 + n]
                    if all(32 <= c < 127 for c in chunk):
                        text = chunk.decode("ascii", "ignore")
                        if text.lower() in {"humanoid", "character", "avatar", "bodycolors", "accessory"}:
                            self.avatar_data_observed = True
                            if text.lower() in {"humanoid", "character"}:
                                self.character_spawn_observed = True
                            break
            if len(self.events) < 64:
                self.events.append({"id": ident, "block_type": block, "length": len(payload)})
        parsed["complete_messages"] = complete_messages
        return parsed

    def snapshot(self) -> dict[str, Any]:
        """Return a bounded lifecycle snapshot suitable for a run report."""
        age = 0.0
        if self.first_data_at is not None:
            import time
            age = max(0.0, (self.last_data_at or time.monotonic()) - self.first_data_at)
        heartbeat_span = 0.0
        if self.first_heartbeat_at is not None and self.last_heartbeat_at is not None:
            heartbeat_span = max(0.0, self.last_heartbeat_at - self.first_heartbeat_at)
        gates = {
            "replicator_registration": self.replicator_registered,
            "player_ready_character_spawn": self.player_instance_observed,
            "avatar_description": self.avatar_data_observed,
            "heartbeat": self.heartbeat_packets > 0,
            "movement_physics": self.physics_packets > 0,
        }
        return {
            "connection_accepted": self.connection_accepted,
            "replicator_registered": self.replicator_registered,
            "player_instance_observed": self.player_instance_observed,
            "avatar_data_observed": self.avatar_data_observed,
            "character_spawn_observed": self.character_spawn_observed,
            "observer_visibility_verified": self.observer_visibility_verified,
            "player_ready_observed": self.player_ready_observed,
            "heartbeat_packets": self.heartbeat_packets,
            "physics_packets": self.physics_packets,
            "block_counts": {f"0x{k:02x}": v for k, v in sorted(self.block_counts.items())},
            "application_ids": {f"0x{k:02x}": v for k, v in sorted(self.application_ids.items())},
            "bootstrap_observed": self.bootstrap_observed,
            "schema_observed": self.schema_observed,
            "split_messages_completed": self.split_messages_completed,
            "data_span_seconds": round(age, 3),
            "heartbeat_span_seconds": round(heartbeat_span, 3),
            "last_sequence": self.last_sequence,
            "last_referent": self.last_referent,
            "gates": gates,
            "all_gates_observed": all(gates.values()),
        }


if __name__ == "__main__":
    from raknet_codec import EncapsulatedFrame
    wire = bytes((0x80, 1, 0, 0)) + EncapsulatedFrame(bytes((ID_DATA, 0x02)), True, True, 1, 1, 0).encode()
    s = ReplicatorState(); s.apply(wire)
    assert s.replicator_registered and s.player_instance_observed
    print("replication selftest: ok")
