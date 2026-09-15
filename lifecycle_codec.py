"""Small codecs for the 0.738 Replicator lifecycle items.

The surrounding RakNet DATA/reliability envelope lives in ``rift_headless``.
This module only owns the fixed-width marker/tag items observed on the wire.
"""
from __future__ import annotations

import struct


ID_DATA = 0x83
ID_MARKER = 0x84
ITEM_MARKER = 0x04
ITEM_PING = 0x05
ITEM_PING_BACK = 0x06
ITEM_TAG = 0x10
ITEM_PROGRESS = 0x23
ITEM_REQUEST_CHARACTER = 0x08
ITEM_ISR_TIMESTAMP = 0x23


def parse_marker(packet: bytes) -> int:
    """Return the server marker from ``84 | marker:u32le``."""
    data = bytes(packet)
    if len(data) != 5 or data[0] != ID_MARKER:
        raise ValueError("invalid marker packet")
    return struct.unpack_from("<I", data, 1)[0]


def build_marker_echo(marker: int) -> bytes:
    """Build the MarkerItem carried by a client DATA message."""
    if not 0 <= int(marker) <= 0xFFFFFFFF:
        raise ValueError("marker out of range")
    return bytes((ID_DATA, ITEM_MARKER)) + struct.pack("<I", int(marker))


def build_marker_isr(marker: int, timestamp_ms: int) -> bytes:
    """Build the native coalesced marker + ISR lifecycle item."""
    if not 0 <= int(marker) <= 0xFFFFFFFF:
        raise ValueError("marker out of range")
    if not 0 <= int(timestamp_ms) <= 0xFFFFFFFF:
        raise ValueError("ISR timestamp out of range")
    return (bytes((ID_DATA, ITEM_MARKER)) + struct.pack("<I", int(marker))
            + bytes((ITEM_ISR_TIMESTAMP,)) + struct.pack("<I", int(timestamp_ms))
            + b"\x00")


def build_tag(tag: int) -> bytes:
    """Build the native TagItem (sub-id 0x10)."""
    if not 0 <= int(tag) <= 0xFFFFFFFF:
        raise ValueError("tag out of range")
    return bytes((ID_DATA, ITEM_TAG)) + struct.pack("<I", int(tag)) + b"\x00"


def parse_tag(packet: bytes) -> tuple[int, bool]:
    data = bytes(packet)
    if len(data) != 7 or data[:2] != bytes((ID_DATA, ITEM_TAG)):
        raise ValueError("invalid tag packet")
    if data[6] != 0:
        raise ValueError("invalid DATA terminator")
    return struct.unpack_from("<I", data, 2)[0], False


def parse_progress_token(packet: bytes) -> int:
    """Read a terminal 0x23 checkpoint from a simple DATA control packet."""
    data = bytes(packet)
    if len(data) < 7 or data[0] != ID_DATA or data[-1] != 0:
        raise ValueError("invalid progress packet")
    offset = 1
    progress = None
    while offset < len(data) - 1:
        item = data[offset]
        if item not in (ITEM_TAG, ITEM_PROGRESS) or offset + 5 > len(data) - 1:
            raise ValueError("not a simple lifecycle control packet")
        value = struct.unpack_from("<I", data, offset + 1)[0]
        if item == ITEM_PROGRESS:
            progress = value
        offset += 5
    if offset != len(data) - 1 or progress is None:
        raise ValueError("progress token missing")
    return progress


def build_progress_ack(token: int) -> bytes:
    if not 0 <= int(token) <= 0xFFFFFFFF:
        raise ValueError("progress token out of range")
    return bytes((ID_DATA, ITEM_PROGRESS)) + struct.pack("<I", int(token)) + b"\x00"


def build_request_character(feature_mask: int, spawn_name: str = "") -> bytes:
    """Build ClientReplicator::RequestCharacterItem for protocol 0.738."""
    if not 0 <= int(feature_mask) <= 0xFFFFFFFF:
        raise ValueError("feature mask out of range")
    raw = str(spawn_name).encode("utf-8")
    if len(raw) > 0xFFFFFFFF:
        raise ValueError("spawn name too large")
    return (bytes((ID_DATA, ITEM_REQUEST_CHARACTER))
            + struct.pack("<II", int(feature_mask), len(raw)) + raw + b"\x00")


def build_isr_timestamp(timestamp_ms: int) -> bytes:
    """Build the native ``ISRTimestampItem`` (type 0x23)."""
    if not 0 <= int(timestamp_ms) <= 0xFFFFFFFF:
        raise ValueError("ISR timestamp out of range")
    return bytes((ID_DATA, ITEM_ISR_TIMESTAMP)) + struct.pack("<I", int(timestamp_ms)) + b"\x00"


def build_ping_item(ping_ms: int, *, clock_ms: int | None = None,
                    sample_flag: bool = False, item_flags: int = 0x00,
                    send_kbps: float = 47.35103225708008,
                    receive_kbps: float = 42.76241683959961,
                    packet_loss: float = 33.01939010620117,
                    feature_mask: int = 0, xor_mask: int = 7,
                    memory_mb: float = 853.47265625) -> bytes:
    """Build the fixed-width 0.738 PingItem captured from the native client."""
    ping = int(ping_ms)
    clock = ping if clock_ms is None else int(clock_ms)
    if not 0 <= ping <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("ping value out of range")
    if not 0 <= clock <= 0xFFFFFFFF:
        raise ValueError("clock value out of range")
    if not 0 <= int(item_flags) <= 0xFF:
        raise ValueError("item flags out of range")
    body = struct.pack(
        "<BQIfffIIBIfB",
        int(item_flags), ping, clock,
        float(send_kbps), float(receive_kbps), float(packet_loss),
        int(feature_mask) & 0xFFFFFFFF, 0xFFFFFFFF, bool(sample_flag),
        (ping & 0xFFFFFFFF) ^ (int(xor_mask) & 0xFFFFFFFF),
        float(memory_mb), 0,
    )
    return bytes((ID_DATA, ITEM_PING)) + body
