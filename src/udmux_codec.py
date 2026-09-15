"""Codec for Roblox's UDMUX/RUPP envelope used by build 0.738.

The four-byte prefix is ``0x01 00 00 H`` where ``H`` is the complete header
length and also identifies the direction (``0x17`` or ``0x1f``).  The header
starts with ``01 11 <subflag>``; established encrypted traffic uses subflag
``02`` and the initial offline exchange uses ``01``.  The rest of the header
contains a 16-byte epoch tag and, for direction ``0x1f``, an 8-byte mux tag.
"""
from __future__ import annotations

from dataclasses import dataclass


UDMUX_RECORD = 0x01
# A four-byte record is used for the clear control envelope observed on the
# first OpenReply1 path.  It has no epoch/mux header; the payload starts at
# offset four (``01 00 00 04 | 7e ...``).
CONTROL_HEADER_SIZE = 0x04
MIN_HEADER_SIZE = 0x17
MAX_HEADER_SIZE = 0x1F


@dataclass(frozen=True, slots=True)
class UdmuxFrame:
    record_type: int
    header: bytes
    payload: bytes
    direction: int
    subflag: int

    @property
    def header_size(self) -> int:
        return self.direction

    @property
    def is_control(self) -> bool:
        """Whether this is the clear four-byte control envelope."""
        return self.direction == CONTROL_HEADER_SIZE

    @property
    def inner_id(self) -> int | None:
        return self.payload[0] if self.payload else None


def decode(packet: bytes) -> UdmuxFrame:
    """Decode one UDMUX record and return its untouched inner payload."""
    if len(packet) < CONTROL_HEADER_SIZE:
        raise ValueError("UDMUX packet is shorter than its fixed header")
    record_type = packet[0]
    if packet[1] or packet[2]:
        raise ValueError("invalid UDMUX reserved header bytes")
    direction = packet[3]
    # Clear control records intentionally omit the normal subflag/epoch
    # header.  Keeping them as a first-class frame prevents the receiver from
    # treating the leading 0x7e/0x78 as an outer record id.
    if direction == CONTROL_HEADER_SIZE:
        return UdmuxFrame(record_type, b"", packet[CONTROL_HEADER_SIZE:], direction, 0)
    if direction not in (0x17, 0x1F):
        raise ValueError(f"invalid UDMUX direction/header size: {direction:#x}")
    if len(packet) < direction:
        raise ValueError("UDMUX packet is truncated before payload")
    header = packet[4:direction]
    if len(header) < 3 or header[:2] != b"\x01\x11" or header[2] not in (1, 2):
        raise ValueError("invalid UDMUX subflags")
    return UdmuxFrame(record_type, header, packet[direction:], direction, header[2])


def encode(payload: bytes, *, header: bytes = b"", direction: int | None = None,
           record_type: int = UDMUX_RECORD) -> bytes:
    """Encode a record when a caller already has a captured header template.

    ``header`` is the exact byte sequence beginning at packet offset 4.  Its
    length determines ``direction`` when omitted, which makes extracted
    per-session templates round-trip without hidden constants.
    """
    if not 0 <= record_type <= 0xFF:
        raise ValueError("record_type out of range")
    if direction is None:
        direction = 4 + len(header)
    if direction == CONTROL_HEADER_SIZE:
        if header:
            raise ValueError("control UDMUX records have no header bytes")
        return bytes((record_type, 0, 0, direction)) + payload
    if direction not in (0x17, 0x1F) or len(header) != direction - 4:
        raise ValueError("UDMUX header size out of range")
    if len(header) < 3 or header[:2] != b"\x01\x11" or header[2] not in (1, 2):
        raise ValueError("UDMUX subflags must be 01 11 01/02")
    return bytes((record_type, 0, 0, direction)) + header + payload


def unwrap_inner(packet: bytes) -> bytes:
    """Return an inner payload, accepting direct RakNet packets as-is."""
    if packet and packet[0] == UDMUX_RECORD and len(packet) >= 4:
        try:
            frame = decode(packet)
            # The four-byte control envelope and subflag-01 offline exchange
            # are cleartext.  Established subflag-02 payloads are AEAD
            # ciphertext and must remain intact for the SessionCrypto layer.
            if frame.is_control or frame.subflag == 1:
                return frame.payload
        except ValueError:
            pass
    return packet
