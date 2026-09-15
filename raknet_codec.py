"""Minimal RakNet datagram codec used by the headless transport boundary."""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field


_RELIABLE = {2, 3, 4, 6, 7}
_ORDERED = {1, 3, 4, 7}
_SEQUENCED = {1, 4}


def _u24(value: int) -> bytes:
    # RakNet's BitStream writes the 24-bit sequence fields least-significant
    # byte first.  The old big-endian helper happened to pass zero/small
    # fixtures but produced invalid message/order numbers on a live stream.
    return int(value & 0xFFFFFF).to_bytes(3, "little")


def _read_u24(data: bytes, offset: int) -> tuple[int, int]:
    end = offset + 3
    if end > len(data):
        raise ValueError("truncated u24")
    return int.from_bytes(data[offset:end], "little"), end


@dataclass(slots=True)
class EncapsulatedFrame:
    payload: bytes
    reliable: bool = True
    ordered: bool = False
    message_index: int = 0
    order_index: int = 0
    order_channel: int = 0
    sequencing_index: int = 0
    split_count: int = 0
    split_id: int = 0
    split_index: int = 0
    reliability_mode: int | None = field(default=None, compare=False)
    wire_size: int = field(default=0, compare=False, repr=False)

    @property
    def split(self) -> bool:
        return self.split_count > 0

    def encode(self) -> bytes:
        # RakNet's encapsulated header: reliability in the high nibble and
        # split flag in bit 4, followed by a 16-bit bit-length payload size.
        reliability = self.reliability_mode
        if reliability is None:
            reliability = 3 if self.reliable and self.ordered else (2 if self.reliable else 0)
        if reliability not in range(8):
            raise ValueError("invalid RakNet reliability mode")
        header = bytes((((reliability << 5) & 0xE0) | (0x10 if self.split else 0),)) + \
            struct.pack(">H", len(self.payload) * 8)
        if reliability in _RELIABLE:
            header += _u24(self.message_index)
        if reliability in _SEQUENCED:
            header += _u24(self.sequencing_index)
        if reliability in _ORDERED:
            header += _u24(self.order_index) + bytes((self.order_channel & 0xFF,))
        if self.split:
            if not 0 < self.split_count <= 0xFFFFFFFF:
                raise ValueError("invalid split count")
            if not 0 <= self.split_index < self.split_count:
                raise ValueError("invalid split index")
            header += struct.pack(">IHI", self.split_count, self.split_id & 0xFFFF,
                                  self.split_index)
        return header + self.payload

    @classmethod
    def decode(cls, data: bytes) -> "EncapsulatedFrame":
        if len(data) < 3:
            raise ValueError("truncated encapsulated frame")
        flags, bit_length = data[0], struct.unpack(">H", data[1:3])[0]
        reliability = (flags >> 5) & 7
        reliable = reliability in _RELIABLE
        ordered = reliability in _ORDERED
        split = bool(flags & 0x10)
        offset = 3
        message_index = 0
        order_index = 0
        channel = 0
        sequencing_index = 0
        if reliable:
            message_index, offset = _read_u24(data, offset)
        if reliability in _SEQUENCED:
            sequencing_index, offset = _read_u24(data, offset)
        if ordered:
            order_index, offset = _read_u24(data, offset)
            if offset >= len(data):
                raise ValueError("truncated ordered frame")
            channel = data[offset]
            offset += 1
        split_count = split_id = split_index = 0
        if split:
            if offset + 10 > len(data):
                raise ValueError("truncated split frame")
            split_count, split_id, split_index = struct.unpack_from(">IHI", data, offset)
            offset += 10
            if not split_count or split_index >= split_count:
                raise ValueError("invalid split frame")
        payload_size = (bit_length + 7) // 8
        payload = data[offset:offset + payload_size]
        if len(payload) != payload_size:
            raise ValueError("truncated payload")
        return cls(payload, reliable, ordered, message_index, order_index, channel,
                   sequencing_index, split_count, split_id, split_index,
                   reliability, offset + payload_size)


@dataclass(slots=True)
class PendingFrame:
    frame: EncapsulatedFrame
    sent_at: float
    attempts: int = 1


class ReliabilityWindow:
    """Bounded ACK/resend bookkeeping; packet I/O stays in the caller."""

    def __init__(self, resend_after: float = 0.75, max_pending: int = 4096):
        self.resend_after = resend_after
        self.max_pending = max_pending
        self.next_message_index = 0
        self.next_order_index: dict[int, int] = {}
        self.pending: dict[int, PendingFrame] = {}

    def track(self, payload: bytes, ordered: bool = False, channel: int = 0) -> EncapsulatedFrame:
        if len(self.pending) >= self.max_pending:
            raise BufferError("reliability window full")
        order_index = self.next_order_index.get(channel & 0xFF, 0) if ordered else 0
        frame = EncapsulatedFrame(payload, True, ordered, self.next_message_index,
                                  order_index, channel)
        self.next_message_index = (self.next_message_index + 1) & 0xFFFFFF
        if ordered:
            self.next_order_index[channel & 0xFF] = (order_index + 1) & 0xFFFFFF
        self.pending[frame.message_index] = PendingFrame(frame, time.monotonic())
        return frame

    def track_split(self, payload: bytes, max_payload: int, *, ordered: bool = False,
                    channel: int = 0, split_id: int = 0) -> list[EncapsulatedFrame]:
        """Track one application message as multiple RakNet split frames."""
        body = bytes(payload)
        if max_payload <= 0:
            raise ValueError("max_payload must be positive")
        count = max(1, (len(body) + max_payload - 1) // max_payload)
        if count == 1:
            return [self.track(body, ordered=ordered, channel=channel)]
        if len(self.pending) + count > self.max_pending:
            raise BufferError("reliability window full")
        order_channel = channel & 0xFF
        order_index = self.next_order_index.get(order_channel, 0) if ordered else 0
        now = time.monotonic()
        frames: list[EncapsulatedFrame] = []
        for index in range(count):
            frame = EncapsulatedFrame(
                body[index * max_payload:(index + 1) * max_payload],
                True, ordered, self.next_message_index, order_index, order_channel,
                split_count=count, split_id=split_id & 0xFFFF, split_index=index,
            )
            self.next_message_index = (self.next_message_index + 1) & 0xFFFFFF
            self.pending[frame.message_index] = PendingFrame(frame, now)
            frames.append(frame)
        if ordered:
            self.next_order_index[order_channel] = (order_index + 1) & 0xFFFFFF
        return frames

    def acknowledge(self, message_index: int) -> bool:
        return self.pending.pop(message_index & 0xFFFFFF, None) is not None

    def due(self, now: float | None = None) -> list[PendingFrame]:
        now = time.monotonic() if now is None else now
        ready: list[PendingFrame] = []
        for pending in self.pending.values():
            if now - pending.sent_at >= self.resend_after:
                pending.sent_at = now
                pending.attempts += 1
                ready.append(pending)
        return ready


class SplitReassembler:
    """Bounded RakNet split-frame reassembly keyed by stream/order identity."""

    def __init__(self, max_groups: int = 128, max_parts: int = 4096,
                 max_bytes: int = 16 * 1024 * 1024):
        self.max_groups = max_groups
        self.max_parts = max_parts
        self.max_bytes = max_bytes
        self._groups: dict[tuple[int, int, int, int], dict[int, bytes]] = {}
        self._counts: dict[tuple[int, int, int, int], int] = {}
        self._templates: dict[tuple[int, int, int, int], EncapsulatedFrame] = {}

    def push(self, frame: EncapsulatedFrame) -> EncapsulatedFrame | None:
        if not frame.split:
            return frame
        if frame.split_count > self.max_parts:
            raise ValueError("split group is too large")
        mode = int(frame.reliability_mode if frame.reliability_mode is not None else
                   (3 if frame.reliable and frame.ordered else 2 if frame.reliable else 0))
        key = (frame.split_id, frame.order_channel, frame.order_index, mode)
        if key not in self._groups and len(self._groups) >= self.max_groups:
            oldest = next(iter(self._groups))
            self._groups.pop(oldest, None)
            self._counts.pop(oldest, None)
            self._templates.pop(oldest, None)
        if key in self._counts and self._counts[key] != frame.split_count:
            self._groups.pop(key, None)
            self._counts.pop(key, None)
            self._templates.pop(key, None)
            raise ValueError("split count changed within group")
        parts = self._groups.setdefault(key, {})
        self._counts[key] = frame.split_count
        self._templates.setdefault(key, frame)
        parts.setdefault(frame.split_index, bytes(frame.payload))
        if sum(map(len, parts.values())) > self.max_bytes:
            self._groups.pop(key, None)
            self._counts.pop(key, None)
            self._templates.pop(key, None)
            raise ValueError("split group exceeds byte limit")
        if len(parts) != frame.split_count:
            return None
        try:
            payload = b"".join(parts[index] for index in range(frame.split_count))
        except KeyError:
            return None
        template = self._templates.pop(key)
        self._groups.pop(key, None)
        self._counts.pop(key, None)
        return EncapsulatedFrame(payload, template.reliable, template.ordered,
                                 template.message_index, template.order_index,
                                 template.order_channel, template.sequencing_index,
                                 reliability_mode=template.reliability_mode)


def parse_connected_datagram(data: bytes) -> tuple[int, list[EncapsulatedFrame]]:
    """Parse a connected RakNet datagram (0x80..0x8f).

    The 24-bit sequence is followed by one or more encapsulated frames.  A
    frame's bit-length makes the parser safe for coalesced packets and keeps
    encrypted/application payloads opaque to the transport layer.
    """
    if len(data) < 4 or not 0x80 <= data[0] <= 0x8F:
        raise ValueError("not a connected RakNet datagram")
    sequence = int.from_bytes(data[1:4], "little")
    frames: list[EncapsulatedFrame] = []
    offset = 4
    while offset < len(data):
        frame = EncapsulatedFrame.decode(data[offset:])
        consumed = frame.wire_size
        if consumed <= 0 or offset + consumed > len(data):
            raise ValueError("truncated connected frame")
        frames.append(frame)
        offset += consumed
    return sequence, frames


def build_ack(sequence: int) -> bytes:
    """Build a single-sequence RakNet ACK datagram.

    The sequence field follows the same little-endian 24-bit BitStream
    convention used by the connected DATA codec.  Keeping ACK generation in
    the codec lets the established transport acknowledge a verified DATA
    frame without coupling reliability to the application schema.
    """
    if not 0 <= int(sequence) <= 0xFFFFFF:
        raise ValueError("ACK sequence out of range")
    # Keep the compact single-record form used by the current wire profile.
    # Some Roblox builds write ``1`` for the record marker even when first and
    # last are equal; ``parse_ack`` accepts that legacy spelling as well.
    return b"\xC0" + (1).to_bytes(2, "big") + b"\x01" + _u24(sequence)


def parse_ack(data: bytes) -> list[int]:
    """Decode ACK/NACK records and expand their bounded ranges."""
    if len(data) < 4 or data[0] not in (0xC0, 0xD0, 0xA0, 0xB0):
        raise ValueError("not an ACK/NACK datagram")
    count = int.from_bytes(data[1:3], "big")
    offset = 3
    result: list[int] = []
    for _ in range(count):
        if offset >= len(data):
            raise ValueError("truncated ACK record")
        marker = data[offset]
        offset += 1
        first, offset = _read_u24(data, offset)
        last = first
        if not marker:
            last, offset = _read_u24(data, offset)
            if last < first or last - first > 0x10000:
                raise ValueError("invalid ACK range")
        if len(result) + last - first + 1 > 0x10000:
            raise ValueError("ACK expansion too large")
        result.extend(range(first, last + 1))
    # 0xd0/0xb0 records append two u24 transport metrics after the ACK list.
    if data[0] in (0xD0, 0xB0) and len(data) - offset == 6:
        offset += 6
    if offset != len(data):
        raise ValueError("unexpected ACK trailing bytes")
    return result
