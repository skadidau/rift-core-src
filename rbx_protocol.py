"""Build-profiled Roblox RakNet application framing.

Only fields confirmed by the 0.737/0.738 IDA notes are encoded here.  The
opaque AEAD body of RbxOpenRequest2 stays an explicit input so callers cannot
accidentally send a fabricated authentication transcript.
"""
from __future__ import annotations

import struct
import ipaddress
from dataclasses import dataclass
from typing import Iterable

from raknet_codec import EncapsulatedFrame

MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")
RBX_OPEN_REPLY1 = 0x7E
RBX_OPEN_REQUEST2 = 0x78
APP_CONNECTION_REQUEST = 0x09
APP_CONNECTION_REQUEST_ACCEPTED = 0x10
APP_NEW_INCOMING_CONNECTION = 0x13
APP_CONNECTED_PING = 0x00
APP_CONNECTED_PONG = 0x03
INTERNAL_ADDRESS_COUNT = 10


class BitWriter:
    """Little-endian bit writer matching RakNet's bit-stream convention.

    The 0.735/0.738 decompile writes RbxOpenRequest2 through a bit buffer,
    aligning before every variable-length byte span.  Keeping this primitive
    here makes the clear transcript reproducible without embedding a guessed
    encryption implementation.
    """

    __slots__ = ("_data", "bit_pos")

    def __init__(self) -> None:
        self._data = bytearray()
        self.bit_pos = 0

    def align(self, boundary: int = 8) -> None:
        if boundary <= 0 or boundary & (boundary - 1):
            raise ValueError("boundary must be a positive power of two")
        self.bit_pos = (self.bit_pos + boundary - 1) & ~(boundary - 1)
        need = (self.bit_pos + 7) // 8
        if need > len(self._data):
            self._data.extend(b"\x00" * (need - len(self._data)))

    def write_bits(self, value: int, count: int) -> None:
        if count < 0 or count > 64:
            raise ValueError("bit count out of range")
        if value < 0 or value >= (1 << count if count else 1):
            raise ValueError("value does not fit bit count")
        need = (self.bit_pos + count + 7) // 8
        if need > len(self._data):
            self._data.extend(b"\x00" * (need - len(self._data)))
        for i in range(count):
            if (value >> i) & 1:
                self._data[(self.bit_pos + i) >> 3] |= 1 << ((self.bit_pos + i) & 7)
        self.bit_pos += count

    def write_bytes(self, value: bytes, *, align: bool = True) -> None:
        if align:
            self.align()
        for byte in value:
            self.write_bits(byte, 8)

    def write_uint_be(self, value: int, width: int) -> None:
        if width not in (1, 2, 4, 8):
            raise ValueError("width must be 1, 2, 4 or 8")
        self.write_bytes(value.to_bytes(width, "big"), align=False)

    def bytes(self) -> bytes:
        return bytes(self._data[: (self.bit_pos + 7) // 8])


def build_rbx_open_request2_parts(
    *,
    static_label: bytes,
    server_early_public_key: bytes,
    mtu: int,
    client_value: int,
    encryption_selector: int = 1,
    key_exchange_version: int = 3,
    reserved: int = 0,
    field_a: int = 0,
    field_b: int = 0,
    rupp_metadata: bytes = b"",
    endpoint_metadata: bytes = b"",
    identity: bytes = b"",
) -> tuple[bytes, bytes]:
    """Serialize the clear prefix and body of RbxOpenRequest2.

    This function deliberately stops before SessionCrypto AEAD.  Every
    variable field is explicit so a captured build-specific transcript can be
    supplied later without changing the wire serializer.
    """
    if len(static_label) != 16:
        raise ValueError("static_label must be exactly 16 bytes")
    if len(server_early_public_key) != 32:
        raise ValueError("server_early_public_key must be exactly 32 bytes")
    if not 576 <= mtu <= 1492:
        raise ValueError("invalid MTU")
    if not 0 <= client_value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("client_value out of range")
    if not 0 <= encryption_selector <= 0xFF:
        raise ValueError("encryption_selector out of range")
    for name, value in (("rupp_metadata", rupp_metadata), ("endpoint_metadata", endpoint_metadata), ("identity", identity)):
        if len(value) > 0xFF:
            raise ValueError(f"{name} is limited to 255 bytes")

    prefix = bytes((RBX_OPEN_REQUEST2,)) + static_label + bytes((key_exchange_version,))
    w = BitWriter()
    w.write_bits(reserved, 8)
    # Two 16-bit network-order values are written by the original bit writer.
    # The serializer uses integer values and emits their wire byte order here.
    w.write_uint_be(field_a, 2)
    w.write_uint_be(field_b, 2)
    w.align()
    w.write_bytes(server_early_public_key)
    w.write_bits(len(rupp_metadata), 8)
    if rupp_metadata:
        w.align(); w.write_bytes(rupp_metadata)
    w.write_bits(len(endpoint_metadata), 8)
    if endpoint_metadata:
        w.align(); w.write_bytes(endpoint_metadata)
    w.align()
    w.write_uint_be(client_value, 8)
    w.write_uint_be(mtu, 2)
    w.write_bits(encryption_selector, 8)
    w.write_bits(4, 8)
    w.write_bits(len(identity), 8)
    if identity:
        w.align(); w.write_bytes(identity)
    return prefix, w.bytes()


def build_rbx_open_request2_clear(**kwargs) -> bytes:
    """Return the prefix concatenated with the unencrypted body.

    The actual client keeps the first 18 bytes clear and passes the returned
    body through SessionCrypto before wrapping the packet.  This concatenated
    form is useful for fixtures and transcript inspection.
    """
    prefix, body = build_rbx_open_request2_parts(**kwargs)
    return prefix + body


def build_rbx_open_request2_clear_0738(
    *,
    server_early_public_key: bytes,
    rupp_aad_type: int,
    rupp_aad: bytes,
    client_value: int,
    client_material: bytes,
    mtu: int,
    encryption_selector: int,
    endpoint_ipv4: bytes,
    endpoint_port: int,
    token_blob: bytes,
    key_exchange_version: int = 3,
    protocol_version: int = 5,
    endpoint_selector: int = 4,
) -> tuple[bytes, bytes]:
    """Build the exact 0.738 Request2 clear AAD/plaintext split.

    Field order and lengths are taken from the 0.738 field-level runtime
    trace.  Every session-dependent span is supplied by the caller.  The
    returned tuple is ``(aad, plaintext)``; :mod:`session_crypto` performs the
    in-place ChaCha20-Poly1305 transform and UDMUX remains an outer layer.
    """
    server_early_public_key = bytes(server_early_public_key)
    rupp_aad = bytes(rupp_aad)
    client_material = bytes(client_material)
    endpoint_ipv4 = bytes(endpoint_ipv4)
    token_blob = bytes(token_blob)
    if len(server_early_public_key) != 32:
        raise ValueError("server_early_public_key must be 32 bytes")
    if len(rupp_aad) > 0xFF:
        raise ValueError("rupp_aad is limited to 255 bytes")
    if len(client_material) != 8:
        raise ValueError("client_material must be 8 bytes")
    if len(endpoint_ipv4) != 4:
        raise ValueError("endpoint_ipv4 must be 4 bytes")
    if len(token_blob) > 0xFF:
        raise ValueError("token_blob is limited to 255 bytes")
    for name, value in (
        ("rupp_aad_type", rupp_aad_type),
        ("key_exchange_version", key_exchange_version),
        ("encryption_selector", encryption_selector),
        ("endpoint_selector", endpoint_selector),
    ):
        if not 0 <= value <= 0xFF:
            raise ValueError(f"{name} out of range")
    if not 0 <= protocol_version <= 0xFFFF:
        raise ValueError("protocol_version out of range")
    if not 0 <= client_value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("client_value out of range")
    if not 576 <= mtu <= 1492:
        raise ValueError("invalid MTU")
    if not 0 <= endpoint_port <= 0xFFFF:
        raise ValueError("endpoint_port out of range")

    aad_tail = (
        protocol_version.to_bytes(2, "big")
        + server_early_public_key
        + bytes((rupp_aad_type, len(rupp_aad)))
        + rupp_aad
    )
    # The builder reserves these three length bytes immediately after the key
    # exchange version, fills the rest of the AAD/body, then seeks back to
    # write them.  Build them directly once the spans are known.
    fixed_without_lengths = bytes((RBX_OPEN_REQUEST2,)) + MAGIC + bytes((key_exchange_version,))
    plaintext = (
        client_value.to_bytes(8, "big")
        + client_material
        + mtu.to_bytes(2, "big")
        + bytes((encryption_selector, endpoint_selector))
        + endpoint_ipv4
        + endpoint_port.to_bytes(2, "big")
        + bytes((len(token_blob),))
        + token_blob
    )
    aad_length = len(fixed_without_lengths) + 3 + len(aad_tail)
    if aad_length > 0xFF or len(plaintext) > 0xFFFF:
        raise ValueError("Request2 clear span is too large")
    aad = (
        fixed_without_lengths
        + bytes((aad_length,))
        + len(plaintext).to_bytes(2, "big")
        + aad_tail
    )
    return aad, plaintext


@dataclass(frozen=True, slots=True)
class RbxOpenReply1:
    server_guid: int
    flags: int
    mtu: int


def parse_open_reply1(packet: bytes) -> RbxOpenReply1:
    """Parse the 28-byte Roblox OpenReply1 envelope."""
    if len(packet) < 28 or packet[0] != RBX_OPEN_REPLY1:
        raise ValueError("not an RbxOpenReply1 packet")
    if packet[1:17] != MAGIC:
        raise ValueError("RbxOpenReply1 magic mismatch")
    mtu = struct.unpack_from(">H", packet, 26)[0]
    if not 576 <= mtu <= 1492:
        raise ValueError(f"invalid RbxOpenReply1 MTU: {mtu}")
    return RbxOpenReply1(struct.unpack_from(">Q", packet, 17)[0], packet[25], mtu)


def build_app_connection_request(client_guid: int, timestamp_ms: int, identity: bytes = b"") -> bytes:
    """Build RakNet ``ID_CONNECTION_REQUEST``.

    The 0.738 wire uses network-order GUID/time values followed by the
    one-byte security flag and a six-byte connection identity.
    """
    if not 0 <= client_guid <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("client_guid out of range")
    if not 0 <= timestamp_ms <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("timestamp out of range")
    identity = bytes(identity)
    if len(identity) not in (0, 6):
        raise ValueError("connection identity must be six bytes")
    return bytes((APP_CONNECTION_REQUEST,)) + struct.pack(">QQ", client_guid, timestamp_ms) + b"\x00" + identity


def encode_system_address(host: str, port: int) -> bytes:
    """Encode the IPv4 SystemAddress form used by the 0.738 RakNet stream."""
    address = ipaddress.IPv4Address(host)
    if not 0 <= int(port) <= 0xFFFF:
        raise ValueError("port out of range")
    return b"\x04" + bytes(octet ^ 0xFF for octet in address.packed) + struct.pack(">H", int(port))


def build_new_incoming_connection(accepted: bytes, server_host: str, server_port: int,
                                  timestamp_ms: int, wall_time_us: int) -> bytes:
    """Answer a 0.738 ``ID_CONNECTION_REQUEST_ACCEPTED`` packet.

    The accepted payload ends with request-time, server-time and wall-time
    fields.  ``ID_NEW_INCOMING_CONNECTION`` echoes the server time, adds the
    client's current monotonic time and the current Unix microsecond clock.
    """
    accepted = bytes(accepted)
    expected = 1 + 7 + 2 + INTERNAL_ADDRESS_COUNT * 7 + 24
    if len(accepted) != expected or accepted[0] != APP_CONNECTION_REQUEST_ACCEPTED:
        raise ValueError("unexpected connection-accepted layout")
    if not 0 <= int(timestamp_ms) <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("timestamp out of range")
    if not 0 <= int(wall_time_us) <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("wall time out of range")
    server_time = accepted[-16:-8]
    internal = encode_system_address("0.0.0.0", 0) * INTERNAL_ADDRESS_COUNT
    return (bytes((APP_NEW_INCOMING_CONNECTION,))
            + encode_system_address(server_host, server_port)
            + internal + server_time
            + struct.pack(">QQ", int(timestamp_ms), int(wall_time_us)))


def build_connected_ping(timestamp_ms: int) -> bytes:
    if not 0 <= int(timestamp_ms) <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("timestamp out of range")
    return bytes((APP_CONNECTED_PING,)) + struct.pack(">Q", int(timestamp_ms))


def build_connected_pong(ping: bytes, timestamp_ms: int, wall_time_us: int) -> bytes:
    """Echo one connected-ping timestamp with both 0.738 client clocks."""
    ping = bytes(ping)
    if len(ping) < 9 or ping[0] != APP_CONNECTED_PING:
        raise ValueError("not a connected ping")
    if not 0 <= int(timestamp_ms) <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("timestamp out of range")
    if not 0 <= int(wall_time_us) <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("wall time out of range")
    return bytes((APP_CONNECTED_PONG,)) + ping[1:9] + struct.pack(">QQ", int(timestamp_ms), int(wall_time_us))


def build_rbx_open_request2(encrypted_body: bytes) -> bytes:
    """Return the packet payload for the encrypted OpenRequest2 stage.

    The first byte and the reliable wrapper are build constants.  The body is
    intentionally required from a SessionCrypto adapter; accepting a caller
    supplied ciphertext prevents this layer from inventing a key transcript.
    """
    if not encrypted_body:
        raise ValueError("encrypted_body is required")
    if len(encrypted_body) > 0xFFFF:
        raise ValueError("encrypted_body too large")
    return bytes((RBX_OPEN_REQUEST2,)) + encrypted_body


def build_rbx_open_request2_frame(encrypted_body: bytes, message_index: int) -> bytes:
    return wrap_reliable(build_rbx_open_request2(encrypted_body), message_index, channel=2)


def wrap_reliable(payload: bytes, message_index: int, channel: int = 2) -> bytes:
    """Wrap an app payload using the confirmed reliable/ordered channel 2."""
    return EncapsulatedFrame(payload, reliable=True, ordered=True,
                             message_index=message_index,
                             order_index=message_index,
                             order_channel=channel).encode()


def unwrap_reliable(packet: bytes) -> EncapsulatedFrame:
    return EncapsulatedFrame.decode(packet)
