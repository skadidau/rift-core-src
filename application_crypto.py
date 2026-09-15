"""Inner application AES envelope used by bootstrap packets.

This is separate from the established UDMUX AEAD layer.  The envelope is
AES-128-CBC with a zero IV, a reversible block-order shuffle, and the native
rolling checksum.  Callers provide all session material; this module contains
only the build-wide protocol-sync key and the observed ticket-key derivation.
"""
from __future__ import annotations

import secrets
from collections.abc import Callable, Sequence

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PROTOCOL_SYNC_KEY = bytes.fromhex("fef9f0ebe2ddd4cfc6c1b8b3aaa59c97")
RandomBytes = Callable[[int], bytes]
_MASK32 = 0xFFFFFFFF
_XXH32_PRIMES = (0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F, 0x165667B1)


def _shuffle_blocks(data: bytes) -> bytes:
    """Keep block zero in place and reverse every later 16-byte block."""
    data = bytes(data)
    if len(data) < 16 or len(data) % 16:
        raise ValueError("application AES data must contain whole 16-byte blocks")
    blocks = [data[offset:offset + 16] for offset in range(0, len(data), 16)]
    return blocks[0] + b"".join(reversed(blocks[1:]))


def application_checksum(data: bytes) -> int:
    """Return the 32-bit checksum stored in an application AES envelope."""
    rolling = 55665
    checksum = 0
    for value in bytes(data):
        transformed = (value ^ (rolling >> 8)) & 0xFF
        rolling = ((transformed + rolling) * 52845 + 22719) & 0xFFFF
        checksum = (checksum + transformed) & 0xFFFFFFFF
    return checksum


def decrypt_application_envelope(ciphertext: bytes, key: bytes) -> bytes:
    """Authenticate/decrypt an inner application envelope and return its body."""
    ciphertext, key = bytes(ciphertext), bytes(key)
    if len(key) != 16:
        raise ValueError("application AES key must be 16 bytes")
    shuffled = _shuffle_blocks(ciphertext)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).decryptor()
    clear = _shuffle_blocks(decryptor.update(shuffled) + decryptor.finalize())
    stored = int.from_bytes(clear[:4], "little")
    calculated = application_checksum(clear[4:])
    if stored != calculated:
        raise ValueError("application AES checksum mismatch")
    padding = clear[5] & 0x0F
    body_offset = 6 + padding
    if body_offset > len(clear):
        raise ValueError("invalid application AES padding")
    return clear[body_offset:]


def encrypt_application_envelope(
    payload: bytes,
    key: bytes,
    *,
    random_bytes: RandomBytes = secrets.token_bytes,
) -> bytes:
    """Build/encrypt an inner application envelope.

    Byte four, the high nibble of byte five, and the padding bytes are random
    in current captures.  ``random_bytes`` is injectable for deterministic
    vector tests.
    """
    payload, key = bytes(payload), bytes(key)
    if len(key) != 16:
        raise ValueError("application AES key must be 16 bytes")
    padding = 0x0F - ((len(payload) + 5) % 16)
    noise = bytes(random_bytes(padding + 2))
    if len(noise) != padding + 2:
        raise ValueError("random_bytes returned the wrong length")
    clear = bytearray(6 + padding + len(payload))
    clear[4] = noise[0]
    clear[5] = (noise[1] & 0xF0) | padding
    clear[6:6 + padding] = noise[2:]
    clear[6 + padding:] = payload
    clear[:4] = application_checksum(clear[4:]).to_bytes(4, "little")
    encryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    encrypted = encryptor.update(_shuffle_blocks(bytes(clear))) + encryptor.finalize()
    return _shuffle_blocks(encrypted)


def as_signed_int32(value: int) -> int:
    """Apply the native two's-complement int32 cast."""
    return ((int(value) + 0x80000000) & 0xFFFFFFFF) - 0x80000000


def derive_submit_ticket_key(place_id: int, version_ids: Sequence[int]) -> bytes:
    """Derive the current 16-byte submit-ticket key from 0x90 material."""
    if len(version_ids) != 5:
        raise ValueError("exactly five version IDs are required")
    values = [as_signed_int32(value) for value in version_ids]
    material = (
        f"{as_signed_int32(place_id)}{values[0]}{values[2]}{values[1]}"
    ).encode("ascii")
    if len(material) < 16:
        raise ValueError("submit-ticket key material is shorter than 16 bytes")
    return material[:16]


def _rol32(value: int, count: int) -> int:
    count &= 31
    value &= _MASK32
    return ((value << count) | (value >> ((32 - count) & 31))) & _MASK32


def xxhash32(data: bytes, seed: int = 0) -> int:
    """Dependency-free XXH32 used by the native ticket builder."""
    p1, p2, p3, p4, p5 = _XXH32_PRIMES
    data = bytes(data)
    size, offset = len(data), 0

    def round32(accumulator: int, lane: int) -> int:
        return (_rol32((accumulator + lane * p2) & _MASK32, 13) * p1) & _MASK32

    if size >= 16:
        v1, v2, v3, v4 = ((seed + p1 + p2) & _MASK32, (seed + p2) & _MASK32,
                          seed & _MASK32, (seed - p1) & _MASK32)
        while offset <= size - 16:
            v1 = round32(v1, int.from_bytes(data[offset:offset + 4], "little")); offset += 4
            v2 = round32(v2, int.from_bytes(data[offset:offset + 4], "little")); offset += 4
            v3 = round32(v3, int.from_bytes(data[offset:offset + 4], "little")); offset += 4
            v4 = round32(v4, int.from_bytes(data[offset:offset + 4], "little")); offset += 4
        result = (_rol32(v1, 1) + _rol32(v2, 7) + _rol32(v3, 12) + _rol32(v4, 18)) & _MASK32
    else:
        result = (seed + p5) & _MASK32
    result = (result + size) & _MASK32
    while offset <= size - 4:
        lane = int.from_bytes(data[offset:offset + 4], "little")
        result = (_rol32((result + lane * p3) & _MASK32, 17) * p4) & _MASK32
        offset += 4
    while offset < size:
        result = (_rol32((result + data[offset] * p5) & _MASK32, 11) * p1) & _MASK32
        offset += 1
    result ^= result >> 15; result = (result * p2) & _MASK32
    result ^= result >> 13; result = (result * p3) & _MASK32
    return (result ^ (result >> 16)) & _MASK32


def mix_ticket_hash(ticket_digest: int, platform_key: int) -> int:
    """Apply the 0.738 native platform-key mixer at builder 0x326E270."""
    key = int(platform_key) & _MASK32
    control = (key * 0xF7ABBB9C) & _MASK32
    fixed, inverse = 0x557BB5D7, 0xAA844A29
    value = _rol32((int(ticket_digest) + fixed) & _MASK32, 25)
    value = (value + (inverse if not control & 4 else -key)) & _MASK32
    value = (value * (fixed if not control & 8 else key)) & _MASK32
    value = _rol32(value, 19 if not control & 0x10 else 13)
    middle = ((fixed if not control & 0x20 else key) - value) & _MASK32
    middle ^= fixed if not control & 0x40 else key
    middle = _rol32(middle, 15 + 2 * ((control >> 7) & 1))
    result = key if control & 0x100 else -key
    result = (result + (fixed if control & 0x200 else inverse) + middle) & _MASK32
    result = _rol32(result, 23 if control & 0x400 else 9)
    result = (-result if control & 0x800 else result) & _MASK32
    result = (result + key) & _MASK32
    result = (-result if control & 0x1000 else result) & _MASK32
    result = _rol32((result + fixed) & _MASK32, 29 if control & 0x2000 else 3)
    result ^= key if control & 0x4000 else fixed
    return (result if control & 0x8000 else -result) & _MASK32


def generate_ticket_hash(client_ticket: str | bytes, platform_key: int) -> int:
    ticket = client_ticket.encode("utf-8") if isinstance(client_ticket, str) else bytes(client_ticket)
    return mix_ticket_hash(xxhash32(ticket, seed=1), platform_key)
