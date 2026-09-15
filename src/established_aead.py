"""Established UDMUX/RakNet AEAD framing (per-direction, per-epoch).

This is deliberately independent from Request2's SessionCrypto envelope.
Once a live profile supplies the two 32-byte direction keys, the codec can
authenticate DATA/ACK datagrams without guessing or logging session material.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

COUNTER_BASE = int.from_bytes(b"UniqueNu", "little")
_MASK16 = 0xFFFF
_TRAILER = 18


def nonce(counter: int) -> bytes:
    return int(counter).to_bytes(8, "little") + b"mbeR"


def counter_candidates(hint: int, *, base: int = COUNTER_BASE,
                       span: int = 256, last_counter: int | None = None) -> Iterable[int]:
    """Yield full counters compatible with a wire low-16-bit hint.

    The first packet of an epoch anchors the native stream to its 16-bit wire
    value (not to the ``"UniqueNu"`` constant).  Later packets extend that
    anchor with the same signed-wrap rule used by the client.  ``base`` is
    retained for callers that already know the high counter bits.
    """
    hint = int(hint) & _MASK16
    if last_counter is None:
        # A newly observed epoch starts at the hint itself.  A short fallback
        # window around it is useful for captures that begin one packet late.
        first = hint
        seen: set[int] = set()
        for candidate in (first, (int(base) & ~_MASK16) | hint):
            if candidate in seen:
                continue
            seen.add(candidate)
            yield candidate
        # A capture can start after a few packets; retain the historical
        # high-word scan as a bounded fallback after the exact anchors.
        for n in range(1, max(1, int(span))):
            for candidate in (first + n, ((int(base) & ~_MASK16) | hint) + n * (_MASK16 + 1)):
                if candidate in seen:
                    continue
                seen.add(candidate)
                yield candidate
        return
    # Signed 16-bit extension around the previously authenticated packet.
    delta = ((hint - (int(last_counter) & _MASK16) + 0x8000) & 0xFFFF) - 0x8000
    first = int(last_counter) + delta
    yield first
    # Retransmissions can arrive out of order; try a bounded neighborhood
    # without allowing a malformed hint to allocate or scan unbounded state.
    radius = max(0, min(int(span), 32))
    for n in range(1, radius + 1):
        yield first - n
        yield first + n


@dataclass(frozen=True, slots=True)
class EstablishedDatagram:
    header: bytes
    ciphertext: bytes
    counter_hint: int
    tag: bytes

    @property
    def encrypted_body(self) -> bytes:
        return self.ciphertext + self.tag


def parse_datagram(packet: bytes) -> EstablishedDatagram:
    if len(packet) < 4 or packet[:3] != b"\x01\x00\x00":
        raise ValueError("not a UDMUX record")
    hlen = packet[3]
    if hlen not in (0x17, 0x1F) or len(packet) < hlen + _TRAILER:
        raise ValueError("invalid established UDMUX length")
    header = packet[4:hlen]
    if header[:3] not in (b"\x01\x11\x01", b"\x01\x11\x02"):
        raise ValueError("not a UDMUX subflag")
    body = packet[hlen:]
    return EstablishedDatagram(header, body[:-_TRAILER],
                               int.from_bytes(body[-18:-16], "little"), body[-16:])


def _aad_candidates(packet: bytes, dg: EstablishedDatagram,
                    explicit: Sequence[bytes] | None) -> list[bytes]:
    """Return deterministic associated-data candidates for a wire record.

    Builds in the wild have used both an empty AEAD associated-data span and
    the UDMUX header (with or without the four-byte record prefix).  The
    ciphertext layout is identical; only the AAD choice changes.  Keeping the
    candidates here makes the decoder tolerant of that transport variation
    without weakening authentication: every candidate still has to pass the
    Poly1305/GCM tag.
    """
    if explicit is not None:
        values = [bytes(value) for value in explicit]
    else:
        values = [b"", bytes(dg.header), bytes(packet[:4] + dg.header)]
    out: list[bytes] = []
    for value in values:
        if value not in out:
            out.append(value)
    return out


def decrypt_datagram(packet: bytes, key: bytes | list[bytes] | tuple[bytes, ...], *, cipher: str = "aes-256-gcm",
                     base: int = COUNTER_BASE, span: int = 256,
                     aad_candidates: Sequence[bytes] | None = None,
                     last_counter: int | None = None) -> tuple[bytes, int, EstablishedDatagram]:
    dg = parse_datagram(packet)
    keys = [bytes(key)] if isinstance(key, (bytes, bytearray)) else [bytes(item) for item in key]
    if not keys or any(len(item) != 32 for item in keys):
        raise ValueError("established key must be 32 bytes")
    impl = AESGCM if cipher == "aes-256-gcm" else ChaCha20Poly1305
    if cipher not in ("aes-256-gcm", "chacha20-poly1305"):
        raise ValueError("unsupported established cipher")
    associated_data = _aad_candidates(packet, dg, aad_candidates)
    for candidate in keys:
        codec = impl(candidate)
        for counter in counter_candidates(dg.counter_hint, base=base, span=span,
                                          last_counter=last_counter):
            for aad in associated_data:
                try:
                    return codec.decrypt(nonce(counter), dg.encrypted_body, aad), counter, dg
                except Exception:
                    continue
    raise ValueError("established AEAD authentication failed")


def encrypt_datagram(header: bytes, plaintext: bytes, key: bytes, counter: int,
                     *, cipher: str = "aes-256-gcm", associated_data: bytes = b"") -> bytes:
    if len(key) != 32:
        raise ValueError("established key must be 32 bytes")
    if len(header) not in (19, 27) or header[:3] not in (b"\x01\x11\x01", b"\x01\x11\x02"):
        raise ValueError("header must be captured UDMUX bytes after the 4-byte prefix")
    impl = AESGCM if cipher == "aes-256-gcm" else ChaCha20Poly1305
    if cipher not in ("aes-256-gcm", "chacha20-poly1305"):
        raise ValueError("unsupported established cipher")
    body = impl(bytes(key)).encrypt(nonce(counter), bytes(plaintext), bytes(associated_data))
    return bytes((1, 0, 0, 4 + len(header))) + bytes(header) + body[:-16] + \
        (int(counter) & _MASK16).to_bytes(2, "little") + body[-16:]


if __name__ == "__main__":
    key = bytes(range(32)); header = b"\x01\x11\x02" + bytes(16)
    packet = encrypt_datagram(header, b"\x80\x00\x00\x00", key, COUNTER_BASE + 7)
    pt, counter, _ = decrypt_datagram(packet, key)
    assert pt == b"\x80\x00\x00\x00" and counter == COUNTER_BASE + 7
    packet = encrypt_datagram(header, b"\x80\x01\x00\x00", key, COUNTER_BASE + 8,
                              associated_data=header)
    pt, counter, _ = decrypt_datagram(packet, key)
    assert pt == b"\x80\x01\x00\x00" and counter == COUNTER_BASE + 8
    print("established AEAD selftest: ok")
