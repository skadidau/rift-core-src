"""Captured 0.738 codecs for DataPing (0xA2) and EarlyDataPing (0xA7).

The packet-specific words are supplied by the caller.  They are native
build/session measurements, not stable protocol constants.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

ID_DATA_PING = 0xA2
ID_EARLY_DATA_PING = 0xA7


@dataclass(frozen=True, slots=True)
class DataPingProfile:
    extension_word_count: int = 7
    trailer_word_count: int = 2

    def __post_init__(self) -> None:
        if self.extension_word_count < 0 or self.trailer_word_count < 0:
            raise ValueError("DataPing word counts must be non-negative")


@dataclass(frozen=True, slots=True)
class EarlyDataPingProfile:
    record_width: int = 16

    def __post_init__(self) -> None:
        if self.record_width <= 0:
            raise ValueError("EarlyDataPing record width must be positive")


DATA_PING_PROFILE_0738 = DataPingProfile()
EARLY_DATA_PING_PROFILE_0738 = EarlyDataPingProfile()


def _u32le(value: int) -> bytes:
    value = int(value)
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("uint32 out of range")
    return value.to_bytes(4, "little")


def _byte(value: int) -> int:
    value = int(value)
    if not 0 <= value <= 0xFF:
        raise ValueError("byte out of range")
    return value


def parse_data_ping(
    packet: bytes, *, profile: DataPingProfile = DATA_PING_PROFILE_0738
) -> dict[str, object]:
    """Parse the native 0xA2 core and the selected extension profile.

    Native RVA 0x3584E78 emits a 14-byte core.  Its full 0.738 branch adds a
    marker, seven dwords, two trailer dwords, then an opaque caller blob.
    """
    packet = bytes(packet)
    if len(packet) < 14 or packet[0] != ID_DATA_PING:
        raise ValueError("expected 14-byte-or-longer DataPing packet")
    core_words = (
        int.from_bytes(packet[1:5], "little"),
        int.from_bytes(packet[5:9], "little"),
        int.from_bytes(packet[10:14], "little"),
    )
    result: dict[str, object] = {
        "core_words": core_words,
        "core_byte": packet[9],
        "extension_marker": None,
        "extension_words": (),
        "trailer_words": (),
        "payload": b"",
    }
    if len(packet) == 14:
        return result

    extension_end = 15 + 4 * profile.extension_word_count
    trailer_end = extension_end + 4 * profile.trailer_word_count
    if len(packet) < trailer_end:
        raise ValueError("truncated DataPing extension for selected profile")
    result.update(
        extension_marker=packet[14],
        extension_words=tuple(
            int.from_bytes(packet[offset : offset + 4], "little")
            for offset in range(15, extension_end, 4)
        ),
        trailer_words=tuple(
            int.from_bytes(packet[offset : offset + 4], "little")
            for offset in range(extension_end, trailer_end, 4)
        ),
        payload=packet[trailer_end:],
    )
    return result


def build_data_ping(
    core_words: Sequence[int],
    core_byte: int,
    *,
    extension_marker: int | None = None,
    extension_words: Sequence[int] = (),
    trailer_words: Sequence[int] = (),
    payload: bytes = b"",
    profile: DataPingProfile = DATA_PING_PROFILE_0738,
) -> bytes:
    """Build a core-only or profile-selected extended 0xA2 packet."""
    if len(core_words) != 3:
        raise ValueError("DataPing requires exactly three core words")
    out = bytearray((ID_DATA_PING,))
    out += _u32le(core_words[0]) + _u32le(core_words[1])
    out.append(_byte(core_byte))
    out += _u32le(core_words[2])
    if extension_marker is None:
        if extension_words or trailer_words or payload:
            raise ValueError("DataPing extension marker is required")
        return bytes(out)
    if len(extension_words) != profile.extension_word_count:
        raise ValueError("wrong DataPing extension word count for profile")
    if len(trailer_words) != profile.trailer_word_count:
        raise ValueError("wrong DataPing trailer word count for profile")
    out.append(_byte(extension_marker))
    for value in (*extension_words, *trailer_words):
        out += _u32le(value)
    out += bytes(payload)
    return bytes(out)


def parse_early_data_ping(
    packet: bytes, *, profile: EarlyDataPingProfile = EARLY_DATA_PING_PROFILE_0738
) -> dict[str, object]:
    """Parse captured fixed-width 0xA7 as ID, u16le count, then records."""
    packet = bytes(packet)
    if len(packet) < 3 or packet[0] != ID_EARLY_DATA_PING:
        raise ValueError("expected EarlyDataPing packet")
    count = int.from_bytes(packet[1:3], "little")
    expected = 3 + count * profile.record_width
    if len(packet) != expected:
        raise ValueError(
            f"EarlyDataPing count requires {expected} bytes, got {len(packet)}"
        )
    return {
        "count": count,
        "record_width": profile.record_width,
        "records": tuple(
            packet[offset : offset + profile.record_width]
            for offset in range(3, expected, profile.record_width)
        ),
    }


def build_early_data_ping(
    records: Iterable[bytes],
    *,
    profile: EarlyDataPingProfile = EARLY_DATA_PING_PROFILE_0738,
) -> bytes:
    """Build the captured fixed-width 0xA7 profile from opaque records."""
    items = tuple(bytes(record) for record in records)
    if len(items) > 0xFFFF:
        raise ValueError("EarlyDataPing record count exceeds uint16")
    if any(len(record) != profile.record_width for record in items):
        raise ValueError("wrong EarlyDataPing record width for profile")
    return (
        bytes((ID_EARLY_DATA_PING,))
        + len(items).to_bytes(2, "little")
        + b"".join(items)
    )
