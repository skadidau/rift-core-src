"""Current (0.738 capture) application bootstrap packet codecs.

The builders accept raw join/session fields rather than embedding an account,
ticket, device profile, or per-session value.  All fixed-width integers in the
captured 0x90/0x8A/0x93 layouts are little-endian.
"""
from __future__ import annotations

import json
import secrets
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from application_crypto import (
    PROTOCOL_SYNC_KEY,
    RandomBytes,
    as_signed_int32,
    decrypt_application_envelope,
    derive_submit_ticket_key,
    encrypt_application_envelope,
)

ID_SUBMIT_TICKET = 0x8A
ID_PREFERRED_SPAWN_NAME = 0x8F
ID_PROTOCOL_SYNC = 0x90
ID_PLACEID_VERIFICATION = 0x92
ID_DICTIONARY_FORMAT = 0x93

JOIN_DATA_PROFILE_0738 = Path(__file__).resolve().parents[1] / "profiles" / "join_data_0738.json"
JOIN_DATA_FIELD_COUNT_0738 = 55


def _utf8(value: str | bytes) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


def _u16le(value: int) -> bytes:
    if not 0 <= int(value) <= 0xFFFF:
        raise ValueError("uint16 out of range")
    return int(value).to_bytes(2, "little")


def _u32le(value: int) -> bytes:
    if not 0 <= int(value) <= 0xFFFFFFFF:
        raise ValueError("uint32 out of range")
    return int(value).to_bytes(4, "little")


def encode_varuint(value: int) -> bytes:
    value = int(value)
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("varuint out of range")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def encode_varsint(value: int) -> bytes:
    value = int(value)
    if not -(1 << 63) <= value < (1 << 63):
        raise ValueError("varsint out of range")
    return encode_varuint((value << 1) ^ (value >> 63))


def encode_varbytes(value: str | bytes) -> bytes:
    raw = _utf8(value)
    return encode_varuint(len(raw)) + raw


class _Reader:
    __slots__ = ("data", "offset")

    def __init__(self, data: bytes):
        self.data = bytes(data)
        self.offset = 0

    def take(self, length: int) -> bytes:
        length = int(length)
        end = self.offset + length
        if length < 0 or end > len(self.data):
            raise ValueError("truncated bootstrap packet")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def u16le(self) -> int:
        return int.from_bytes(self.take(2), "little")

    def u32le(self) -> int:
        return int.from_bytes(self.take(4), "little")

    def varuint(self) -> int:
        result = 0
        for shift in range(0, 70, 7):
            byte = self.u8()
            if shift == 63 and byte > 1:
                raise ValueError("varuint overflow")
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
        raise ValueError("varuint overflow")

    def varsint(self) -> int:
        value = self.varuint()
        return (value >> 1) ^ -(value & 1)

    def varbytes(self) -> bytes:
        return self.take(self.varuint())

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise ValueError(f"unexpected {len(self.data) - self.offset} trailing bytes")


def _body(packet: bytes, packet_id: int) -> bytes:
    packet = bytes(packet)
    if not packet or packet[0] != packet_id:
        raise ValueError(f"expected application packet 0x{packet_id:02x}")
    return packet[1:]


def serialize_join_data(value: Mapping[str, Any]) -> bytes:
    """Compact-serialize an already assembled JoinData mapping.

    Insertion order is preserved.  The caller still supplies the native/device
    fields: the 0x90 JoinData object is not the raw join-game response.
    """
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def load_join_data_profile(path: str | Path = JOIN_DATA_PROFILE_0738) -> dict[str, Any]:
    """Load and validate the ordered 0.738 JoinData projection profile."""
    profile = json.loads(Path(path).read_text(encoding="utf-8"))
    defaults = profile.get("defaults") if isinstance(profile, dict) else None
    if (
        not isinstance(defaults, dict)
        or profile.get("field_count") != JOIN_DATA_FIELD_COUNT_0738
        or len(defaults) != JOIN_DATA_FIELD_COUNT_0738
    ):
        raise ValueError("invalid JoinData profile field count")
    known = set(defaults)
    for section in ("payload_aliases", "coercions"):
        values = profile.get(section, {})
        if not isinstance(values, dict) or not set(values) <= known:
            raise ValueError(f"invalid JoinData profile {section}")
    for section in ("skip_empty_fields", "sensitive_fields", "unresolved_profile_fields"):
        values = profile.get(section, [])
        if not isinstance(values, list) or not set(values) <= known:
            raise ValueError(f"invalid JoinData profile {section}")
    return profile


def _projection_payload(source: Any) -> Mapping[str, Any]:
    if isinstance(source, Mapping):
        return source
    payload = getattr(source, "join_payload", None)
    if payload is None:
        return {}
    if not isinstance(payload, Mapping):
        raise TypeError("SessionMaterial.join_payload must be a mapping")
    return payload


def _coerce_projection_value(value: Any, coercion: str | None) -> Any:
    if coercion is None:
        return value
    if coercion == "str":
        return str(value)
    if coercion == "int":
        return int(value)
    if coercion == "bool":
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes"}
        return bool(value)
    raise ValueError(f"unsupported JoinData coercion: {coercion}")


def _project_join_data(
    source: Any, profile: Mapping[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    payload = _projection_payload(source)
    aliases = profile.get("payload_aliases", {})
    coercions = profile.get("coercions", {})
    skip_empty = set(profile.get("skip_empty_fields", []))
    projected: dict[str, Any] = {}
    overridden: list[str] = []
    for field, default in profile["defaults"].items():
        value = default
        for source_field in (field, *aliases.get(field, [])):
            candidate = payload.get(source_field)
            if candidate is None or (field in skip_empty and candidate == ""):
                continue
            value = _coerce_projection_value(candidate, coercions.get(field))
            overridden.append(field)
            break
        projected[field] = value
    return projected, overridden


def project_join_data(
    source: Any,
    *,
    profile: Mapping[str, Any] | None = None,
    profile_path: str | Path = JOIN_DATA_PROFILE_0738,
) -> dict[str, Any]:
    """Project raw transient join material into the ordered 55-field object.

    ``source`` may be a :class:`SessionMaterial` or its raw ``join_payload``.
    Exact JoinData field names take precedence, then build-profile aliases;
    fields without a live source retain the explicit profile default.
    """
    loaded = dict(profile) if profile is not None else load_join_data_profile(profile_path)
    return _project_join_data(source, loaded)[0]


def summarize_join_data_projection(
    source: Any,
    *,
    profile: Mapping[str, Any] | None = None,
    profile_path: str | Path = JOIN_DATA_PROFILE_0738,
) -> dict[str, Any]:
    """Return projection provenance only; field values never enter reports."""
    loaded = dict(profile) if profile is not None else load_join_data_profile(profile_path)
    projected, overridden = _project_join_data(source, loaded)
    overridden_set = set(overridden)
    reused = [field for field in projected if field not in overridden_set]
    unresolved = [
        field for field in loaded.get("unresolved_profile_fields", []) if field in reused
    ]
    return {
        "build": loaded.get("build"),
        "field_count": len(projected),
        "payload_override_count": len(overridden),
        "payload_override_fields": overridden,
        "profile_reused_count": len(reused),
        "profile_reused_fields": reused,
        "unresolved_profile_fields": unresolved,
        "sensitive_fields_present": [
            field
            for field in loaded.get("sensitive_fields", [])
            if projected.get(field) not in (None, "", 0, False)
        ],
    }


def parse_dictionary_format(packet: bytes) -> dict[str, Any]:
    reader = _Reader(_body(packet, ID_DICTIONARY_FORMAT))
    flags = reader.u8()
    count = reader.u16le()
    entries: list[tuple[str, str]] = []
    for _ in range(count):
        name = reader.take(reader.u16le()).decode("utf-8")
        value = reader.take(reader.u16le()).decode("utf-8")
        entries.append((name, value))
    reader.finish()
    return {
        "flags": flags,
        "protocol_schema_sync": bool(flags & 1),
        "api_dictionary_compression": bool(flags & 2),
        "entries": entries,
    }


def build_dictionary_format(
    entries: Mapping[str, Any] | Iterable[tuple[str, Any]], *, flags: int = 0
) -> bytes:
    items = entries.items() if isinstance(entries, Mapping) else entries
    encoded: list[tuple[bytes, bytes]] = []
    for name, value in items:
        key = _utf8(str(name))
        if isinstance(value, bool):
            raw_value = b"true" if value else b"false"
        else:
            raw_value = _utf8(str(value))
        if len(key) > 0xFFFF or len(raw_value) > 0xFFFF:
            raise ValueError("dictionary string exceeds uint16 length")
        encoded.append((key, raw_value))
    if len(encoded) > 0xFFFF or not 0 <= int(flags) <= 0xFF:
        raise ValueError("dictionary count/flags out of range")
    out = bytearray((ID_DICTIONARY_FORMAT, int(flags)))
    out += _u16le(len(encoded))
    for name, value in encoded:
        out += _u16le(len(name)) + name + _u16le(len(value)) + value
    return bytes(out)


def _read_version_ids(reader: _Reader) -> tuple[tuple[int, ...], tuple[int, ...]]:
    raw: list[int] = []
    first = reader.u32le()
    raw.append(first)
    if first & 0x0C == 0 and reader.u32le() != first:
        raise ValueError("invalid version-ID repeat after index 0")
    raw.append(reader.u32le())
    if first & 0x50 == 0 and reader.u32le() != first:
        raise ValueError("invalid version-ID repeat after index 1")
    raw.append(reader.u32le())
    if first & 0xA0 == 0 and reader.u32le() != first:
        raise ValueError("invalid version-ID repeat after index 2")
    raw.append(reader.u32le())
    if first & 0x900 == 0 and reader.u32le() != first:
        raise ValueError("invalid version-ID repeat after index 3")
    raw.append(reader.u32le())
    signed = tuple(as_signed_int32(value) for value in raw)
    return signed, tuple(raw)


def _write_version_ids(version_ids: Sequence[int]) -> bytes:
    if len(version_ids) != 5:
        raise ValueError("exactly five version IDs are required")
    raw = [int(value) & 0xFFFFFFFF for value in version_ids]
    first = raw[0]
    out = bytearray(_u32le(first))
    if first & 0x0C == 0:
        out += _u32le(first)
    out += _u32le(raw[1])
    if first & 0x50 == 0:
        out += _u32le(first)
    out += _u32le(raw[2])
    if first & 0xA0 == 0:
        out += _u32le(first)
    out += _u32le(raw[3])
    if first & 0x900 == 0:
        out += _u32le(first)
    out += _u32le(raw[4])
    return bytes(out)


def parse_protocol_sync(packet: bytes) -> dict[str, Any]:
    clear = decrypt_application_envelope(_body(packet, ID_PROTOCOL_SYNC), PROTOCOL_SYNC_KEY)
    reader = _Reader(clear)
    int2 = reader.u8()
    schema_version = reader.u32le()
    int1 = reader.u8()
    profile_byte = reader.u8()
    flag_count = reader.u16le()
    requested_flags = [reader.varbytes().decode("utf-8") for _ in range(flag_count)]
    join_data_bytes = reader.varbytes()
    version_ids, version_ids_raw = _read_version_ids(reader)
    reader.finish()
    return {
        "int2": int2,
        "schema_version": schema_version,
        "int1": int1,
        "profile_byte": profile_byte,
        "requested_flags": requested_flags,
        "join_data": join_data_bytes.decode("utf-8"),
        "join_data_bytes": join_data_bytes,
        "version_ids": version_ids,
        "version_ids_raw": version_ids_raw,
    }


def build_protocol_sync(
    *,
    requested_flags: Sequence[str],
    join_data: str | bytes | Mapping[str, Any],
    version_ids: Sequence[int],
    schema_version: int = 36,
    int2: int = 1,
    int1: int = 3,
    profile_byte: int = 0x0E,
    random_bytes: RandomBytes = secrets.token_bytes,
) -> bytes:
    """Build current 0x90; raw JoinData bytes are passed through unchanged."""
    if len(requested_flags) > 0xFFFF:
        raise ValueError("too many requested flags")
    if not all(0 <= int(value) <= 0xFF for value in (int2, int1, profile_byte)):
        raise ValueError("0x90 byte field out of range")
    join_bytes = serialize_join_data(join_data) if isinstance(join_data, Mapping) else _utf8(join_data)
    clear = bytearray((int(int2),))
    clear += _u32le(schema_version)
    clear += bytes((int(int1), int(profile_byte))) + _u16le(len(requested_flags))
    for flag in requested_flags:
        clear += encode_varbytes(flag)
    clear += encode_varbytes(join_bytes)
    clear += _write_version_ids(version_ids)
    return bytes((ID_PROTOCOL_SYNC,)) + encrypt_application_envelope(
        bytes(clear), PROTOCOL_SYNC_KEY, random_bytes=random_bytes
    )


def parse_placeid_verification(packet: bytes, *, profile_value: int = 0x5860DBFE) -> dict[str, int]:
    """Decode current 0x92 into its per-send random and build-profile words."""
    reader = _Reader(_body(packet, ID_PLACEID_VERIFICATION))
    packed = reader.varsint() & 0xFFFFFFFFFFFFFFFF
    reader.finish()
    random_value = (packed >> 32) & 0xFFFFFFFF
    derived_profile = (packed & 0xFFFFFFFF) ^ random_value
    if derived_profile != (int(profile_value) & 0xFFFFFFFF):
        raise ValueError("place verification profile mismatch")
    return {
        "random_value": random_value,
        "profile_value": derived_profile,
        "packed_value": packed,
    }


def build_placeid_verification(
    *,
    random_value: int | None = None,
    profile_value: int = 0x5860DBFE,
) -> bytes:
    """Build current 0x92; the upper word is fresh for every send."""
    random_value = secrets.randbits(32) if random_value is None else int(random_value)
    if not 0 <= random_value <= 0xFFFFFFFF or not 0 <= int(profile_value) <= 0xFFFFFFFF:
        raise ValueError("place verification word out of range")
    packed = (random_value << 32) | (random_value ^ int(profile_value))
    signed = packed - (1 << 64) if packed & (1 << 63) else packed
    return bytes((ID_PLACEID_VERIFICATION,)) + encode_varsint(signed)


def parse_submit_ticket(
    packet: bytes, *, place_id: int, version_ids: Sequence[int]
) -> dict[str, Any]:
    key = derive_submit_ticket_key(place_id, version_ids)
    clear = decrypt_application_envelope(_body(packet, ID_SUBMIT_TICKET), key)
    reader = _Reader(clear)
    player_id = reader.varsint()
    client_ticket = reader.varbytes()
    protocol_version = reader.u32le()
    security_key = reader.varbytes()
    platform = reader.varbytes()
    product_name = reader.varbytes()
    ticket_hash = reader.varuint()
    hash2 = reader.varuint()
    luau_response = reader.varsint()
    session_id = reader.varbytes()
    golden_hash = reader.u32le()
    reader.finish()
    return {
        "player_id": player_id,
        "client_ticket": client_ticket.decode("utf-8"),
        # These legacy fields have no bytes or length prefix in the captured
        # 0.738 layout.  They remain explicit here to prevent positional mixups.
        "data_model_hash": None,
        "protocol_version": protocol_version,
        "security_key": security_key.decode("utf-8"),
        "platform": platform.decode("utf-8"),
        "product_name": product_name.decode("utf-8"),
        "ticket_hash": ticket_hash,
        "hash2": hash2,
        "luau_response": luau_response,
        "crypto_hash": None,
        "session_id": session_id.decode("utf-8"),
        "session_id_bytes": session_id,
        "golden_hash": golden_hash,
    }


def build_submit_ticket(
    *,
    place_id: int,
    version_ids: Sequence[int],
    player_id: int,
    client_ticket: str | bytes,
    security_key: str | bytes,
    platform: str | bytes,
    product_name: str | bytes,
    ticket_hash: int,
    session_id: str | bytes | Mapping[str, Any],
    protocol_version: int = 36,
    hash2: int | None = None,
    luau_response: int = 0,
    golden_hash: int = 0xC001CAFE,
    random_bytes: RandomBytes = secrets.token_bytes,
) -> bytes:
    """Build the captured 0.738 0x8A layout.

    DataModelHash and CryptoHash from older layouts are intentionally absent:
    current vectors have neither a value nor a zero-length prefix at those
    positions.
    """
    if not 0 <= int(ticket_hash) <= 0xFFFFFFFF:
        raise ValueError("ticket_hash out of uint32 range")
    if hash2 is None:
        hash2 = (int(ticket_hash) - 0x0BADF00D) & 0xFFFFFFFF
    if not 0 <= int(hash2) <= 0xFFFFFFFF:
        raise ValueError("hash2 out of uint32 range")
    session_bytes = serialize_join_data(session_id) if isinstance(session_id, Mapping) else _utf8(session_id)
    clear = bytearray(encode_varsint(player_id))
    clear += encode_varbytes(client_ticket)
    clear += _u32le(protocol_version)
    clear += encode_varbytes(security_key)
    clear += encode_varbytes(platform)
    clear += encode_varbytes(product_name)
    clear += encode_varuint(ticket_hash)
    clear += encode_varuint(hash2)
    # The native field is a signed-zigzag int32 even though response helpers
    # commonly expose its uint32 bit pattern.
    clear += encode_varsint(as_signed_int32(luau_response))
    clear += encode_varbytes(session_bytes)
    clear += _u32le(golden_hash)
    key = derive_submit_ticket_key(place_id, version_ids)
    return bytes((ID_SUBMIT_TICKET,)) + encrypt_application_envelope(
        bytes(clear), key, random_bytes=random_bytes
    )


def build_preferred_spawn_name(name: str | bytes = b"") -> bytes:
    return bytes((ID_PREFERRED_SPAWN_NAME,)) + encode_varbytes(name)


def parse_preferred_spawn_name(packet: bytes) -> str:
    reader = _Reader(_body(packet, ID_PREFERRED_SPAWN_NAME))
    name = reader.varbytes().decode("utf-8")
    reader.finish()
    return name
