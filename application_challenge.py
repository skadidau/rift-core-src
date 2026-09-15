"""Application packet 0x92 / 0x9B codecs for the Android x86-64 0.738 fixture.

Native evidence (image base 0):

* ``0x326F244`` / ``0x327045C`` build packet 0x92.
* ``0x6963907`` writes unsigned LEB128 (seven payload bits per byte).
* ``0x3575989`` produces the 0.738 verification profile word.
* ``0x3281B04`` parses packet 0x9B.
* ``0x69641C4`` reads its native little-endian u32 fields.
* ``0x6964A06`` reads ``u32 byte_length + raw bytes``.
* ``0x327FB92`` calls ``challenge(a3, a2)`` and replies with
  ``0x9B + u32le(a3) + u32le(result)``.

The challenge program is not a fixed native expression.  It is an RSB1-wrapped,
Zstandard-compressed Luau bytecode blob supplied in the inbound packet.  The
standalone evaluator below unwraps/decompiles that blob, runs only its arithmetic
prefix in the local Luau VM, and adds the stable environment contribution for
this fixture profile.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

ID_PLACE_ID_VERIFICATION = 0x92
ID_CHALLENGE = 0x9B

# sub_3575989 for libroblox_2738_x86_64.so.  Both independent official
# captures recover this word from high32(packed) XOR low32(packed).
PLACE_VERIFICATION_PROFILE_0738 = 0x5860DBFE

# Inputs visible in sub_3575989.  sub_3575823 is the obfuscated bit-mixing
# primitive; these document the exact build profile even though callers only
# need the already-evaluated word above.
PLACE_PROFILE_GLOBAL_0738 = 0x71375635
PLACE_PROFILE_MULTIPLIER_A = 0xDCFCA9F3  # signed -587421197
PLACE_PROFILE_MULTIPLIER_B = 0xA23005C5  # signed -1573911099
PLACE_PROFILE_OR_MASK = 0xB68B0000

# PCG constants used by Random.new / Random:NextInteger in this client.
PCG32_MULTIPLIER = 0x5851F42D4C957F2D
PCG32_INCREMENT = 0x69
PCG32_SEED_OFFSET = (PCG32_INCREMENT * (PCG32_MULTIPLIER + 1)) & MASK64

# Everything after sum(game.JobId bytes) in the decoded 0.738 challenge:
# two UserSettings tostring loops + os.exit xpcall + IsStudio xpcall +
# newproxy/namecall xpcall.  It was isolated from the official response vector.
CHALLENGE_ENVIRONMENT_FIXED_0738 = 14_259

RSB1_MAGIC = b"RSB1"
ZSTD_FRAME_MAGIC = b"\x28\xb5\x2f\xfd"

NATIVE_OFFSETS = {
    "build_0x92_a": 0x326F244,
    "build_0x92_b": 0x327045C,
    "random_pcg32": 0x1D8CF5E,
    "write_uleb128": 0x6963907,
    "verification_profile": 0x3575989,
    "decode_0x9b": 0x3281B04,
    "read_u32": 0x69641C4,
    "read_string_u32": 0x6964A06,
    "evaluate_and_build_0x9b": 0x327FB92,
}


class ChallengeCodecError(ValueError):
    """Malformed application packet or challenge container."""


@dataclass(frozen=True)
class PlaceIdVerification:
    random_u32: int
    profile_u32: int
    packed_u64: int
    packed_signed: int
    zigzag_u64: int


@dataclass(frozen=True)
class ChallengePacket:
    int1: int
    challenge_id: int
    script: bytes

    @property
    def script_len(self) -> int:
        return len(self.script)


@dataclass(frozen=True)
class ChallengeResponse:
    challenge_id: int
    response: int


@dataclass(frozen=True)
class Rsb1Script:
    xor_key: bytes
    container: bytes
    raw_size: int
    compressed: bytes
    bytecode: bytes | None

    @property
    def encoded_sha256(self) -> str:
        # ``container`` is already decoded; callers interested in the original
        # wire hash can hash ChallengePacket.script directly.
        return hashlib.sha256(self.container).hexdigest()

    @property
    def bytecode_sha256(self) -> str | None:
        if self.bytecode is None:
            return None
        return hashlib.sha256(self.bytecode).hexdigest()


def _u32(value: int, name: str = "value") -> int:
    value = int(value)
    if not 0 <= value <= MASK32:
        raise ValueError(f"{name} must be in [0, 0xffffffff]")
    return value


def encode_varuint(value: int) -> bytes:
    """Encode a non-negative 64-bit integer as canonical unsigned LEB128."""

    value = int(value)
    if not 0 <= value <= MASK64:
        raise ValueError("varuint must be in [0, 0xffffffffffffffff]")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        out.append(byte)
        if not value:
            return bytes(out)


def decode_varuint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Return ``(value, next_offset)`` for canonical 64-bit ULEB128."""

    data = bytes(data)
    value = 0
    start = offset
    for index in range(10):
        if offset >= len(data):
            raise ChallengeCodecError("truncated varuint")
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise ChallengeCodecError("varuint exceeds 64 bits")
        value |= (byte & 0x7F) << (index * 7)
        if not byte & 0x80:
            if data[start:offset] != encode_varuint(value):
                raise ChallengeCodecError("non-canonical varuint")
            return value, offset
    raise ChallengeCodecError("unterminated varuint")


def zigzag64_encode_bits(bits: int) -> int:
    """ZigZag-encode a signed int64 represented by its raw 64-bit bits."""

    bits &= MASK64
    sign_fill = MASK64 if bits & (1 << 63) else 0
    return (((bits << 1) & MASK64) ^ sign_fill) & MASK64


def zigzag64_decode_bits(encoded: int) -> int:
    """Decode ZigZag to the raw two's-complement int64 bit pattern."""

    encoded &= MASK64
    return ((encoded >> 1) ^ (-(encoded & 1) & MASK64)) & MASK64


def build_place_id_verification(
    random_u32: int,
    profile_u32: int = PLACE_VERIFICATION_PROFILE_0738,
) -> bytes:
    """Build packet 0x92.

    Native formula::

        packed_bits = random_u32 << 32 | (random_u32 ^ profile_u32)
        wire_value  = ZigZag64(packed_bits interpreted as signed int64)
        packet      = 0x92 || ULEB128(wire_value)
    """

    random_u32 = _u32(random_u32, "random_u32")
    profile_u32 = _u32(profile_u32, "profile_u32")
    packed = (random_u32 << 32) | (random_u32 ^ profile_u32)
    return bytes((ID_PLACE_ID_VERIFICATION,)) + encode_varuint(
        zigzag64_encode_bits(packed)
    )


def parse_place_id_verification(packet: bytes) -> PlaceIdVerification:
    packet = bytes(packet)
    if not packet or packet[0] != ID_PLACE_ID_VERIFICATION:
        raise ChallengeCodecError("expected application packet 0x92")
    zigzag, end = decode_varuint(packet, 1)
    if end != len(packet):
        raise ChallengeCodecError("trailing bytes after packet 0x92 value")
    packed = zigzag64_decode_bits(zigzag)
    random_u32 = packed >> 32
    low_u32 = packed & MASK32
    signed = packed if packed < (1 << 63) else packed - (1 << 64)
    return PlaceIdVerification(
        random_u32=random_u32,
        profile_u32=random_u32 ^ low_u32,
        packed_u64=packed,
        packed_signed=signed,
        zigzag_u64=zigzag,
    )


def build_challenge_packet(int1: int, challenge_id: int, script: bytes) -> bytes:
    """Build the server-side 0x9B fixture form for tests/replay."""

    int1 = _u32(int1, "int1")
    challenge_id = _u32(challenge_id, "challenge_id")
    script = bytes(script)
    return struct.pack("<BIII", ID_CHALLENGE, int1, challenge_id, len(script)) + script


def parse_challenge(packet: bytes) -> ChallengePacket:
    """Parse ``0x9B | int1:u32le | id:u32le | length:u32le | script``."""

    packet = bytes(packet)
    if len(packet) < 13 or packet[0] != ID_CHALLENGE:
        raise ChallengeCodecError("expected inbound application packet 0x9B")
    int1, challenge_id, script_len = struct.unpack_from("<III", packet, 1)
    if len(packet) != 13 + script_len:
        raise ChallengeCodecError(
            f"0x9B script length says {script_len}, packet carries {len(packet) - 13}"
        )
    return ChallengePacket(int1=int1, challenge_id=challenge_id, script=packet[13:])


def build_challenge_response(challenge_id: int, response: int) -> bytes:
    """Build ``0x9B | challenge_id:u32le | response:u32le``."""

    return struct.pack(
        "<BII",
        ID_CHALLENGE,
        _u32(challenge_id, "challenge_id"),
        _u32(response, "response"),
    )


def parse_challenge_response(packet: bytes) -> ChallengeResponse:
    packet = bytes(packet)
    if len(packet) != 9 or packet[0] != ID_CHALLENGE:
        raise ChallengeCodecError("expected nine-byte 0x9B response")
    challenge_id, response = struct.unpack_from("<II", packet, 1)
    return ChallengeResponse(challenge_id=challenge_id, response=response)


def recover_rsb1_key(encoded_script: bytes) -> bytes:
    """Recover the four-byte rolling-XOR key from known plaintext ``RSB1``."""

    encoded_script = bytes(encoded_script)
    if len(encoded_script) < 4:
        raise ChallengeCodecError("RSB1 script is shorter than its magic")
    return bytes(
        ((encoded_script[i] ^ RSB1_MAGIC[i]) - i * 41) & 0xFF for i in range(4)
    )


def decode_rsb1_bytes(encoded_script: bytes) -> tuple[bytes, bytes]:
    """Return ``(four_byte_key, decoded_RSB1_container)``."""

    encoded_script = bytes(encoded_script)
    key = recover_rsb1_key(encoded_script)
    decoded = bytes(
        byte ^ ((key[index & 3] + index * 41) & 0xFF)
        for index, byte in enumerate(encoded_script)
    )
    if len(decoded) < 12 or decoded[:4] != RSB1_MAGIC:
        raise ChallengeCodecError("bad RSB1 container header")
    if decoded[8:12] != ZSTD_FRAME_MAGIC:
        raise ChallengeCodecError("RSB1 payload is not a Zstandard frame")
    return key, decoded


def _candidate_zstd_dlls() -> Iterable[Path]:
    yield Path.home() / (
        ".cache/codex-runtimes/codex-primary-runtime/dependencies/native/"
        "poppler/Library/bin/zstd.dll"
    )
    yield Path("zstd.dll")
    yield Path("libzstd.dll")


def _zstd_decompress_ctypes(
    compressed: bytes,
    expected_size: int,
    zstd_dll: str | Path | None = None,
) -> bytes:
    candidates = [Path(zstd_dll)] if zstd_dll is not None else list(_candidate_zstd_dlls())
    last_error: Exception | None = None
    library = None
    for candidate in candidates:
        try:
            library = ctypes.CDLL(str(candidate))
            break
        except OSError as exc:
            last_error = exc
    if library is None:
        raise ChallengeCodecError(f"Zstandard DLL was not found: {last_error}")

    library.ZSTD_decompress.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    library.ZSTD_decompress.restype = ctypes.c_size_t
    library.ZSTD_isError.argtypes = [ctypes.c_size_t]
    library.ZSTD_isError.restype = ctypes.c_uint
    library.ZSTD_getErrorName.argtypes = [ctypes.c_size_t]
    library.ZSTD_getErrorName.restype = ctypes.c_char_p

    source = ctypes.create_string_buffer(compressed)
    destination = ctypes.create_string_buffer(expected_size)
    result = library.ZSTD_decompress(
        destination,
        expected_size,
        source,
        len(compressed),
    )
    if library.ZSTD_isError(result):
        name = library.ZSTD_getErrorName(result).decode("ascii", "replace")
        raise ChallengeCodecError(f"Zstandard decompression failed: {name}")
    if result != expected_size:
        raise ChallengeCodecError(
            f"RSB1 raw size says {expected_size}, decompressor returned {result}"
        )
    return destination.raw[:result]


def decode_rsb1_script(
    encoded_script: bytes,
    *,
    decompress: bool = True,
    zstd_dll: str | Path | None = None,
    decompressor: Callable[[bytes, int], bytes] | None = None,
) -> Rsb1Script:
    """Decode an RSB1 challenge, optionally returning raw Luau bytecode."""

    key, container = decode_rsb1_bytes(encoded_script)
    raw_size = struct.unpack_from("<I", container, 4)[0]
    if raw_size > 64 * 1024 * 1024:
        raise ChallengeCodecError(f"implausible RSB1 raw size: {raw_size}")
    compressed = container[8:]
    bytecode: bytes | None = None
    if decompress:
        if decompressor is None:
            bytecode = _zstd_decompress_ctypes(compressed, raw_size, zstd_dll)
        else:
            bytecode = bytes(decompressor(compressed, raw_size))
            if len(bytecode) != raw_size:
                raise ChallengeCodecError(
                    f"RSB1 raw size says {raw_size}, callback returned {len(bytecode)}"
                )
    return Rsb1Script(
        xor_key=key,
        container=container,
        raw_size=raw_size,
        compressed=compressed,
        bytecode=bytecode,
    )


class Pcg32:
    """Native Random.new generator used by the decoded challenge program."""

    def __init__(self, seed: int):
        seed = int(seed) & MASK64
        self.state = (seed * PCG32_MULTIPLIER + PCG32_SEED_OFFSET) & MASK64

    def next_u32(self) -> int:
        old = self.state
        self.state = (old * PCG32_MULTIPLIER + PCG32_INCREMENT) & MASK64
        value = (((old >> 18) ^ old) >> 27) & MASK32
        rotation = old >> 59
        return ((value >> rotation) | (value << ((-rotation) & 31))) & MASK32

    def next_integer(self, a: int, b: int) -> int:
        """Inclusive native mapping: lo + high32(span * next_u32())."""

        a, b = int(a), int(b)
        lo = min(a, b)
        span = abs(a - b) + 1
        if not 1 <= span <= (1 << 32):
            raise ValueError("NextInteger span must fit in uint32")
        return lo + ((span * self.next_u32()) >> 32)


def _tool_candidates() -> tuple[list[Path], list[Path]]:
    executor_root = Path(__file__).resolve().parents[2]
    lifters = [
        executor_root
        / "LegacyWork/artifacts/Tovek_reference/target/release/luau-lifter.exe",
        executor_root
        / "LegacyWork/artifacts/Tovek_reference/target/release/deps/luau_lifter.exe",
    ]
    luaus = [
        executor_root / "SharedTools/luau-build-731/Release/luau.exe",
        executor_root / "SharedTools/luau-build-731-host5/luau.exe",
        executor_root / "SharedTools/luau-ref-debug-vs/Release/luau.exe",
    ]
    return lifters, luaus


def _resolve_tool(explicit: str | Path | None, candidates: Iterable[Path], label: str) -> Path:
    if explicit is not None:
        result = Path(explicit)
        if result.is_file():
            return result
        raise ChallengeCodecError(f"{label} does not exist: {result}")
    for result in candidates:
        if result.is_file():
            return result
    raise ChallengeCodecError(f"local {label} was not found")


def decompile_challenge_bytecode(
    bytecode: bytes,
    *,
    lifter_path: str | Path | None = None,
    timeout: float = 10.0,
) -> str:
    """Decompile raw v9 bytecode with the local lifter (opcode profile 203)."""

    lifters, _ = _tool_candidates()
    lifter = _resolve_tool(lifter_path, lifters, "luau-lifter.exe")
    with tempfile.TemporaryDirectory(prefix="rift-challenge-lift-") as directory:
        bytecode_path = Path(directory) / "challenge.luac"
        bytecode_path.write_bytes(bytes(bytecode))
        result = subprocess.run(
            [str(lifter), str(bytecode_path), "-e"],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise ChallengeCodecError(f"Luau lifter failed ({result.returncode}): {detail}")
    source = result.stdout.lstrip("\ufeff")
    if "local v, v2 = ..." not in source or "local jobId = game.JobId" not in source:
        raise ChallengeCodecError("unexpected challenge decompilation template")
    return source


def _random_result_fixture(seed: int, count: int = 128) -> tuple[list[int], list[int]]:
    """Precompute exact native values consumed by the local Luau wrapper."""

    rng = Pcg32(seed)
    maxima = [4, 3, 2] + [2_147_483_647] * max(0, count - 3)
    return [rng.next_integer(1, maximum) for maximum in maxima], maxima


def build_luau_core_runner(decompiled_source: str, challenge_id: int, int1: int) -> str:
    """Create a local-VM runner for only the challenge's arithmetic prefix."""

    challenge_id = _u32(challenge_id, "challenge_id")
    int1 = _u32(int1, "int1")
    source = decompiled_source.lstrip("\ufeff")
    source, substitutions = re.subn(
        r"(?m)^local\s+v,\s*v2\s*=\s*\.\.\.\s*$",
        f"local v, v2 = {challenge_id}, {int1}",
        source,
        count=1,
    )
    if substitutions != 1:
        raise ChallengeCodecError("challenge argument declaration was not found")
    marker = "local jobId = game.JobId"
    marker_offset = source.find(marker)
    if marker_offset < 0:
        raise ChallengeCodecError("challenge environment-tail marker was not found")
    source = source[:marker_offset]
    core_matches = re.findall(
        r"(?m)^local\s+([A-Za-z_]\w*)\s*=\s*bit32\.bor\(", source
    )
    if not core_matches:
        raise ChallengeCodecError("challenge core result variable was not found")
    core_variable = core_matches[-1]

    # The first three calls are Fisher-Yates bounds 4, 3, 2.  Every remaining
    # call in the 0.738 generator uses [1, 2147483647].  Precomputing in Python
    # avoids precision loss from a 32x32 high multiply in a double-only VM.
    random_values, maxima = _random_result_fixture(challenge_id + int1)
    values_literal = ",".join(str(value) for value in random_values)
    maxima_literal = ",".join(str(value) for value in maxima)
    prelude = f"""
local __rift_values = {{{values_literal}}}
local __rift_maxima = {{{maxima_literal}}}
local __rift_index = 0
Random = {{}}
function Random.new(_seed)
    return {{NextInteger = function(_self, lo, hi)
        __rift_index += 1
        if lo ~= 1 or hi ~= __rift_maxima[__rift_index] then
            error("unexpected Random:NextInteger bounds at call " .. __rift_index)
        end
        local result = __rift_values[__rift_index]
        if result == nil then error("challenge consumed too many random values") end
        return result
    end}}
end
"""
    return (
        prelude
        + "\n"
        + source
        + f'\nprint("__RIFT_CHALLENGE_CORE__" .. tostring({core_variable}))\n'
    )


def evaluate_decompiled_challenge_core(
    decompiled_source: str,
    challenge_id: int,
    int1: int,
    *,
    luau_path: str | Path | None = None,
    timeout: float = 10.0,
) -> int:
    """Evaluate the changing arithmetic program in a local Luau CLI."""

    _, luaus = _tool_candidates()
    luau = _resolve_tool(luau_path, luaus, "luau.exe")
    runner = build_luau_core_runner(decompiled_source, challenge_id, int1)
    with tempfile.TemporaryDirectory(prefix="rift-challenge-run-") as directory:
        source_path = Path(directory) / "runner.luau"
        source_path.write_text(runner, encoding="utf-8")
        result = subprocess.run(
            [str(luau), str(source_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    output = result.stdout + "\n" + result.stderr
    if result.returncode != 0:
        raise ChallengeCodecError(f"local Luau evaluation failed ({result.returncode}): {output.strip()}")
    match = re.search(r"__RIFT_CHALLENGE_CORE__(\d+)", output)
    if not match:
        raise ChallengeCodecError(f"local Luau result marker was not emitted: {output.strip()}")
    return int(match.group(1)) & MASK32


def byte_sum(value: str | bytes) -> int:
    """Sum bytes exactly as the Luau ``string.byte`` loops do for ASCII IDs."""

    if isinstance(value, str):
        value = value.encode("utf-8")
    return sum(bytes(value))


def evaluate_challenge_0738(
    packet: bytes | ChallengePacket,
    job_id: str | bytes,
    *,
    environment_fixed: int = CHALLENGE_ENVIRONMENT_FIXED_0738,
    zstd_dll: str | Path | None = None,
    lifter_path: str | Path | None = None,
    luau_path: str | Path | None = None,
    timeout: float = 10.0,
) -> int:
    """Evaluate an inbound 0x9B packet and return its uint32 response value."""

    challenge = packet if isinstance(packet, ChallengePacket) else parse_challenge(packet)
    decoded = decode_rsb1_script(challenge.script, zstd_dll=zstd_dll)
    assert decoded.bytecode is not None
    source = decompile_challenge_bytecode(
        decoded.bytecode,
        lifter_path=lifter_path,
        timeout=timeout,
    )
    core = evaluate_decompiled_challenge_core(
        source,
        challenge.challenge_id,
        challenge.int1,
        luau_path=luau_path,
        timeout=timeout,
    )
    return (core + byte_sum(job_id) + int(environment_fixed)) & MASK32


def solve_challenge_packet_0738(
    packet: bytes,
    job_id: str | bytes,
    **kwargs: object,
) -> bytes:
    """One-call live API: inbound packet -> exact nine-byte 0x9B response."""

    challenge = parse_challenge(packet)
    response = evaluate_challenge_0738(challenge, job_id, **kwargs)
    return build_challenge_response(challenge.challenge_id, response)


# ---------------------------------------------------------------------------
# In-file regression tests


def test_place_id_verification_vectors() -> None:
    first = bytes.fromhex("92e9bea986c392fa858001")
    second = bytes.fromhex("92f098aaaec4f1ce85f501")
    decoded_first = parse_place_id_verification(first)
    decoded_second = parse_place_id_verification(second)
    assert decoded_first.random_u32 == 0xBFFA0BB5
    assert decoded_second.random_u32 == 0x7A859DC6
    assert decoded_first.profile_u32 == PLACE_VERIFICATION_PROFILE_0738
    assert decoded_second.profile_u32 == PLACE_VERIFICATION_PROFILE_0738
    assert build_place_id_verification(decoded_first.random_u32) == first
    assert build_place_id_verification(decoded_second.random_u32) == second


def test_challenge_wire_vector() -> None:
    response = bytes.fromhex("9b63358fbe8a0f7a46")
    decoded = parse_challenge_response(response)
    assert decoded.challenge_id == 0xBE8F3563
    assert decoded.response == 0x467A0F8A
    assert build_challenge_response(decoded.challenge_id, decoded.response) == response

    synthetic = build_challenge_packet(0x9E74015E, 0xBE8F3563, b"abc")
    parsed = parse_challenge(synthetic)
    assert parsed.int1 == 0x9E74015E
    assert parsed.challenge_id == 0xBE8F3563
    assert parsed.script == b"abc"


def _official_inbound_vector() -> tuple[bytes, str] | None:
    fixture = Path(__file__).resolve().parents[1] / "runs/official_established_decoded_full_20260914.json"
    if not fixture.is_file():
        return None
    document = json.loads(fixture.read_text(encoding="utf-8"))
    inbound = next(
        message
        for message in document["messages"]
        if message.get("direction") == "in" and message.get("id") == "0x9b"
    )
    return bytes.fromhex(inbound["hex"]), "9493e9cc-1124-4cd1-8bed-9b29322c75fe"


def test_official_rsb1_vector() -> None:
    fixture = _official_inbound_vector()
    if fixture is None:
        return
    packet, _ = fixture
    challenge = parse_challenge(packet)
    assert challenge.int1 == 0x9E74015E
    assert challenge.challenge_id == 0xBE8F3563
    assert challenge.script_len == 1875
    assert hashlib.sha256(challenge.script).hexdigest() == (
        "6b66fb2e75b635d42dadf36e71a96fd040e3a9390c48588a00d39f635b8cfaa0"
    )
    decoded = decode_rsb1_script(challenge.script)
    assert decoded.xor_key == bytes.fromhex("ddab379f")
    assert decoded.raw_size == 7011
    assert decoded.bytecode is not None and decoded.bytecode[0] == 9
    assert decoded.bytecode_sha256 == (
        "827acc753acf39c17182a9738a7a4b6b6714f45a79a8ac435bdfb08874175e9b"
    )


def test_official_challenge_evaluator() -> None:
    fixture = _official_inbound_vector()
    if fixture is None:
        return
    packet, job_id = fixture
    response = solve_challenge_packet_0738(packet, job_id)
    assert response == bytes.fromhex("9b63358fbe8a0f7a46")


def self_test() -> None:
    test_place_id_verification_vectors()
    test_challenge_wire_vector()
    test_official_rsb1_vector()
    test_official_challenge_evaluator()
    print("application_challenge: all tests passed")


if __name__ == "__main__":
    self_test()
