"""SessionCrypto AEAD framing recovered from the 0.738 runtime trace.

The client leaves a 90-byte AAD span untouched, encrypts the following body
with ChaCha20-Poly1305, then stores the 12-byte ``UniqueNumber`` nonce label
between ciphertext and the 16-byte authentication tag.  The caller still
supplies the per-session key and the already-serialized clear transcript; no
key derivation or token values are invented here.
"""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


NONCE_LABEL = b"UniqueNumber"
TAG_BYTES = 16
AAD_BYTES = 90
REPLY2_FIXED_BYTES = 21
ESTABLISHED_PUBLIC_BYTES = 32


def derive_native_key_pair(*, scalar: bytes, peer_public: bytes, aux: bytes) -> tuple[bytes, bytes]:
    """Candidate KDF shape for comparison against the native 0.738 helper.

    IDA shows a Curve25519-compatible multiply followed by a 64-byte BLAKE2b
    state (parameter word ``0x01010040``), updated with
    ``shared || peer_public || aux``. Its two output pointers receive the
    digest halves in reverse order. The multiply is custom/obfuscated in the
    client, so this standard X25519 candidate stays separate from Request2
    until a fresh runtime trace maps the holder pair to the active AEAD key.
    """
    scalar, peer_public, aux = bytes(scalar), bytes(peer_public), bytes(aux)
    if len(scalar) != 32 or len(peer_public) != 32 or len(aux) != 32:
        raise ValueError("scalar, peer_public and aux must each be 32 bytes")
    shared = X25519PrivateKey.from_private_bytes(scalar).exchange(
        X25519PublicKey.from_public_bytes(peer_public)
    )
    digest = hashlib.blake2b(shared + peer_public + aux, digest_size=64).digest()
    return digest[32:], digest[:32]


def derive_client_session_key(*, client_private: bytes, server_ephemeral_public: bytes,
                              client_public: bytes) -> bytes:
    """Derive the 0.738 client AEAD key from the observed holder layout.

    The native helper's holder fields are not arranged as
    ``(server_public, client_public, seed)``.  Runtime correlation shows:

    ``holder+0x00 = client_public``
    ``holder+0x20 = client_private``
    ``holder+0x40 = server_ephemeral_public``

    Its validation/multiply stage is X25519(client_private,
    server_ephemeral_public), followed by BLAKE2b-512 over that shared value,
    the peer public key, and the client public key.  The active AEAD key is
    the second 32-byte digest half (digest[32:]).
    """
    client_private = bytes(client_private)
    server_ephemeral_public = bytes(server_ephemeral_public)
    client_public = bytes(client_public)
    if any(len(v) != 32 for v in (client_private, server_ephemeral_public, client_public)):
        raise ValueError("client_private, server_ephemeral_public and client_public must each be 32 bytes")
    # Keep the public/private relationship explicit; this catches accidental
    # mixing of material from two joins before a packet is emitted.
    derived_public = X25519PrivateKey.from_private_bytes(client_private).public_key().public_bytes_raw()
    if derived_public != client_public:
        raise ValueError("client_public does not match client_private")
    return derive_client_session_key_pair(
        client_private=client_private,
        server_ephemeral_public=server_ephemeral_public,
        client_public=client_public,
    )[0]


def derive_client_session_key_pair(*, client_private: bytes, server_ephemeral_public: bytes,
                                   client_public: bytes) -> tuple[bytes, bytes]:
    """Return the two direction keys as ``(client, server)`` halves.

    The runtime stores both BLAKE2b digest halves at holder ``+0xc0`` and
    ``+0xe0``.  The first half is used for the outbound Request2 body; the
    paired second half authenticates the server Reply2 envelope.
    """
    client_private = bytes(client_private)
    server_ephemeral_public = bytes(server_ephemeral_public)
    client_public = bytes(client_public)
    if any(len(v) != 32 for v in (client_private, server_ephemeral_public, client_public)):
        raise ValueError("client_private, server_ephemeral_public and client_public must each be 32 bytes")
    derived_public = X25519PrivateKey.from_private_bytes(client_private).public_key().public_bytes_raw()
    if derived_public != client_public:
        raise ValueError("client_public does not match client_private")
    shared = X25519PrivateKey.from_private_bytes(client_private).exchange(
        X25519PublicKey.from_public_bytes(server_ephemeral_public)
    )
    digest = hashlib.blake2b(shared + client_public + server_ephemeral_public,
                             digest_size=64).digest()
    return digest[32:], digest[:32]


def derive_blake2_key_pair(*, state: bytes, external: bytes, field: bytes) -> tuple[bytes, bytes]:
    """Comparison candidate for the 0.738 native helper.

    The IDA body shows a BLAKE2b-512 state updated with three 32-byte spans
    after a build-specific validation gate.  The gate's internal transform is
    not an exported X25519 primitive, so this helper keeps the observable
    hash ordering explicit without pretending to reproduce that opaque gate.
    """
    state, external, field = bytes(state), bytes(external), bytes(field)
    if len(state) != 32 or len(external) != 32 or len(field) != 32:
        raise ValueError("state, external and field must each be 32 bytes")
    digest = hashlib.blake2b(state + external + field, digest_size=64).digest()
    return digest[32:], digest[:32]


def derive_hkdf_sha256(shared_secret: bytes, *, salt: bytes = b"", info: bytes = b"", length: int = 32) -> bytes:
    """Derive a candidate SessionCrypto key from explicit X25519 output.

    Salt/info stay caller-supplied because the client build chooses them; this
    helper makes candidate KDF variants reproducible without embedding a
    guessed protocol label in the transport.
    """
    if length <= 0 or length > 255 * 32:
        raise ValueError("invalid HKDF output length")
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=bytes(salt) or None,
                info=bytes(info)).derive(bytes(shared_secret))


def _validate_key(key: bytes) -> bytes:
    key = bytes(key)
    if len(key) != 32:
        raise ValueError("SessionCrypto ChaCha20 key must be 32 bytes")
    return key


def encrypt_body(key: bytes, aad: bytes, plaintext: bytes, *, nonce: bytes = NONCE_LABEL) -> bytes:
    """Return ``ciphertext || nonce || tag`` for one SessionCrypto body."""
    key = _validate_key(key)
    aad = bytes(aad)
    plaintext = bytes(plaintext)
    nonce = bytes(nonce)
    if len(nonce) != 12:
        raise ValueError("SessionCrypto nonce must be 12 bytes")
    encrypted = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    ciphertext, tag = encrypted[:-TAG_BYTES], encrypted[-TAG_BYTES:]
    return ciphertext + nonce + tag


def decrypt_body(key: bytes, aad: bytes, wire: bytes, *, nonce: bytes = NONCE_LABEL) -> bytes:
    """Verify and decrypt ``ciphertext || nonce || tag``."""
    key = _validate_key(key)
    aad = bytes(aad)
    wire = bytes(wire)
    nonce = bytes(nonce)
    if len(nonce) != 12:
        raise ValueError("SessionCrypto nonce must be 12 bytes")
    if len(wire) < len(nonce) + TAG_BYTES:
        raise ValueError("SessionCrypto body is shorter than nonce and tag")
    embedded_nonce = wire[-(len(nonce) + TAG_BYTES):-TAG_BYTES]
    if embedded_nonce != nonce:
        raise ValueError("SessionCrypto nonce label mismatch")
    ciphertext = wire[:-(len(nonce) + TAG_BYTES)]
    tag = wire[-TAG_BYTES:]
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext + tag, aad)


def split_reply2(payload: bytes, *, magic: bytes) -> tuple[bytes, bytes, bytes]:
    """Split the server Reply2 envelope into fixed header, AAD and AEAD wire.

    Reply2 carries dynamic lengths: ``id|magic|version|aad:u8|sealed:u16be``.
    The AAD length is measured from the beginning of the payload (including
    the marker and metadata), while the trailing 28 bytes are the embedded
    nonce label and authentication tag.  The 16-bit sealed field is retained
    as metadata by the native reader and is not used as the slicing boundary.
    """
    payload = bytes(payload)
    if len(magic) != 16 or len(payload) < REPLY2_FIXED_BYTES:
        raise ValueError("truncated Reply2")
    if payload[0] != 0x7D or payload[1:17] != magic:
        raise ValueError("Reply2 marker mismatch")
    aad_bytes = payload[18]
    sealed_bytes = int.from_bytes(payload[19:21], "big")
    if sealed_bytes < TAG_BYTES:
        raise ValueError("Reply2 sealed length is too small")
    if aad_bytes < REPLY2_FIXED_BYTES or len(payload) < aad_bytes + len(NONCE_LABEL) + TAG_BYTES:
        raise ValueError("Reply2 AAD/body spans are truncated")
    return (payload[:REPLY2_FIXED_BYTES], payload[:aad_bytes], payload[aad_bytes:])


def decrypt_reply2(key: bytes, payload: bytes, *, magic: bytes) -> bytes:
    """Authenticate and decrypt one length-described Reply2 payload."""
    _fixed, aad, wire = split_reply2(payload, magic=magic)
    return decrypt_body(key, aad, wire)


def derive_established_key_pair(*, client_private: bytes, client_public: bytes,
                                server_public: bytes) -> tuple[bytes, bytes]:
    """Return post-Reply2 ``(TX, RX)`` AES keys for the gameplay epoch."""
    return derive_client_session_key_pair(
        client_private=client_private,
        server_ephemeral_public=server_public,
        client_public=client_public,
    )


def reply2_established_public(payload: bytes, clear_body: bytes, *, magic: bytes) -> bytes:
    """Extract the 32-byte gameplay peer key crossing Reply2 AAD/body."""
    _fixed, aad, _wire = split_reply2(payload, magic=magic)
    transcript = aad + bytes(clear_body)
    end = REPLY2_FIXED_BYTES + ESTABLISHED_PUBLIC_BYTES
    if len(transcript) < end:
        raise ValueError("Reply2 gameplay public key is truncated")
    return transcript[REPLY2_FIXED_BYTES:end]


def encrypt_request2(key: bytes, packet_prefix: bytes, aad: bytes, body: bytes) -> bytes:
    """Join a clear prefix/AAD with the recovered encrypted body format."""
    packet_prefix = bytes(packet_prefix)
    aad = bytes(aad)
    if len(aad) != AAD_BYTES:
        raise ValueError(f"SessionCrypto AAD must be {AAD_BYTES} bytes")
    return packet_prefix + aad + encrypt_body(key, aad, body)


def split_request2(packet: bytes, *, prefix_bytes: int = 31, aad_bytes: int = AAD_BYTES) -> tuple[bytes, bytes, bytes]:
    """Split a traced request2 into ``prefix``, clear AAD and AEAD body."""
    packet = bytes(packet)
    if prefix_bytes < 0 or aad_bytes < 0 or len(packet) < prefix_bytes + aad_bytes:
        raise ValueError("request2 packet is shorter than its clear spans")
    return (
        packet[:prefix_bytes],
        packet[prefix_bytes:prefix_bytes + aad_bytes],
        packet[prefix_bytes + aad_bytes:],
    )
