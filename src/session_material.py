"""Parse the shape of join-time SessionCrypto material.

The parser keeps decoded values in memory for the caller that will eventually
serialize the build-specific RbxOpenRequest2 frame. Its public summary contains
only lengths and algorithm metadata, so diagnostic reports never persist keys,
tokens, or seeds.
"""
from __future__ import annotations

import base64
import json
import urllib.parse
from dataclasses import dataclass
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
except ImportError:  # pragma: no cover - parser remains usable without crypto extras
    X25519PrivateKey = None  # type: ignore[assignment,misc]


def _b64(value: Any, *, urlsafe: bool = True) -> bytes:
    if not isinstance(value, str):
        return b""
    raw = urllib.parse.unquote(value).encode("ascii", "ignore")
    decoder = base64.urlsafe_b64decode if urlsafe else base64.b64decode
    try:
        return decoder(raw + b"=" * ((4 - len(raw) % 4) % 4))
    except (ValueError, base64.binascii.Error):
        return b""


@dataclass(frozen=True)
class SessionMaterial:
    early_public_key: bytes = b""
    ephemeral_early_public_key: bytes = b""
    random_seed1: bytes = b""
    # RandomSeed2 is nested in the SessionId envelope on current join
    # responses.  It is kept separate because the 0.738 RUPP token builder
    # prefixes one of the 64-byte seeds with its two-byte algorithm marker.
    random_seed2: bytes = b""
    token_value: bytes = b""
    netstack_token_value: bytes = b""
    api_security_token: str = ""
    # ClientTicket is a semicolon-delimited join artifact.  Segments 2 and 3
    # are the native 0.738 RUPP identity (33 bytes) and token (66 bytes).
    client_ticket: str = ""
    # Full join fields remain transient and feed the later application
    # bootstrap. Public reports expose only the shape through ``summary``.
    join_payload: dict[str, Any] | None = None
    session_id_json: str = ""
    rupp_identity: bytes = b""
    rupp_token: bytes = b""
    netstack_public_key: bytes = b""
    netstack_port: int | None = None
    token_algorithm: int | None = None

    def new_context(self, mtu: int, netstack_port: int | None = None) -> "SessionContext":
        """Create an in-memory handshake context for the current join.

        The private ephemeral key is intentionally never serialised.  The
        context is the adapter input for the build-specific encrypted
        RbxOpenRequest2 frame; it does not guess the KDF or AAD transcript.
        """
        if X25519PrivateKey is None:
            raise RuntimeError("cryptography package is required for SessionCrypto")
        private = X25519PrivateKey.generate()
        public = private.public_key().public_bytes_raw()
        return SessionContext(
            mtu=int(mtu),
            client_guid=0,
            early_public_key=self.early_public_key,
            ephemeral_early_public_key=self.ephemeral_early_public_key,
            client_ephemeral_public_key=public,
            _client_ephemeral_private=private,
            random_seed1=self.random_seed1,
            token_value=self.token_value,
            netstack_token_value=self.netstack_token_value,
            netstack_public_key=self.netstack_public_key,
            netstack_port=netstack_port if netstack_port is not None else self.netstack_port,
            token_algorithm=self.token_algorithm,
        )

    @classmethod
    def from_join_payload(cls, payload: dict[str, Any]) -> "SessionMaterial":
        early = b""
        keyring = payload.get("ClientPublicKeyData")
        if isinstance(keyring, str):
            try:
                keyring_obj = json.loads(keyring)
                versions = keyring_obj.get("applications", {}).get("RakNetEarlyPublicKey", {}).get("versions", [])
                if versions and isinstance(versions[0], dict):
                    early = _b64(versions[0].get("value"))
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
        net_key = b""
        net_port: int | None = None
        cfg = payload.get("NetStackConfig")
        if isinstance(cfg, str):
            try:
                cfg_obj = json.loads(urllib.parse.unquote(cfg))
                net_key = _b64(cfg_obj.get("pubKey"))
                if cfg_obj.get("port") is not None:
                    net_port = int(cfg_obj["port"])
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
        algorithm = payload.get("TokenGenAlgorithm")
        try:
            algorithm = int(algorithm) if algorithm is not None else None
        except (TypeError, ValueError):
            algorithm = None
        random_seed2 = b""
        session_id = payload.get("SessionId")
        if isinstance(session_id, str):
            try:
                session_obj = json.loads(session_id)
                if isinstance(session_obj, dict):
                    random_seed2 = _b64(session_obj.get("RandomSeed2"), urlsafe=False)
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
        client_ticket = str(payload.get("ClientTicket") or "")
        rupp_identity = b""
        rupp_token = b""
        # Native ClientRuppGenerator consumes ClientTicket fields 2/3 after
        # base64 decoding; preserving these transiently avoids guessing from
        # unrelated seed/key fields.
        try:
            parts = client_ticket.split(";")
            if len(parts) >= 4:
                rupp_identity = _b64(parts[2], urlsafe=False)
                rupp_token = _b64(parts[3], urlsafe=False)
        except (TypeError, ValueError):
            pass
        return cls(
            early_public_key=early,
            ephemeral_early_public_key=_b64(payload.get("EphemeralEarlyPubKey")),
            random_seed1=_b64(payload.get("RandomSeed1")),
            random_seed2=random_seed2,
            token_value=_b64(payload.get("TokenValue"), urlsafe=False),
            netstack_token_value=_b64(payload.get("NetStackTokenValue"), urlsafe=False),
            api_security_token=str(payload.get("APIsecurityToken") or ""),
            client_ticket=client_ticket,
            join_payload=dict(payload),
            session_id_json=session_id if isinstance(session_id, str) else "",
            rupp_identity=rupp_identity,
            rupp_token=rupp_token,
            netstack_public_key=net_key,
            netstack_port=net_port,
            token_algorithm=algorithm,
        )

    def summary(self) -> dict[str, Any]:
        return {
            "early_public_key_bytes": len(self.early_public_key),
            "ephemeral_early_public_key_bytes": len(self.ephemeral_early_public_key),
            "random_seed1_bytes": len(self.random_seed1),
            "random_seed2_bytes": len(self.random_seed2),
            "token_value_bytes": len(self.token_value),
            "netstack_token_value_bytes": len(self.netstack_token_value),
            "api_security_token_chars": len(self.api_security_token),
            "client_ticket_chars": len(self.client_ticket),
            "join_payload_keys": len(self.join_payload or {}),
            "session_id_chars": len(self.session_id_json),
            "rupp_identity_bytes": len(self.rupp_identity),
            "rupp_token_bytes": len(self.rupp_token),
            "netstack_public_key_bytes": len(self.netstack_public_key),
            "netstack_port": self.netstack_port,
            "token_algorithm": self.token_algorithm,
        }

    def token_blob_candidate(self) -> bytes:
        """Return the observed 0.738 RUPP token shape for adapter use.

        Runtime traces show a 66-byte token beginning with ``06 01`` and a
        64-byte per-session seed.  The source seed is selected from the
        nested RandomSeed2 when present, with RandomSeed1 as the legacy
        fallback.  This helper only constructs the clear field; callers still
        need the live SessionCrypto key and UDMUX context before sending it.
        """
        if len(self.rupp_token) == 66:
            return self.rupp_token
        seed = self.random_seed2 or self.random_seed1
        if len(seed) != 64:
            raise ValueError("a 64-byte RandomSeed1/RandomSeed2 is required")
        return b"\x06\x01" + seed


@dataclass
class SessionContext:
    """Transient, non-serialisable state for one SessionCrypto handshake."""

    mtu: int
    client_guid: int
    early_public_key: bytes
    ephemeral_early_public_key: bytes
    client_ephemeral_public_key: bytes
    _client_ephemeral_private: Any
    random_seed1: bytes
    token_value: bytes
    netstack_token_value: bytes
    netstack_public_key: bytes
    netstack_port: int | None
    token_algorithm: int | None

    # The 0.738 Request2 AAD carries the client-generated public key.  Older
    # fixtures used ``early_public_key`` for this field, so keep an explicit
    # override that lets the live adapter select the correct per-join value
    # without changing fixture semantics.
    request2_public_key: bytes | None = None

    # 0.738 traces show the same 64-bit client value on every captured
    # Request2.  Keep it in the context rather than burying it in the wire
    # serializer so a future profile can override it without changing code.
    request2_client_value: int = 0x000DD3C758B7EAFA

    def summary(self) -> dict[str, Any]:
        return {
            "mtu": self.mtu,
            "client_guid_bits": self.client_guid.bit_length(),
            "early_public_key_bytes": len(self.early_public_key),
            "ephemeral_early_public_key_bytes": len(self.ephemeral_early_public_key),
            "client_ephemeral_public_key_bytes": len(self.client_ephemeral_public_key),
            "random_seed1_bytes": len(self.random_seed1),
            "token_value_bytes": len(self.token_value),
            "netstack_token_value_bytes": len(self.netstack_token_value),
            "netstack_public_key_bytes": len(self.netstack_public_key),
            "netstack_port": self.netstack_port,
            "token_algorithm": self.token_algorithm,
            "request2_client_value": self.request2_client_value,
            "request2_public_key_bytes": len(self.request2_public_key or b""),
        }

    def client_material_bytes(self) -> bytes:
        """Serialize the getter's GUID as the Request2 wire u64.

        The runtime getter exposes the GUID in little-endian object storage,
        then the Request2 builder byte-swaps it before writing the 64-bit
        field.  Keeping that conversion here matches the field-level trace.
        """
        if not 0 <= self.client_guid <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("client_guid out of range")
        return int(self.client_guid).to_bytes(8, "big")
