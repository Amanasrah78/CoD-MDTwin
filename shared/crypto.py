from __future__ import annotations

import base64
import json
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii"))


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_keypair() -> Tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sk_raw = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk_raw = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64u(sk_raw), b64u(pk_raw)


def sign_json(private_key_b64u: str, payload: Dict[str, Any]) -> str:
    sk = Ed25519PrivateKey.from_private_bytes(b64u_decode(private_key_b64u))
    return b64u(sk.sign(canonical_json(payload)))


def verify_json(public_key_b64u: str, payload: Dict[str, Any], signature_b64u: str) -> bool:
    try:
        pk = Ed25519PublicKey.from_public_bytes(b64u_decode(public_key_b64u))
        pk.verify(b64u_decode(signature_b64u), canonical_json(payload))
        return True
    except Exception:
        return False


def holder_proof_payload(
    capability_hash: str,
    request: Dict[str, Any],
    challenge: str,
) -> Dict[str, Any]:
    """Return the canonical request-bound message signed by the capability holder."""
    return {
        "capability_hash": capability_hash,
        "did_req": request.get("actor_did"),
        "scope": request.get("scope"),
        "service": request.get("service"),
        "resource": request.get("resource"),
        "action": request.get("action"),
        "audience": request.get("audience"),
        "request_time": request.get("timestamp"),
        "challenge": challenge,
    }


def sign_holder_proof(
    private_key_b64u: str,
    capability_hash: str,
    request: Dict[str, Any],
    challenge: str,
) -> Dict[str, Any]:
    payload = holder_proof_payload(capability_hash, request, challenge)
    return {"payload": payload, "signature": sign_json(private_key_b64u, payload)}


def verify_holder_proof(
    public_key_b64u: str,
    proof: Dict[str, Any],
    capability_hash: str,
    request: Dict[str, Any],
    challenge: str,
) -> bool:
    expected = holder_proof_payload(capability_hash, request, challenge)
    return proof.get("payload") == expected and verify_json(
        public_key_b64u,
        expected,
        str(proof.get("signature", "")),
    )
