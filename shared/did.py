from __future__ import annotations

from typing import Dict

from .crypto import generate_keypair

_REGISTRY: Dict[str, Dict[str, str]] = {}


def create_local_did(name: str, key_fragment: str = "key1") -> Dict[str, str]:
    private_key, public_key = generate_keypair()
    did = f"did:local:{name}"
    kid = f"{did}#{key_fragment}"
    doc = {
        "did": did,
        "kid": kid,
        "public_key": public_key,
        "private_key": private_key,
    }
    _REGISTRY[did] = doc
    _REGISTRY[kid] = doc
    return doc


def register_did(did: str, public_key: str, kid: str | None = None) -> None:
    resolved_kid = kid or f"{did}#key1"
    doc = {"did": did, "kid": resolved_kid, "public_key": public_key}
    _REGISTRY[did] = doc
    _REGISTRY[resolved_kid] = doc


def resolve_did(identifier: str) -> Dict[str, str]:
    if identifier not in _REGISTRY:
        raise KeyError(f"DID or verification method not found: {identifier}")
    return _REGISTRY[identifier]
