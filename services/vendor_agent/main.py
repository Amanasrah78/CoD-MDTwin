from __future__ import annotations

from typing import Any, Dict

from fastapi import FastAPI
from pydantic import BaseModel

from shared.crypto import sign_holder_proof
from shared.did import create_local_did
from shared.tracing import Trace, sha256_json

app = FastAPI(title="Vendor Agent", version="0.6.0")
VENDOR_AGENT = create_local_did("vendor-agent")


class HolderProofRequest(BaseModel):
    capability: Dict[str, Any]
    request: Dict[str, Any]
    challenge: str


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "vendor-agent"}


@app.get("/")
def root() -> Dict[str, Any]:
    return domain_info()


@app.get("/domain-info")
def domain_info() -> Dict[str, Any]:
    return {
        "service": "vendor-agent",
        "domain": "VendorB",
        "role": "external vendor service agent requesting delegated read access",
        "port": 8003,
        "actor": {
            "did": VENDOR_AGENT["did"],
            "kid": VENDOR_AGENT["kid"],
            "public_key": VENDOR_AGENT["public_key"],
        },
        "default_request": {
            "actor_did": VENDOR_AGENT["did"],
            "scope": "diagnostics.read",
            "service": "diagnostics-api",
            "action": "read-status",
            "resource": "asset:compressor-7",
            "audience": "vendor-b",
        },
        "endpoints": {
            "GET /health": "service readiness",
            "GET /domain-info": "human-readable service metadata",
            "GET /did": "agent DID, verification-method identifier, and public key",
            "POST /holder-proof": "sign a capability-bound request and verifier challenge",
        },
    }


@app.get("/did")
def did() -> Dict[str, str]:
    return {
        "did": VENDOR_AGENT["did"],
        "kid": VENDOR_AGENT["kid"],
        "public_key": VENDOR_AGENT["public_key"],
    }


@app.post("/holder-proof")
def holder_proof(req: HolderProofRequest) -> Dict[str, Any]:
    trace = Trace(operation="create_holder_proof", actor="VendorAgent", domain="VendorB")
    payload = req.capability.get("payload", {})
    trace.inputs = {
        "capability_id": payload.get("id"),
        "kid_s": payload.get("kid_s"),
        "request": req.request,
    }

    if payload.get("subject") != VENDOR_AGENT["did"]:
        trace.mark("rejected", "capability subject is not VendorAgent")
        return {"accepted": False, "reason": trace.reason, "trace": trace.to_dict()}
    if payload.get("kid_s") != VENDOR_AGENT["kid"]:
        trace.mark("rejected", "capability is not bound to VendorAgent verification method")
        return {"accepted": False, "reason": trace.reason, "trace": trace.to_dict()}
    if req.request.get("actor_did") != VENDOR_AGENT["did"]:
        trace.mark("rejected", "requester DID is not VendorAgent")
        return {"accepted": False, "reason": trace.reason, "trace": trace.to_dict()}
    if not req.challenge:
        trace.mark("rejected", "verifier challenge is missing")
        return {"accepted": False, "reason": trace.reason, "trace": trace.to_dict()}

    capability_hash = sha256_json(req.capability)
    with trace.timer("holder_signature_generation"):
        proof = sign_holder_proof(
            VENDOR_AGENT["private_key"],
            capability_hash,
            req.request,
            req.challenge,
        )
    trace.artifacts["capability_hash"] = capability_hash
    trace.artifacts["holder_kid"] = VENDOR_AGENT["kid"]
    trace.mark("accepted", "holder proof generated")
    return {
        "accepted": True,
        "reason": trace.reason,
        "holder_proof": proof,
        "kid": VENDOR_AGENT["kid"],
        "trace": trace.to_dict(),
    }
