# Holder Proof-of-Possession Update

This revision changes the realized capability from a bearer-style artifact to a holder-key-bound capability.

## Implemented protocol changes

- Capabilities now contain `kid_s`, set to `did:local:vendor-agent#key1` for the running case study.
- The verifier resolves the corresponding public key from the trusted local VendorAgent metadata endpoint.
- `POST /challenge` issues a fresh capability-bound challenge and persists it in SQLite.
- `POST /holder-proof` makes VendorAgent sign a canonical payload containing the capability hash, requester DID, scope, service, resource, action, audience, request time, and verifier challenge.
- Capability verification checks the holder proof, challenge binding and freshness, request freshness, capability nonce, revocation state, and protected fields.
- The capability nonce and challenge are atomically consumed in one SQLite transaction for the normal access path.
- Separate challenge-only consumption is retained for the presentation-proof replay experiment.

## Added/updated evaluation evidence

- Wrong holder key / stolen capability rejection.
- Missing holder proof rejection.
- Modified request after signature rejection.
- Holder-proof replay rejection.
- Concurrent capability replay and concurrent holder-proof replay.
- Holder signing and holder-proof verification primitive costs.
- Challenge issuance and nonce-plus-challenge stateful verification costs.
- Ablation variants without holder proof, with holder proof but no state, and with full stateful enforcement.

## Run

```bash
cd delegation-auth-prototype
docker compose down
docker compose up --build -d
python3 experiments/run_holder_pop_evaluation.py quick
```

After the quick run passes, execute the paper-grade run:

```bash
python3 experiments/run_holder_pop_evaluation.py full
```

The consolidated output is written to:

```text
results/metrics/holder_pop_evaluation.json
```

Additional CSV files are written by the performance, ablation, and stress endpoints under `results/metrics/`.

## Important measurement note

Use the results generated on the stated experimental host (Apple M4 Pro, 24 GB RAM, macOS 15.7.7, Docker 29.5.3, Python 3.9.6) in the paper. Results generated on another machine are validation results only and must not replace the paper's canonical measurements.
