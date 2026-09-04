# CoD-MDTwin
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21953261.svg)](https://doi.org/10.5281/zenodo.21953261)

CoD-MDTwin is a Chain-of-Delegation authorization framework for cross-domain Industrial Digital Twin agents. It validates the complete delegation path, enforces monotonic authority reduction, realizes accepted authority as a short-lived holder-bound capability, prevents capability and presentation replay, supports cascading revocation, preserves relying-domain policy control, and records authorization-related audit evidence.

This repository contains the research prototype, experiment scripts, processed results, and Tamarin model associated with the CoD-MDTwin paper.

**Latest reproducible release:** [CoD-MDTwin v1.2.0](https://github.com/Amanasrah78/CoD-MDTwin/releases/tag/V1.2.0)


## Artifact contents

| Location | Description |
|---|---|
| `services/` | Eight HTTP microservices implementing the authorization workflow |
| `shared/` | Credential, cryptographic, DID, policy, tracing, and selective-disclosure utilities |
| `experiments/` | Functional, security, performance, replay, revocation, and scalability experiments |
| `experiments/baselines/wave/` | Pinned Docker wrapper for the public WAVE chain-depth baseline |
| `tamarin/cod_mdtwin.spthy` | Tamarin model containing the 14 reported lemmas |
| `results/metrics/` | Processed measurements used to evaluate the prototype |
| `results/baselines/` | Measurements from independently reproduced external baselines |
| `docker-compose.yml` | Docker Compose deployment |
| `IMPLEMENTATION_NOTES.md` | Protocol and implementation details |

## Services

| Service | Port | Role |
|---|---:|---|
| `vendor-b` | 8000 | Domain B protected resource and local-policy enforcement |
| `factory-a` | 8001 | Domain A root delegation issuer |
| `twin-agent` | 8002 | Industrial Digital Twin agent |
| `vendor-agent` | 8003 | Vendor-side capability holder and requester |
| `verifier` | 8010 | Chain-of-Delegation and capability verifier |
| `client` | 8020 | Experiment and workflow orchestrator |
| `ledger-service` | 9000 | Local append-only audit service |
| `metrics-service` | 9100 | Trace collection and performance summaries |

## Requirements

The prototype was evaluated using:

- Docker 29.5.3 with Docker Compose
- Python 3.9.6 for local experiment scripts
- Tamarin Prover 1.10.0
- Maude 2.7.1

The Docker image uses Python 3.12 and installs the pinned dependencies listed in `requirements.txt`.

## Quick start

Build and start all services:

```bash
docker compose up --build -d
```

Check that the services are running:

```bash
docker compose ps
```

Run one valid holder-bound authorization flow:

```bash
python3 experiments/run_http_valid_flow.py
```

Stop the deployment:

```bash
docker compose down
```

## Functional and security tests

Run the focused delegation and capability tests:

```bash
python3 experiments/run_http_negative_tests.py
python3 experiments/run_http_token_tests.py
python3 experiments/run_http_capability_tests.py
```

Run the complete revised evaluation:

```bash
python3 experiments/run_holder_pop_evaluation.py quick
```

A longer evaluation can be started with:

```bash
python3 experiments/run_holder_pop_evaluation.py full
```

## Performance and scalability experiments

Sequential authorization performance:

```bash
python3 experiments/run_http_performance.py 100
```

Chain-depth sensitivity, single session:

```bash
python3 experiments/run_http_chain_depth_sensitivity.py 100
```

To reproduce the publication-scale chain-depth experiment, run ten independent
sessions. Each session evaluates depths 1, 2, 3, 5, and 10 using five warm-up
operations followed by 100 measured validations per depth:

```bash
mkdir -p results/metrics/chain_depth_sessions
for i in {1..10}; do
  n=$(printf "%02d" "$i")
  python3 experiments/run_http_chain_depth_sensitivity.py 100 \
    > "results/metrics/chain_depth_sessions/run_${n}_results.json"
  cp results/metrics/chain_depth_sensitivity.csv \
    "results/metrics/chain_depth_sessions/run_${n}_raw.csv"
done
python3 experiments/summarize_chain_depth_sessions.py
```

The summarizer validates the session and observation counts, then writes the
combined raw measurements, aggregate summary, and JSON report to
`results/metrics/chain_depth_sensitivity_multisession_*`. The archived run
contains 5,000 accepted validations and no rejected valid chain.

Cryptographic and stateful operation costs:

```bash
python3 experiments/run_http_crypto_cost.py 5000 1000
```

Complete stress suite:

```bash
python3 experiments/run_http_stress.py all
```

Concurrent replay test:

```bash
python3 experiments/run_http_stress.py replay 50
```

Concurrent workload test:

```bash
python3 experiments/run_http_stress.py load 1000 10
```

Single-use capability renewal and pre-issued-pool comparison:

```bash
python3 experiments/run_single_use_renewal.py quick
```

Run the publication-scale configuration with 10 independent sessions per workload:

```bash
python3 experiments/run_single_use_renewal.py full
```

The experiment writes raw operation measurements, aggregate summaries, and a JSON report under `results/metrics/`. It also revokes a parent delegation midway through each renewal mode and checks that no later operation is accepted.

### Revocation propagation and outage experiment

Run the short validation configuration:

```bash
python3 experiments/run_revocation_propagation.py quick
```

Performance values depend on the host, container runtime, operating system, and current system load. Security decisions and acceptance or rejection counts should remain consistent under the stated assumptions.

### Stratified chain-security experiment

Run the short validation configuration:

```bash
python3 experiments/run_stratified_chain_security.py quick
```

### Public WAVE baseline

The repository includes a Docker wrapper that obtains the official WAVE source at commit `3b90ec17ea9dde89e995a9a46222a93df0f992d4`. It measures warmed, in-process proof verification at delegation depths 1, 2, 3, 5, and 10.

The archived publication-scale experiment contains ten independent sessions, 100 measured verifications per depth and session, and five untimed warm-up verifications per depth. Per-operation raw measurements, per-session results, an aggregate summary, and the processing utility are included under `results/baselines/` and `experiments/baselines/wave/`.

Build the pinned native ARM64 image with:

```bash
docker build --platform linux/arm64 \
  -t cod-mdtwin-wave-baseline:3b90ec1-arm64 \
  experiments/baselines/wave
```

See `experiments/baselines/wave/README.md` for the exact ten-session commands, recorded results, measured path, and comparison limitations.

## Formal verification

Run the Tamarin model with:

```bash
tamarin-prover tamarin/cod_mdtwin.spthy
```

The model contains 14 lemmas covering:

- Honest protocol execution
- Two-capability execution
- Authentic delegation-chain origins
- Exact chain structure
- Capability-origin authenticity
- Capability-holder proof
- Exact access binding
- Injective replay resistance
- Denial of dependent access after revocation
- Rejection of wrong subject, resource, action, audience, and scope

The model represents a bounded instance with three delegation credentials, two dependent capabilities, and the fixed authorization fields of the running case study.

## Reproducing the reported evidence

| Evidence | Command | Expected high-level result |
|---|---|---|
| Valid authorization flow | `python3 experiments/run_http_valid_flow.py` | Valid holder-bound access accepted |
| Negative authorization tests | `python3 experiments/run_http_negative_tests.py` | Invalid and expanding chains rejected |
| Capability tests | `python3 experiments/run_http_capability_tests.py` | Invalid holder proofs and replay rejected |
| Concurrent replay | `python3 experiments/run_http_stress.py replay 50` | One accepted request; remaining attempts rejected |
| Single-use renewal | `python3 experiments/run_single_use_renewal.py full` | Both renewal modes accept valid operations and reject all post-revocation operations |
| Public WAVE baseline | Commands in `experiments/baselines/wave/README.md` | WAVE proof-verification measurements at five delegation depths |
| Tamarin verification | `tamarin-prover tamarin/cod_mdtwin.spthy` | All 14 lemmas verified |
| Full evaluation | `python3 experiments/run_holder_pop_evaluation.py full` | Updated result files under `results/metrics/` |

## Important limitations

This repository contains a research prototype, not a production authorization service.

- The deployment runs on a controlled local Docker Compose environment.
- DIDs and verification metadata are resolved locally.
- Nonce, challenge, and revocation state use a single SQLite-backed verifier store.
- A replicated deployment would require shared or strongly consistent replay state.
- Audit anchoring uses a local append-only service with simulated IOTA-style receipts.
- Selective disclosure is represented by a salted-hash simulation and is not a standards-complete SD-JWT or BBS+ implementation.
- The evaluation does not represent production industrial throughput, public-ledger finality, or geographically distributed operation.
- The external WAVE baseline uses warmed in-process proof verification; its raw latency is not directly comparable with the HTTP-based CoD-MDTwin measurement.

## Security

Do not use the example identities, keys, policies, or deployment configuration in production. Report security concerns privately to the repository maintainers rather than opening a public issue containing exploit details.

## Citation

If you use this artifact, cite the versioned software release:

> Ahmed Manasrah. *CoD-MDTwin* (Version 1.2.0). Zenodo. https://doi.org/10.5281/zenodo.21960381

Machine-readable citation metadata is provided in `CITATION.cff`.

## License

The software is distributed under the GNU General Public License version 3. See `LICENSE` for the complete terms.

## Authors

- Ahmed Manasrah
