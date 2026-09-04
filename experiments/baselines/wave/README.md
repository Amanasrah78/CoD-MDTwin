# WAVE chain-depth baseline

This directory contains the wrapper used to execute a controlled chain-depth baseline against the public WAVE implementation. The WAVE source is not vendored in this repository. The Docker build obtains the official source and checks out commit `3b90ec17ea9dde89e995a9a46222a93df0f992d4`.

## Measured operation

At each depth, the harness constructs a valid linear WAVE authorization proof and calls `eapi.VerifyProof`. Delegation depth denotes the number of attestations in the proof. Proof construction, publication, graph synchronization, and container startup are outside the timed interval.

The archived experiment used:

- Delegation depths 1, 2, 3, 5, and 10.
- Ten independent sessions.
- Five untimed warm-up verifications per depth and session.
- 100 measured verifications per depth and session.
- 1,000 measured verifications per depth and 5,000 overall.
- One logical processor through `GOMAXPROCS(1)`.
- Native Linux ARM64 execution in Docker on an Apple M4 Pro host.

The harness records every measured verification together with the session, depth, source revision, and serialized proof size. The summarizer reports pooled mean, p95, p99, minimum, and maximum latency. It also calculates the 95% confidence interval across the ten session means.

## Reproduction

From the repository root, build the pinned image:

```bash
docker build --platform linux/arm64 \
  -t cod-mdtwin-wave-baseline:3b90ec1-arm64 \
  experiments/baselines/wave
```

Run ten independent sessions:

```bash
mkdir -p results/baselines/wave_depth_sessions

for i in {1..10}; do
  n=$(printf "%02d" "$i")
  docker run --rm --platform linux/arm64 \
    -e WAVE_ITERATIONS=100 \
    -e WAVE_WARMUPS=5 \
    -e WAVE_SESSION="${n}" \
    -e WAVE_RESULTS_PATH="/results/wave_depth_sessions/run_${n}_results.json" \
    -e WAVE_RAW_PATH="/results/wave_depth_sessions/run_${n}_raw.csv" \
    -v "$(pwd)/results/baselines:/results" \
    cod-mdtwin-wave-baseline:3b90ec1-arm64
done
```

Aggregate and validate the sessions:

```bash
python3 experiments/baselines/wave/summarize_wave_depth_sessions.py
```

On another native architecture, change both the platform and image suffix. Results obtained through architecture emulation should not be directly compared with native measurements.

## Recorded results

All 5,000 measured WAVE proofs were verified successfully.

| Depth | Mean (ms) | p95 (ms) | 95% CI of session means (ms) | Proof size (bytes) |
|---:|---:|---:|---:|---:|
| 1 | 3.204 | 3.526 | 0.026 | 49,026 |
| 2 | 5.149 | 5.594 | 0.154 | 96,035 |
| 3 | 7.046 | 7.529 | 0.143 | 143,040 |
| 5 | 10.877 | 11.688 | 0.131 | 237,050 |
| 10 | 20.622 | 22.733 | 0.153 | 472,075 |

The archived evidence comprises:

- Per-session raw CSV and JSON files under `results/baselines/wave_depth_sessions/`.
- Combined raw measurements in `results/baselines/wave_depth_multisession_raw.csv`.
- Aggregate values in `results/baselines/wave_depth_multisession_summary.csv`.
- Methodology, aggregate results, and per-session statistics in `results/baselines/wave_depth_multisession_results.json`.

## Interpretation limits

These results measure warmed, repeated, in-process WAVE proof verification. They exclude proof construction, graph synchronization, network delay, and invocation through a WAVE service API. The corresponding CoD-MDTwin chain-depth experiment measures a local HTTP verifier endpoint. The absolute latency values therefore do not establish that either implementation is generally faster.

The WAVE proof and the CoD-MDTwin serialized credential chain also implement different semantics and carry different data. Their sizes provide system-specific scaling evidence rather than a normalized storage comparison.

WAVE source: <https://github.com/immesys/wave>

WAVE paper: <https://www.usenix.org/conference/usenixsecurity19/presentation/andersen>