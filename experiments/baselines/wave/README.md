# WAVE chain-depth baseline

This directory contains the wrapper used to execute a controlled chain-depth
baseline against the public WAVE implementation. The WAVE source is not
vendored in this repository. The Docker build obtains it from the official
repository and checks out commit
`3b90ec17ea9dde89e995a9a46222a93df0f992d4` before compiling the benchmark.

## Measured operation

For each depth, the harness constructs a valid linear WAVE authorization proof
and calls WAVE's `eapi.VerifyProof` operation. Delegation depth denotes the
number of attestations in that proof. Proof construction, publication, graph
synchronization, and Docker startup are outside the timed interval.

The reported measurements use:

- Delegation depths 1, 2, 3, 5, and 10
- Five untimed warm-up verifications per depth
- 100 measured verifications per depth
- One logical processor through `GOMAXPROCS(1)`
- Native Linux ARM64 execution on an Apple M4 Pro host

The harness records mean, p50, p95, p99, minimum, and maximum verification
latency, together with the serialized WAVE proof size.

## Reproduction

From the root of this repository, build the pinned image:

```bash
docker build --platform linux/arm64 \
  -t cod-mdtwin-wave-baseline:3b90ec1-arm64 \
  experiments/baselines/wave
```

Run the experiment and write its JSON result under `results/baselines/`:

```bash
docker run --rm --platform linux/arm64 \
  -e WAVE_ITERATIONS=100 \
  -e WAVE_WARMUPS=5 \
  -e WAVE_RESULTS_PATH=/results/wave_depth_results.json \
  -v "$(pwd)/results/baselines:/results" \
  cod-mdtwin-wave-baseline:3b90ec1-arm64
```

On another native architecture, change both platform and image suffix. Running
an AMD64 image through emulation on an ARM64 host is possible, but its latency
must not be compared with native measurements.

## Recorded result

The reference run is stored in
`results/baselines/wave_depth_results.json`. It produced the following values:

| Depth | Mean (ms) | p95 (ms) | Proof size (bytes) |
|---:|---:|---:|---:|
| 1 | 3.361 | 3.622 | 49,026 |
| 2 | 5.457 | 5.680 | 96,035 |
| 3 | 7.419 | 7.829 | 143,040 |
| 5 | 11.517 | 12.343 | 237,050 |
| 10 | 21.597 | 22.418 | 472,075 |

## Interpretation limits

These results measure warmed, repeated, in-process WAVE proof verification.
They do not measure proof construction, graph synchronization, network delay,
or a WAVE service API. The CoD-MDTwin chain-depth experiment currently measures
an HTTP verifier endpoint. Therefore, the raw latencies are not evidence of an
implementation speedup unless both systems are later measured through a
matched execution path. WAVE proof size and CoD-MDTwin serialized chain size
also represent different protocol artifacts and should be identified as such.

WAVE source: <https://github.com/immesys/wave>

WAVE paper: <https://www.usenix.org/conference/usenixsecurity19/presentation/andersen>
