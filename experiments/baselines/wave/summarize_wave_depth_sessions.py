from __future__ import annotations

import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List


ROOT = Path(__file__).resolve().parents[3]
SESSION_DIR = ROOT / "results" / "baselines" / "wave_depth_sessions"
COMBINED_RAW = ROOT / "results" / "baselines" / "wave_depth_multisession_raw.csv"
SUMMARY_CSV = ROOT / "results" / "baselines" / "wave_depth_multisession_summary.csv"
RESULTS_JSON = ROOT / "results" / "baselines" / "wave_depth_multisession_results.json"

EXPECTED_COMMIT = "3b90ec17ea9dde89e995a9a46222a93df0f992d4"
EXPECTED_DEPTHS = [1, 2, 3, 5, 10]
EXPECTED_ITERATIONS = 100
EXPECTED_SESSIONS = 10


def percentile(values: Iterable[float], pct: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = int(round((pct / 100.0) * (len(ordered) - 1)))
    return ordered[index]


def rounded(value: float) -> float:
    return round(value, 6)


def main() -> None:
    raw_paths = sorted(SESSION_DIR.glob("run_*_raw.csv"))
    if len(raw_paths) != EXPECTED_SESSIONS:
        raise RuntimeError(
            f"expected {EXPECTED_SESSIONS} raw session files, found {len(raw_paths)}"
        )

    rows: List[Dict[str, Any]] = []
    by_depth: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    session_depth_latencies: Dict[tuple[str, int], List[float]] = defaultdict(list)

    for path in raw_paths:
        session = path.name.removeprefix("run_").removesuffix("_raw.csv")
        with path.open(newline="", encoding="utf-8") as handle:
            session_rows = list(csv.DictReader(handle))

        if len(session_rows) != len(EXPECTED_DEPTHS) * EXPECTED_ITERATIONS:
            raise RuntimeError(
                f"{path.name}: expected {len(EXPECTED_DEPTHS) * EXPECTED_ITERATIONS} "
                f"rows, found {len(session_rows)}"
            )

        counts: Dict[int, int] = defaultdict(int)
        for source in session_rows:
            depth = int(source["depth"])
            if depth not in EXPECTED_DEPTHS:
                raise RuntimeError(f"{path.name}: unexpected depth {depth}")
            if source["source_commit"] != EXPECTED_COMMIT:
                raise RuntimeError(f"{path.name}: unexpected WAVE source revision")
            if source["session"] != session:
                raise RuntimeError(f"{path.name}: inconsistent session identifier")
            counts[depth] += 1
            accepted = source["accepted"].strip().lower() == "true"
            latency = float(source["latency_ms"])
            row: Dict[str, Any] = {
                "session": session,
                "system": source["system"],
                "source_commit": source["source_commit"],
                "depth": depth,
                "iteration": int(source["iteration"]),
                "accepted": accepted,
                "latency_ms": latency,
                "proof_bytes": int(source["proof_bytes"]),
            }
            rows.append(row)
            by_depth[depth].append(row)
            if accepted:
                session_depth_latencies[(session, depth)].append(latency)

        for depth in EXPECTED_DEPTHS:
            if counts[depth] != EXPECTED_ITERATIONS:
                raise RuntimeError(
                    f"{path.name}: depth {depth} has {counts[depth]} rows, "
                    f"expected {EXPECTED_ITERATIONS}"
                )

    raw_fields = [
        "session",
        "system",
        "source_commit",
        "depth",
        "iteration",
        "accepted",
        "latency_ms",
        "proof_bytes",
    ]
    with COMBINED_RAW.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
    handle, fieldnames=raw_fields, lineterminator="\n"
)
        writer.writeheader()
        writer.writerows(rows)

    summaries: List[Dict[str, Any]] = []
    per_session: List[Dict[str, Any]] = []
    for depth in EXPECTED_DEPTHS:
        depth_rows = by_depth[depth]
        accepted_rows = [row for row in depth_rows if row["accepted"]]
        latencies = [float(row["latency_ms"]) for row in accepted_rows]
        session_means: List[float] = []

        for path in raw_paths:
            session = path.name.removeprefix("run_").removesuffix("_raw.csv")
            values = session_depth_latencies[(session, depth)]
            mean = statistics.fmean(values) if values else 0.0
            session_means.append(mean)
            per_session.append(
                {
                    "session": session,
                    "depth": depth,
                    "accepted": len(values),
                    "mean_ms": rounded(mean),
                    "p95_ms": rounded(percentile(values, 95)),
                }
            )

        session_std = statistics.stdev(session_means) if len(session_means) > 1 else 0.0
        session_ci95 = 1.96 * session_std / math.sqrt(len(session_means))
        sizes = [int(row["proof_bytes"]) for row in accepted_rows]
        summaries.append(
            {
                "depth": depth,
                "sessions": len(raw_paths),
                "iterations_per_session": EXPECTED_ITERATIONS,
                "accepted": len(accepted_rows),
                "rejected": len(depth_rows) - len(accepted_rows),
                "count": len(latencies),
                "mean_ms": rounded(statistics.fmean(latencies)),
                "p95_ms": rounded(percentile(latencies, 95)),
                "p99_ms": rounded(percentile(latencies, 99)),
                "min_ms": rounded(min(latencies)),
                "max_ms": rounded(max(latencies)),
                "session_mean_std_ms": rounded(session_std),
                "ci95_across_session_means_ms": rounded(session_ci95),
                "proof_bytes_mean": rounded(statistics.fmean(sizes)),
            }
        )

    with SUMMARY_CSV.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
    handle,
    fieldnames=list(summaries[0].keys()),
    lineterminator="\n",
)
        writer.writeheader()
        writer.writerows(summaries)

    report = {
        "test": "wave_depth_multisession",
        "source_commit": EXPECTED_COMMIT,
        "methodology": {
            "sessions": EXPECTED_SESSIONS,
            "depths": EXPECTED_DEPTHS,
            "warmups_per_depth_per_session": 5,
            "measured_iterations_per_depth_per_session": EXPECTED_ITERATIONS,
            "total_measured_operations": len(rows),
            "mean_and_percentiles": "pooled accepted-proof verification latencies",
            "ci95": "normal-approximation confidence interval across ten session means",
        },
        "summary": summaries,
        "per_session": per_session,
        "files": {
            "combined_raw": str(COMBINED_RAW.relative_to(ROOT)),
            "summary_csv": str(SUMMARY_CSV.relative_to(ROOT)),
        },
    }
    with RESULTS_JSON.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")

    print(json.dumps(report["summary"], indent=2))
    print(f"Wrote {COMBINED_RAW}")
    print(f"Wrote {SUMMARY_CSV}")
    print(f"Wrote {RESULTS_JSON}")


if __name__ == "__main__":
    main()
