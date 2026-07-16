import matplotlib.pyplot as plt
from pathlib import Path

# Revocation propagation scalability results
capabilities = [1, 10, 50, 100, 500, 1000]
total_rejection_ms = [1.665, 7.178, 34.247, 68.211, 339.903, 723.619]
mean_rejection_ms = [1.661, 0.716, 0.683, 0.681, 0.678, 0.722]
p95_rejection_ms = [1.661, 0.808, 0.749, 0.763, 0.722, 0.880]

out_dir = Path("Figures")
out_dir.mkdir(parents=True, exist_ok=True)

plt.figure(figsize=(6.6, 4.2))

plt.plot(
    capabilities,
    total_rejection_ms,
    marker="o",
    linewidth=2,
    label="Total rejection-check latency"
)

plt.xlabel("Invalidated dependent capabilities")
plt.ylabel("Total rejection-check latency (ms)")
plt.xticks(capabilities, [str(x) for x in capabilities], rotation=35)
plt.grid(True, linestyle="--", linewidth=0.6, alpha=0.6)
plt.legend(frameon=False)
plt.tight_layout()

plt.savefig(out_dir / "revocation_scalability.png", dpi=600, bbox_inches="tight")
plt.savefig(out_dir / "revocation_scalability.pdf", bbox_inches="tight")
plt.close()

print("Saved:")
print(out_dir / "revocation_scalability.png")
print(out_dir / "revocation_scalability.pdf")
