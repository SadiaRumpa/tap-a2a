
import glob
import sys

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import seaborn as sns  # noqa: E402

DEFAULT_CU_BUDGET = 200_000
MAX_CU_BUDGET = 1_400_000

candidates = sorted(glob.glob("gateway_*_iterations.csv"))
if not candidates:
    print("ERROR: no gateway_*_iterations.csv found. Run full_gateway_benchmark.py first.")
    sys.exit(1)

csv_path = candidates[-1]
print(f"Loading '{csv_path}'")
df = pd.read_csv(csv_path)
n = len(df)

if n == 0:
    print("ERROR: benchmark CSV is empty — the benchmark produced no successful iterations.")
    sys.exit(1)

stage_columns = ["Ed25519_Verify_ms", "Policy_Read_ms", "OnChain_Decision_ms"]
missing = [c for c in stage_columns if c not in df.columns]
if missing:
    print(f"ERROR: CSV is missing {missing}. Re-run the updated full_gateway_benchmark.py.")
    sys.exit(1)

# --- Figure 6.1: per-stage latency distribution ------------------------
plt.figure(figsize=(10, 6))
sns.boxplot(data=df[stage_columns], width=0.5)
plt.title(f"Figure 6.1: Access Decision Latency by Stage ({n} Iterations)", fontsize=14)
plt.ylabel("Latency (milliseconds)", fontsize=12)
plt.xticks(range(len(stage_columns)),
           ["Ed25519 verify", "Policy read", "On-chain decision"])
plt.yscale("log")
plt.ylabel("Latency (ms, log scale)", fontsize=12)
plt.grid(axis="y", linestyle="--", alpha=0.7)
plt.tight_layout()
plt.savefig("figure_6_1_latency_by_stage.png", dpi=300)
plt.close()
print("Saved 'figure_6_1_latency_by_stage.png'")

# --- Figure 6.2: compute-unit consumption vs budget --------------------
if "Compute_Units" not in df.columns:
    print("ERROR: no 'Compute_Units' column — re-run the benchmark.")
    sys.exit(1)

median_cu = df["Compute_Units"].median()
max_cu = df["Compute_Units"].max()

plt.figure(figsize=(10, 6))
labels = ["Median CU\n(this protocol)", "Max CU\n(this protocol)",
          "Default tx budget", "Max tx budget"]
values = [median_cu, max_cu, DEFAULT_CU_BUDGET, MAX_CU_BUDGET]
colors = ["#4C72B0", "#DD8452", "#55A868", "#8172B3"]

bars = plt.bar(labels, values, color=colors, edgecolor="black", width=0.6)
plt.title("Figure 6.2: Compute Unit Consumption vs Solana Transaction Budget", fontsize=14)
plt.ylabel("Compute units", fontsize=12)
plt.yscale("log")
for bar in bars:
    y = bar.get_height()
    plt.text(bar.get_x() + bar.get_width() / 2, y * 1.05, f"{int(y):,}",
             ha="center", va="bottom", fontsize=11)
plt.grid(axis="y", linestyle="--", alpha=0.7)
plt.tight_layout()
plt.savefig("figure_6_2_cu_bar_chart.png", dpi=300)
plt.close()
print("Saved 'figure_6_2_cu_bar_chart.png'")

headroom = DEFAULT_CU_BUDGET / max_cu if max_cu else float("inf")
print(f"\nMedian CU: {median_cu:,.0f} | Max CU: {max_cu:,.0f}")
print(f"Headroom against the default 200,000 CU transaction budget: {headroom:.1f}x")
