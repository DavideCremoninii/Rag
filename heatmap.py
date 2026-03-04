"""
CWE Top-25 Heatmap Generator

Generates a heatmap showing, for each model and each CWE in the Top-25 list,
the best F1-Score obtained across the two datasets (Sven and PrimeVul).

For each (model, CWE) cell, the value displayed is:
    max(F1_Sven, F1_PrimeVul)  rounded to 2 decimal places.

Usage:
    python heatmap.py [--models-dir PATH]

Default models directory: Rag2/Models
"""

import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

# --- CONFIGURATION ---

# Top-25 CWE list (in the required order)
TOP_25_CWES = [
    "CWE-79", "CWE-89", "CWE-352", "CWE-862", "CWE-787",
    "CWE-22", "CWE-416", "CWE-125", "CWE-78", "CWE-94",
    "CWE-120", "CWE-434", "CWE-476", "CWE-121", "CWE-502",
    "CWE-122", "CWE-863", "CWE-20", "CWE-284", "CWE-200",
    "CWE-306", "CWE-918", "CWE-77", "CWE-639", "CWE-770",
]

# Models to include (display names → folder names)
MODELS = {
    "Gemini 2.0 Flash": "gemini-2.0-flash",
    "Gemini 2.5 Flash": "gemini-2.5-flash",
    "Gemini 2.5 Pro": "gemini-2.5-pro",
}

# Datasets to scan
DATASETS = ["Sven", "PrimeVul"]


def read_f1_scores(metrics_dir: Path) -> dict[str, float]:
    """
    Reads all metrics_2_*.xlsx files in a metrics-scenario-2 directory
    and returns a dict {CWE_ID: best_F1_score} across all prompt files.
    """
    f1_scores: dict[str, float] = {}

    if not metrics_dir.is_dir():
        return f1_scores

    for xlsx_file in metrics_dir.glob("metrics_2_*.xlsx"):
        try:
            df = pd.read_excel(xlsx_file, sheet_name="Per_Class_Metrics")
        except Exception:
            continue

        if "Class" not in df.columns or "F1-Score" not in df.columns:
            continue

        for _, row in df.iterrows():
            cwe = str(row["Class"]).strip().upper()
            f1 = float(row["F1-Score"])
            # Keep the best F1 across multiple prompt files
            if cwe not in f1_scores or f1 > f1_scores[cwe]:
                f1_scores[cwe] = f1

    return f1_scores


def build_heatmap_data(models_dir: Path) -> tuple[pd.DataFrame, set[str]]:
    """
    Builds a DataFrame with models as rows and Top-25 CWEs as columns.
    Each cell = max(F1_Sven, F1_PrimeVul) for that (model, CWE) pair.

    Returns:
        A tuple of (DataFrame, set of CWE IDs actually found in the data).
    """
    data: dict[str, list[float]] = {}
    all_found_cwes: set[str] = set()

    for display_name, folder_name in MODELS.items():
        model_path = models_dir / folder_name
        best_f1_per_cwe: dict[str, float] = {}

        for dataset in DATASETS:
            metrics_dir = model_path / dataset / "metrics-scenario-2"
            dataset_f1 = read_f1_scores(metrics_dir)

            for cwe, f1 in dataset_f1.items():
                if cwe not in best_f1_per_cwe or f1 > best_f1_per_cwe[cwe]:
                    best_f1_per_cwe[cwe] = f1

        # Track which Top-25 CWEs were actually found
        for cwe in TOP_25_CWES:
            if cwe in best_f1_per_cwe:
                all_found_cwes.add(cwe)

        # Build a row for this model using the Top-25 order
        row = []
        for cwe in TOP_25_CWES:
            row.append(round(best_f1_per_cwe.get(cwe, 0.0), 2))
        data[display_name] = row

    return pd.DataFrame(data, index=TOP_25_CWES).T, all_found_cwes


def plot_heatmap(df: pd.DataFrame, output_path: Path):
    """
    Generates and saves the heatmap figure.
    """
    n_rows, n_cols = df.shape
    fig, ax = plt.subplots(figsize=(n_cols * 0.72, n_rows * 0.6 + 1.5))

    sns.heatmap(
        df,
        annot=True,
        fmt=".2f",
        annot_kws={"size": 8},
        cmap="Blues",
        linewidths=0.4,
        linecolor="white",
        vmin=0,
        vmax=1,
        square=True,
        cbar_kws={"label": "F1-Score", "shrink": 0.6},
        ax=ax,
    )

    ax.set_xlabel("")
    ax.set_ylabel("")
    ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha="right", fontsize=8)
    ax.set_yticklabels(ax.get_yticklabels(), rotation=0, fontsize=9)
    ax.tick_params(left=False, bottom=False)

    plt.tight_layout()
    plt.savefig(output_path, dpi=200, bbox_inches="tight")
    print(f"✅ Heatmap saved to: {output_path.resolve()}")
    plt.show()


def main():
    parser = argparse.ArgumentParser(description="Generate CWE Top-25 F1-Score Heatmap")
    parser.add_argument(
        "--models-dir",
        type=Path,
        default=Path(__file__).parent / "Models",
        help="Path to the Models directory (default: ./Models)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Output image path (default: heatmap_top25_cwe.png in models dir parent)",
    )
    args = parser.parse_args()

    models_dir = args.models_dir
    if not models_dir.is_dir():
        print(f"❌ ERROR: Models directory not found: {models_dir}")
        return

    print(f"📂 Scanning models in: {models_dir.resolve()}")
    df, found_cwes = build_heatmap_data(models_dir)

    # Print the data table to the console
    print("\n📊 Heatmap data (best F1-Score per model/CWE):\n")
    print(df.to_string())
    print()

    # --- 1) Full heatmap (all Top-25 CWEs, 0.00 for absent ones) ---
    output_path = args.output or (models_dir.parent / "heatmap_top25_cwe.png")
    plot_heatmap(df, output_path)

    # --- 2) Filtered heatmap (only CWEs present in at least one dataset) ---
    absent_cwes = [cwe for cwe in TOP_25_CWES if cwe not in found_cwes]
    if absent_cwes:
        print(f"\n🔍 CWEs not found in any dataset: {', '.join(absent_cwes)}")
    df_filtered = df.drop(columns=absent_cwes, errors="ignore")
    print(f"\n📊 Filtered heatmap data ({df_filtered.shape[1]} CWEs present):\n")
    print(df_filtered.to_string())
    print()

    output_filtered = output_path.parent / "heatmap_top25_cwe_f.png"
    plot_heatmap(df_filtered, output_filtered)


if __name__ == "__main__":
    main()
