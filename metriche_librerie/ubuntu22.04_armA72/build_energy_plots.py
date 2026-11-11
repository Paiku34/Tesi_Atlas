#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
PLOTS_DIR = BASE_DIR / "plots"
MANUAL_RESULTS_FILE = BASE_DIR.parent / "misura_energia_manuale" / "risultati_energia.csv"


def load_manual_results() -> pd.DataFrame:
    if not MANUAL_RESULTS_FILE.exists():
        raise FileNotFoundError(
            f"File non trovato: {MANUAL_RESULTS_FILE}. "
            "Esegui prima measure_energy.py."
        )
    return pd.read_csv(MANUAL_RESULTS_FILE)


def compute_bulk_energy(results: pd.DataFrame) -> pd.DataFrame:
    src = results[results["category"] == "AEAD Bulk Encryption"].copy()
    return src.rename(
        columns={
            "algorithm": "algorithm",
            "payload_bytes": "payload_bytes",
            "reference_latency_us": "latency_us",
        }
    )[
        [
            "algorithm", "payload_bytes", "latency_us", "voltage_v",
            "i_idle_a", "i_active_a", "p_dyn_w", "e_dyn_uj", "e_per_byte_nj",
        ]
    ].sort_values(["algorithm", "payload_bytes"]).reset_index(drop=True)


def compute_keymgmt_energy(results: pd.DataFrame) -> pd.DataFrame:
    src = results[results["category"] == "Key Management"].copy()
    return src.rename(
        columns={
            "algorithm": "scheme",
            "payload_bytes": "exchanged_bytes",
            "reference_latency_us": "latency_us",
        }
    )[
        [
            "scheme", "exchanged_bytes", "latency_us", "voltage_v",
            "i_idle_a", "i_active_a", "p_dyn_w", "e_dyn_uj", "e_per_byte_nj",
        ]
    ].reset_index(drop=True)


def plot_bulk_energy(bulk_df: pd.DataFrame) -> None:
    plt.figure(figsize=(9, 5.5))
    for algo, group in bulk_df.groupby("algorithm"):
        g = group.sort_values("payload_bytes")
        plt.plot(g["payload_bytes"], g["e_dyn_uj"], marker="^", label=algo)

    plt.xlabel("Payload Dimension (Bytes)")
    plt.ylabel("Net Dynamic Energy per Packet (μJ)")
    plt.title("Physical Energy Consumption per Packet")
    plt.xticks([8, 16, 32, 64, 128, 256, 512, 1024])
    plt.grid(True, alpha=0.4)
    plt.legend(frameon=True)
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "bulk_energy.png", dpi=300)
    plt.close()


def plot_keymgmt_energy(km_df: pd.DataFrame) -> None:
    plt.figure(figsize=(10, 5.5))
    display_labels = km_df["scheme"].str.replace(" (Libsodium)", "", regex=False)
    plt.barh(display_labels, km_df["e_dyn_uj"], color="#e67e22", alpha=0.85)
    plt.gca().invert_yaxis()
    plt.xlabel("Net Dynamic Energy Consumption (μJ)")
    plt.title("Key Management Roadmap: Energy Consumption per Operation")
    plt.grid(True, axis="x", alpha=0.4)
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "key_management_energy.png", dpi=300)
    plt.close()


def main() -> None:
    results = load_manual_results()
    bulk_df = compute_bulk_energy(results)
    km_df = compute_keymgmt_energy(results)
    plot_bulk_energy(bulk_df)
    plot_keymgmt_energy(km_df)

    print(f"[OK] Grafici energia rigenerati in: {PLOTS_DIR}")


if __name__ == "__main__":
    main()
