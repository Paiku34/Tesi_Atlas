#!/usr/bin/env python3
"""
Zeno Atlas - Radio Telemetry & KEM Benchmark Visualization
Tesi Magistrale: Secure Sonobuoy Telemetry (NATO ANEP-96)

Questo script analizza i 4 file CSV generati dal benchmark:
  Lato Boa:
    - radio_telemetry_results.csv
    - radio_kem_results.csv
  Lato Ground Station:
    - ground_station_kem_results.csv
    - ground_station_log.csv

Supporta sia la cartella principale data/ sia sottocartelle per le diverse run/configurazioni:
  Utilizzo:
    python3 python/analyze_radio_benchmarks.py                         # analizza data/ e salva in plots/
    python3 python/analyze_radio_benchmarks.py data/run_64k           # analizza data/run_64k e salva in plots/run_64k
    python3 python/analyze_radio_benchmarks.py --all                  # analizza data/ e tutte le sue sottocartelle
"""

import os
import sys
from pathlib import Path
import numpy as np
import pandas as pd
import scipy.stats as st
import matplotlib.pyplot as plt

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
DEFAULT_DATA_DIR = BASE_DIR / "data"
DEFAULT_PLOTS_DIR = BASE_DIR / "plots"

plt.rcParams.update({
    'font.size': 11,
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.titlesize': 14,
    'lines.linewidth': 2.0,
    'lines.markersize': 6,
    'grid.alpha': 0.4,
    'grid.linestyle': '--'
})

PALETTE = {
    "Baseline (In Chiaro)": "#2c3e50",
    "Ascon-AEAD128 (ascon-c)": "#27ae60",
    "AES-256-GCM (OpenSSL)": "#2980b9",
    "ChaCha20-Poly1305 (Libsodium)": "#e67e22",
    "ChaCha20-Poly1305 (OpenSSL)": "#8e44ad",
    "X25519 (Libsodium)": "#16a085",
    "ML-KEM-512 (liboqs)": "#3498db",
    "ML-KEM-768 (liboqs)": "#e74c3c",
    "ML-KEM-1024 (liboqs)": "#9b59b6"
}

KEM_ID_MAP = {
    1: "X25519 (Libsodium)",
    2: "ML-KEM-512 (liboqs)",
    3: "ML-KEM-768 (liboqs)",
    4: "ML-KEM-1024 (liboqs)"
}

def clean_label(label: str) -> str:
    return str(label).replace(" (Libsodium)", "").replace(" (liboqs)", "").replace(" (OpenSSL)", "").replace(" (ascon-c)", "")

def compute_ci95(data):
    clean = np.array(data[~np.isnan(data)], dtype=float)
    n = len(clean)
    if n < 2:
        return (np.mean(clean) if n == 1 else 0.0), 0.0, 0.0, n
    mean = np.mean(clean)
    sem = st.sem(clean)
    margin = st.t.ppf(0.975, df=n - 1) * sem
    return mean, np.std(clean, ddof=1), margin, n

# =============================================================================
# 1. Analisi Telemetria
# =============================================================================
def plot_telemetry_metrics(csv_path: Path, out_dir: Path):
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return

    print(f"  [+] Telemetria da: {csv_path.name}")
    df = pd.read_csv(csv_path)

    df["Payload_B"] = pd.to_numeric(df["Payload_B"], errors="coerce")
    df["Success"] = pd.to_numeric(df["Success"], errors="coerce").fillna(0).astype(int)
    lat_col = "E2E_Latency_ms" if "E2E_Latency_ms" in df.columns else "RTT_ms"
    df["Latency_Num"] = pd.to_numeric(df[lat_col], errors="coerce")
    tp_col = "Goodput_bps" if "Goodput_bps" in df.columns else "Throughput_bps"
    df["Goodput_kbps"] = pd.to_numeric(df[tp_col], errors="coerce") / 1000.0
    df["Overhead_pct"] = pd.to_numeric(df["Overhead_pct"], errors="coerce")

    algos = df["Algorithm"].unique()

    # Grafico 1: Goodput
    fig, ax = plt.subplots(figsize=(8, 5))
    for algo in algos:
        sub = df[(df["Algorithm"] == algo) & (df["Success"] == 1)]
        means, errs, payloads = [], [], []
        for pz, group in sub.groupby("Payload_B"):
            m, _, ci, _ = compute_ci95(group["Goodput_kbps"])
            payloads.append(pz)
            means.append(m)
            errs.append(ci)
        ax.errorbar(payloads, means, yerr=errs, marker='o', capsize=4, label=clean_label(algo), color=PALETTE.get(algo, None))

    ax.set_title("Goodput Effettivo vs Dimensione Payload (Uplink Telemetria, IC 95%)")
    ax.set_xlabel("Dimensione Payload Dati [Byte]")
    ax.set_ylabel("Goodput Utile [kbit/s]")
    ax.set_xticks(sorted(df["Payload_B"].dropna().unique()))
    ax.grid(True)
    ax.legend()
    plt.tight_layout()
    plt.savefig(out_dir / "radio_telemetry_goodput_ci95.png", dpi=300)
    plt.close()

    # Grafico 2: Latenza
    fig, ax = plt.subplots(figsize=(8, 5))
    for algo in algos:
        sub = df[(df["Algorithm"] == algo) & (df["Success"] == 1)]
        means, errs, payloads = [], [], []
        for pz, group in sub.groupby("Payload_B"):
            m, _, ci, _ = compute_ci95(group["Latency_Num"])
            payloads.append(pz)
            means.append(m)
            errs.append(ci)
        ax.errorbar(payloads, means, yerr=errs, marker='s', capsize=4, label=clean_label(algo), color=PALETTE.get(algo, None))

    ax.set_title("Latenza End-to-End (RTT) vs Dimensione Payload (IC 95%)")
    ax.set_xlabel("Dimensione Payload Dati [Byte]")
    ax.set_ylabel("Latenza Media E2E [ms]")
    ax.set_xticks(sorted(df["Payload_B"].dropna().unique()))
    ax.grid(True)
    ax.legend()
    plt.tight_layout()
    plt.savefig(out_dir / "radio_telemetry_latency_ci95.png", dpi=300)
    plt.close()

    # Grafico 3: Overhead %
    fig, ax = plt.subplots(figsize=(8, 5))
    grouped_oh = df.groupby(["Payload_B", "Algorithm"])["Overhead_pct"].mean().unstack()
    payload_labels = [f"{int(p)} B" for p in grouped_oh.index]
    x = np.arange(len(payload_labels))
    width = 0.8 / len(grouped_oh.columns)
    for i, col in enumerate(grouped_oh.columns):
        ax.bar(x + i * width, grouped_oh[col], width, label=clean_label(col), color=PALETTE.get(col, None))
    ax.set_title("Overhead di Protocollo e Cifratura sul Canale RF")
    ax.set_xlabel("Dimensione Payload Dati")
    ax.set_ylabel("Overhead [% rispetto al payload grezzo]")
    ax.set_xticks(x + width * (len(grouped_oh.columns) - 1) / 2)
    ax.set_xticklabels(payload_labels)
    ax.grid(axis='y')
    ax.legend()
    plt.tight_layout()
    plt.savefig(out_dir / "radio_telemetry_overhead.png", dpi=300)
    plt.close()

    # Grafico 4: PDR
    fig, ax = plt.subplots(figsize=(8, 5))
    pdr = (df.groupby(["Payload_B", "Algorithm"])["Success"].mean() * 100.0).unstack()
    for col in pdr.columns:
        ax.plot(pdr.index, pdr[col], marker='^', label=clean_label(col), color=PALETTE.get(col, None))
    ax.set_title("Packet Delivery Ratio (PDR) vs Dimensione Payload")
    ax.set_xlabel("Dimensione Payload [Byte]")
    ax.set_ylabel("PDR [% con successo]")
    ax.set_ylim(-5, 105)
    ax.set_xticks(sorted(df["Payload_B"].dropna().unique()))
    ax.grid(True)
    ax.legend(loc='lower left')
    plt.tight_layout()
    plt.savefig(out_dir / "radio_telemetry_pdr.png", dpi=300)
    plt.close()

# =============================================================================
# 2. Analisi KEM Handshake
# =============================================================================
def plot_kem_metrics(buoy_kem_path: Path, gs_kem_path: Path, out_dir: Path):
    df_buoy = pd.read_csv(buoy_kem_path) if buoy_kem_path.exists() and buoy_kem_path.stat().st_size > 0 else None
    df_gs = pd.read_csv(gs_kem_path) if gs_kem_path.exists() and gs_kem_path.stat().st_size > 0 else None

    if df_buoy is None and df_gs is None:
        return

    print("  [+] KEM Handshake metrics...")

    if df_gs is not None:
        df_gs["Success"] = pd.to_numeric(df_gs["Success"], errors="coerce").fillna(0).astype(int)
        df_gs["E2E_Handshake_ms"] = pd.to_numeric(df_gs["E2E_Handshake_ms"], errors="coerce")
        df_gs["KEM_Name"] = df_gs["KEM_Id"].map(KEM_ID_MAP).fillna("Unknown")

        succ_gs = df_gs[df_gs["Success"] == 1]
        if not succ_gs.empty:
            kem_order = ["X25519 (Libsodium)", "ML-KEM-512 (liboqs)", "ML-KEM-768 (liboqs)", "ML-KEM-1024 (liboqs)"]
            data_to_plot, labels_to_plot, colors = [], [], []
            means, cis = [], []

            for k in kem_order:
                vals = succ_gs[succ_gs["KEM_Name"] == k]["E2E_Handshake_ms"].dropna().values
                if len(vals) > 0:
                    data_to_plot.append(vals)
                    labels_to_plot.append(clean_label(k))
                    colors.append(PALETTE.get(k, "#34495e"))
                    m, _, ci, _ = compute_ci95(vals)
                    means.append(m)
                    cis.append(ci)

            # Boxplot
            fig, ax = plt.subplots(figsize=(7.5, 5))
            bplot = ax.boxplot(data_to_plot, patch_artist=True, labels=labels_to_plot)
            for patch, color in zip(bplot['boxes'], colors):
                patch.set_facecolor(color)
                patch.set_alpha(0.7)
            ax.set_title("Latenza End-to-End di Handshake KEM (Canale Radio)")
            ax.set_ylabel("Tempo E2E [ms]")
            ax.grid(axis='y')
            plt.tight_layout()
            plt.savefig(out_dir / "radio_kem_e2e_latency_boxplot.png", dpi=300)
            plt.close()

            # Bar chart CI 95%
            fig, ax = plt.subplots(figsize=(7.5, 5))
            x_pos = np.arange(len(labels_to_plot))
            ax.bar(x_pos, means, yerr=cis, capsize=5, color=colors, alpha=0.85, edgecolor='black')
            ax.set_xticks(x_pos)
            ax.set_xticklabels(labels_to_plot)
            ax.set_title("Latenza Media Handshake KEM (IC 95%)")
            ax.set_ylabel("Latenza Media E2E [ms]")
            ax.grid(axis='y')
            plt.tight_layout()
            plt.savefig(out_dir / "radio_kem_latency_ci95_bar.png", dpi=300)
            plt.close()

    if df_buoy is not None:
        kem_grouped = df_buoy.groupby("KEM_Algorithm")[["Ciphertext_B", "Total_Handshake_B"]].mean().reset_index()
        fig, ax = plt.subplots(figsize=(7.5, 5))
        x = np.arange(len(kem_grouped))
        w = 0.35
        labels = [clean_label(name) for name in kem_grouped["KEM_Algorithm"]]
        ax.bar(x - w/2, kem_grouped["Ciphertext_B"], w, label="Ciphertext KEM", color="#3498db")
        ax.bar(x + w/2, kem_grouped["Total_Handshake_B"], w, label="Footprint Totale Handshake", color="#2c3e50")
        ax.set_title("Footprint sul Canale RF per Negoziazione Chiave")
        ax.set_ylabel("Dimensione Trasmessa [Byte]")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=15)
        ax.grid(axis='y')
        ax.legend()
        plt.tight_layout()
        plt.savefig(out_dir / "radio_kem_footprint_bytes.png", dpi=300)
        plt.close()

# =============================================================================
# 3. Analisi Log Ground Station
# =============================================================================
def plot_gs_log_metrics(log_path: Path, out_dir: Path):
    if not log_path.exists() or log_path.stat().st_size == 0:
        return

    print(f"  [+] Ground Station log da: {log_path.name}")
    df = pd.read_csv(log_path)
    status_counts = df.groupby(["Type", "Status"]).size().unstack(fill_value=0)
    fig, ax = plt.subplots(figsize=(8, 5))
    status_counts.plot(kind="bar", stacked=True, ax=ax, colormap="viridis")
    ax.set_title("Stato e Cause di Perdita dei Pacchetti Ricevuti (Ground Station)")
    ax.set_xlabel("Tipologia Flusso")
    ax.set_ylabel("Numero di Pacchetti / Eventi")
    ax.set_xticklabels(status_counts.index, rotation=0)
    ax.grid(axis='y')
    ax.legend(title="Esito Ricezione")
    plt.tight_layout()
    plt.savefig(out_dir / "ground_station_packet_outcomes.png", dpi=300)
    plt.close()

# =============================================================================
# Elaborazione di una cartella specifica
# =============================================================================
def process_directory(data_path: Path, plots_path: Path):
    os.makedirs(plots_path, exist_ok=True)
    print(f"\n---> Analisi cartella: {data_path.relative_to(BASE_DIR) if data_path.is_relative_to(BASE_DIR) else data_path}")
    print(f"     Output grafici:   {plots_path.relative_to(BASE_DIR) if plots_path.is_relative_to(BASE_DIR) else plots_path}")

    t_csv = data_path / "radio_telemetry_results.csv"
    bk_csv = data_path / "radio_kem_results.csv"
    gk_csv = data_path / "ground_station_kem_results.csv"
    gl_csv = data_path / "ground_station_log.csv"

    has_any = any(p.exists() and p.stat().st_size > 0 for p in [t_csv, bk_csv, gk_csv, gl_csv])
    if not has_any:
        print("     [SKIP] Nessun CSV valido trovato in questa cartella.")
        return False

    plot_telemetry_metrics(t_csv, plots_path)
    plot_kem_metrics(bk_csv, gk_csv, plots_path)
    plot_gs_log_metrics(gl_csv, plots_path)
    print(f"     [OK] Grafici generati in: {plots_path}")
    return True

# =============================================================================
# Main con supporto ad argomenti CLI
# =============================================================================
def main():
    print("=" * 65)
    print("  ZENO ATLAS - Analisi Dati e Generazione Grafici Radio")
    print("=" * 65)

    args = sys.argv[1:]

    # Modalità --all: analizza data/ e tutte le sue sottocartelle
    if "--all" in args:
        print("[MODALITÀ] Analisi batch di tutte le sottocartelle in data/...")
        process_directory(DEFAULT_DATA_DIR, DEFAULT_PLOTS_DIR)
        for sub in sorted(DEFAULT_DATA_DIR.iterdir()):
            if sub.is_dir() and not sub.name.startswith("."):
                out_sub = DEFAULT_PLOTS_DIR / sub.name
                process_directory(sub, out_sub)
        print("\n[FINITO] Tutte le configurazioni sono state elaborate!")
        return

    # Se viene passata una cartella specifica da riga di comando (es. python script.py data/run_64k)
    if len(args) >= 1 and not args[0].startswith("-"):
        custom_data = Path(args[0]).resolve()
        sub_name = custom_data.name if custom_data != DEFAULT_DATA_DIR else ""
        custom_plots = DEFAULT_PLOTS_DIR / sub_name if sub_name else DEFAULT_PLOTS_DIR
        process_directory(custom_data, custom_plots)
        return

    # Comportamento predefinito: analizza data/ e cerca automaticamente se ci sono sottocartelle di run
    processed_any = process_directory(DEFAULT_DATA_DIR, DEFAULT_PLOTS_DIR)
    
    # Se la cartella data/ principale non ha CSV ma contiene sottocartelle di run, le processa tutte
    subdirs = [d for d in DEFAULT_DATA_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")]
    if subdirs:
        print(f"\n[INFO] Trovate {len(subdirs)} sottocartelle di run in data/:")
        for sub in sorted(subdirs):
            out_sub = DEFAULT_PLOTS_DIR / sub.name
            process_directory(sub, out_sub)

    print("\n[OK] Elaborazione completata con successo!")

if __name__ == "__main__":
    main()
