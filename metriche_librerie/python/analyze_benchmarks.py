#!/usr/bin/env python3
"""
Zeno Atlas - Cryptographic Benchmark Statistical Analysis & Visualization
Tesi Magistrale: Secure Sonobuoy Telemetry (NATO ANEP-96)
Calcolo completo di TUTTE le metriche della presentazione (Cicli, Latenza, RAM, Code Size, Energia RAPL, Overhead Radio).
"""

import os
import sys
import subprocess
import glob
import numpy as np
import pandas as pd
import scipy.stats as st
import matplotlib.pyplot as plt

# Directory paths relative to repository structure
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATA_DIR = os.path.join(BASE_DIR, "data")
PLOTS_DIR = os.path.join(BASE_DIR, "plots")
BUILD_DIR = os.path.join(BASE_DIR, "build")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(PLOTS_DIR, exist_ok=True)

# Configurazione stile grafici scientifici (per tesi / LaTeX)
plt.rcParams.update({
    'font.size': 11,
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.titlesize': 14,
    'lines.linewidth': 1.8,
    'lines.markersize': 6,
    'grid.alpha': 0.4,
    'grid.linestyle': '--'
})

def find_csv(filenames):
    if isinstance(filenames, str):
        filenames = [filenames]
    search_dirs = [DATA_DIR, BUILD_DIR, BASE_DIR, os.getcwd(), os.path.join(os.getcwd(), "data")]
    for name in filenames:
        for d in search_dirs:
            p = os.path.join(d, name)
            if os.path.exists(p) and os.path.getsize(p) > 0:
                return p
    return None

def compute_ci95(data, filter_interrupts=True):
    """
    Calcola Media, Mediana, Deviazione Standard, Errore Standard e Margine di Confidenza al 95% (Student-t).
    Se filter_interrupts=True, scarta gli spike da preemption/context switch del kernel OS (> Q3 + 5*IQR o > 5*median).
    """
    data = np.array(data, dtype=float)
    orig_len = len(data)
    if filter_interrupts and orig_len > 20:
        median = np.median(data)
        q25, q75 = np.percentile(data, [25, 75])
        iqr = q75 - q25
        cutoff = max(q75 + 5.0 * iqr, median * 5.0)
        clean = data[data <= cutoff]
        if len(clean) >= orig_len * 0.90:
            data = clean

    n = len(data)
    if n < 2:
        return np.mean(data), np.median(data), 0.0, 0.0, n
    mean = np.mean(data)
    median = np.median(data)
    std = np.std(data, ddof=1)
    sem = st.sem(data)
    margin = st.t.ppf(0.975, df=n - 1) * sem
    return mean, median, std, margin, n

# =========================================================================
# 1. BULK ENCRYPTION (AEAD) ANALYSIS
# =========================================================================
def analyze_bulk_encryption():
    csv_path = find_csv(["bulk_encryption_raw.csv", "bulk_encryption_samples.csv"])
    if not csv_path:
        print("[SKIP] bulk_encryption_raw.csv non trovato.")
        return

    print("\n" + "=" * 115)
    print(" 1. ANALISI BULK ENCRYPTION (AEAD) — METRICHE COMPLETE (LATENZA, CICLI, ENERGIA, RAM, THROUGHPUT)")
    print("=" * 115)

    df = pd.read_csv(csv_path)
    df['algorithm'] = df['algorithm'].astype(str).str.strip('"')

    has_added_bytes = 'added_bytes' in df.columns
    has_energy = 'energy_uj' in df.columns
    has_ram = 'ram_kb' in df.columns
    has_cycles_op = 'cycles_per_op' in df.columns

    results = []
    has_real_energy = False

    for (algo, size), group in df.groupby(['algorithm', 'payload_bytes']):
        latencies = group['latency_us'].values
        mean_us, median_us, std_us, ci95, valid_n = compute_ci95(latencies)
        
        cycles_per_byte = group['cycles_per_byte'].iloc[0]
        cycles_per_op = group['cycles_per_op'].iloc[0] if has_cycles_op else int(cycles_per_byte * size)
        added_bytes = int(group['added_bytes'].iloc[0]) if has_added_bytes else 16
        ram_kb = int(group['ram_kb'].iloc[0]) if has_ram else 0
        
        # Gestione Energia Intel RAPL
        energy_val = -1.0
        energy_str = "N/A"
        if has_energy:
            e_series = group['energy_uj']
            if not e_series.empty and e_series.iloc[0] > 0:
                energy_val = float(e_series.iloc[0])
                energy_str = f"{energy_val:0.2f}"
                has_real_energy = True

        throughput_mb_s = size / mean_us if mean_us > 0 else 0.0

        results.append({
            'Algorithm': algo,
            'Payload (B)': int(size),
            'Added Overhead (B)': added_bytes,
            'Mean Latency (us)': round(mean_us, 3),
            'Median Latency (us)': round(median_us, 3),
            'StdDev (us)': round(std_us, 3),
            'CI95 (+/- us)': round(ci95, 3),
            'Throughput (MB/s)': round(throughput_mb_s, 1),
            'Cycles/Op': int(cycles_per_op),
            'Cycles/Byte': round(cycles_per_byte, 2),
            'Energy/Op (uJ)': energy_str,
            'RAM Peak (KB)': ram_kb,
            'Samples': valid_n,
            '_energy_val': energy_val
        })

    res_df = pd.DataFrame(results)

    # Stampa tabella a console
    print(f"{'Algoritmo':<32} | {'Payload':<8} | {'Tempo Medio':<18} | {'Mediana':<10} | {'Throughput':<11} | {'Cycles/B':<9} | {'Energia(uJ)':<11} | {'RAM(KB)':<8}")
    print("-" * 125)
    for _, r in res_df.iterrows():
        print(f"{r['Algorithm']:<32} | {r['Payload (B)']:<8} | {r['Mean Latency (us)']:0.2f} +/- {r['CI95 (+/- us)']:0.3f} us | {r['Median Latency (us)']:0.2f} us   | {r['Throughput (MB/s)']:0.1f} MB/s | {r['Cycles/Byte']:0.2f}     | {r['Energy/Op (uJ)']:<11} | {r['RAM Peak (KB)']}")

    # Salva sintesi completa in CSV
    summary_path = os.path.join(DATA_DIR, "bulk_encryption_summary_ci95.csv")
    export_df = res_df.drop(columns=['_energy_val'])
    export_df.to_csv(summary_path, index=False)
    print(f"\n[OK] Tabella completa salvata in: {summary_path}")

    # --- GRAFICO 1: Latenza vs Payload (CI 95%) ---
    fig, ax = plt.subplots(figsize=(9, 5.5))
    for algo, group in res_df.groupby('Algorithm'):
        group_sorted = group.sort_values('Payload (B)')
        ax.errorbar(
            group_sorted['Payload (B)'],
            group_sorted['Mean Latency (us)'],
            yerr=group_sorted['CI95 (+/- us)'],
            label=algo,
            marker='o',
            capsize=4,
            capthick=1.2
        )
    ax.set_xlabel('Payload Dimension (Bytes)')
    ax.set_ylabel('Latency per Packet (μs)')
    ax.set_title('Bulk Encryption Latency vs Packet Size (with 95% CI)')
    ax.set_xticks([32, 64, 128, 255, 512, 1024])
    ax.grid(True)
    ax.legend(frameon=True)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'bulk_latency_ci95.png'), dpi=300)
    plt.close()

    # --- GRAFICO 2: Throughput vs Payload ---
    fig, ax = plt.subplots(figsize=(9, 5.5))
    for algo, group in res_df.groupby('Algorithm'):
        group_sorted = group.sort_values('Payload (B)')
        ax.plot(
            group_sorted['Payload (B)'],
            group_sorted['Throughput (MB/s)'],
            label=algo,
            marker='s'
        )
    ax.set_xlabel('Payload Dimension (Bytes)')
    ax.set_ylabel('Effective Throughput (MB/s)')
    ax.set_title('Symmetric AEAD Throughput Scaling across Packet Sizes')
    ax.set_xticks([32, 64, 128, 255, 512, 1024])
    ax.grid(True)
    ax.legend(frameon=True)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'bulk_throughput.png'), dpi=300)
    plt.close()

    # --- GRAFICO 3: Energia Intel RAPL (se disponibile o annotazione testbed) ---
    fig, ax = plt.subplots(figsize=(9, 5.5))
    if has_real_energy:
        for algo, group in res_df.groupby('Algorithm'):
            group_sorted = group.sort_values('Payload (B)')
            valid_energy = group_sorted[group_sorted['_energy_val'] > 0]
            if not valid_energy.empty:
                ax.plot(valid_energy['Payload (B)'], valid_energy['_energy_val'], marker='^', label=algo)
        ax.set_ylabel('Energy per Packet (μJ)')
    else:
        ax.text(0.5, 0.5, 'Sensore Intel RAPL non disponibile su macOS / VM\n(Eseguire sudo ./run_all.sh su banco di prova Linux per visualizzare i μJ reali)', 
                ha='center', va='center', fontsize=12, color='#7f8c8d', 
                bbox=dict(boxstyle='round,pad=0.8', facecolor='#f8f9fa', edgecolor='#bdc3c7'))
        ax.set_ylabel('Energy per Packet (μJ) [N/A su Mac/WSL]')

    ax.set_xlabel('Payload Dimension (Bytes)')
    ax.set_title('Physical Energy Consumption per Packet (Intel RAPL)')
    ax.set_xticks([32, 64, 128, 255, 512, 1024])
    ax.grid(True)
    if has_real_energy:
        ax.legend(frameon=True)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'bulk_energy.png'), dpi=300)
    plt.close()
    print(f"[OK] Grafici bulk salvati in {PLOTS_DIR}/ (PNG 300 DPI)")

# =========================================================================
# 2. KEY MANAGEMENT ANALYSIS
# =========================================================================
def analyze_key_management():
    csv_path = find_csv(["key_management_raw.csv", "key_management_samples.csv"])
    if not csv_path:
        print("[SKIP] key_management_raw.csv non trovato.")
        return

    print("\n" + "=" * 115)
    print(" 2. ANALISI KEY MANAGEMENT ROADMAP — METRICHE COMPLETE (LATENZA, CICLI, ENERGIA, FRAME ANEP-96, RAM)")
    print("=" * 115)

    df = pd.read_csv(csv_path)
    df['scheme'] = df['scheme'].astype(str).str.strip('"')
    df['paradigm'] = df['paradigm'].astype(str).str.strip('"')

    has_energy = 'energy_uj' in df.columns
    has_cycles = 'cycles' in df.columns

    results = []
    order = [
        "PSK + KDF (Libsodium)",
        "PSK + HKDF (OpenSSL)",
        "Symmetric Handshake",
        "ECDH X25519 (Libsodium)",
        "ECDH X25519 (OpenSSL)",
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024"
    ]

    has_real_energy = False

    for scheme, group in df.groupby('scheme'):
        latencies = group['latency_us'].values
        mean_us, median_us, std_us, ci95, valid_n = compute_ci95(latencies)
        exchanged = int(group['exchanged_bytes'].iloc[0])
        frames = int(group['anep_frames'].iloc[0])
        paradigm = group['paradigm'].iloc[0]
        ram_kb = int(group['ram_kb'].iloc[0])
        cycles = int(group['cycles'].iloc[0]) if has_cycles else 0

        energy_val = -1.0
        energy_str = "N/A"
        if has_energy:
            e_series = group['energy_uj']
            if not e_series.empty and e_series.iloc[0] > 0:
                energy_val = float(e_series.iloc[0])
                energy_str = f"{energy_val:0.2f}"
                has_real_energy = True

        results.append({
            'Scheme': scheme,
            'Paradigm': paradigm,
            'Exchanged (B)': exchanged,
            'ANEP Frames': frames,
            'Mean Latency (us)': round(mean_us, 3),
            'Median Latency (us)': round(median_us, 3),
            'StdDev (us)': round(std_us, 3),
            'CI95 (+/- us)': round(ci95, 3),
            'Cycles/Op': cycles,
            'Energy/Op (uJ)': energy_str,
            'RAM Peak (KB)': ram_kb,
            'Samples': valid_n,
            '_energy_val': energy_val
        })

    res_df = pd.DataFrame(results)
    res_df['sort_key'] = res_df['Scheme'].apply(lambda x: order.index(x) if x in order else 99)
    res_df = res_df.sort_values('sort_key').drop(columns=['sort_key'])

    print(f"{'Schema':<26} | {'Paradigma':<22} | {'Scambiati':<10} | {'Tempo Medio':<18} | {'Mediana':<10} | {'Energia(uJ)':<11} | {'RAM(KB)':<8}")
    print("-" * 115)
    for _, r in res_df.iterrows():
        print(f"{r['Scheme']:<26} | {r['Paradigm']:<22} | {str(r['Exchanged (B)']) + ' B':<10} | {r['Mean Latency (us)']:0.2f} +/- {r['CI95 (+/- us)']:0.3f} us | {r['Median Latency (us)']:0.2f} us   | {r['Energy/Op (uJ)']:<11} | {r['RAM Peak (KB)']}")

    summary_path = os.path.join(DATA_DIR, "key_management_summary_ci95.csv")
    export_df = res_df.drop(columns=['_energy_val'])
    export_df.to_csv(summary_path, index=False)
    print(f"\n[OK] Tabella completa salvata in: {summary_path}")

    # --- GRAFICO 4: Trade-off Tempo di Handshake vs Byte Scambiati ---
    fig, ax1 = plt.subplots(figsize=(10, 6))

    schemes = res_df['Scheme'].values
    y_pos = np.arange(len(schemes))
    means = res_df['Mean Latency (us)'].values
    errors = res_df['CI95 (+/- us)'].values
    bytes_exchanged = res_df['Exchanged (B)'].values

    bars = ax1.barh(y_pos, means, xerr=errors, capsize=4, color='#3498db', alpha=0.85, label='Compute Latency (μs, 95% CI)')
    ax1.set_yticks(y_pos)
    ax1.set_yticklabels(schemes)
    ax1.invert_yaxis()
    ax1.set_xlabel('Computation Latency (μs)', color='#2980b9')
    ax1.tick_params(axis='x', labelcolor='#2980b9')
    ax1.grid(True, axis='x')

    for i, (b, mean) in enumerate(zip(bytes_exchanged, means)):
        ax1.text(mean + errors[i] + 1.5, i, f"{b} B", va='center', fontsize=9.5, fontweight='bold', color='#2c3e50')

    ax1.set_title('Key Management Roadmap: Computation Latency vs Exchanged Bytes')
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'key_management_tradeoff.png'), dpi=300)
    plt.close()

    # --- GRAFICO 5: Boxplot della Distribuzione dei Campioni Singoli ---
    fig, ax = plt.subplots(figsize=(11, 6))
    data_to_plot = []
    labels = []
    for s in order:
        sub = df[df['scheme'] == s]
        if not sub.empty:
            data_to_plot.append(sub['latency_us'].values)
            labels.append(s)

    box = ax.boxplot(data_to_plot, patch_artist=True, tick_labels=labels, showmeans=True, showfliers=False)
    for patch in box['boxes']:
        patch.set_facecolor('#ecf0f1')
        patch.set_edgecolor('#2c3e50')

    ax.set_ylabel('Latency (μs)')
    ax.set_title('Key Management Stability & Dispersion (Individual Sample Distributions)')
    plt.xticks(rotation=25, ha='right')
    ax.grid(True, axis='y')
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'key_management_dispersion_boxplot.png'), dpi=300)
    plt.close()

    # --- GRAFICO 6: Energia Key Management (Intel RAPL) ---
    fig, ax = plt.subplots(figsize=(10, 5.5))
    if has_real_energy:
        energy_vals = res_df['_energy_val'].values
        bars = ax.barh(y_pos, energy_vals, color='#e67e22', alpha=0.85)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(schemes)
        ax.invert_yaxis()
        ax.set_xlabel('Energy Consumption (μJ/op)')
    else:
        ax.text(0.5, 0.5, 'Sensore Intel RAPL non disponibile su macOS / VM\n(Eseguire sudo ./run_all.sh su Linux per misurare i μJ di handshake)', 
                ha='center', va='center', fontsize=12, color='#7f8c8d', 
                bbox=dict(boxstyle='round,pad=0.8', facecolor='#f8f9fa', edgecolor='#bdc3c7'))
        ax.set_yticks(y_pos)
        ax.set_yticklabels(schemes)
        ax.invert_yaxis()
        ax.set_xlabel('Energy Consumption (μJ/op) [N/A su Mac/WSL]')

    ax.set_title('Key Management Roadmap: Energy Consumption per Operation')
    ax.grid(True, axis='x')
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'key_management_energy.png'), dpi=300)
    plt.close()
    print(f"[OK] Grafici Key Management salvati in {PLOTS_DIR}/ (PNG 300 DPI)")

# =========================================================================
# 3. CODE SIZE & BINARY FOOTPRINT (FLASH / ROM vs RAM)
# =========================================================================
def analyze_code_size():
    print("\n" + "=" * 115)
    print(" 3. ANALISI CODE SIZE & MEMORY FOOTPRINT (FLASH/ROM & RAM vs LIMITI EMBEDDED CORTEX-M)")
    print("=" * 115)

    binaries = [
        ("Ascon AEAD (opt64 stand-alone)", "build/CMakeFiles/bench_ascon.dir/src/ascon-c/crypto_aead/asconaead128/opt64/aead.c.o"),
        ("Benchmark Ascon (ELF)", "build/bench_ascon"),
        ("Benchmark Libsodium (ELF)", "build/bench_libsodium"),
        ("Benchmark OpenSSL (ELF)", "build/bench_openssl"),
        ("Benchmark Key Management (ELF)", "build/bench_key_management"),
        ("Benchmark ML-KEM liboqs (ELF)", "build/bench_mlkem")
    ]

    size_results = []
    for label, rel_path in binaries:
        abs_path = os.path.join(BASE_DIR, rel_path)
        if not os.path.exists(abs_path):
            continue

        try:
            out = subprocess.check_output(["size", abs_path], stderr=subprocess.DEVNULL).decode('utf-8')
            lines = [l.strip() for l in out.strip().split('\n') if l.strip()]
            if len(lines) >= 2:
                # Format: text data bss dec hex filename OR __TEXT __DATA ...
                headers = lines[0].split()
                values = lines[1].split()
                text_bytes = int(values[0]) if len(values) > 0 and values[0].isdigit() else 0
                data_bytes = int(values[1]) if len(values) > 1 and values[1].isdigit() else 0
                bss_bytes = int(values[2]) if len(values) > 2 and values[2].isdigit() else 0
                total_dec = int(values[3]) if len(values) > 3 and values[3].isdigit() else (text_bytes + data_bytes + bss_bytes)
                
                # Su Cortex-M il limite tipico Flash è 512 KB e SRAM 128 KB (slide 5 presentazione)
                fits_flash = "Sì (<= 512 KB)" if text_bytes <= 512 * 1024 else "Supera 512 KB"

                size_results.append({
                    'Component': label,
                    'Path': rel_path,
                    'Flash_Text_Bytes': text_bytes,
                    'RAM_Data_Bytes': data_bytes,
                    'RAM_BSS_Bytes': bss_bytes,
                    'Total_Bytes': total_dec,
                    'Fits_Cortex_M_Flash': fits_flash
                })
        except Exception:
            pass

    if size_results:
        size_df = pd.DataFrame(size_results)
        print(f"{'Componente':<34} | {'Flash (Text B)':<15} | {'Data (RAM B)':<13} | {'BSS (B)':<8} | {'Cortex-M Fit':<15}")
        print("-" * 95)
        for _, r in size_df.iterrows():
            print(f"{r['Component']:<34} | {r['Flash_Text_Bytes']:<15} | {r['RAM_Data_Bytes']:<13} | {r['RAM_BSS_Bytes']:<8} | {r['Fits_Cortex_M_Flash']:<15}")

        size_csv_path = os.path.join(DATA_DIR, "code_size_summary.csv")
        size_df.to_csv(size_csv_path, index=False)
        print(f"\n[OK] Tabella code size salvata in: {size_csv_path}")

        # --- GRAFICO 7: Code Size Comparison ---
        fig, ax = plt.subplots(figsize=(10, 5))
        components = size_df['Component'].values
        flash_kb = size_df['Flash_Text_Bytes'].values / 1024.0
        y_pos = np.arange(len(components))

        bars = ax.barh(y_pos, flash_kb, color='#27ae60', alpha=0.85)
        ax.axvline(x=512, color='#c0392b', linestyle='--', linewidth=1.5, label='Limite Flash Cortex-M (512 KB)')
        ax.set_yticks(y_pos)
        ax.set_yticklabels(components)
        ax.invert_yaxis()
        ax.set_xlabel('Flash / ROM Footprint (KB)')
        ax.set_title('Binary & Code Size Comparison (Flash Memory Footprint)')
        ax.grid(True, axis='x')
        ax.legend(frameon=True)
        plt.tight_layout()
        plt.savefig(os.path.join(PLOTS_DIR, 'code_size_comparison.png'), dpi=300)
        plt.close()
        print(f"[OK] Grafico Code Size salvato in {PLOTS_DIR}/ (PNG 300 DPI)")

def main():
    print("=" * 70)
    print(" ZENO ATLAS - GENERATORE STATISTICO E GRAFICI TESI")
    print("=" * 70)
    analyze_bulk_encryption()
    analyze_key_management()
    analyze_code_size()
    print("\n" + "=" * 70)
    print(f" ELABORAZIONE COMPLETATA CON SUCCESSO!")
    print(f" - CSV Dati grezzi e Sintesi: '{DATA_DIR}/'")
    print(f" - Grafici PNG ad alta risoluzione: '{PLOTS_DIR}/'")
    print("=" * 70 + "\n")

if __name__ == '__main__':
    main()
