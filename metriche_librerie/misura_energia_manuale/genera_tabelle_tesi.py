#!/usr/bin/env python3
import os
import sys
import csv

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_INPUT = os.path.join(SCRIPT_DIR, "risultati_energia.csv")

def generate_latex():
    if not os.path.exists(CSV_INPUT):
        print(f"File {CSV_INPUT} non trovato. Esegui prima 'run_guida_misure.py'.")
        return

    with open(CSV_INPUT, "r") as f:
        reader = list(csv.DictReader(f))

    if not reader:
        print("Il CSV non contiene dati.")
        return

    print("\n% ==========================================================================")
    print("% TABELLA LATEX: AEAD BULK ENCRYPTION (Payload 64, 255, 1024 B)")
    print("% ==========================================================================")
    print(r"""\begin{table}[htbp]
\centering
\caption{Consumo Energetico Dinamico e Throughput su Raspberry Pi (AEAD)}
\label{tab:energia_aead}
\begin{tabular}{l c r r r r r}
\toprule
\textbf{Algoritmo} & \textbf{Payload} & \textbf{Latenza} [$\mu$s] & \textbf{Cicli/Op} & $\mathbf{P_{dyn}}$ [W] & $\mathbf{E_{dyn}}$ [$\mu$J] & \textbf{nJ/Byte} \\
\midrule""")

    for row in reader:
        if row["category"] == "AEAD Bulk Encryption":
            algo = row["algorithm"].replace("_", r"\_")
            payload = row["payload_bytes"]
            lat = float(row["latency_us"])
            cycles = int(row["cycles_per_op"])
            pdyn = float(row["p_dyn_w"])
            edyn = float(row["e_dyn_uj"])
            enj = float(row["e_per_byte_nj"])
            print(f"{algo} & {payload} B & {lat:.2f} & {cycles} & {pdyn:.3f} & \\textbf{{{edyn:.4f}}} & {enj:.2f} \\\\")

    print(r"""\bottomrule
\end{tabular}
\end{table}""")

    print("\n% ==========================================================================")
    print("% TABELLA LATEX: KEY MANAGEMENT ROADMAP")
    print("% ==========================================================================")
    print(r"""\begin{table}[htbp]
\centering
\caption{Consumo Energetico Schemi di Key Management su Raspberry Pi}
\label{tab:energia_keymgmt}
\begin{tabular}{l c r r r r}
\toprule
\textbf{Schema / Protocollo} & \textbf{Scambiati} & \textbf{Latenza} [$\mu$s] & \textbf{Cicli/Op} & $\mathbf{P_{dyn}}$ [W] & $\mathbf{E_{dyn}}$ [$\mu$J] \\
\midrule""")

    for row in reader:
        if row["category"] == "Key Management":
            algo = row["algorithm"].replace("_", r"\_")
            payload = row["payload_bytes"]
            lat = float(row["latency_us"])
            cycles = int(row["cycles_per_op"])
            pdyn = float(row["p_dyn_w"])
            edyn = float(row["e_dyn_uj"])
            print(f"{algo} & {payload} B & {lat:.2f} & {cycles} & {pdyn:.3f} & \\textbf{{{edyn:.4f}}} \\\\")

    print(r"""\bottomrule
\end{tabular}
\end{table}""")

if __name__ == "__main__":
    generate_latex()

