#!/usr/bin/env python3
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
PLOTS_DIR = BASE_DIR / "plots"
CURRENT_FILE = DATA_DIR / "current_values.txt"


@dataclass
class CurrentConfig:
    voltage_v: float
    current_idle_a: float
    currents: dict[tuple[str, int], float]
    currents_keymgmt: dict[str, float]


def normalize_name(name: str) -> str:
    name = name.strip().lower()
    name = re.sub(r"\s+", " ", name)
    # Tolleranza typo nel file correnti.
    name = name.replace("opessl", "openssl")
    name = name.replace("opesnssl", "openssl")
    return name


def parse_currents(path: Path) -> CurrentConfig:
    text = path.read_text(encoding="utf-8")

    m_v = re.search(r"voltage\s*=\s*([0-9]*\.?[0-9]+)", text, re.IGNORECASE)
    m_idle = re.search(r"current\s+baseline\s*=\s*([0-9]*\.?[0-9]+)", text, re.IGNORECASE)
    if not m_v or not m_idle:
        raise ValueError("Impossibile leggere voltage/current baseline da current_values.txt")

    voltage_v = float(m_v.group(1))
    current_idle_a = float(m_idle.group(1))

    aead_entries: dict[str, list[tuple[int, float]]] = {}
    km_entries: dict[str, float] = {}

    pattern = re.compile(r"^\s*([^=]+?)\s*=\s*\{([^}]*)\}\s*$")
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line or "{" not in line:
            continue
        m = pattern.match(line)
        if not m:
            continue

        lhs = normalize_name(m.group(1))
        rhs_vals = [v.strip() for v in m.group(2).split(",") if v.strip()]
        vals = [float(v) for v in rhs_vals]
        i_mean = sum(vals) / len(vals)

        if lhs.startswith("mlkem "):
            km_entries[lhs] = i_mean
            continue

        m_size = re.match(r"(.+?)\s+(\d+)$", lhs)
        if m_size:
            algo = normalize_name(m_size.group(1))
            size = int(m_size.group(2))
            aead_entries.setdefault(algo, []).append((size, i_mean))
            continue

        km_entries[lhs] = i_mean

    currents: dict[tuple[str, int], float] = {}

    for algo, entries in aead_entries.items():
        # Caso specifico nel file allegato: "aes openssl" compare 3 volte con size=64.
        if algo == "aes openssl" and len(entries) >= 3 and all(size == 64 for size, _ in entries[:3]):
            for payload, (_, i_mean) in zip((64, 255, 1024), entries[:3]):
                currents[(algo, payload)] = i_mean
            for size, i_mean in entries[3:]:
                currents[(algo, size)] = i_mean
            continue

        for size, i_mean in entries:
            currents[(algo, size)] = i_mean

    return CurrentConfig(
        voltage_v=voltage_v,
        current_idle_a=current_idle_a,
        currents=currents,
        currents_keymgmt=km_entries,
    )


def compute_bulk_energy(cfg: CurrentConfig) -> pd.DataFrame:
    src = pd.read_csv(DATA_DIR / "bulk_encryption_summary_ci95.csv")

    algo_map = {
        "Ascon-AEAD128 (ascon-c opt64)": "ascon",
        "AES-256-GCM (OpenSSL)": "aes openssl",
        "ChaCha20-Poly1305 (Libsodium)": "chacha libsodium",
        "ChaCha20-Poly1305 (OpenSSL)": "chacha openssl",
    }
    payloads = {64, 255, 1024}

    rows: list[dict[str, float | int | str]] = []
    for _, r in src.iterrows():
        algo = str(r["Algorithm"]) 
        payload = int(r["Payload (B)"])
        if algo not in algo_map or payload not in payloads:
            continue

        key = (algo_map[algo], payload)
        if key not in cfg.currents:
            raise KeyError(f"Corrente non trovata per {key}")

        latency_us = float(r["Mean Latency (us)"])
        i_active = float(cfg.currents[key])
        delta_i = max(0.0, i_active - cfg.current_idle_a)
        p_dyn = cfg.voltage_v * delta_i
        e_dyn_uj = p_dyn * latency_us
        e_per_byte_nj = (e_dyn_uj * 1000.0) / payload

        rows.append(
            {
                "algorithm": algo,
                "payload_bytes": payload,
                "latency_us": latency_us,
                "voltage_v": cfg.voltage_v,
                "i_idle_a": cfg.current_idle_a,
                "i_active_a": i_active,
                "delta_i_a": delta_i,
                "p_dyn_w": p_dyn,
                "e_dyn_uj": e_dyn_uj,
                "e_per_byte_nj": e_per_byte_nj,
            }
        )

    out = pd.DataFrame(rows).sort_values(["algorithm", "payload_bytes"]).reset_index(drop=True)
    return out


def compute_keymgmt_energy(cfg: CurrentConfig) -> pd.DataFrame:
    src = pd.read_csv(DATA_DIR / "key_management_summary_ci95.csv")

    scheme_map = {
        "PSK + KDF (Libsodium)": "psk + kdf",
        "Symmetric Handshake": "symm hand",
        "ECDH X25519 (Libsodium)": "ecdh",
        "ML-KEM-512": "mlkem 512",
        "ML-KEM-768": "mlkem 768",
        "ML-KEM-1024": "mlkem 1024",
    }

    rows: list[dict[str, float | int | str]] = []
    for _, r in src.iterrows():
        scheme = str(r["Scheme"])
        if scheme not in scheme_map:
            continue

        key = scheme_map[scheme]
        if key not in cfg.currents_keymgmt:
            raise KeyError(f"Corrente non trovata per schema '{key}'")

        latency_us = float(r["Mean Latency (us)"])
        exchanged = int(r["Exchanged (B)"])
        i_active = float(cfg.currents_keymgmt[key])
        delta_i = max(0.0, i_active - cfg.current_idle_a)
        p_dyn = cfg.voltage_v * delta_i
        e_dyn_uj = p_dyn * latency_us
        e_per_byte_nj = (e_dyn_uj * 1000.0 / exchanged) if exchanged > 0 else 0.0

        rows.append(
            {
                "scheme": scheme,
                "exchanged_bytes": exchanged,
                "latency_us": latency_us,
                "voltage_v": cfg.voltage_v,
                "i_idle_a": cfg.current_idle_a,
                "i_active_a": i_active,
                "delta_i_a": delta_i,
                "p_dyn_w": p_dyn,
                "e_dyn_uj": e_dyn_uj,
                "e_per_byte_nj": e_per_byte_nj,
            }
        )

    order = [
        "PSK + KDF (Libsodium)",
        "Symmetric Handshake",
        "ECDH X25519 (Libsodium)",
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
    ]
    out = pd.DataFrame(rows)
    out["_order"] = out["scheme"].apply(order.index)
    out = out.sort_values("_order").drop(columns=["_order"]).reset_index(drop=True)
    return out


def save_outputs(bulk_df: pd.DataFrame, km_df: pd.DataFrame) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    bulk_path = DATA_DIR / "bulk_energy_net.csv"
    km_path = DATA_DIR / "key_management_energy_net.csv"

    bulk_df.to_csv(bulk_path, index=False)
    km_df.to_csv(km_path, index=False)


def plot_bulk_energy(bulk_df: pd.DataFrame) -> None:
    plt.figure(figsize=(9, 5.5))
    for algo, group in bulk_df.groupby("algorithm"):
        g = group.sort_values("payload_bytes")
        plt.plot(g["payload_bytes"], g["e_dyn_uj"], marker="^", label=algo)

    plt.xlabel("Payload Dimension (Bytes)")
    plt.ylabel("Net Dynamic Energy per Packet (μJ)")
    plt.title("Physical Energy Consumption per Packet")
    plt.xticks([64, 255, 1024])
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
    cfg = parse_currents(CURRENT_FILE)
    bulk_df = compute_bulk_energy(cfg)
    km_df = compute_keymgmt_energy(cfg)
    save_outputs(bulk_df, km_df)
    plot_bulk_energy(bulk_df)
    plot_keymgmt_energy(km_df)

    print(f"[OK] CSV creati in: {DATA_DIR}")
    print(f"[OK] Grafici energia rigenerati in: {PLOTS_DIR}")


if __name__ == "__main__":
    main()
