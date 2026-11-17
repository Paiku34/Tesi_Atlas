#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import signal
import csv

# Directory del progetto
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.join(SCRIPT_DIR, "build")
BENCHMARK_DATA_DIR = os.environ.get(
    "ATLAS_BENCHMARK_DATA_DIR",
    os.path.join(SCRIPT_DIR, "..", "ubuntu22.04_armA72", "data")
)
AEAD_BIN = os.path.join(BUILD_DIR, "bench_energia_aead")
KM_BIN = os.path.join(BUILD_DIR, "bench_energia_keymgmt")
CSV_OUTPUT = os.path.join(SCRIPT_DIR, "risultati_energia.csv")

# Colori terminale ANSI
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

PAYLOADS = [8, 16, 32, 64, 128, 256, 512, 1024]

AEAD_TESTS = [
    ("ascon", "Ascon-AEAD128"),
    ("aes256", "AES-256-GCM (OpenSSL)"),
    ("chacha_sodium", "ChaCha20-Poly1305 (Libsodium)"),
    ("chacha_openssl", "ChaCha20-Poly1305 (OpenSSL)")
]

KM_TESTS = [
    ("psk", "PSK + KDF (BLAKE2b)", 0),
    ("symm_handshake", "Symmetric Handshake (2-Way HKDF)", 96),
    ("x25519", "ECDH X25519 One-Way (PSK Auth)", 128),
    ("mlkem512", "ML-KEM-512", 864),
    ("mlkem768", "ML-KEM-768", 1184),
    ("mlkem1024", "ML-KEM-1024", 1664)
]

AEAD_REFERENCE_NAMES = {
    "ascon": "Ascon-AEAD128",
    "aes256": "AES-256-GCM",
    "chacha_sodium": "ChaCha20-Poly1305 (Libsodium)",
    "chacha_openssl": "ChaCha20-Poly1305 (OpenSSL)",
}

KM_REFERENCE_NAMES = {
    "psk": "PSK + KDF (Libsodium)",
    "symm_handshake": "Symmetric Handshake",
    "x25519": "ECDH X25519 (Libsodium)",
    "mlkem512": "ML-KEM-512",
    "mlkem768": "ML-KEM-768",
    "mlkem1024": "ML-KEM-1024",
}

def check_build():
    if not os.path.exists(AEAD_BIN) or not os.path.exists(KM_BIN):
        print(f"{YELLOW}[*] Binari non trovati. Avvio compilazione CMake...{RESET}")
        os.makedirs(BUILD_DIR, exist_ok=True)
        subprocess.run(["cmake", "-B", BUILD_DIR, "-S", SCRIPT_DIR], check=True)
        subprocess.run(["cmake", "--build", BUILD_DIR, "-j4"], check=True)
        print(f"{GREEN}[OK] Compilazione completata con successo.{RESET}\n")

def load_reference_rows(filename):
    path = os.path.join(BENCHMARK_DATA_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Summary benchmark non trovato: {path}. "
            "Esegui prima il benchmark computazionale."
        )
    with open(path, newline="") as handle:
        return list(csv.DictReader(handle))


def get_reference_latency(rows, name, payload=None):
    matches = [row for row in rows if row.get("Algorithm", row.get("Scheme")) == name]
    if name == "Ascon-AEAD128":
        matches = [row for row in rows if row.get("Algorithm", row.get("Scheme", "")).startswith(name)]
    if payload is not None:
        matches = [row for row in matches if int(row.get("Payload (B)", -1)) == payload]
    # First try exact match on Algorithm or Scheme
    matches = [row for row in rows if row.get("Algorithm", row.get("Scheme")) == name]
    # If no exact match, try prefix match (handles Ascon and algorithms with variant suffixes)
    if not matches:
        matches = [row for row in rows if row.get("Algorithm", row.get("Scheme", "")).startswith(name)]
    # If still no matches, try case‑insensitive containment (e.g., "AES-256-GCM" inside "AES-256-GCM (OpenSSL)")
    if not matches:
        lowered = name.lower()
        matches = [row for row in rows if lowered in row.get("Algorithm", row.get("Scheme", "")).lower()]
    if payload is not None:
        matches = [row for row in matches if int(row.get("Payload (B)", -1)) == payload]
    # Fallback: if payload filter removed all matches, retry without payload filter for the algorithm
    if not matches and payload is not None:
        # Re‑search using only algorithm name (without payload constraint)
        matches = [row for row in rows if row.get("Algorithm", row.get("Scheme", "")).startswith(name)]
        if not matches:
            matches = [row for row in rows if lowered in row.get("Algorithm", row.get("Scheme", "")).lower()]
    if not matches:
        raise ValueError(f"Latenza di riferimento non trovata per {name}, payload={payload}")
    return float(matches[0]["Mean Latency (us)"])

def cooldown_timer(seconds=8):
    print(f"{CYAN}--- Raffreddamento CPU ({seconds}s per stabilizzare temperatura) ---{RESET}")
    for s in range(seconds, 0, -1):
        print(f"\r  Pausa cooldown: {s}s rimanenti...  ", end="", flush=True)
        time.sleep(1)
    print("\r  [OK] CPU pronta per il prossimo test.          ")

def main():
    check_build()
    bulk_rows = load_reference_rows("bulk_encryption_summary_ci95.csv")
    km_rows = load_reference_rows("key_management_summary_ci95.csv")

    print(f"{BOLD}{CYAN}==========================================================================")
    print("   GUIDA INTERATTIVA MISURA ENERGIA STEADY-STATE (Raspberry Pi)")
    print("   Tesi Magistrale: Secure Sonobuoy Telemetry (NATO ANEP-96)")
    print(f"=========================================================================={RESET}\n")

    print(f"{YELLOW}Istruzioni per la misura:{RESET}")
    print("1. Mantieni il Raspberry Pi a riposo per 10 secondi e leggi la corrente IDLE.")
    print("2. Durante ogni test, la CPU andrà al 100% di carico continuo.")
    print("3. Guarda il display: la corrente si stabilizzerà su un valore medio.")
    print("4. Digita il valore letto in Ampere e premi INVIO.\n")

    # Richiesta Tensione e Idle
    try:
        v_in = input(f"{BOLD}Inserisci la TENSIONE del display in Volt [default 5.0]: {RESET}").strip()
        voltage = float(v_in) if v_in else 5.0

        i_idle_in = input(f"{BOLD}Inserisci la CORRENTE A RIPOSO (IDLE) in Ampere (es. 0.48): {RESET}").strip()
        i_idle = float(i_idle_in) if i_idle_in else 0.50
    except ValueError:
        print(f"{RED}Valore numerico non valido. Uscita.{RESET}")
        return

    p_idle = voltage * i_idle
    print(f"\n{GREEN}[OK] Configurazione:{RESET} V = {voltage:.2f} V | I_idle = {i_idle:.3f} A | P_idle = {p_idle:.3f} W\n")

    # Costruzione lista completa dei test
    test_queue = []
    # 1. AEAD (Payloads 8, 16, 32, 64, 128, 256, 512, 1024)
    for algo_id, algo_name in AEAD_TESTS:
        for payload in PAYLOADS:
            test_queue.append({
                "category": "AEAD Bulk Encryption",
                "id": algo_id,
                "name": algo_name,
                "payload": payload,
                "is_km": False
            })

    # 2. Key Management
    for scheme_id, scheme_name, payload_bytes in KM_TESTS:
        test_queue.append({
            "category": "Key Management",
            "id": scheme_id,
            "name": scheme_name,
            "payload": payload_bytes,
            "is_km": True
        })

    total_tests = len(test_queue)
    results = []

    print(f"{BOLD}Inizio sessione di misura: {total_tests} test totali.{RESET}\n")

    try:
        for idx, t in enumerate(test_queue, start=1):
            cat = t["category"]
            name = t["name"]
            payload = t["payload"]
            is_km = t["is_km"]
            tid = t["id"]

            print(f"{BOLD}{CYAN}--------------------------------------------------------------------------")
            print(f" [{idx}/{total_tests}] {cat.upper()}: {name}")
            print(f" Payload / Scambiati: {payload} Bytes")
            print(f"--------------------------------------------------------------------------{RESET}")

            if not is_km:
                reference_name = AEAD_REFERENCE_NAMES[tid]
                lat_mean_us = get_reference_latency(bulk_rows, reference_name, payload)
            else:
                reference_name = KM_REFERENCE_NAMES[tid]
                lat_mean_us = get_reference_latency(km_rows, reference_name)
            print(f"[*] Latenza di riferimento da summary: {lat_mean_us:.3f} µs")

            # 2. Avvio Carico Continuo (Steady-State Burn)
            print(f"\n{BOLD}{YELLOW}>>> ATTENZIONE: AVVIO CARICO CONTINUO AL 100% SULLA CPU... <<<{RESET}")
            if not is_km:
                proc = subprocess.Popen([AEAD_BIN, "--burn", tid, str(payload), "0"],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                proc = subprocess.Popen([KM_BIN, "--burn", tid, "0"],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # 3. Attesa inserimento utente
            time.sleep(1.5) # Lascia stabilizzare la corrente 1.5s
            print(f"{BOLD}>>> GUARDA IL DISPLAY DELLO STRUMENTO.{RESET}")
            print(f"    Annota il valore stabile di corrente in Ampere.")

            user_val = None
            while user_val is None:
                try:
                    raw = input(f"{BOLD}{GREEN}Inserisci Corrente ATTIVA in Ampere (es. 0.65) o 's' per saltare: {RESET}").strip()
                    if raw.lower() == 's':
                        print(f"{YELLOW}Test saltato dall'utente.{RESET}")
                        break
                    val = float(raw)
                    if val < 0.05 or val > 5.0:
                        print(f"{RED}Valore anomalo ({val} A). Inserisci un valore verosimile (es. 0.40 - 1.50 A).{RESET}")
                        continue
                    user_val = val
                except ValueError:
                    print(f"{RED}Inserisci un numero decimale valido (es. 0.63).{RESET}")

            # Stop del carico continuo
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

            if user_val is not None:
                i_active = user_val
                delta_i = max(0.0, i_active - i_idle)
                p_active = voltage * i_active
                p_dyn = voltage * delta_i

                # Latenza in secondi per calcolo energia
                t_sec = lat_mean_us * 1e-6

                # Energia totale per operazione (comprensiva dell'idle durante l'operazione)
                e_tot_uj = (p_active * t_sec) * 1e6
                # Energia dinamica netta (attribuibile unicamente al calcolo crittografico)
                e_dyn_uj = (p_dyn * t_sec) * 1e6

                # Energia normalizzata per byte (solo per payload > 0)
                e_per_byte_nj = (e_dyn_uj * 1000.0 / payload) if payload > 0 else 0.0

                print(f"\n{BOLD}{GREEN}[RISULTATO CALCOLATO]:{RESET}")
                print(f"  • Corrente Attiva I_act:    {i_active:.3f} A  (Delta: +{delta_i:.3f} A)")
                print(f"  • Potenza Dinamica P_dyn:   {p_dyn:.3f} W")
                print(f"  • Energia Dinamica / Op:    {BOLD}{e_dyn_uj:.4f} µJ{RESET} ({e_dyn_uj*1000:.2f} nJ)")
                print(f"  • Energia Totale / Op:      {e_tot_uj:.4f} µJ")
                if payload > 0:
                    print(f"  • Efficienza per Byte:      {BOLD}{e_per_byte_nj:.2f} nJ/Byte{RESET}")

                results.append({
                    "category": cat,
                    "algorithm": name,
                    "payload_bytes": payload,
                    "reference_latency_us": lat_mean_us,
                    "voltage_v": voltage,
                    "i_idle_a": i_idle,
                    "i_active_a": i_active,
                    "p_active_w": p_active,
                    "p_dyn_w": p_dyn,
                    "e_dyn_uj": e_dyn_uj,
                    "e_tot_uj": e_tot_uj,
                    "e_per_byte_nj": e_per_byte_nj
                })

            # Cooldown tra un test e l'altro per far calare il calore
            if idx < total_tests:
                cooldown_timer(seconds=6)
            print("\n")

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Sessione interrotta dall'utente. Salvataggio dei dati acquisiti fino ad ora...{RESET}\n")

    # Salvataggio dati
    if results:
        save_results(results, voltage, i_idle)
    else:
        print(f"{YELLOW}Nessun dato raccolto.{RESET}")

def save_results(results, voltage, i_idle):
    # 1. Scrittura CSV
    fieldnames = [
        "category", "algorithm", "payload_bytes", "reference_latency_us",
        "voltage_v", "i_idle_a", "i_active_a", "p_active_w", "p_dyn_w",
        "e_dyn_uj", "e_tot_uj", "e_per_byte_nj"
    ]
    with open(CSV_OUTPUT, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"{GREEN}[OK] File CSV salvato con successo: {CSV_OUTPUT}{RESET}")

    print(f"{BOLD}{CYAN}Campagna di misura terminata con successo!{RESET}\n")

if __name__ == "__main__":
    main()

