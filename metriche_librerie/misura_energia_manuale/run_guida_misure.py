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
AEAD_BIN = os.path.join(BUILD_DIR, "bench_energia_aead")
KM_BIN = os.path.join(BUILD_DIR, "bench_energia_keymgmt")
CSV_OUTPUT = os.path.join(SCRIPT_DIR, "risultati_energia.csv")
MD_OUTPUT = os.path.join(SCRIPT_DIR, "risultati_energia.md")

# Colori terminale ANSI
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

PAYLOADS = [64, 255, 1024]

AEAD_TESTS = [
    ("ascon", "Ascon-AEAD128"),
    ("aes128", "AES-128-GCM (OpenSSL)"),
    ("aes256", "AES-256-GCM (OpenSSL)"),
    ("chacha_sodium", "ChaCha20-Poly1305 (Libsodium)"),
    ("chacha_openssl", "ChaCha20-Poly1305 (OpenSSL)")
]

KM_TESTS = [
    ("psk", "PSK + KDF (BLAKE2b)", 0),
    ("symm_handshake", "Symmetric Handshake (2-Way HKDF)", 80),
    ("x25519", "ECDH X25519", 64),
    ("mlkem512", "ML-KEM-512 (Kyber512)", 1568),
    ("mlkem768", "ML-KEM-768 (Kyber768)", 2272),
    ("mlkem1024", "ML-KEM-1024 (Kyber1024)", 3136)
]

def check_build():
    if not os.path.exists(AEAD_BIN) or not os.path.exists(KM_BIN):
        print(f"{YELLOW}[*] Binari non trovati. Avvio compilazione CMake...{RESET}")
        os.makedirs(BUILD_DIR, exist_ok=True)
        subprocess.run(["cmake", "-B", BUILD_DIR, "-S", SCRIPT_DIR], check=True)
        subprocess.run(["cmake", "--build", BUILD_DIR, "-j4"], check=True)
        print(f"{GREEN}[OK] Compilazione completata con successo.{RESET}\n")

def get_latency_aead(algo_id, payload):
    try:
        res = subprocess.run([AEAD_BIN, "--latency", algo_id, str(payload)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        for line in res.stdout.splitlines():
            if line.startswith("LATENCY_RESULT|"):
                parts = line.strip().split("|")
                # parts: ['LATENCY_RESULT', algo_id, name, payload, mean_us, std_us, cycles]
                return float(parts[4]), float(parts[5]), int(parts[6])
    except Exception as e:
        print(f"{RED}[ERRORE] Calcolo latenza AEAD fallito: {e}{RESET}")
    return 0.0, 0.0, 0

def get_latency_km(scheme_id):
    try:
        res = subprocess.run([KM_BIN, "--latency", scheme_id],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        for line in res.stdout.splitlines():
            if line.startswith("LATENCY_RESULT|"):
                parts = line.strip().split("|")
                return float(parts[4]), float(parts[5]), int(parts[6])
    except Exception as e:
        print(f"{RED}[ERRORE] Calcolo latenza Key Management fallito: {e}{RESET}")
    return 0.0, 0.0, 0

def cooldown_timer(seconds=8):
    print(f"{CYAN}--- Raffreddamento CPU ({seconds}s per stabilizzare temperatura) ---{RESET}")
    for s in range(seconds, 0, -1):
        print(f"\r  Pausa cooldown: {s}s rimanenti...  ", end="", flush=True)
        time.sleep(1)
    print("\r  [OK] CPU pronta per il prossimo test.          ")

def main():
    check_build()

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
    # 1. AEAD (Payloads 64, 255, 1024)
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

            # 1. Calcolo latenza software
            print(f"[*] Calcolo latenza software ({name})...", end="", flush=True)
            if not is_km:
                lat_mean_us, lat_std_us, cycles = get_latency_aead(tid, payload)
            else:
                lat_mean_us, lat_std_us, cycles = get_latency_km(tid)
            print(f" {GREEN}OK: {lat_mean_us:.3f} µs (± {lat_std_us:.3f}) | {cycles} cicli/op{RESET}")

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
                    "latency_us": lat_mean_us,
                    "cycles_per_op": cycles,
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
        "category", "algorithm", "payload_bytes", "latency_us", "cycles_per_op",
        "voltage_v", "i_idle_a", "i_active_a", "p_active_w", "p_dyn_w",
        "e_dyn_uj", "e_tot_uj", "e_per_byte_nj"
    ]
    with open(CSV_OUTPUT, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"{GREEN}[OK] File CSV salvato con successo: {CSV_OUTPUT}{RESET}")

    # 2. Generazione Report Markdown e Tabelle LaTeX per la tesi
    with open(MD_OUTPUT, "w") as f:
        f.write("# Report Misure Energetiche - Tesi Magistrale Atlas\n\n")
        f.write(f"- **Data Acquisizione:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **Tensione di Alimentazione ($V$):** {voltage:.2f} V\n")
        f.write(f"- **Corrente IDLE ($I_{{idle}}$):** {i_idle:.3f} A ({voltage*i_idle:.3f} W)\n\n")

        f.write("## 1. Crittografia Simmetrica / AEAD (Payload: 64, 255, 1024 B)\n\n")
        f.write("| Algoritmo | Payload | Latenza (µs) | Cicli/Op | $I_{attivo}$ (A) | $P_{dyn}$ (W) | $E_{dyn}$ (µJ) | nJ/Byte |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for r in results:
            if r["category"] == "AEAD Bulk Encryption":
                f.write(f"| **{r['algorithm']}** | {r['payload_bytes']} B | {r['latency_us']:.2f} | {r['cycles_per_op']} | {r['i_active_a']:.3f} | {r['p_dyn_w']:.3f} | **{r['e_dyn_uj']:.4f}** | {r['e_per_byte_nj']:.2f} |\n")

        f.write("\n## 2. Key Management Roadmap (PSK, Handshake, X25519, ML-KEM)\n\n")
        f.write("| Schema | Scambio (Bytes) | Latenza (µs) | Cicli/Op | $I_{attivo}$ (A) | $P_{dyn}$ (W) | $E_{dyn}$ (µJ) |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for r in results:
            if r["category"] == "Key Management":
                f.write(f"| **{r['algorithm']}** | {r['payload_bytes']} B | {r['latency_us']:.2f} | {r['cycles_per_op']} | {r['i_active_a']:.3f} | {r['p_dyn_w']:.3f} | **{r['e_dyn_uj']:.4f}** |\n")

        f.write("\n\n## Formule Adottate per la Tesi:\n")
        f.write("$$\\Delta I = I_{attivo} - I_{idle}$$\n")
        f.write("$$P_{dyn} = V \\cdot \\Delta I$$\n")
        f.write("$$E_{dyn} = P_{dyn} \\cdot t_{op} \\quad [\\mu\\text{J}]$$\n")
        f.write("$$E_{byte} = \\frac{E_{dyn}}{\\text{Payload}} \\quad [\\text{nJ/Byte}]$$\n")

    print(f"{GREEN}[OK] Report Markdown generato: {MD_OUTPUT}{RESET}")
    print(f"{BOLD}{CYAN}Campagna di misura terminata con successo!{RESET}\n")

if __name__ == "__main__":
    main()

