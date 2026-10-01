#!/bin/bash

echo "=========================================================================="
echo " ZENO ATLAS - CRYPTO BENCHMARK SUITE"
echo " Tesi Magistrale: Crittografia per Telemetria Sonobuoy Sicura"
echo "=========================================================================="
echo ""

# =========================================================================
# FASE 0: SETUP CPU & RAPL (richiede root)
# =========================================================================
echo "--- [FASE 0] Verifica Ambiente di Esecuzione ---"

# Mostra info CPU
echo "CPU: $(cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d: -f2 | xargs)"
echo "Cores: $(nproc)"
echo "Hostname: $(hostname)"
echo ""

# Verifica se siamo root (necessario per RAPL e cpufreq)
if [ "$(id -u)" -ne 0 ]; then
    echo "[WARNING] Non stai eseguendo come root!"
    echo "          Per misure affidabili esegui: sudo ./run_all.sh"
    echo "          - RAPL potrebbe essere bloccato"
    echo "          - La frequenza CPU potrebbe non essere fissata"
    echo ""
fi

# Fissa la frequenza CPU a performance (disabilita scaling dinamico)
if command -v cpupower &> /dev/null; then
    echo "--- Fissaggio frequenza CPU a 'performance' (niente turbo/throttle) ---"
    cpupower frequency-set -g performance 2>/dev/null
    # Disabilita turbo boost Intel
    if [ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
        echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null
        echo "[OK] Intel Turbo Boost disabilitato"
    fi
    echo "[OK] Governor impostato a 'performance'"
    cpupower frequency-info 2>/dev/null | grep "current CPU frequency"
else
    echo "[WARNING] cpupower non trovato. Installa con: sudo apt install linux-tools-common linux-tools-$(uname -r)"
    echo "          Senza cpupower la frequenza CPU potrebbe variare durante il benchmark!"
fi
echo ""

# Verifica accesso RAPL
if [ -f /sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj ]; then
    echo "[OK] Sensore Intel RAPL accessibile - misure energetiche disponibili"
else
    echo "[WARNING] Sensore Intel RAPL non accessibile"
    echo "          Prova: sudo chmod 444 /sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj"
fi
echo ""

# =========================================================================
# FASE 1: CODE SIZE & BINARY FOOTPRINT
# =========================================================================
echo "=========================================================================="
echo " 1. CODE SIZE & BINARY FOOTPRINT COMPARISON (size command)"
echo "    (Misura lo spazio reale in Flash/ROM del codice macchina compilato)"
echo "=========================================================================="
echo "--- Ascon-c (opt64 aead.c.o) ---"
size CMakeFiles/bench_ascon.dir/ascon-c/crypto_aead/asconaead128/opt64/aead.c.o 2>/dev/null

echo ""
echo "--- Eseguibili Completi (ELF Flash Footprint) ---"
size bench_ascon bench_libsodium bench_openssl bench_mlkem 2>/dev/null

# =========================================================================
# FASE 2: BENCHMARK ISOLATI (ogni algoritmo in processo fork separato)
# =========================================================================
echo ""
echo "=========================================================================="
echo " 2. ESECUZIONE BENCHMARK ISOLATI (fork-based RSS isolation)"
echo "=========================================================================="
./bench_ascon
./bench_libsodium
./bench_openssl
if [ -f "./bench_mlkem" ]; then
    ./bench_mlkem
fi

echo ""
echo "=========================================================================="
echo " BENCHMARK COMPLETATO"
echo "=========================================================================="
