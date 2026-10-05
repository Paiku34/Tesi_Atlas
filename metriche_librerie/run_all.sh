#!/bin/bash

# Determine directory of this script and move to it
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$SCRIPT_DIR"

echo "=========================================================================="
echo " ZENO ATLAS - CRYPTO BENCHMARK SUITE"
echo " Tesi Magistrale: Crittografia per Telemetria Sonobuoy Sicura (NATO ANEP-96)"
echo "=========================================================================="
echo ""

# Assicura la presenza delle cartelle organizzate
mkdir -p data plots build

# =========================================================================
# FASE 0: SETUP CPU & AMBIENTE
# =========================================================================
echo "--- [FASE 0] Verifica Ambiente di Esecuzione ---"

if [ -f /proc/cpuinfo ]; then
    echo "CPU: $(cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d: -f2 | xargs)"
    echo "Cores: $(nproc 2>/dev/null || echo 'N/A')"
elif command -v sysctl &> /dev/null; then
    echo "CPU: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)"
fi
echo "Hostname: $(hostname)"
echo ""

# Verifica privilegi di root (solo per Linux con RAPL e cpufreq)
if [ "$(id -u)" -ne 0 ] && [ -f /proc/cpuinfo ]; then
    echo "[WARNING] Non stai eseguendo come root!"
    echo "          Per misure energetiche RAPL e fissaggio frequenza esegui: sudo ./run_all.sh"
fi

# Fissa la frequenza CPU a performance (se cpupower è disponibile su Linux)
if command -v cpupower &> /dev/null; then
    echo "--- Fissaggio frequenza CPU a 'performance' ---"
    cpupower frequency-set -g performance 2>/dev/null
    if [ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
        echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null
        echo "[OK] Intel Turbo Boost disabilitato"
    fi
    echo "[OK] Governor impostato a 'performance'"
fi

# Sensore RAPL
if [ -f /sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj ]; then
    echo "[OK] Sensore Intel RAPL accessibile"
fi
echo ""

# =========================================================================
# FASE 1: BUILD DEI BINARI CON CMAKE
# =========================================================================
echo "=========================================================================="
echo " 1. COMPILAZIONE BINARI OTTIMIZZATI (-O3) IN build/"
echo "=========================================================================="
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)

if [ $? -ne 0 ]; then
    echo "[ERRORE] Compilazione fallita!"
    exit 1
fi

echo ""
echo "=========================================================================="
echo " 2. CODE SIZE & BINARY FOOTPRINT (Flash/ROM Memory Footprint)"
echo "=========================================================================="
size build/bench_ascon build/bench_libsodium build/bench_openssl build/bench_key_management build/bench_mlkem 2>/dev/null

# =========================================================================
# FASE 2: ESECUZIONE BENCHMARK ISOLATI
# =========================================================================
echo ""
echo "=========================================================================="
echo " 3. ESECUZIONE BENCHMARK ISOLATI (Misure 1-a-1 salvate in data/)"
echo "=========================================================================="

# Resetta i CSV dei dati grezzi per nuova run pulita
rm -f data/bulk_encryption_raw.csv data/key_management_raw.csv data/mlkem_breakdown_raw.csv

./build/bench_ascon
./build/bench_libsodium
./build/bench_openssl

if [ -f "./build/bench_key_management" ]; then
    ./build/bench_key_management
fi

if [ -f "./build/bench_mlkem" ]; then
    ./build/bench_mlkem
fi

# =========================================================================
# FASE 3: ANALISI STATISTICA (CI 95%) & GENERAZIONE GRAFICI TESI
# =========================================================================
echo ""
echo "=========================================================================="
echo " 4. ELABORAZIONE STATISTICA & GRAFICI TESI (python/analyze_benchmarks.py)"
echo "=========================================================================="
if command -v python3 &> /dev/null; then
    python3 python/analyze_benchmarks.py
else
    echo "[ERRORE] Python 3 non trovato. Installa python3 con scipy, pandas e matplotlib."
fi

echo ""
echo "=========================================================================="
echo " COMPLETATO CON SUCCESSO!"
echo " - Dati grezzi e tabelle: data/"
echo " - Grafici scientifici:   plots/"
echo "=========================================================================="
