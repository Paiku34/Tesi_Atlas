#!/bin/bash
# Script per interrogare e salvare la configurazione attuale del modem RFD868+
# Utilizzo: ./dump_rfd868_config.sh /dev/ttyUSB0

DEVICE=${1:-/dev/ttyUSB0}
BAUD=57600
OUT_FILE="rfd868_backup_$(date +%Y%m%d_%H%M%S).txt"

echo "=== RFD868+ Configuration Dumper ==="
echo "Dispositivo: $DEVICE ($BAUD baud)"
echo "Output file: $OUT_FILE"

# Configura la porta seriale locale a 57600 baud
stty -F "$DEVICE" "$BAUD" raw -echo -echoe -echok -echoctl -echoke

# Apri descriptor di lettura in background
exec 3<"$DEVICE"

# Invia sequenza di escape per entrare in AT command mode (guard time 1s)
sleep 1.2
echo -n "+++" > "$DEVICE"
sleep 1.2

# Invia comandi di interrogazione registri SiK
{
    echo "ATI"   # Info firmware / versione
    sleep 0.2
    echo "ATI5"  # Dump tutti i parametri S-Registers (Air speed, tx power, netid, ecc.)
    sleep 0.5
    echo "ATO"   # Torna in data mode
} > "$DEVICE"

# Leggi l'output dal descriptor 3
timeout 3 cat <&3 | tr -d '\r' > "$OUT_FILE"
exec 3<&-

echo "Configurazione salvata con successo in $OUT_FILE"
cat "$OUT_FILE"
