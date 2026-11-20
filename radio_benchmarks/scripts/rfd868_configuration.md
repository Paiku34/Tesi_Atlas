# ZENO ATLAS — Guida Operativa Testbed Laboratorio (RFD868+)

Questa guida raccoglie tutti i comandi pronti all'uso per compilare i nodi, configurare i modem RFD868+, eseguire la campagna sperimentale e salvare i log CSV tra un test e l'altro.

---

## 1. Compilazione e Provisioning (PC Ground Station & Raspberry Pi Boa)

Esegui questi comandi su **entrambi** i dispositivi (PC Ground Station e Raspberry Pi):

```bash
# 1. Verifica che le cartelle di lavoro esistano
mkdir -p provisioning data

# 2. Compilazione pulita
make clean && make
# (Oppure, se usi CMake: cmake -B build && cmake --build build)

# 3. Generazione chiavi e PSK (da eseguire UNA VOLTA SOLA su un nodo, poi copiare provisioning/ sull'altro)
./generate_keys provisioning
```

> **Nota sul provisioning:** La cartella `provisioning/` deve contenere le **stesse chiavi** (`PK_GS`, `PSK`, e `SK_GS` solo lato Ground Station) su entrambi i dispositivi. Usa `scp` per copiarla dal PC al Raspberry Pi:
> ```bash
> scp -r provisioning/ pi@<IP_RASPBERRY>:/percorso/progetto/
> ```

---

## 2. Configurazione Modem RFD868+ (Comandi AT)

Prima di avviare gli eseguibili C++, puoi ispezionare o modificare i parametri radio (come `AIR_SPEED` per il Punto 2 degli esperimenti) collegandoti alla seriale del modem con `screen` o `minicom`.

### Accesso alla modalità AT
```bash
# Apri terminale seriale a 57600 baud (verifica la porta con: ls /dev/ttyUSB*)
screen /dev/ttyUSB0 57600
```
Una volta aperto `screen`:
1. Attendi almeno **1 secondo** senza digitare nulla.
2. Digita **`+++`** (senza premere Invio) e attendi 1 secondo: il modem risponderà con `OK`.

### Comandi AT principali (da digitare in modalità AT)

| Comando | Descrizione |
| :--- | :--- |
| `ATI` | Mostra versione firmware del modem RFD868+ |
| `ATI5` | Mostra **tutti i registri EEPROM** correnti (`SERIAL_SPEED`, `AIR_SPEED`, `NETID`, `TXPOWER`, ecc.) |
| `ATS1?` | Legge velocità UART (`57` = 57600 baud) |
| `ATS2?` | Legge velocità radio (`AIR_SPEED` in kbps, default `64`) |
| `ATS2=12` | Imposta `AIR_SPEED` a **12 kbps** (valori tipici RFD868+: `4`, `8`, `12`, `16`, `24`, `32`, `64`, `125`) |
| `ATS2=64` | Ripristina `AIR_SPEED` a **64 kbps** (default) |
| `ATS3=25` | Imposta `NETID` = 25 (**deve essere identico** su entrambi i modem) |
| `ATS4=20` | Imposta potenza TX (es. `20` = 20 dBm / 100 mW per test a corto raggio in laboratorio; max `30` = 1 W) |
| `ATS10=0` | Disabilita MAVLink framing (`0` = Raw/Transparent mode, consigliato per il nostro protocollo binario) |
| `AT&W` | **Salva i parametri in EEPROM** (obbligatorio per renderli permanenti) |
| `ATZ` | **Riavvia il modem** applicando le nuove impostazioni |
| `ATO` | Esce dalla modalità AT tornando alla modalità dati trasparente |

> **Per chiudere `screen`:** premi `Ctrl+A`, poi `K`, poi `Y`.  
> **Importante:** qualsiasi modifica a `AIR_SPEED` (`ATS2`) o `NETID` (`ATS3`) va applicata **identica su entrambi i modem** (PC e Raspberry Pi).

---

## 3. Esecuzione della Campagna Sperimentale

### Step 1 — Avvia la Ground Station (sul PC)
```bash
./ground_station /dev/ttyUSB0 57600 provisioning data
```
Attendi che a schermo compaia:
`[OK] Ground station pronta. In attesa di MAGIC_START dalla boa (termina con Ctrl+C)...`

### Step 2 — Avvia la Boa (sul Raspberry Pi)
```bash
./buoy_node /dev/ttyUSB0 57600 provisioning data
```
La boa invierà `MAGIC_START` e avvierà automaticamente:
1. **200 Handshake KEM** (50 × X25519, ML-KEM-512, ML-KEM-768, ML-KEM-1024).
2. **3.000 pacchetti Telemetria** (5 algoritmi × 6 payload × 100 pacchetti).

### Step 3 — Chiusura e Salvataggio Log
1. Attendi che sul Raspberry Pi compaia:
   `[OK] Campagna completata con successo!`
2. Vai sul terminale della Ground Station (PC) e premi **`Ctrl+C`** (non chiudere la finestra direttamente, altrimenti non viene eseguito `csv.close()`).

---

## 4. Salvataggio e Organizzazione Risultati tra i Run

Ogni esecuzione sovrascrive i 4 file CSV dentro `data/`. Prima di cambiare bitrate (`AIR_SPEED`) o distanza/attenuazione tra i nodi, sposta i file in una sottocartella dedicata:

```bash
# Sul Raspberry Pi (Boa):
mkdir -p data/run_64kbps_2m
mv data/radio_telemetry_results.csv data/radio_kem_results.csv data/run_64kbps_2m/

# Sul PC (Ground Station):
mkdir -p data/run_64kbps_2m
mv data/ground_station_log.csv data/ground_station_kem_results.csv data/run_64kbps_2m/
```

### Riepilogo dei 4 file generati per ogni run
* **Lato Boa (`Raspberry Pi`):**
  * `radio_telemetry_results.csv` $\rightarrow$ Latenza E2E completa, Goodput Stop-and-Wait, Overhead %, PDR round-trip telemetria.
  * `radio_kem_results.csv` $\rightarrow$ Esito handshake lato boa, dimensioni ciphertext/handshake totali.
* **Lato Ground Station (`PC`):**
  * `ground_station_kem_results.csv` $\rightarrow$ Latenza E2E completa (`E2E_Handshake_ms`) e stato (`OK` / `TIMEOUT` / `CORRUPTED_TRUNCATED` / `PSK_AUTH_FAIL`) per ciascuno dei 200 handshake.
  * `ground_station_log.csv` $\rightarrow$ Log completo di tutti i pacchetti ricevuti con classificazione errori (`OK`, `CORRUPTED_TRUNCATED`, `AUTH_FAIL`) per calcolare il PDR uplink e distinguere le cause di perdita.