# ZENO ATLAS — Guida Operativa Testbed Laboratorio (RFD868+)

Questa guida raccoglie tutti i comandi pronti all'uso per compilare i nodi, configurare i modem RFD868+, eseguire la campagna sperimentale (con o senza ritrasmissioni applicative) e salvare i log CSV tra un test e l'altro.

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
>
> ```bash
> scp -r provisioning/ pi@<IP_RASPBERRY>:/percorso/progetto/
> ```

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
| `ATI5` | Mostra **tutti i registri EEPROM** correnti (`SERIAL_SPEED`, `AIR_SPEED`, `NETID`, `TXPOWER`, `ECC`, `MAVLINK`, `MAX_WINDOW`, ecc.) |
| `ATS1?` | Legge velocità UART (`57` = 57600 baud) |
| `ATS2?` | Legge velocità radio (`AIR_SPEED` in kbps, default `64`) |
| `ATS2=12` | Imposta `AIR_SPEED` a **12 kbps** (valori tipici RFD868+: `4`, `8`, `12`, `16`, `24`, `32`, `64`, `125`) |
| `ATS2=64` | Ripristina `AIR_SPEED` a **64 kbps** (default) |
| `ATS3=25` | Imposta `NETID` = 25 (**deve essere identico** su entrambi i modem) |
| `ATS4=20` | Imposta potenza TX (es. `20` = 20 dBm / 100 mW per test a corto raggio in laboratorio; max `30` = 1 W) |
| `ATS5=0` | Disabilita ECC/FEC (`0` = nessun raddoppio bit, `1` = FEC attivo) |
| `ATS6=0` | Modalità trasparente pura (`0` = Raw/Transparent senza MAVLink framing/ARQ nascosto) |
| `AT&W` | **Salva i parametri in EEPROM** (obbligatorio per renderli permanenti) |
| `ATZ` | **Riavvia il modem** applicando le nuove impostazioni |
| `ATO` | Esce dalla modalità AT tornando alla modalità dati trasparente |

> **Per chiudere `screen`:** premi `Ctrl+A`, poi `K`, poi `Y`.
>
> **Importante:** qualsiasi modifica a `AIR_SPEED` (`ATS2`) o `NETID` (`ATS3`) va applicata **identica su entrambi i modem** (PC e Raspberry Pi). Salva l'output completo di `ATI5` in un file di testo per documentare i parametri fisici del link.

## 3. Esecuzione della Campagna Sperimentale

Entrambi gli eseguibili accettano 5 argomenti posizionali:
`./eseguibile <device> <baudrate> <prov_dir> <data_dir> [max_retries]` (dove `max_retries` è opzionale e vale **`0`** di default).

### Caso A — Test Standard (senza ritrasmissioni applicative: `max_retries = 0`)

1. **Avvia la Ground Station (sul PC):**

```bash
./ground_station /dev/ttyUSB0 57600 provisioning data 0
```

Attendi che a schermo compaia:
`[OK] Ground station pronta. In attesa di MAGIC_START dalla boa (termina con Ctrl+C)...`

2. **Avvia la Boa (sul Raspberry Pi):**

```bash
./buoy_node /dev/ttyUSB0 57600 provisioning data 0
```

### Caso B — Test Collegamento Degradato con Ritrasmissioni (es. `max_retries = 3`)

> **Importante:** passa lo **stesso valore** di `max_retries` su **entrambi** i nodi affinché sia i KEM (guidati dalla GS) sia la telemetria (guidata dalla Boa) siano sincronizzati.

1. **Avvia la Ground Station (sul PC):**

```bash
./ground_station /dev/ttyUSB0 57600 provisioning data 3
```

2. **Avvia la Boa (sul Raspberry Pi):**

```bash
./buoy_node /dev/ttyUSB0 57600 provisioning data 3
```

### Chiusura e Salvataggio Log (per entrambi i casi)

1. Attendi che sul Raspberry Pi compaia:
   `[OK] Campagna completata con successo!`
2. Vai sul terminale della Ground Station (PC) e premi **`Ctrl+C`** (non chiudere la finestra direttamente, altrimenti non viene eseguito `csv.close()`).

## 4. Salvataggio e Organizzazione Risultati tra i Run

Ogni esecuzione sovrascrive i 4 file CSV dentro `data/`. Prima di cambiare bitrate (`AIR_SPEED`), distanza/attenuazione o `max_retries`, sposta i file in una sottocartella dedicata:

```bash
# Sul Raspberry Pi (Boa):
mkdir -p data/run_64kbps_2m_retries0
mv data/radio_telemetry_results.csv data/radio_kem_results.csv data/run_64kbps_2m_retries0/

# Sul PC (Ground Station):
mkdir -p data/run_64kbps_2m_retries0
mv data/ground_station_log.csv data/ground_station_kem_results.csv data/run_64kbps_2m_retries0/
```

### Riepilogo dei 4 file generati per ogni run

* **Lato Boa (`Raspberry Pi`):**
  * `radio_telemetry_results.csv` $\rightarrow$ Latenza E2E completa (inclusi eventuali retries), Goodput Stop-and-Wait, Overhead %, PDR round-trip telemetria, `Retries`.
  * `radio_kem_results.csv` $\rightarrow$ Esito handshake lato boa, dimensioni ciphertext/handshake totali, `Retries`.
* **Lato Ground Station (`PC`):**
  * `ground_station_kem_results.csv` $\rightarrow$ Latenza E2E completa (`E2E_Handshake_ms` inclusi eventuali retries), `Retries` e stato (`OK` / `TIMEOUT` / `CORRUPTED_TRUNCATED` / `PSK_AUTH_FAIL`) per ciascuno dei 200 handshake.
  * `ground_station_log.csv` $\rightarrow$ Log completo di tutti i pacchetti ricevuti con classificazione errori (`OK`, `CORRUPTED_TRUNCATED`, `AUTH_FAIL`) per calcolare il PDR uplink e distinguere le cause di perdita.