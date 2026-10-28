# Suite di Misura Energetica a Regime (Raspberry Pi)

Questa suite è progettata per misurare con rigore scientifico il **consumo energetico per operazione** ($\mu\text{J/op}$) e l'**efficienza per byte** ($\text{nJ/Byte}$) su Raspberry Pi, utilizzando uno strumento esterno (power meter USB o multimetro) dotato esclusivamente di display digitale (senza datalogging automatico).

---

## 1. Fondamento Metodologico: Perché "Steady-State" e non "Picco"?

Nelle analisi energetiche di algoritmi crittografici, utilizzare il **picco massimo di corrente** è un errore metodologico:
1. **L'energia dipende dalla media e dal tempo:**
   $$E = V \int I(t) \, dt = V \cdot I_{\text{medio}} \cdot t$$
   Moltiplicare per il picco massimo sovrastima l'energia del 20%–50% poiché presuppone che la corrente rimanga al valore massimo per l'intera durata.
2. **Paradosso del "Race-to-Sleep":**  
   Algoritmi che sfruttano le estensioni hardware o vettoriali (es. AES-NI / ARM NEON) possono assorbire una corrente istantanea leggermente più alta, ma completare l'operazione in un decimo del tempo. Considerare solo il picco porterebbe alla conclusione errata che siano meno efficienti, mentre in realtà consumano molta meno energia totale.
3. **Frequenza di aggiornamento dei display:**  
   I display commerciali aggiornano a 2–4 Hz e non possono catturare la dinamica di un'operazione che dura pochi microsecondi.

### La soluzione adottata:
- Il codice C++ misura la **latenza media al microsecondo** ($t_{\text{op}}$) e i cicli CPU su migliaia di iterazioni.
- L'eseguibile entra quindi in un **carico continuo al 100% CPU** (*steady-state burn*): la corrente sul display si stabilizza su un valore costante $I_{\text{attivo}}$, consentendo all'operatore di annotarlo con calma e precisione.
- Si sottrae il consumo a riposo ($I_{\text{idle}}$) per ottenere la sola **potenza dinamica crittografica**:
  $$\Delta I = I_{\text{attivo}} - I_{\text{idle}}$$
  $$P_{\text{dyn}} = V \cdot \Delta I$$
  $$E_{\text{dyn}} = P_{\text{dyn}} \cdot t_{\text{op}} \quad [\mu\text{J}]$$
  $$E_{\text{byte}} = \frac{E_{\text{dyn}}}{\text{Payload (Bytes)}} \quad [\text{nJ/Byte}]$$

---

## 2. Algoritmi e Payload Inclusi

### Crittografia Simmetrica / AEAD
- **Ascon-AEAD128** (implementazione ufficiale C `opt64`)
- **AES-128-GCM** (OpenSSL EVP)
- **AES-256-GCM** (OpenSSL EVP)
- **ChaCha20-Poly1305** (Libsodium IETF)
- **ChaCha20-Poly1305** (OpenSSL EVP)

**Payload testati:** esattamente **64, 255 e 1024 Bytes** (in accordo con i frame di telemetria sonobuoy NATO ANEP-96).

### Key Management Roadmap
- **PSK + KDF** (Libsodium BLAKE2b su contatore di pacchetto)
- **Symmetric Handshake** (2-Way Challenge-Response con HMAC-SHA256 e HKDF)
- **ECDH X25519** (Key exchange ellittico Libsodium `crypto_kx`)
- **ML-KEM-512 / 768 / 1024** (Key Encapsulation Mechanism Post-Quantum via `liboqs`, se presente nel sistema)

---

## 3. Guida Rapida all'Esecuzione

### Passo 1: Compilazione (se non già compilato)
```bash
cd metriche_librerie/misura_energia_manuale
cmake -B build -S .
cmake --build build -j$(nproc)
```

### Passo 2: Avvio della procedura guidata
Assicurati di avere il Raspberry Pi con la frequenza CPU bloccata (`sudo cpupower frequency-set -g performance`):

```bash
python3 run_guida_misure.py
```

Lo script ti guiderà interattivamente:
1. Chiederà la **tensione** $V$ (default: 5.0 V).
2. Chiederà la **corrente di IDLE** $I_{\text{idle}}$ a scheda a riposo (es. 0.48 A).
3. Per ciascun algoritmo e payload:
   - Calcolerà la latenza software esatta;
   - Avvierà il carico costante al 100% CPU;
   - Ti inviterà a leggere la corrente $I_{\text{attivo}}$ sul display e scriverla nel terminale;
   - Fermerà il carico all'istante e calcolerà in tempo reale i microJoule per operazione;
   - Inserirà un cooldown automatico di 6 secondi per evitare il surriscaldamento (thermal throttling).

### Passo 3: Output Generati
Al termine della sessione vengono generati automaticamente:
- `risultati_energia.csv`: tabella completa con tutti i valori numerici.
- `risultati_energia.md`: report riassuntivo in formato Markdown.

### Passo 4: Generazione Tabelle per la Tesi (LaTeX)
Per stampare direttamente il codice LaTeX con le tabelle da incollare nella relazione o su Overleaf:
```bash
python3 genera_tabelle_tesi.py
```

