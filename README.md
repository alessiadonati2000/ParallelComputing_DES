# DES Password Cracker: CPU vs GPU Benchmark with CUDA

Analisi prestazionale e implementazione dell'algoritmo **DES (Data Encryption Standard)** per l'esecuzione di attacchi a dizionario. Il progetto confronta l'efficienza di un'esecuzione sequenziale su **CPU** rispetto a un'accelerazione massiva su **GPU** utilizzando la piattaforma **NVIDIA CUDA**.

## 📌 Descrizione del Progetto
L'obiettivo è identificare le password corrispondenti a determinati hash cifrati tramite l'algoritmo DES. Il sistema mappa il problema in modo parallelo, assegnando a ogni thread della GPU il compito di cifrare una parola del dizionario e confrontarla con l'obiettivo.



L'algoritmo opera su blocchi di 64 bit tramite una rete di Feistel a 16 round, coinvolgendo:
* Permutazioni iniziali e finali ($IP$ e $FP$).
* Espansioni di bit e sostituzioni tramite **S-Box**.
* Generazione di 16 sottochiavi da 48 bit.

## 🛠️ Strategie di Ottimizzazione
Per massimizzare il throughput sulla GPU, sono state implementate diverse tecniche avanzate:
* **Constant Memory**: Le tabelle di permutazione e le S-Box sono state caricate nella `__constant__` memory. Essendo dati in sola lettura e acceduti simultaneamente da tutti i thread di un warp, questa scelta riduce drasticamente la latenza di memoria rispetto alla memoria globale.
* **Loop Unrolling & Templates**: L'uso di template C++ per le funzioni di permutazione permette al compilatore di ottimizzare i calcoli bit-a-bit a tempo di compilazione.
* **Warp-Level Efficiency**: Il cracking è un problema *embarrassingly parallel*; la distribuzione del carico è stata ottimizzata testando diversi `blockSize` per saturare gli Streaming Multiprocessors (SM).

## 📊 Performance & Risultati
I test sono stati condotti su architettura **NVIDIA Turing (GTX 1650)** confrontata con un'esecuzione single-thread su CPU.

| Configurazione | Tempo Medio (ms) | Speedup | Efficienza |
| :--- | :---: | :---: | :---: |
| **Sequenziale (CPU)** | 42500.12 | **1.0x** | Baseline |
| **Parallelo (BS: 64)** | 14.58 | **2915.0x** | Ottima |
| **Parallelo (BS: 128)** | 14.33 | **2965.8x** | Massima |



### Analisi dello Speedup
Il raggiungimento di uno speedup di oltre **2900x** dimostra l'estrema efficacia delle GPU nell'elaborazione di algoritmi crittografici legacy. Mentre la CPU subisce una degradazione lineare al crescere del dizionario, la GPU gestisce il carico quasi in tempo costante fino alla saturazione delle risorse hardware, rendendo la forzatura del DES computazionalmente immediata.

## 🚀 Getting Started

### Requisiti
* **CUDA Toolkit** 12.x o superiore
* Compilatore C++17 compatibile (GCC o MSVC)
* **CMake** 3.28 o superiore
* GPU NVIDIA con Compute Capability 7.5+

### Build & Run
1. Clona il repo: `git clone https://github.com/tuo-username/DES-CUDA-Cracker.git`
2. Crea la cartella build: `mkdir build && cd build`
3. Genera i file con CMake: `cmake ..`
4. Compila il progetto: `cmake --build . --config Release`
5. Esegui il benchmark: `./DES`

## 📂 Struttura del Repository
* `main.cu`: Motore di benchmark e gestione dei test.
* `DES_parallel.cu`: Implementazione dei kernel CUDA e gestione `__constant__` memory.
* `DES.cpp`: Versione sequenziale di riferimento per la CPU.
* `utility.h`: Tabelle standard DES e generatori di password.
* `Results/`: Log dettagliati delle sessioni di benchmark.

---
**Autore:** Alessia Donati  
*Progetto per il corso di Parallel Computing - Università degli Studi di Firenze.*
