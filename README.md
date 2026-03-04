# RAG for Vulnerability Detection with Code2Vec Embeddings

Sistema RAG (Retrieval-Augmented Generation) per il rilevamento delle vulnerabilità nel codice C/C++ che utilizza embeddings generati con [Code2Vec](https://github.com/seekbytes/code2vec_llm) per il recupero di esempi simili da aggiungere come contesto nella generazione della risposta dell'LLM che identifica e classifica vulnerabilità CWE (Common Weakness Enumeration).

Dataset utilizzati: Sven e PrimeVul.

## Requisiti

- Python 3.12+
- PostgreSQL con estensione pgvector
- Supabase account (locale o cloud)
- API Key Gemini (Google AI Studio)

## Setup

### 1. Clone del repository

```bash
git clone <repository-url>
cd NewRag
```

### 2. Creazione ambiente virtuale

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Installazione dipendenze

```bash
pip install -r requirements.txt
```

### 4. Configurazione variabili d'ambiente

Crea un file `.env` nella directory principale con:

```env
# Supabase Configuration
SUPABASE_URL=http://localhost:54321
SUPABASE_KEY=your-supabase-anon-key

# Gemini API
GEMINI_API_KEY=your-gemini-api-key
```


### 5. Setup Database

**Creazione tabelle:**

```bash
python setup_database.py
```

Questo script esegue automaticamente le migrations SQL da `supabase/migrations/`.

**Popolamento dati:**

```bash
# Carica dataset Sven
python load_sven.py

# Carica dataset PrimeVul
python load_primevul.py
```

Popola il database con i frammenti di codice dei due dataset + embeddings contenuti in `dataset_embeddings_c2v/`.


## Utilizzo

### Analisi Completa su Dataset

**Sven:**
```bash
python full_sven_c2v.py
```

**PrimeVul:**
```bash
python full_primevul_c2v.py
```

### Esportazione Risultati in Excel
I risultati vengono salvati nel database. 
Prima di effettuare una nuova analisi e sovrascrivere i dati, salvare in excel con:

**Sven:**
```bash
python save_sven_results.py
```
**PrimeVul:**
```bash
python save_primevul_results.py
```

Genera due file:
- `results.xlsx` - 3 colonne (File Name, Found CWE, Actual CWE)
- `results_exp.xlsx` - 4 colonne (+ Explanation - per mantenere traccia delle motiaazioni delle risposte)

Questi file vengono salvati nella cartella Models, nel percorso atteso dagli script per il calcolo dei risultati (metrics-scenario1/2/3.py e detect-hallucinations.py)


### Pulizia Database per nuova analisi con altro modello

```bash
# Cancella risultati Sven
python clear_sven_results.py

# Cancella risultati PrimeVul
python clear_primevul_results.py
```

Per cambiare il modello Gemini, modifica la variabile `GEMINI_MODEL_NAME`.

## Autore
Cremonini Davide

Università degli Studi di Verona