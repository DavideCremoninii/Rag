#!/usr/bin/env python3
"""
Carica il dataset sven con embeddings Code2Vec precomputati nel database Supabase.
"""

import os
import re
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from supabase import create_client
from dotenv import load_dotenv
from tqdm import tqdm
import time

load_dotenv()

# Configurazione
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Path agli embeddings precomputati
EMBEDDINGS_BASE = Path("dataset_embeddings_c2v/sven")
TRAINING_DIR = EMBEDDINGS_BASE / "Training"
TEST_DIR = EMBEDDINGS_BASE / "testSet"

# Path al database CWE
CWE_DB_PATH = Path("cwec_latest.xml")

# Cache per CWE info (evita parsing ripetuto)
CWE_CACHE = {}
CWE_DATABASE = None

def load_cwe_database():
    """Carica database CWE da file XML locale"""
    global CWE_DATABASE
    
    if CWE_DATABASE is not None:
        return CWE_DATABASE
    
    if not CWE_DB_PATH.exists():
        print(f"ATTENZIONE: File CWE non trovato: {CWE_DB_PATH}")
        CWE_DATABASE = {}
        return CWE_DATABASE
    
    try:
        tree = ET.parse(CWE_DB_PATH)
        root = tree.getroot()
        ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}
        
        cwe_db = {}
        
        for weakness in root.findall('.//cwe:Weakness', ns):
            cwe_id = weakness.get('ID')
            if not cwe_id:
                continue
            
            cwe_full_id = f"CWE-{cwe_id}"
            name = weakness.get('Name', '')
            
            # Estrai description
            description = None
            desc_elem = weakness.find('.//cwe:Description', ns)
            if desc_elem is not None:
                desc_text = ''.join(desc_elem.itertext()).strip()
                if desc_text:
                    description = desc_text
            
            cwe_db[cwe_full_id] = {
                'title': name,
                'description': description
            }
        
        CWE_DATABASE = cwe_db
        return cwe_db
        
    except Exception as e:
        print(f"ERRORE: Caricamento database CWE: {e}")
        CWE_DATABASE = {}
        return CWE_DATABASE

def fetch_cwe_info(cwe_id):
    """Recupera title e description di una CWE dal database XML locale"""
    if not cwe_id:
        return {'cwe_title': None, 'cwe_description': None}
    
    if cwe_id in CWE_CACHE:
        return CWE_CACHE[cwe_id]
    
    cwe_db = load_cwe_database()
    
    # Normalizza CWE ID (rimuovi zeri iniziali: CWE-022 -> CWE-22)
    normalized_id = f"CWE-{int(cwe_id.split('-')[1])}"
    
    if normalized_id in cwe_db:
        result = {
            'cwe_title': cwe_db[normalized_id]['title'],
            'cwe_description': cwe_db[normalized_id]['description']
        }
    else:
        result = {'cwe_title': None, 'cwe_description': None}
    
    CWE_CACHE[cwe_id] = result
    return result

def extract_info_from_filename(filename):
    """
    Estrae informazioni dal nome del file.
    Formato: nome_funzione_cwe-XXX.c o nome_funzione_not_vulnerable.c
    
    Returns:
        dict: {
            'function_name': str,
            'is_vulnerable': bool,
            'cwe': str | None
        }
    """
    # Rimuovi estensione .c2v se presente
    if filename.endswith('.c2v'):
        filename = filename[:-4]
    
    # Rimuovi estensione .c/.cpp
    name = filename.rsplit('.', 1)[0] if '.' in filename else filename
    
    # Check se è vulnerabile
    if 'not_vulnerable' in name.lower():
        function_name = name.replace('_not_vulnerable', '').replace('not_vulnerable', '')
        return {
            'function_name': function_name,
            'is_vulnerable': False,
            'cwe': None
        }
    
    # Cerca CWE pattern
    cwe_match = re.search(r'cwe-(\d+)', name, re.IGNORECASE)
    if cwe_match:
        cwe_number = cwe_match.group(1)
        # Rimuovi la parte CWE dal nome della funzione
        function_name = re.sub(r'_cwe-\d+$', '', name, flags=re.IGNORECASE)
        return {
            'function_name': function_name,
            'is_vulnerable': True,
            'cwe': f'CWE-{cwe_number}'
        }
    
    # Default: considera non vulnerabile se non specificato
    return {
        'function_name': name,
        'is_vulnerable': False,
        'cwe': None
    }

def read_c2v_embedding(filepath):
    """
    Legge un file .c2v e restituisce l'embedding come lista di float.
    Gestisce valori NaN sostituendoli con 0.0
    
    Args:
        filepath: Path al file .c2v
        
    Returns:
        list: Lista di 384 float
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            
        # Parse l'array JSON (formato: [val1, val2, ...])
        embedding = json.loads(content)
        
        # Sostituisci NaN e Inf con 0.0
        import math
        embedding = [
            0.0 if (math.isnan(x) or math.isinf(x)) else x 
            for x in embedding
        ]
        
        # Verifica dimensione
        if len(embedding) != 384:
            print(f"ATTENZIONE: {filepath.name} ha {len(embedding)} dimensioni invece di 384")
            return None
        
        return embedding
        
    except Exception as e:
        print(f"ERRORE: Lettura {filepath.name}: {str(e)}")
        return None

def read_source_code(c2v_filepath):
    """
    Legge il codice sorgente corrispondente al file .c2v
    
    Args:
        c2v_filepath: Path al file .c2v
        
    Returns:
        str: Codice sorgente o None se non trovato
    """
    # Rimuovi .c2v per ottenere il nome del file sorgente
    source_path = Path(str(c2v_filepath)[:-4])
    
    if not source_path.exists():
        print(f"ATTENZIONE: File sorgente non trovato: {source_path.name}")
        return None
    
    try:
        with open(source_path, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        # Prova con latin-1 se utf-8 fallisce
        try:
            with open(source_path, 'r', encoding='latin-1') as f:
                return f.read()
        except Exception as e:
            print(f"ATTENZIONE: Errore lettura codice {source_path.name}: {str(e)}")
            return None

def process_c2v_file(c2v_filepath):
    """
    Processa un file .c2v e crea il record da inserire nel DB.
    
    Args:
        c2v_filepath: Path al file .c2v
        
    Returns:
        dict: Record da inserire nel database, o None se errore
    """
    filename = c2v_filepath.name
    
    # Leggi embedding
    embedding = read_c2v_embedding(c2v_filepath)
    if embedding is None:
        return None
    
    # Leggi codice sorgente
    code = read_source_code(c2v_filepath)
    if code is None:
        return None
    
    # Estrai info dal filename
    info = extract_info_from_filename(filename)
    
    # Recupera CWE info da XML locale
    if info['cwe']:
        cwe_info = fetch_cwe_info(info['cwe'])
    else:
        cwe_info = {'cwe_title': None, 'cwe_description': None}
    
    # Crea record
    # IMPORTANTE: pgvector richiede il formato stringa "[val1,val2,...]" per i vettori
    # Non passare lista Python diretta
    return {
        'file_name': filename.replace('.c2v', ''),  # Nome senza .c2v
        'function_code': code,
        'function_embedding': embedding,  # Passa come lista, Supabase lo converte
        'cwe': info['cwe'],
        'cwe_title': cwe_info['cwe_title'],
        'cwe_description': cwe_info['cwe_description'],
        'is_vulnerable': info['is_vulnerable']
    }

def populate_table(table_name, directory, supabase_client, batch_size=50):
    """
    Popola una tabella Supabase con embeddings da file .c2v
    
    Args:
        table_name: Nome della tabella ('sven_training' o 'sven_test')
        directory: Path alla directory con i file .c2v
        supabase_client: Client Supabase
        batch_size: Numero di record da inserire per batch
        
    Returns:
        tuple: (success_count, error_count)
    """
    if not directory.exists():
        print(f"ERRORE: Directory non trovata: {directory}")
        return 0, 0
    
    # Trova tutti i file .c2v
    c2v_files = sorted(directory.glob('*.c2v'))
    print(f"\nTrovati {len(c2v_files)} file .c2v in {directory.name}")
    
    # Processa file in batch
    batch = []
    total_inserted = 0
    errors = 0
    
    for c2v_filepath in tqdm(c2v_files, desc=f"Caricamento {table_name}"):
        try:
            record = process_c2v_file(c2v_filepath)
            
            if record is None:
                errors += 1
                continue
            
            batch.append(record)
            
            # Inserisci batch quando raggiunge la dimensione
            if len(batch) >= batch_size:
                supabase_client.table(table_name).insert(batch).execute()
                total_inserted += len(batch)
                batch = []
                time.sleep(0.1)  # Rate limiting leggero
                
        except Exception as e:
            print(f"\nATTENZIONE: Errore su file {c2v_filepath.name}: {str(e)}")
            errors += 1
            continue
    
    # Inserisci eventuali record rimanenti
    if batch:
        try:
            supabase_client.table(table_name).insert(batch).execute()
            total_inserted += len(batch)
        except Exception as e:
            print(f"\nATTENZIONE: Errore inserimento batch finale: {str(e)}")
            errors += len(batch)
    
    print(f"Inseriti {total_inserted} record in {table_name}")
    if errors > 0:
        print(f"ATTENZIONE: {errors} errori durante il processamento")
    
    return total_inserted, errors

def main():
    print("=" * 70)
    print("CARICAMENTO EMBEDDINGS CODE2VEC PRECOMPUTATI")
    print("=" * 70)
    print()
    
    # Verifica variabili d'ambiente
    if not all([SUPABASE_URL, SUPABASE_KEY]):
        print("ERRORE: Variabili d'ambiente mancanti")
        print("Assicurati che .env contenga:")
        print("  - SUPABASE_URL")
        print("  - SUPABASE_KEY")
        return
    
    # Verifica directory esistano
    if not TRAINING_DIR.exists():
        print(f"ERRORE: Directory training non trovata: {TRAINING_DIR}")
        return
    
    if not TEST_DIR.exists():
        print(f"ERRORE: Directory test non trovata: {TEST_DIR}")
        return
    
    # Conta file
    training_files = len(list(TRAINING_DIR.glob('*.c2v')))
    test_files = len(list(TEST_DIR.glob('*.c2v')))
    
    print(f"File da caricare:")
    print(f"  - Training: {training_files} file .c2v")
    print(f"  - Test: {test_files} file .c2v")
    print(f"  - TOTALE: {training_files + test_files} embeddings")
    print()
    
    # Inizializza client Supabase
    print("Connessione a Supabase...")
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    
    # Test connessione e conta record esistenti
    print("Verifica tabelle database...")
    try:
        training_count = supabase.table('sven_training').select('id', count='exact').limit(1).execute()
        test_count = supabase.table('sven_test').select('id', count='exact').limit(1).execute()
        print(f"  Record esistenti in sven_training: {training_count.count}")
        print(f"  Record esistenti in sven_test: {test_count.count}")
    except Exception as e:
        print(f"ERRORE: Connessione: {str(e)}")
        return
    
    print()
    response = input("Vuoi continuare con il caricamento? (yes/no): ")
    if response.lower() not in ['yes', 'y', 'si', 's']:
        print("Operazione annullata")
        return
    
    print()
    start_time = time.time()
    
    # Popola tabelle
    print("=" * 70)
    print("CARICAMENTO TRAINING SET")
    print("=" * 70)
    train_success, train_errors = populate_table('sven_training', TRAINING_DIR, supabase, batch_size=50)
    
    print()
    print("=" * 70)
    print("CARICAMENTO TEST SET")
    print("=" * 70)
    test_success, test_errors = populate_table('sven_test', TEST_DIR, supabase, batch_size=50)
    
    elapsed = time.time() - start_time
    
    print()
    print("=" * 70)
    print("COMPLETATO")
    print("=" * 70)
    
    # Verifica finale
    training_count = supabase.table('sven_training').select('id', count='exact').limit(1).execute()
    test_count = supabase.table('sven_test').select('id', count='exact').limit(1).execute()
    
    print()
    print(f"Risultati:")
    print(f"  Training:")
    print(f"    Successo: {train_success}")
    print(f"    Errori:   {train_errors}")
    print(f"    Totale DB: {training_count.count}")
    print()
    print(f"  Test:")
    print(f"    Successo: {test_success}")
    print(f"    Errori:   {test_errors}")
    print(f"    Totale DB: {test_count.count}")
    print()
    print(f"  TOTALE DATABASE: {training_count.count + test_count.count} record")
    print(f"  Tempo totale: {elapsed:.1f}s")
    print()

if __name__ == "__main__":
    main()
