#!/usr/bin/env python3
"""
Carica il dataset PrimeVul con embeddings Code2Vec precomputati nel database Supabase.
"""

import os
import json
import re
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
EMBEDDINGS_BASE = Path("dataset_embeddings_c2v/PrimeVul")
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


def parse_filename(filename: str):
    """Estrae informazioni dal nome del file PrimeVul"""
    if filename.endswith('.c2v'):
        filename = filename[:-4]
    
    vuln_pattern = r'^(\d+)_CWE-(\d+)\.(c|cpp)$'
    vuln_match = re.match(vuln_pattern, filename)
    
    if vuln_match:
        cwe_num = vuln_match.group(2)
        return {
            'is_vulnerable': True,
            'cwe': f'CWE-{int(cwe_num)}',
            'parsed_file_name': filename
        }
    
    safe_pattern = r'^(\d+)_not_vulnerable\.(c|cpp)$'
    safe_match = re.match(safe_pattern, filename)
    
    if safe_match:
        return {
            'is_vulnerable': False,
            'cwe': None,
            'parsed_file_name': filename
        }
    
    return None

def read_c2v_embedding(filepath):
    """Legge un file .c2v e restituisce l'embedding come lista di float"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
        
        embedding = json.loads(content)
        
        if isinstance(embedding, dict):
            embedding = embedding.get('embedding', None)
        
        if not embedding:
            return None
        
        import math
        embedding = [
            0.0 if (math.isnan(x) or math.isinf(x)) else x 
            for x in embedding
        ]
        
        if len(embedding) != 384:
            print(f"ATTENZIONE: {filepath.name} ha {len(embedding)} dimensioni invece di 384")
            return None
        
        return embedding
        
    except Exception as e:
        print(f"ERRORE: Lettura {filepath.name}: {str(e)}")
        return None

def read_source_code(c2v_filepath):
    """Legge il codice sorgente corrispondente al file .c2v"""
    source_path = Path(str(c2v_filepath)[:-4])
    
    if not source_path.exists():
        print(f"ATTENZIONE: File sorgente non trovato: {source_path.name}")
        return None
    
    try:
        with open(source_path, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        try:
            with open(source_path, 'r', encoding='latin-1') as f:
                return f.read()
        except Exception as e:
            print(f"ATTENZIONE: Errore lettura codice {source_path.name}: {str(e)}")
            return None


def process_c2v_file(c2v_filepath):
    """Processa un file .c2v e crea il record da inserire nel DB"""
    filename = c2v_filepath.name
    
    embedding = read_c2v_embedding(c2v_filepath)
    if embedding is None:
        return None
    
    code = read_source_code(c2v_filepath)
    if code is None:
        return None
    
    info = parse_filename(filename)
    if info is None:
        return None
    
    if info['cwe']:
        cwe_info = fetch_cwe_info(info['cwe'])
    else:
        cwe_info = {'cwe_title': None, 'cwe_description': None}
    
    return {
        'file_name': filename.replace('.c2v', ''),
        'function_code': code,
        'function_embedding': embedding,
        'cwe': info['cwe'],
        'cwe_title': cwe_info['cwe_title'],
        'cwe_description': cwe_info['cwe_description'],
        'is_vulnerable': info['is_vulnerable']
    }

def populate_table(table_name, directory, supabase_client, batch_size=50):
    """Popola una tabella Supabase con embeddings da file .c2v"""
    if not directory.exists():
        print(f"ERRORE: Directory non trovata: {directory}")
        return 0, 0
    
    c2v_files = sorted(directory.glob('*.c2v'))
    print(f"\nTrovati {len(c2v_files)} file .c2v in {directory.name}")
    
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
            
            if len(batch) >= batch_size:
                supabase_client.table(table_name).insert(batch).execute()
                total_inserted += len(batch)
                batch = []
                time.sleep(0.1)
                
        except Exception as e:
            print(f"\nATTENZIONE: Errore su file {c2v_filepath.name}: {str(e)}")
            errors += 1
            continue
    
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
    
    if not all([SUPABASE_URL, SUPABASE_KEY]):
        print("ERRORE: Variabili d'ambiente mancanti")
        print("Assicurati che .env contenga:")
        print("  - SUPABASE_URL")
        print("  - SUPABASE_KEY")
        return
    
    if not TRAINING_DIR.exists():
        print(f"ERRORE: Directory training non trovata: {TRAINING_DIR}")
        return
    
    if not TEST_DIR.exists():
        print(f"ERRORE: Directory test non trovata: {TEST_DIR}")
        return
    
    training_files = len(list(TRAINING_DIR.glob('*.c2v')))
    test_files = len(list(TEST_DIR.glob('*.c2v')))
    
    print(f"File da caricare:")
    print(f"  - Training: {training_files} file .c2v")
    print(f"  - Test: {test_files} file .c2v")
    print(f"  - TOTALE: {training_files + test_files} embeddings")
    print()
    
    print("Connessione a Supabase...")
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    
    print("Verifica tabelle database...")
    try:
        training_count = supabase.table('primevul_training').select('id', count='exact').limit(1).execute()
        test_count = supabase.table('primevul_test').select('id', count='exact').limit(1).execute()
        print(f"  Record esistenti in primevul_training: {training_count.count}")
        print(f"  Record esistenti in primevul_test: {test_count.count}")
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
    
    print("=" * 70)
    print("CARICAMENTO TRAINING SET")
    print("=" * 70)
    train_success, train_errors = populate_table('primevul_training', TRAINING_DIR, supabase, batch_size=50)
    
    print()
    print("=" * 70)
    print("CARICAMENTO TEST SET")
    print("=" * 70)
    test_success, test_errors = populate_table('primevul_test', TEST_DIR, supabase, batch_size=50)
    
    elapsed = time.time() - start_time
    
    print()
    print("=" * 70)
    print("COMPLETATO")
    print("=" * 70)
    
    training_count = supabase.table('primevul_training').select('id', count='exact').limit(1).execute()
    test_count = supabase.table('primevul_test').select('id', count='exact').limit(1).execute()
    
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
