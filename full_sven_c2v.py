#!/usr/bin/env python3
"""
Script completo RAG con Code2Vec su TUTTI i file sven

Flusso:
1. Cicla tutti i file del test set
2. Per ognuno: retrieval top 10 simili da training set (con similarita coseno tra embeddings code2vec) + analisi LLM
3. Salva risultati in database
"""

import os
import json
import time
import random
import numpy as np
from datetime import datetime
from supabase import create_client
from dotenv import load_dotenv
from google import genai
from google.genai import types
from tqdm import tqdm

load_dotenv()


# Configurazione modello Gemini
GEMINI_MODEL_NAME = "gemini-2.0-flash"

# modelli:
# - "gemini-2.0-flash-lite" NO
# - "gemini-2.0-flash"
#
# - "gemini-2.5-flash-lite" NO
# - "gemini-2.5-flash"
# - "gemini-2.5-pro"



# Template del prompt diviso in due parti

# sezione "content"
PROMPT_TEMPLATE_PT1 = """If this C/C++ code snippet has vulnerabilities, output the list of corresponding CWE (Common Weakness Enumeration) identifiers; otherwise, output ``Not Vulnerable``

### TARGET CODE:
{target_code}
"""

# sezione "system_instruction"
PROMPT_TEMPLATE_PT2 = """Use the following similar examples as context to analyze the target code.

### REFERENCE EXAMPLES (CONTEXT):
{reference_examples}

### INSTRUCTION:

Follow these rules for the JSON output fields:

**IF NOT VULNERABLE (Safe)**
1. `is_vulnerable`: Set to `false`.
2. `assigned_cwes`: You MUST return an empty list `[]`.
3. `explanation`: Explain why the code is considered safe.

**IF VULNERABLE**
1. `is_vulnerable`: Set to `true`.
2. `assigned_cwes`: Return the list of detected CWE IDs.
3. `explanation`: Provide a technical reason for the verdict.


If you cannot identify the specific data required to fill the JSON fields:
- Set `explanation` strictly to the string "NaN".
- Set `is_vulnerable` to `false`.
- Set `assigned_cwes` to `[]`.
"""


# Funzioni 

def cosine_similarity(a, b):
    """Calcola similarita coseno tra due vettori
    
    Args:
        a: primo vettore
        b: secondo vettore

    Returns:
        Similarità coseno tra a e b (float tra -1 e 1)
    """
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    
    # if per vettori nulli
    if norm_a == 0 or norm_b == 0:
        return 0.0
    
    return np.dot(a, b) / (norm_a * norm_b)

#############
# RETRIEVAL #
#############
def retrieve_similar_documents(supabase, test_example, all_training_docs, top_n=10):
    """
    Cerca i top N documenti più simili usando cosine similarity su embeddings Code2Vec.
    
    Args:
        supabase: Client Supabase
        test_example: Documento di test con embedding
        all_training_docs: Lista completa dei documenti del training set (pre-caricati)
        top_n: Numero di documenti da recuperare
        
    Returns:
        Lista di documenti simili ordinati per similarità decrescente
    """
    # Ottengo embedding
    query_embedding = test_example['function_embedding']
    if isinstance(query_embedding, str):
        query_embedding = json.loads(query_embedding)
    
    if len(query_embedding) != 384:
        return []
    
    # Calcolo similarità per ogni documento
    similarities = []
    for doc in all_training_docs:
        try:
            # Ottengo embedding
            doc_embedding = doc['function_embedding']
            if isinstance(doc_embedding, str):
                doc_embedding = json.loads(doc_embedding)
            
            # Verifico che gli embeddings abbiano la stessa dimensione
            if len(doc_embedding) != len(query_embedding):
                continue
            
            # Calcolo similarità coseno e aggiungo a lista risultati
            sim = cosine_similarity(query_embedding, doc_embedding)
            similarities.append({
                'id': doc['id'],
                'file_name': doc['file_name'],
                'is_vulnerable': doc['is_vulnerable'],
                'cwe': doc['cwe'],
                'cwe_title': doc.get('cwe_title'),
                'cwe_description': doc.get('cwe_description'),
                'function_code': doc['function_code'],
                'similarity': float(sim)
            })
        except Exception:
            continue
    
    # Ordino per similarità decrescente e prendo top N
    similarities.sort(key=lambda x: x['similarity'], reverse=True)
    return similarities[:top_n]

def normalize_cwe(cwe: str) -> str:
    """
    Normalizza un identificatore CWE rimuovendo gli zeri iniziali.
    
    Es: "CWE-022" -> "CWE-22"
        "CWE-125" -> "CWE-125"

    Args:
        cwe: Stringa CWE da normalizzare
    Returns:
        Stringa CWE normalizzata
    """
    if not cwe or not isinstance(cwe, str):
        return cwe
    
    parts = cwe.split('-')
    if len(parts) == 2 and parts[0] == 'CWE':
        try:
            number = int(parts[1])
            return f"CWE-{number}"
        except ValueError:
            return cwe
    
    return cwe

def retry_with_exponential_backoff(func, max_retries=5, initial_delay=5, max_delay=120):
    """
    Esegue una funzione con retry usando backoff esponenziale troncato.
    
    Args:
        func: Funzione da eseguire
        max_retries: Numero massimo di tentativi
        initial_delay: Delay iniziale in secondi
        max_delay: Delay massimo in secondi (troncato)
    
    Returns:
        Risultato della funzione o None se tutti i tentativi falliscono
    """
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            error_str = str(e)
            
            # Controllo se è un errore 429 o 503
            is_rate_limit = '429' in error_str or 'RESOURCE_EXHAUSTED' in error_str
            is_unavailable = '503' in error_str or 'UNAVAILABLE' in error_str or 'Deadline' in error_str
            
            if not (is_rate_limit or is_unavailable):
                # Non è un errore retriable, propago eccezione
                raise
            
            if attempt == max_retries - 1:
                # Ultimo tentativo fallito
                print(f"      Errore dopo {max_retries} tentativi: {e}")
                return None
            
            # Calcolo delay con backoff esponenziale + jitter
            delay = min(initial_delay * (2 ** attempt), max_delay)
            jitter = random.uniform(0, delay * 0.1)  # 10% jitter
            total_delay = delay + jitter
            
            print(f"      Errore {error_str[:50]}... Retry {attempt + 1}/{max_retries} tra {total_delay:.1f}s")
            time.sleep(total_delay)
    
    return None

def format_reference_examples(relevant_documents: list) -> str:
    """Formatta i documenti come lista di oggetti con codice leggibile (newline e identazione preservate)
    
    es:
    [{
      function_code: SNIPPET_CODE,
      is_vulnerable: True,
      cwe: "CWE-79",
      cwe_title: "Cross-site Scripting",
      cwe_description: "The product does not neutralize or...",
    },
    {
      function_code: SNIPPET_CODE,
      is_vulnerable: False,
    }, {...}]

    Args:
        relevant_documents: Lista di documenti rilevanti da formattare
    Returns:
        Stringa formattata da inserire nel prompt
    """
    
    formatted_items = []
    
    for doc in relevant_documents:
        if doc["is_vulnerable"]:
            # vulnerabile
            item = f"""{{\n  "function_code": '''\n{doc['function_code']}\n''',\n  "is_vulnerable": True,\n  "cwe": "{doc['cwe']}",\n  "cwe_title": "{doc.get('cwe_title', 'N/A')}",\n  "cwe_description": "{doc.get('cwe_description', 'N/A')}"\n}}"""
        else:
            # safe
            item = f"""{{\n  "function_code": '''\n{doc['function_code']}\n''',\n  "is_vulnerable": False\n}}"""
        formatted_items.append(item)
    
    # Costruisco lista
    return "[\n" + ",\n".join(formatted_items) + "\n]"

def analyze_with_gemini(test_example, relevant_documents):
    """Analizza il codice usando Gemini LLM con retry automatico

    Args:
        test_example: Dizionario contenente il codice e l'embedding del test
        relevant_documents: Lista di documenti rilevanti da usare come contesto
    Returns:
        Dizionario con i risultati dell'analisi (is_vulnerable, explanation, assigned_cwes)
    """

    # Formatto esempi da inserire nel prompt
    reference_examples = format_reference_examples(relevant_documents)
    
    # Costruisco le due parti del prompt
    prompt_pt1 = PROMPT_TEMPLATE_PT1.format(
        target_code=test_example["function_code"]
    )
    prompt_pt2 = PROMPT_TEMPLATE_PT2.format(
        reference_examples=reference_examples
    )
    
    # # DEBUG per salvare promp buildato in file
    # debug_file = os.path.join(os.path.dirname(__file__), 'test_z.txt')
    # with open(debug_file, 'w', encoding='utf-8') as f:
    #     f.write(system_prompt)
    # time.sleep(15)
    
    def make_gemini_call():
        """Funzione interna per la chiamata Gemini (usata dal retry)"""
        
        client = genai.Client(
            api_key=os.environ["GEMINI_API_KEY"],
            http_options={'api_version': 'v1alpha'}  # endpoint globale
        )
        
        response = client.models.generate_content(
            model=GEMINI_MODEL_NAME,
            contents=prompt_pt1, # prima parte del prompt come contenuto
            config={
                'response_mime_type': 'application/json',
                'response_schema': {
                    'type': 'object',
                    'properties': {
                        'is_vulnerable': {
                            'type': 'boolean',
                            'description': 'True if code is vulnerable, False otherwise'
                        },
                        'explanation': {
                            'type': 'string',
                            'description': 'Detailed explanation of the analysis'
                        },
                        'assigned_cwes': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'pattern': '^CWE-[0-9]+$'
                            },
                            'description': 'List of CWE identifiers (e.g., ["CWE-125", "CWE-787"]), or empty array if safe'
                        }
                    },
                    'required': ['is_vulnerable', 'explanation', 'assigned_cwes']
                },
                "system_instruction": prompt_pt2,  # seconda parte del prompt come istruzione di sistema
                "temperature": 1, 
            }
        )
        
        return response.parsed
    
    # Invoco con retry automatico
    return retry_with_exponential_backoff(make_gemini_call, max_retries=5, initial_delay=5, max_delay=120)

def analyze_vulnerability(supabase, test_example, all_training_docs):
    """
    Analizza un singolo file del test set.

    Args:
        supabase: Client Supabase
        test_example: Dizionario con i dati del file di test da analizzare
        all_training_docs: Lista completa dei documenti del training set (pre-caricati)
    
    Returns:
        Tuple (status, result_dict) dove:
        - status: 'success', 'skipped', 'error'
        - result_dict: dati analisi se success, None altrimenti
    """

    # Controllo duplicati: salto se già analizzato
    try:
        response = supabase.rpc('find_result_c2v_by_code', {
            "code_to_find": test_example["function_code"]
        }).execute()
        
        if response.data:
            return 'skipped', None  # gia analizzato, skip
    except Exception:
        pass
    
    # Retrieval: prendo top 10 simili
    relevant_documents = retrieve_similar_documents(supabase, test_example, all_training_docs, top_n=10)
    
    if not relevant_documents:
        return 'error', None
    
    # Analisi LLM
    analysis_result = analyze_with_gemini(test_example, relevant_documents)
    
    if not analysis_result:
        return 'error', None
    
    # Controllo "NaN" nel risultato
    if analysis_result.get('explanation') == 'NaN':
        print(f"      Risposta LLM con explanation='NaN' - analisi non salvata")
        return 'error', None # non salvo nel db result
    
    
    # Salvo risultato nel database

    assigned_cwes = analysis_result.get('assigned_cwes', [])
    
    result_record = {
        "file_name": test_example["file_name"],
        "function_code": test_example["function_code"],
        "actual_cwe": test_example["cwe"],  # Ground truth
        "actually_vulnerable": test_example["is_vulnerable"],  # Ground truth
        "assigned_cwes": assigned_cwes,  # Lista CWE predette
        "found_vulnerable": analysis_result.get("is_vulnerable", False),  # Predizione
        "motivation": analysis_result.get("explanation", ""),
        "relevant_documents": [doc['id'] for doc in relevant_documents]  # ID dei 10 esempi
    }
    
    try:
        supabase.table("sven_results_c2v").insert(result_record).execute()
        return 'success', result_record
    except Exception as e:
        print(f"      Errore salvataggio DB: {e}")
        return 'error', None


# Funzione principale con chiamate a funzioni definite sopra

def main():
    """Funzione principale"""

    print("=" * 80)
    print("TEST SVEN + CODE2VEC")
    print("=" * 80)
    print()
    
    if "GEMINI_API_KEY" not in os.environ:
        print("GEMINI_API_KEY non trovata nelle variabili d'ambiente!")
        return
    
    # Connessione a Supabase
    print("Connessione a Supabase...")
    supabase = create_client(
        os.environ["SUPABASE_URL"],
        os.environ["SUPABASE_KEY"]
    )
    print("   Connesso")
    print()
    
    # Verifica database popolato
    try:
        training_count = supabase.table('sven_training').select('id', count='exact').limit(1).execute()
        test_count = supabase.table('sven_test').select('id', count='exact').limit(1).execute()
        
        print(f"Database:")
        print(f"   Training set: {training_count.count} records")
        print(f"   Test set: {test_count.count} records")
        print()
        
        if training_count.count == 0 or test_count.count == 0:
            print("Database non popolato! Esegui prima load_precomputed_c2v.py")
            return
            
    except Exception as e:
        print(f"Errore durante verifica database: {e}")
        return
    
    # Carico training set una volta sola
    print("Caricamento training set in memoria...")
    try:
        all_training_docs = supabase.table('sven_training').select('*').execute().data
        print(f"   Caricati {len(all_training_docs)} documenti")
    except Exception as e:
        print(f"Errore caricamento training: {e}")
        return
    print()
    
    # Carica test set
    print("Caricamento test set...")
    try:
        test_vulnerabilities = supabase.table("sven_test").select("*").execute().data
        print(f"   Trovati {len(test_vulnerabilities)} file da analizzare")
    except Exception as e:
        print(f"Errore caricamento test set: {e}")
        return
    print()
    

    # Analizzo ogni file del test set
    print("Inizio analisi...")
    print("-" * 80)
    print()
    
    success_count = 0
    error_count = 0
    skipped_count = 0
    
    for idx, test_example in enumerate(tqdm(test_vulnerabilities, desc="Analisi", unit="file"), 1):
        try:
            # Analisi file in oggetto
            status, result = analyze_vulnerability(supabase, test_example, all_training_docs)
            
            if status == 'success':
                success_count += 1
                
                # Print a video del risultato della risposta

                ground_truth = f"{test_example['cwe']}" if test_example['is_vulnerable'] else "SAFE"
                predicted = f"{', '.join(result['assigned_cwes'])}" if result['assigned_cwes'] else "SAFE"
                
                if test_example['is_vulnerable'] == result['found_vulnerable']:
                    if test_example['is_vulnerable']: # Entrambi vulnerabili: controlla CWE con normalizzazione
                        normalized_gt = normalize_cwe(test_example['cwe'])
                        normalized_pred = [normalize_cwe(c) for c in result['assigned_cwes']]
                        cwe_correct = normalized_gt in normalized_pred
                        verdict = "OK" if cwe_correct else "OK, CWE ERRATO"
                    else:
                        verdict = "OK"
                else:
                    verdict = "NO"
                
                print(f"   #{idx:3d} {test_example['file_name'][:40]:<40} | GT: {ground_truth:<15} | Pred: {predicted:<15} | {verdict}")
            elif status == 'skipped':
                skipped_count += 1 # skip gia analiszzati (output silenzioso senza print)
            else:  # status == 'error'
                error_count += 1
                print(f"   #{idx:3d} {test_example['file_name'][:40]:<40} | ERRORE ANALISI")
            
            # Sleep per rate limit
            if idx < len(test_vulnerabilities):
                if status == 'skipped':
                    time.sleep(0.2)  # 0.2 secondi per file gia analizzati
                else:
                    time.sleep(3)  # 3 secondi per chiamate API (success o error)
            
        except Exception as e:
            error_count += 1
            print(f"   #{idx:3d} {test_example.get('file_name', 'unknown')[:40]:<40} | ECCEZIONE: {e}")
            continue
    
    # Stats finali
    print()
    print("-" * 80)
    print(f"Analisi completata!")
    print(f"   Successi: {success_count}/{len(test_vulnerabilities)}")
    print(f"   Già analizzati (skip): {skipped_count}/{len(test_vulnerabilities)}")
    print(f"   Errori: {error_count}/{len(test_vulnerabilities)}")
    print(f"   Totale da analizzare: {success_count + error_count}/{len(test_vulnerabilities)}")
    print()
    print("Test completato!")
    print("=" * 80)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTest interrotto da tastiera")
    except Exception as e:
        print(f"Errore critico: {e}")
        import traceback
        traceback.print_exc()
