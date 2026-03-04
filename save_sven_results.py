#!/usr/bin/env python3
"""
Script per esportare i risultati del test SVEN in formato Excel.
Genera un file results.xlsx con i risultati dalla tabella sven_results_c2v.
"""

import os
import re
from supabase import create_client
from dotenv import load_dotenv
from openpyxl import Workbook
from openpyxl.styles import Font
from openpyxl.utils.exceptions import IllegalCharacterError

load_dotenv()


def clean_text_for_excel(text: str) -> str:
    """
    Rimuove caratteri non validi per Excel.
    Excel non accetta caratteri di controllo come \\x00-\\x1F eccetto \\t, \\n, \\r.
    """
    if not isinstance(text, str):
        return text
    
    # Rimuove caratteri di controllo non validi (mantiene tab, newline, carriage return)
    cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', '', text)
    
    return cleaned

# Configurazione modello (deve corrispondere a quello usato nei test)
GEMINI_MODEL_NAME = "gemini-2.5-pro"
# modelli:
#
# - "gemini-2.0-flash"
#
# - "gemini-2.5-flash"
# - "gemini-2.5-pro"

def export_results_to_excel():
    """Esporta i risultati dal database a un file Excel"""
    
    print("=" * 80)
    print("📊 ESPORTAZIONE RISULTATI SVEN")
    print("=" * 80)
    print()
    
    # Connessione a Supabase
    print("📡 Connessione a Supabase...")
    supabase = create_client(
        os.environ["SUPABASE_URL"],
        os.environ["SUPABASE_KEY"]
    )
    print("   ✅ Connesso")
    print()
    
    # Recupera tutti i risultati
    print("📥 Recupero risultati da database...")
    try:
        response = supabase.table('sven_results_c2v').select('*').execute()
        results = response.data
        print(f"   ✅ Trovati {len(results)} risultati")
    except Exception as e:
        print(f"   ❌ Errore: {e}")
        return
    print()
    
    if not results:
        print("⚠️  Nessun risultato da esportare")
        return
    
    # Crea directory se non esiste
    output_dir = os.path.join(os.path.dirname(__file__), 'Models', GEMINI_MODEL_NAME, 'sven')
    os.makedirs(output_dir, exist_ok=True)
    
    # ========================================================================
    # FILE 1: results.xlsx (3 colonne - senza Explanation)
    # ========================================================================
    print("📝 Creazione file results.xlsx (3 colonne)...")
    wb1 = Workbook()
    ws1 = wb1.active
    ws1.title = "SVEN Results"
    
    # Header
    headers1 = ["File Name", "Found CWE", "Actual CWE"]
    ws1.append(headers1)
    
    # Formatta header (grassetto)
    for cell in ws1[1]:
        cell.font = Font(bold=True)
    
    # Aggiungi dati
    skipped_count = 0
    for result in results:
        try:
            file_name = clean_text_for_excel(result.get('file_name', ''))
            
            # Found CWE: formatta assigned_cwes
            found_vulnerable = result.get('found_vulnerable', False)
            assigned_cwes = result.get('assigned_cwes', [])
            
            if found_vulnerable and assigned_cwes:
                found_cwe = ';'.join(assigned_cwes)
            else:
                found_cwe = 'NOT VULNERABLE'
            
            # Actual CWE
            actually_vulnerable = result.get('actually_vulnerable', False)
            actual_cwe = result.get('actual_cwe', '')
            
            if actually_vulnerable and actual_cwe:
                actual_cwe_str = actual_cwe
            else:
                actual_cwe_str = 'NOT VULNERABLE'
            
            ws1.append([file_name, found_cwe, actual_cwe_str])
        except (IllegalCharacterError, Exception) as e:
            skipped_count += 1
            print(f"   ⚠️  Riga saltata (errore caratteri): {result.get('file_name', 'unknown')[:40]}")
            continue
    
    # Adatta larghezza colonne
    ws1.column_dimensions['A'].width = 30  # File Name
    ws1.column_dimensions['B'].width = 30  # Found CWE
    ws1.column_dimensions['C'].width = 20  # Actual CWE
    
    # Salva file 1
    output_file1 = os.path.join(output_dir, 'results.xlsx')
    wb1.save(output_file1)
    if skipped_count > 0:
        print(f"   ✅ File creato: {output_file1} ({skipped_count} righe saltate)")
    else:
        print(f"   ✅ File creato: {output_file1}")
    
    # ========================================================================
    # FILE 2: results_exp.xlsx (4 colonne - con Explanation)
    # ========================================================================
    print("📝 Creazione file results_exp.xlsx (4 colonne)...")
    wb2 = Workbook()
    ws2 = wb2.active
    ws2.title = "SVEN Results"
    
    # Header
    headers2 = ["File Name", "Found CWE", "Actual CWE", "Explanation"]
    ws2.append(headers2)
    
    # Formatta header (grassetto)
    for cell in ws2[1]:
        cell.font = Font(bold=True)
    
    # Aggiungi dati
    skipped_count_exp = 0
    for result in results:
        try:
            file_name = clean_text_for_excel(result.get('file_name', ''))
            
            # Found CWE: formatta assigned_cwes
            found_vulnerable = result.get('found_vulnerable', False)
            assigned_cwes = result.get('assigned_cwes', [])
            
            if found_vulnerable and assigned_cwes:
                found_cwe = ';'.join(assigned_cwes)
            else:
                found_cwe = 'NOT VULNERABLE'
            
            # Actual CWE
            actually_vulnerable = result.get('actually_vulnerable', False)
            actual_cwe = result.get('actual_cwe', '')
            
            if actually_vulnerable and actual_cwe:
                actual_cwe_str = actual_cwe
            else:
                actual_cwe_str = 'NOT VULNERABLE'
            
            # Explanation - pulizia caratteri problematici
            explanation = clean_text_for_excel(result.get('motivation', ''))
            
            ws2.append([file_name, found_cwe, actual_cwe_str, explanation])
        except (IllegalCharacterError, Exception) as e:
            skipped_count_exp += 1
            print(f"   ⚠️  Riga saltata (errore caratteri): {result.get('file_name', 'unknown')[:40]}")
            continue
    
    # Adatta larghezza colonne
    ws2.column_dimensions['A'].width = 30  # File Name
    ws2.column_dimensions['B'].width = 30  # Found CWE
    ws2.column_dimensions['C'].width = 20  # Actual CWE
    ws2.column_dimensions['D'].width = 80  # Explanation
    
    # Salva file 2
    output_file2 = os.path.join(output_dir, 'results_exp.xlsx')
    wb2.save(output_file2)
    if skipped_count_exp > 0:
        print(f"   ✅ File creato: {output_file2} ({skipped_count_exp} righe saltate)")
    else:
        print(f"   ✅ File creato: {output_file2}")
    
    print()
    print("✅ Esportazione completata!")
    print("=" * 80)


if __name__ == "__main__":
    try:
        export_results_to_excel()
    except KeyboardInterrupt:
        print("\n⚠️  Esportazione interrotta dall'utente")
    except Exception as e:
        print(f"❌ Errore critico: {e}")
        import traceback
        traceback.print_exc()
