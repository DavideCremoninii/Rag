#!/usr/bin/env python3
"""
Script per svuotare la tabella primevul_results_c2v nel database Supabase.
Utilizzare per pulire i risultati prima di ri-eseguire i test.
"""

import os
import sys
from supabase import create_client
from dotenv import load_dotenv

load_dotenv()

# Configurazione
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")


def clear_results_table(supabase_client):
    """
    Svuota la tabella primevul_results_c2v.
    
    Args:
        supabase_client: Client Supabase
        
    Returns:
        int: Numero di record eliminati
    """
    table_name = 'primevul_results_c2v'
    
    print(f"\n🗑️  Svuotamento tabella {table_name}...")
    
    try:
        # Conta i record prima dell'eliminazione
        count_response = supabase_client.table(table_name).select('id', count='exact').execute()
        record_count = count_response.count if hasattr(count_response, 'count') else 0
        
        if record_count == 0:
            print(f"   ✅ La tabella {table_name} è già vuota")
            return 0
        
        print(f"   📊 Trovati {record_count} record da eliminare")
        
        # Usa la RPC function se disponibile
        try:
            supabase_client.rpc('clear_primevul_results_c2v').execute()
            print(f"   ✅ Utilizzata RPC function clear_primevul_results_c2v()")
        except Exception as rpc_error:
            # Fallback: elimina manualmente
            print(f"   ⚠️  RPC function non disponibile, elimino manualmente...")
            supabase_client.table(table_name).delete().neq('id', '00000000-0000-0000-0000-000000000000').execute()
        
        # Verifica che la tabella sia vuota
        verify_response = supabase_client.table(table_name).select('id', count='exact').execute()
        verify_count = verify_response.count if hasattr(verify_response, 'count') else 0
        
        if verify_count == 0:
            print(f"   ✅ Tabella {table_name} svuotata con successo!")
            print(f"   📉 Record eliminati: {record_count}")
            return record_count
        else:
            print(f"   ⚠️  Attenzione: rimangono ancora {verify_count} record")
            return record_count - verify_count
            
    except Exception as e:
        print(f"   ❌ Errore durante lo svuotamento: {e}")
        return 0


def main():
    """Funzione principale"""
    print("=" * 70)
    print("🧹 CLEAR PRIMEVUL RESULTS")
    print("=" * 70)
    
    # Verifica variabili d'ambiente
    if not SUPABASE_URL or not SUPABASE_KEY:
        print("❌ Errore: SUPABASE_URL e SUPABASE_KEY devono essere definite nel file .env")
        sys.exit(1)
    
    # Connessione a Supabase
    print("\n📡 Connessione a Supabase...")
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        print("   ✅ Connesso")
    except Exception as e:
        print(f"   ❌ Errore connessione: {e}")
        sys.exit(1)
    
    # Chiedi conferma
    print("\n⚠️  ATTENZIONE: Questa operazione eliminerà TUTTI i risultati dei test PrimeVul!")
    print("   Tabella interessata: primevul_results_c2v")
    
    response = input("\n   Vuoi continuare? (s/N): ")
    
    if response.lower() not in ['s', 'si', 'sì', 'y', 'yes']:
        print("\n❌ Operazione annullata")
        sys.exit(0)
    
    # Svuota tabella risultati
    deleted = clear_results_table(supabase)
    
    # Riepilogo finale
    print("\n" + "=" * 70)
    print("📊 RIEPILOGO")
    print("=" * 70)
    print(f"Totale record eliminati: {deleted}")
    print("\n✅ Operazione completata!")
    print("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operazione interrotta dall'utente")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Errore critico: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
