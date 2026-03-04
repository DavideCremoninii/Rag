#!/usr/bin/env python3
"""
Script per creare le tabelle del database eseguendo le migrations di Supabase.
Esegue automaticamente tutti i file SQL nella cartella supabase/migrations/.
"""

import os
from pathlib import Path
from dotenv import load_dotenv
from supabase import create_client

# Carica variabili d'ambiente
load_dotenv()


def read_sql_file(file_path: str) -> str:
    """Legge il contenuto di un file SQL"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()


def run_migrations():
    """Esegue tutte le migrations nella cartella supabase/migrations/"""
    print("=" * 80)
    print("SETUP DATABASE - Esecuzione Migrations")
    print("=" * 80)
    print()
    
    # Verifica variabili d'ambiente
    if "SUPABASE_URL" not in os.environ or "SUPABASE_KEY" not in os.environ:
        print("ERRORE: SUPABASE_URL o SUPABASE_KEY non trovate nelle variabili d'ambiente")
        print("Crea un file .env con:")
        print("  SUPABASE_URL=http://localhost:54321")
        print("  SUPABASE_KEY=your-supabase-key")
        return False
    
    # Connessione a Supabase
    print("Connessione a Supabase...")
    try:
        supabase = create_client(
            os.environ["SUPABASE_URL"],
            os.environ["SUPABASE_KEY"]
        )
        print(f"Connesso a {os.environ['SUPABASE_URL']}")
    except Exception as e:
        print(f"ERRORE: Connessione fallita: {e}")
        return False
    print()
    
    # Trova migrations
    migrations_dir = Path(__file__).parent / "supabase" / "migrations"
    
    if not migrations_dir.exists():
        print(f"ERRORE: Cartella migrations non trovata: {migrations_dir}")
        return False
    
    # Elenca file SQL in ordine
    migration_files = sorted([f for f in migrations_dir.iterdir() if f.suffix == '.sql'])
    
    if not migration_files:
        print(f"ERRORE: Nessun file SQL trovato in {migrations_dir}")
        return False
    
    print(f"Trovati {len(migration_files)} file di migration:")
    for mf in migration_files:
        print(f"   - {mf.name}")
    print()
    
    # Esegui ogni migration
    success_count = 0
    error_count = 0
    
    for migration_file in migration_files:
        print(f"Esecuzione migration: {migration_file.name}")
        
        try:
            sql_content = read_sql_file(str(migration_file))
            
            import psycopg2
            from urllib.parse import urlparse
            
            # Parse DATABASE_URL (se esiste) o costruisci da SUPABASE_URL
            db_url = os.environ.get("DATABASE_URL")
            
            if not db_url:
                parsed_url = urlparse(os.environ["SUPABASE_URL"])
                host = parsed_url.hostname
                db_url = f"postgresql://postgres:postgres@{host}:54322/postgres"
            
            # Connetti e esegui SQL
            conn = psycopg2.connect(db_url)
            conn.autocommit = True
            cursor = conn.cursor()
            
            # Esegui SQL
            cursor.execute(sql_content)
            
            cursor.close()
            conn.close()
            
            success_count += 1
            print(f"Migration completata: {migration_file.name}")
            print()
            
        except Exception as e:
            error_count += 1
            print(f"ERRORE: {e}")
            print()
    
    # Riepilogo
    print("=" * 80)
    print("RIEPILOGO")
    print("=" * 80)
    print(f"Totale migrations: {len(migration_files)}")
    print(f"Successo: {success_count}")
    print(f"Errori: {error_count}")
    print()
    
    if error_count == 0:
        print("Database configurato correttamente")
        return True
    else:
        print("ATTENZIONE: Alcune migrations sono fallite")
        return False


def main():
    """Funzione principale"""
    try:
        # Verifica dipendenza psycopg2
        try:
            import psycopg2
        except ImportError:
            print("ERRORE: Modulo psycopg2 non trovato")
            print("Installalo con: pip install psycopg2-binary")
            return
        
        success = run_migrations()
        
        if not success:
            exit(1)
            
    except KeyboardInterrupt:
        print("\nScript interrotto dall'utente")
        exit(1)
    except Exception as e:
        print(f"ERRORE: {e}")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    main()
