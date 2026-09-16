# import_ncrb_data.py
"""Bulk import script for official NCRB CSV files.

Place official NCRB CSV files inside the project's ``ncrb`` directory (sibling to ``app.py``).
Running this script will scan the directory, detect all CSV files, dynamically read and preserve
all column structures, and import all rows into the ``ncrb_raw_data`` SQLite table.

Features:
- Completely dynamic: does not enforce or require fixed column names.
- Stores each row as a full JSON object in the ``raw_data`` column, preserving original headers.
- SHA-256 ``row_hash`` (source_file + JSON) guarantees zero duplicates on re-import.
- Accurate duplicate tracking via database cursor row count.
- Clear reporting of all files detected, successfully imported, skipped, and per-file statistics.
"""

import os
import csv
import json
import sqlite3
import hashlib
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "crms.db"
NCRB_DIR = BASE_DIR / "ncrb"

os.makedirs(DATA_DIR, exist_ok=True)

# Human-friendly table titles
TABLE_NAME_MAP = {
    'NCRB_ADSI_2023_Table_1A.3_2.csv':          'Table 1A.3.2 — Accidental Deaths by Mode of Transport (2023)',
    'NCRB_ADSI_2023_Table_1A.3_2 (1).csv':      'Table 1A.3.2 (Duplicate File) — Accidental Deaths by Mode of Transport (2023)',
    'NCRB_ADSI_2023_Table_1.11.csv':            'Table 1.11 — Accidental Fire Incidents, Injuries & Deaths by Cause (2022–2023)',
    'NCRB_ADSI_2023_Table_2.4.csv':              'Table 2.4 — Causes of Suicides by Gender (2022–2023)',
    'NCRB_ADSI_2023_Table_2.6.csv':              'Table 2.6 — Suicides by Profession of Victim (2023)',
    'NCRB_ADSI_2023_Table_2.12.csv':             'Table 2.12 — Means/Mode of Suicide by Gender (2023)',
    'AkolaPolice2025_0_1.csv':                   'Akola District Police Station Crime & Performance Metrics (2025)',
    'All_India_Index_Upto_Apr25.csv':            'All India Consumer & Socio-Economic Price Index (Upto April 2025)',
    'All_India_Index_Upto_Jan25.csv':            'All India Consumer & Socio-Economic Price Index (Upto January 2025)',
    'Rajya_Sabha_Session_234_AU2375_1.csv':     'Rajya Sabha Parliamentary Report (Session 234) — Foreign National Arrivals by Country (2011–2013)',
    'Rajya_Sabha_Session_237_AU1971_1.1.csv':   'Rajya Sabha Parliamentary Report (Session 237) — Crimes Against Children',
    'rs_session240_au2685_1.1.csv':             'Rajya Sabha Parliamentary Report (Session 240) — National Crime Head Statistics',
    'rs_session_239_AU1970_1.2.csv':            'Rajya Sabha Parliamentary Report (Session 239) — Crimes Committed Against Women by State/UT',
}

def derive_table_name(source_file: str) -> str:
    """Derive a descriptive, human-readable table name from the file name."""
    if source_file in TABLE_NAME_MAP:
        return TABLE_NAME_MAP[source_file]
    m = re.search(r"Table[_\-]?([0-9A-Za-z\.]+)", source_file, re.IGNORECASE)
    if m:
        return "Table " + m.group(1).replace('_', ' ').replace('.', ' ')
    clean = re.sub(r'\.csv$', '', source_file, flags=re.IGNORECASE)
    return clean.replace('_', ' ').replace('-', ' ').title()

# Database schema

def ensure_table(conn: sqlite3.Connection):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ncrb_raw_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT NOT NULL,
            table_name TEXT,
            row_hash TEXT UNIQUE,
            raw_data TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    conn.commit()

# Row hashing for exact deduplication
def compute_row_hash(source_file: str, row_dict: dict) -> str:
    json_blob = json.dumps(row_dict, sort_keys=True, separators=(",", ":"))
    hash_input = f"{source_file}\0{json_blob}".encode('utf-8')
    return hashlib.sha256(hash_input).hexdigest()

# Import a single CSV file dynamically
def import_file(conn: sqlite3.Connection, file_path: Path):
    imported = 0
    duplicates = 0
    errors = 0
    rows_found = 0

    source_file = file_path.name
    table_name = derive_table_name(source_file)

    try:
        with file_path.open('r', encoding='utf-8-sig', errors='ignore') as f:
            reader = csv.DictReader(f)
            headers = [h.strip() for h in (reader.fieldnames or []) if h]
            print(f"[INFO] {source_file}: Detected {len(headers)} columns")

            for row_num, raw_row in enumerate(reader, start=2):
                rows_found += 1
                # Clean up whitespace and drop None keys
                row = {str(k).strip(): (v.strip() if isinstance(v, str) else v)
                       for k, v in raw_row.items() if k is not None}

                row_hash = compute_row_hash(source_file, row)
                try:
                    cur = conn.execute(
                        "INSERT OR IGNORE INTO ncrb_raw_data (source_file, table_name, row_hash, raw_data) VALUES (?,?,?,?)",
                        (source_file, table_name, row_hash, json.dumps(row))
                    )
                    if cur.rowcount > 0:
                        imported += 1
                    else:
                        duplicates += 1
                except Exception as e:
                    errors += 1
                    print(f"[ERROR] {source_file}:{row_num} – {e}")

        conn.commit()
    except Exception as e:
        errors += 1
        print(f"[ERROR] Could not process {source_file}: {e}")
        return imported, duplicates, rows_found, errors, table_name, 0

    return imported, duplicates, rows_found, errors, table_name, len(headers)

def sync_ncrb_csvs(conn: sqlite3.Connection):
    """Scan ncrb/ directory and import any new CSV files into ncrb_raw_data."""
    if not NCRB_DIR.is_dir():
        return 0, 0
    ensure_table(conn)
    csv_files = [f for f in sorted(NCRB_DIR.iterdir()) if f.is_file() and f.suffix.lower() == '.csv']
    total_new = 0
    for csv_path in csv_files:
        imported, _, _, _, _, _ = import_file(conn, csv_path)
        total_new += imported
    # Ensure all table_name values match TABLE_NAME_MAP
    for sf, tname in TABLE_NAME_MAP.items():
        conn.execute("UPDATE ncrb_raw_data SET table_name = ? WHERE source_file = ? AND (table_name IS NULL OR table_name != ?)", (tname, sf, tname))
    conn.commit()
    return len(csv_files), total_new


# Main execution
def main():
    if not NCRB_DIR.is_dir():
        print(f"[ERROR] No 'ncrb' directory found at {NCRB_DIR}. Aborting.")
        return

    all_entries = sorted(NCRB_DIR.iterdir())
    csv_files = [f for f in all_entries if f.is_file() and f.suffix.lower() == '.csv']
    non_csv_files = [f for f in all_entries if f.is_file() and f.suffix.lower() != '.csv']

    print("=" * 70)
    print("NCRB DATASET SCAN & IMPORT AUDIT")
    print("=" * 70)
    print(f"Total entries found in ncrb/: {len(all_entries)}")
    print(f"Total CSV files detected:     {len(csv_files)}")
    print(f"Non-CSV files skipped:        {len(non_csv_files)}")
    for ncf in non_csv_files:
        reason = "Hidden OS metadata file" if ncf.name.startswith(".") else f"Binary spreadsheet ({ncf.suffix}) - not a CSV text file"
        print(f"  - [SKIPPED] {ncf.name}: {reason}")
    print("=" * 70)

    if not csv_files:
        print("[INFO] No CSV files in the 'ncrb' directory to process.")
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    ensure_table(conn)

    results = []
    total_imported = 0
    total_duplicates = 0
    total_rows = 0
    total_errors = 0

    for csv_path in csv_files:
        print(f"\n[IMPORTING] {csv_path.name} ...")
        imported, duplicates, rows_found, errors, table_name, col_count = import_file(conn, csv_path)
        total_imported += imported
        total_duplicates += duplicates
        total_rows += rows_found
        total_errors += errors
        results.append({
            'file': csv_path.name,
            'table': table_name,
            'columns': col_count,
            'rows_found': rows_found,
            'imported': imported,
            'duplicates': duplicates,
            'errors': errors
        })
        print(f"    → Table: '{table_name}'")
        print(f"    → Rows in CSV: {rows_found} | New: {imported} | Duplicates: {duplicates} | Errors: {errors}")

    # Synchronize table names for any previously imported records
    for sf, tname in TABLE_NAME_MAP.items():
        conn.execute("UPDATE ncrb_raw_data SET table_name = ? WHERE source_file = ?", (tname, sf))
    conn.commit()

    total_in_db = conn.execute("SELECT COUNT(*) FROM ncrb_raw_data").fetchone()[0]
    distinct_files_in_db = conn.execute("SELECT COUNT(DISTINCT source_file) FROM ncrb_raw_data").fetchone()[0]
    conn.close()

    print("\n" + "=" * 70)
    print("FINAL IMPORT AUDIT REPORT")
    print("=" * 70)
    print(f"{'Source File':<40} {'Rows':<8} {'Imported':<10} {'Duplicates':<10}")
    print("-" * 70)
    for r in results:
        print(f"{r['file'][:39]:<40} {r['rows_found']:<8} {r['imported']:<10} {r['duplicates']:<10}")
    print("-" * 70)
    print(f"Total CSV Files Processed:     {len(csv_files)}")
    print(f"Total Data Rows in Files:      {total_rows}")
    print(f"Newly Imported Rows:           {total_imported}")
    print(f"Duplicates Skipped (Ignored):  {total_duplicates}")
    print(f"Total Import Errors:           {total_errors}")
    print(f"Total Rows in ncrb_raw_data:   {total_in_db}")
    print(f"Distinct Tables in Database:   {distinct_files_in_db}")
    print("=" * 70)

if __name__ == "__main__":
    main()
