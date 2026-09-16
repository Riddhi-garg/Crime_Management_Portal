"""
import_cbi_data.py
Pipeline to import genuine, publicly available CBI FIR & Case records into SQLite data/crms.db.

Usage:
1. Place official CBI public case records (CSV format) into the `data/cbi/` directory.
2. Run: python3 import_cbi_data.py
"""

import os
import csv
import json
import sqlite3
import re
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "crms.db"
CBI_DIR = DATA_DIR / "cbi"

os.makedirs(CBI_DIR, exist_ok=True)


def ensure_cbi_table(conn: sqlite3.Connection):
    """Ensure cbi_firs table exists with all required public case fields."""
    conn.execute("""
    CREATE TABLE IF NOT EXISTS cbi_firs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rc_number TEXT UNIQUE NOT NULL,
        fir_number TEXT,
        fir_date DATE,
        title_or_subject TEXT,
        offence TEXT,
        agency TEXT DEFAULT 'Central Bureau of Investigation (CBI)',
        branch TEXT,
        location TEXT,
        status TEXT DEFAULT 'Under Investigation',
        pdf_url TEXT,
        source_page_url TEXT DEFAULT 'https://cbi.gov.in/view-fir',
        source TEXT DEFAULT 'Public CBI Portal (cbi.gov.in)',
        first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    # Migration check
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(cbi_firs)")
    existing_cols = [row[1] for row in cur.fetchall()]
    for col_name, col_def in [
        ('offence', 'TEXT'),
        ('agency', "TEXT DEFAULT 'Central Bureau of Investigation (CBI)'"),
        ('branch', 'TEXT'),
        ('location', 'TEXT'),
        ('status', "TEXT DEFAULT 'Under Investigation'"),
        ('source', "TEXT DEFAULT 'Public CBI Portal (cbi.gov.in)'")
    ]:
        if col_name not in existing_cols:
            cur.execute(f"ALTER TABLE cbi_firs ADD COLUMN {col_name} {col_def}")
    conn.commit()


def parse_date(date_str):
    if not date_str:
        return None
    date_str = str(date_str).strip()
    formats = ['%Y-%m-%d', '%d/%m/%Y', '%d-%m-%Y', '%d.%m.%Y', '%Y/%m/%d']
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt).date().isoformat()
        except ValueError:
            pass
    return date_str if re.match(r'^\d{4}-\d{2}-\d{2}$', date_str) else None


def import_cbi_csv(conn: sqlite3.Connection, file_path: Path):
    """Parses a CSV file containing genuine CBI public case data."""
    imported = 0
    updated = 0
    skipped = 0

    with file_path.open('r', encoding='utf-8-sig', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Map common variations of column names
            rc_number = (row.get('rc_number') or row.get('RC_Number') or row.get('rc_no') or 
                         row.get('RC_No') or row.get('case_number') or row.get('Case_No') or '').strip()
            
            if not rc_number:
                skipped += 1
                continue

            fir_number = (row.get('fir_number') or row.get('FIR_Number') or row.get('fir_no') or '').strip() or None
            fir_date = parse_date(row.get('fir_date') or row.get('FIR_Date') or row.get('date') or row.get('Date'))
            title_or_subject = (row.get('title_or_subject') or row.get('subject') or row.get('title') or 
                                row.get('Subject') or row.get('Title') or '').strip() or None
            offence = (row.get('offence') or row.get('crime') or row.get('sections') or row.get('Offence') or '').strip() or None
            agency = (row.get('agency') or row.get('Agency') or 'Central Bureau of Investigation (CBI)').strip()
            branch = (row.get('branch') or row.get('Branch') or row.get('police_station') or row.get('unit') or '').strip() or None
            location = (row.get('location') or row.get('Location') or row.get('city') or row.get('state') or '').strip() or None
            status = (row.get('status') or row.get('Status') or 'Under Investigation').strip()
            pdf_url = (row.get('pdf_url') or row.get('PDF_URL') or row.get('fir_pdf') or '').strip() or None
            source_page_url = (row.get('source_page_url') or row.get('source_url') or 'https://cbi.gov.in/view-fir').strip()
            source = (row.get('source') or 'Public CBI Portal (cbi.gov.in)').strip()

            cur = conn.cursor()
            cur.execute("SELECT id FROM cbi_firs WHERE rc_number = ?", (rc_number,))
            existing = cur.fetchone()

            if existing:
                conn.execute("""
                    UPDATE cbi_firs SET
                        fir_number = COALESCE(?, fir_number),
                        fir_date = COALESCE(?, fir_date),
                        title_or_subject = COALESCE(?, title_or_subject),
                        offence = COALESCE(?, offence),
                        agency = COALESCE(?, agency),
                        branch = COALESCE(?, branch),
                        location = COALESCE(?, location),
                        status = COALESCE(?, status),
                        pdf_url = COALESCE(?, pdf_url),
                        source_page_url = COALESCE(?, source_page_url),
                        source = COALESCE(?, source),
                        last_seen_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (fir_number, fir_date, title_or_subject, offence, agency, branch, location, status, pdf_url, source_page_url, source, existing[0]))
                updated += 1
            else:
                conn.execute("""
                    INSERT INTO cbi_firs (
                        rc_number, fir_number, fir_date, title_or_subject, offence,
                        agency, branch, location, status, pdf_url, source_page_url, source
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (rc_number, fir_number, fir_date, title_or_subject, offence,
                      agency, branch, location, status, pdf_url, source_page_url, source))
                imported += 1

    conn.commit()
    return imported, updated, skipped


def sync_all_cbi_files(conn: sqlite3.Connection):
    """Scans data/cbi/ and imports all files into cbi_firs."""
    ensure_cbi_table(conn)
    if not CBI_DIR.is_dir():
        return 0, 0, 0
    csv_files = [f for f in sorted(CBI_DIR.iterdir()) if f.is_file() and f.suffix.lower() == '.csv']
    total_imported = 0
    total_updated = 0
    total_skipped = 0
    for file_path in csv_files:
        imp, upd, skp = import_cbi_csv(conn, file_path)
        total_imported += imp
        total_updated += upd
        total_skipped += skp
    return len(csv_files), total_imported, total_updated


def main():
    print("=" * 70)
    print("CBI PUBLIC CASE & FIR INGESTION PIPELINE")
    print("=" * 70)
    print(f"Target Database:      {DB_PATH}")
    print(f"CBI Ingestion Folder: {CBI_DIR}")

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    ensure_cbi_table(conn)

    csv_files = [f for f in sorted(CBI_DIR.iterdir()) if f.is_file() and f.suffix.lower() == '.csv']

    if not csv_files:
        print("\n[STATUS] No CSV files found in data/cbi/ directory.")
        print("\nINSTRUCTIONS TO IMPORT GENUINE CBI PUBLIC DATA:")
        print("1. Obtain genuine public CBI FIR records or case lists from the official portal:")
        print("   - Portal: https://cbi.gov.in/view-fir or https://cbi.gov.in/press-releases")
        print("2. Save the records as a CSV file (e.g. data/cbi/cbi_firs.csv) with columns:")
        print("   - rc_number (Required: Regular Case identifier, e.g. RC0042024E0001)")
        print("   - fir_number (FIR number)")
        print("   - fir_date (Date: YYYY-MM-DD)")
        print("   - title_or_subject (Allegation / Subject of the case)")
        print("   - offence (Sections of IPC / Prevention of Corruption Act)")
        print("   - branch (e.g. CBI, ACB, New Delhi)")
        print("   - location (City / Jurisdiction)")
        print("   - status (e.g. Under Investigation / Chargesheet Filed)")
        print("   - pdf_url (Public link to official FIR PDF)")
        print("3. Run: python3 import_cbi_data.py")
        print("=" * 70)
        conn.close()
        return

    total_new = 0
    total_upd = 0
    for cf in csv_files:
        print(f"\n[PROCESSING] {cf.name} ...")
        imp, upd, skp = import_cbi_csv(conn, cf)
        total_new += imp
        total_upd += upd
        print(f"  → Newly Imported: {imp} | Updated: {upd} | Skipped: {skp}")

    total_in_db = conn.execute("SELECT COUNT(*) FROM cbi_firs").fetchone()[0]
    conn.close()

    print("\n" + "=" * 70)
    print("CBI INGESTION AUDIT REPORT")
    print("=" * 70)
    print(f"Files Processed:           {len(csv_files)}")
    print(f"Newly Imported Records:    {total_new}")
    print(f"Updated Records:           {total_upd}")
    print(f"Total Rows in cbi_firs:    {total_in_db}")
    print("=" * 70)


if __name__ == "__main__":
    main()
