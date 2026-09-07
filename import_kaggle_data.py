"""
Import and Cleaning Pipeline for Kaggle/NCRB Crime Datasets
Processes district-wise IPC crimes, crimes against women, crimes against children,
property stolen & recovered, arrest statistics, and police infrastructure into SQLite data/crms.db.
"""

import os
import csv
import sqlite3
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ARCHIVE_DIR = os.path.join(BASE_DIR, 'archive')
DATA_DIR = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(DATA_DIR, 'crms.db')

os.makedirs(DATA_DIR, exist_ok=True)


def clean_name(val):
    if not val:
        return ""
    val = val.strip().replace('\ufeff', '')
    # Standardize State & District formatting
    val = re.sub(r'\s+', ' ', val)
    return val


def is_total_row(name):
    if not name:
        return True
    upper = name.strip().upper()
    total_keywords = ['TOTAL', 'TOTAL (ALL INDIA)', 'TOTAL (STATES)', 'TOTAL (UTS)', 'ZZ TOTAL', 'TOTAL (UT)']
    for kw in total_keywords:
        if upper == kw or upper.startswith('TOTAL ') or upper.endswith(' TOTAL'):
            return True
    return False


def safe_int(val):
    if not val:
        return 0
    val_str = str(val).strip().replace(',', '')
    try:
        return int(float(val_str))
    except (ValueError, TypeError):
        return 0


def safe_float(val):
    if not val:
        return 0.0
    val_str = str(val).strip().replace(',', '')
    try:
        return float(val_str)
    except (ValueError, TypeError):
        return 0.0


def create_schema(conn):
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    # 1. Primary IPC Crime Statistics Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS crime_statistics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        state TEXT NOT NULL,
        district TEXT NOT NULL,
        year INTEGER NOT NULL,
        crime_type TEXT NOT NULL,
        case_count INTEGER NOT NULL DEFAULT 0,
        source TEXT NOT NULL DEFAULT 'Kaggle/NCRB IPC Crimes'
    );
    """)
    
    # 2. Crimes Against Women Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS women_crime_statistics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        state TEXT NOT NULL,
        district TEXT NOT NULL,
        year INTEGER NOT NULL,
        crime_type TEXT NOT NULL,
        case_count INTEGER NOT NULL DEFAULT 0,
        source TEXT NOT NULL DEFAULT 'Kaggle/NCRB Crimes Against Women'
    );
    """)

    # 3. Crimes Against Children Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS children_crime_statistics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        state TEXT NOT NULL,
        district TEXT NOT NULL,
        year INTEGER NOT NULL,
        crime_type TEXT NOT NULL,
        case_count INTEGER NOT NULL DEFAULT 0,
        source TEXT NOT NULL DEFAULT 'Kaggle/NCRB Crimes Against Children'
    );
    """)

    # 4. Property Crime Statistics Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS property_crime_statistics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        state TEXT NOT NULL,
        year INTEGER,
        property_type TEXT NOT NULL,
        stolen_cases INTEGER DEFAULT 0,
        stolen_value REAL DEFAULT 0,
        recovered_cases INTEGER DEFAULT 0,
        recovered_value REAL DEFAULT 0,
        source TEXT NOT NULL DEFAULT 'Kaggle/NCRB Property Stolen & Recovered'
    );
    """)

    # 5. Arrest Statistics Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS arrest_statistics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        state TEXT NOT NULL,
        year INTEGER NOT NULL,
        crime_head TEXT NOT NULL,
        persons_arrested INTEGER DEFAULT 0,
        persons_convicted INTEGER DEFAULT 0,
        persons_acquitted INTEGER DEFAULT 0,
        source TEXT NOT NULL DEFAULT 'Kaggle/NCRB Arrest & Disposal'
    );
    """)

    # 6. Dataful Police Stations and Outposts Dataset
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS police_infrastructure_statistics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        data_as_on TEXT NOT NULL,
        state TEXT NOT NULL,
        station_or_outpost TEXT NOT NULL,
        station_or_outpost_type TEXT NOT NULL,
        category TEXT NOT NULL,
        value INTEGER DEFAULT 0,
        unit TEXT,
        note TEXT,
        source TEXT NOT NULL DEFAULT 'Dataful/BPRD Police Organizations'
    );
    """)

    # Create Indexes for fast querying & dynamic charts
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cs_state ON crime_statistics(state);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cs_district ON crime_statistics(district);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cs_year ON crime_statistics(year);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cs_crime_type ON crime_statistics(crime_type);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cs_composite ON crime_statistics(state, district, year);")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_wcs_state ON women_crime_statistics(state);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_wcs_year ON women_crime_statistics(year);")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ccs_state ON children_crime_statistics(state);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ccs_year ON children_crime_statistics(year);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pis_state ON police_infrastructure_statistics(state);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pis_date ON police_infrastructure_statistics(data_as_on);")

    conn.commit()


def process_district_crimes(conn, files, table_name, default_source):
    cursor = conn.cursor()
    
    total_raw_rows = 0
    valid_rows = 0
    duplicate_rows = 0
    invalid_rows = 0
    inserted_records = 0
    
    seen_composite_keys = set()
    states_found = set()
    districts_found = set()
    years_found = set()
    crime_categories = set()
    
    records_to_insert = []
    
    for filename in files:
        filepath = os.path.join(ARCHIVE_DIR, filename)
        if not os.path.exists(filepath):
            print(f"File not found: {filename}")
            continue
            
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            try:
                header = [clean_name(c).upper() for c in next(reader)]
            except StopIteration:
                continue
                
            state_idx = 0
            dist_idx = 1
            year_idx = 2
            
            for row in reader:
                total_raw_rows += 1
                if not row or len(row) < 3:
                    invalid_rows += 1
                    continue
                    
                state = clean_name(row[state_idx]).upper()
                district = clean_name(row[dist_idx]).upper()
                
                try:
                    year = int(clean_name(row[year_idx]))
                except (ValueError, TypeError):
                    invalid_rows += 1
                    continue
                    
                if not state or not district or is_total_row(state) or is_total_row(district):
                    invalid_rows += 1
                    continue
                    
                valid_rows += 1
                states_found.add(state)
                districts_found.add(district)
                years_found.add(year)
                
                # Check column data
                for c_idx in range(3, len(row)):
                    if c_idx >= len(header):
                        break
                    col_name = header[c_idx]
                    
                    # Skip total columns to prevent double counting
                    if 'TOTAL' in col_name:
                        continue
                        
                    case_count = safe_int(row[c_idx])
                    
                    composite_key = (state, district, year, col_name)
                    if composite_key in seen_composite_keys:
                        duplicate_rows += 1
                        continue
                    seen_composite_keys.add(composite_key)
                    
                    crime_categories.add(col_name)
                    records_to_insert.append((state, district, year, col_name, case_count, default_source))
                    inserted_records += 1
                    
                    if len(records_to_insert) >= 5000:
                        cursor.executemany(f"""
                        INSERT INTO {table_name} (state, district, year, crime_type, case_count, source)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """, records_to_insert)
                        records_to_insert = []

    if records_to_insert:
        cursor.executemany(f"""
        INSERT INTO {table_name} (state, district, year, crime_type, case_count, source)
        VALUES (?, ?, ?, ?, ?, ?)
        """, records_to_insert)
        
    conn.commit()
    
    return {
        'total_raw_rows': total_raw_rows,
        'valid_rows': valid_rows,
        'duplicate_rows': duplicate_rows,
        'invalid_rows': invalid_rows,
        'inserted_records': inserted_records,
        'states_count': len(states_found),
        'districts_count': len(districts_found),
        'years': sorted(list(years_found)),
        'crime_categories_count': len(crime_categories)
    }


def process_property_crimes(conn):
    cursor = conn.cursor()
    filepath = os.path.join(ARCHIVE_DIR, '10_Property_stolen_and_recovered.csv')
    if not os.path.exists(filepath):
        return 0
        
    inserted = 0
    records = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return 0
        for row in reader:
            if len(row) >= 4:
                state = clean_name(row[0]).upper()
                if not state or is_total_row(state):
                    continue
                try:
                    year = int(row[1].strip())
                except:
                    year = None
                prop_type = clean_name(row[2]) or clean_name(row[3]) or "General Property"
                stolen_c = safe_int(row[4]) if len(row) > 4 else 0
                stolen_v = safe_float(row[5]) if len(row) > 5 else 0.0
                rec_c = safe_int(row[6]) if len(row) > 6 else 0
                rec_v = safe_float(row[7]) if len(row) > 7 else 0.0
                
                records.append((state, year, prop_type, stolen_c, stolen_v, rec_c, rec_v, 'Kaggle/NCRB Property Stolen & Recovered'))
                inserted += 1
                
    if records:
        cursor.executemany("""
        INSERT INTO property_crime_statistics (state, year, property_type, stolen_cases, stolen_value, recovered_cases, recovered_value, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, records)
        conn.commit()
    return inserted


def process_arrest_statistics(conn):
    cursor = conn.cursor()
    files = [
        '04_02_Person_arrested_and_their_disposal_by_police_and_court_IPC_crime_2012.csv',
        '04_02_Person_arrested_and_their_disposal_by_police_and_court_IPC_crime_2013.csv',
        '04_02_Person_arrested_and_their_disposal_by_police_and_court_IPC_crime_2014.csv'
    ]
    inserted = 0
    records = []
    
    for fn in files:
        filepath = os.path.join(ARCHIVE_DIR, fn)
        if not os.path.exists(filepath):
            continue
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            try:
                header = next(reader)
            except StopIteration:
                continue
            
            # Determine year from filename if not in columns
            yr_match = re.search(r'20\d{2}', fn)
            default_yr = int(yr_match.group(0)) if yr_match else 2012
            
            for row in reader:
                if len(row) >= 3:
                    state = clean_name(row[0]).upper()
                    if not state or is_total_row(state):
                        continue
                    crime_head = clean_name(row[1])
                    arr = safe_int(row[3]) if len(row) > 3 else 0
                    conv = safe_int(row[8]) if len(row) > 8 else 0
                    acq = safe_int(row[9]) if len(row) > 9 else 0
                    
                    records.append((state, default_yr, crime_head, arr, conv, acq, 'Kaggle/NCRB Arrest Statistics'))
                    inserted += 1
                    
    if records:
        cursor.executemany("""
        INSERT INTO arrest_statistics (state, year, crime_head, persons_arrested, persons_convicted, persons_acquitted, source)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, records)
        conn.commit()
    return inserted


def process_police_infrastructure(conn):
    """Import Dataful dataset 20145 downloaded as a CSV export."""
    filepath = os.path.join(ARCHIVE_DIR, 'dataful_police_stations_and_outposts.csv')
    if not os.path.exists(filepath):
        print(f"File not found: {os.path.basename(filepath)} (download Dataful dataset 20145 first)")
        return 0

    cursor = conn.cursor()
    records = []
    with open(filepath, 'r', encoding='utf-8-sig', errors='ignore') as f:
        reader = csv.DictReader(f)
        required = {
            'data_as_on', 'state', 'station_or_outpost',
            'station_or_outpost_type', 'category', 'value', 'unit', 'note'
        }
        headers = {clean_name(name).lower() for name in (reader.fieldnames or [])}
        missing = required - headers
        if missing:
            raise ValueError(
                f"Dataful police infrastructure CSV is missing columns: {', '.join(sorted(missing))}"
            )

        for row in reader:
            normalized = {clean_name(key).lower(): clean_name(value) for key, value in row.items()}
            state = normalized.get('state', '')
            if not state or is_total_row(state):
                continue
            records.append((
                normalized.get('data_as_on', ''), state,
                normalized.get('station_or_outpost', ''),
                normalized.get('station_or_outpost_type', ''),
                normalized.get('category', ''), safe_int(normalized.get('value')),
                normalized.get('unit', ''),
                normalized.get('note', '').replace('<nil>', '') or None,
                'Dataful/BPRD Police Organizations (Dataset 20145)'
            ))

    if records:
        cursor.executemany("""
        INSERT INTO police_infrastructure_statistics
        (data_as_on, state, station_or_outpost, station_or_outpost_type, category, value, unit, note, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, records)
        conn.commit()
    return len(records)


def run_pipeline():
    print("=" * 60)
    print("KAGGLE/NCRB CRIME DATA IMPORT & CLEANING PIPELINE")
    print("=" * 60)
    
    conn = sqlite3.connect(DB_PATH)
    create_schema(conn)
    
    # Clear previous import data cleanly
    cursor = conn.cursor()
    cursor.execute("DELETE FROM crime_statistics;")
    cursor.execute("DELETE FROM women_crime_statistics;")
    cursor.execute("DELETE FROM children_crime_statistics;")
    cursor.execute("DELETE FROM property_crime_statistics;")
    cursor.execute("DELETE FROM arrest_statistics;")
    cursor.execute("DELETE FROM police_infrastructure_statistics;")
    conn.commit()
    
    # 1. Main IPC Crime Datasets
    ipc_files = [
        '01_District_wise_crimes_committed_IPC_2001_2012.csv',
        '01_District_wise_crimes_committed_IPC_2013.csv',
        '01_District_wise_crimes_committed_IPC_2014.csv'
    ]
    ipc_res = process_district_crimes(conn, ipc_files, 'crime_statistics', 'Kaggle/NCRB IPC Crimes')
    
    # 2. Crimes Against Women Datasets
    women_files = [
        '42_District_wise_crimes_committed_against_women_2001_2012.csv',
        '42_District_wise_crimes_committed_against_women_2013.csv',
        '42_District_wise_crimes_committed_against_women_2014.csv'
    ]
    women_res = process_district_crimes(conn, women_files, 'women_crime_statistics', 'Kaggle/NCRB Crimes Against Women')
    
    # 3. Crimes Against Children Datasets
    children_files = [
        '03_District_wise_crimes_committed_against_children_2001_2012.csv',
        '03_District_wise_crimes_committed_against_children_2013.csv'
    ]
    children_res = process_district_crimes(conn, children_files, 'children_crime_statistics', 'Kaggle/NCRB Crimes Against Children')

    # 4. Property Crimes
    prop_count = process_property_crimes(conn)

    # 5. Arrest Statistics
    arrest_count = process_arrest_statistics(conn)

    # 6. Dataful Police Stations and Outposts Dataset (2011-2024)
    police_infrastructure_count = process_police_infrastructure(conn)

    conn.close()

    print("\n" + "=" * 60)
    print("FINAL IMPORT & CLEANING SUMMARY REPORT")
    print("=" * 60)
    print(f"Main IPC Crimes:")
    print(f"  - Original Raw Rows: {ipc_res['total_raw_rows']}")
    print(f"  - Valid District/Year Rows: {ipc_res['valid_rows']}")
    print(f"  - Duplicate Composite Keys Removed: {ipc_res['duplicate_rows']}")
    print(f"  - Invalid Rows Filtered: {ipc_res['invalid_rows']}")
    print(f"  - Records Inserted: {ipc_res['inserted_records']}")
    print(f"  - States/UTs Covered: {ipc_res['states_count']}")
    print(f"  - Districts Covered: {ipc_res['districts_count']}")
    print(f"  - Years Range: {min(ipc_res['years'])} to {max(ipc_res['years'])}")
    print(f"  - Crime Categories: {ipc_res['crime_categories_count']}")
    print("-" * 60)
    print(f"Crimes Against Women Records Inserted: {women_res['inserted_records']}")
    print(f"Crimes Against Children Records Inserted: {children_res['inserted_records']}")
    print(f"Property Stolen/Recovered Records Inserted: {prop_count}")
    print(f"Arrest & Disposal Records Inserted: {arrest_count}")
    print(f"Police Stations & Outposts Records Inserted: {police_infrastructure_count}")
    print("=" * 60 + "\n")


if __name__ == '__main__':
    run_pipeline()
