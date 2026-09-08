"""
Crime Management Portal - Application Entry Point & Web Server
Integrated with Real Kaggle/NCRB Crime Statistics Dataset (2001-2014)
"""

import os
import json
import sqlite3
import datetime
from html import escape
from flask import Flask, render_template_string, request, jsonify, redirect, flash, url_for, send_from_directory
from werkzeug.utils import secure_filename
from crime_pattern_analysis import get_filter_options, get_districts_for_state, run_full_analysis

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(DATA_DIR, 'crms.db')
POLICE_STATIONS_GEOJSON = os.path.join(
    DATA_DIR, 'police', 'stations', 'INDIA_POLICE_STATIONS.geojson'
)

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'crms-kaggle-ncrb-key-2026'
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB limit


def get_db_connection():
    """Open and return a configured SQLite connection. Does nothing else."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create operational tables if they don't exist. Called once at startup."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'Officer',
        full_name TEXT NOT NULL,
        email TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS police_stations (
        station_id INTEGER PRIMARY KEY AUTOINCREMENT,
        station_name TEXT NOT NULL UNIQUE,
        address TEXT NOT NULL,
        city TEXT NOT NULL,
        state TEXT NOT NULL,
        contact_number TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS police_officers (
        officer_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        rank TEXT NOT NULL,
        badge_number TEXT NOT NULL UNIQUE,
        phone TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        station_id INTEGER NOT NULL,
        user_id INTEGER UNIQUE NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS crimes (
        crime_id INTEGER PRIMARY KEY AUTOINCREMENT,
        crime_type TEXT NOT NULL,
        description TEXT NOT NULL,
        crime_date DATE NOT NULL,
        crime_time TIME,
        location TEXT NOT NULL,
        city TEXT NOT NULL,
        state TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'Major',
        status TEXT DEFAULT 'Reported',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS victims (
        victim_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        age INTEGER,
        gender TEXT NOT NULL,
        address TEXT,
        phone TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS FIR (
        fir_id INTEGER PRIMARY KEY AUTOINCREMENT,
        fir_number TEXT NOT NULL UNIQUE,
        crime_id INTEGER NOT NULL,
        victim_id INTEGER NOT NULL,
        station_id INTEGER NOT NULL,
        filing_date DATE NOT NULL,
        description TEXT NOT NULL,
        status TEXT DEFAULT 'Pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS criminals (
        criminal_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        alias TEXT,
        date_of_birth DATE,
        gender TEXT NOT NULL,
        address TEXT,
        phone TEXT,
        identification_details TEXT,
        status TEXT DEFAULT 'Wanted',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cases (
        case_id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_number TEXT NOT NULL UNIQUE,
        fir_id INTEGER NOT NULL UNIQUE,
        investigating_officer_id INTEGER,
        case_status TEXT NOT NULL DEFAULT 'Active',
        priority TEXT NOT NULL DEFAULT 'Medium',
        start_date DATE NOT NULL,
        closing_date DATE NULL,
        remarks TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Additional tables for analytics
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS crime_statistics (
        year INTEGER NOT NULL,
        state TEXT NOT NULL,
        district TEXT NOT NULL,
        crime_type TEXT NOT NULL,
        case_count INTEGER NOT NULL,
        PRIMARY KEY (year, state, district, crime_type)
    );
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS property_crime_statistics (
        state TEXT NOT NULL PRIMARY KEY,
        stolen_cases INTEGER NOT NULL,
        recovered_cases INTEGER NOT NULL
    );
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS arrest_statistics (
        crime_head TEXT NOT NULL PRIMARY KEY,
        persons_arrested INTEGER NOT NULL,
        persons_convicted INTEGER NOT NULL,
        persons_acquitted INTEGER NOT NULL
    );
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS women_crime_statistics (
        crime_type TEXT NOT NULL PRIMARY KEY,
        case_count INTEGER NOT NULL
    );
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS children_crime_statistics (
        crime_type TEXT NOT NULL PRIMARY KEY,
        case_count INTEGER NOT NULL
    );
    """)
    # Load canonical crime statistics if empty or if only dummy TOTAL exists
    cur = conn.cursor()
    cur.execute("SELECT COUNT(DISTINCT crime_type) FROM crime_statistics")
    crime_types_count = cur.fetchone()[0] or 0
    if crime_types_count <= 1:
        import csv, glob, os
        data_dir = os.path.join(BASE_DIR, "archive")
        canonical_crimes = [
            'MURDER', 'ATTEMPT TO MURDER', 'CULPABLE HOMICIDE NOT AMOUNTING TO MURDER',
            'RAPE', 'KIDNAPPING & ABDUCTION', 'DACOITY', 'PREPARATION AND ASSEMBLY FOR DACOITY',
            'ROBBERY', 'BURGLARY', 'THEFT', 'RIOTS', 'CRIMINAL BREACH OF TRUST',
            'CHEATING', 'COUNTERFIETING', 'ARSON', 'HURT/GREVIOUS HURT', 'DOWRY DEATHS',
            'ASSAULT ON WOMEN WITH INTENT TO OUTRAGE HER MODESTY', 'INSULT TO MODESTY OF WOMEN',
            'CRUELTY BY HUSBAND OR HIS RELATIVES', 'IMPORTATION OF GIRLS FROM FOREIGN COUNTRIES',
            'CAUSING DEATH BY NEGLIGENCE', 'OTHER IPC CRIMES'
        ]
        ipc_files = [
            os.path.join(data_dir, "01_District_wise_crimes_committed_IPC_2001_2012.csv"),
            os.path.join(data_dir, "01_District_wise_crimes_committed_IPC_2013.csv")
        ]
        cur.execute("DELETE FROM crime_statistics")
        records = []
        for file_path in ipc_files:
            if not os.path.exists(file_path):
                continue
            with open(file_path, newline='', encoding='utf-8-sig', errors='ignore') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    state = (row.get("STATE/UT") or "").strip()
                    district = (row.get("DISTRICT") or "").strip()
                    if not state or not district or "TOTAL" in district.upper():
                        continue
                    try:
                        year = int(row.get("YEAR"))
                    except (TypeError, ValueError):
                        continue
                    for crime in canonical_crimes:
                        val = row.get(crime)
                        if val:
                            try:
                                cnt = int(val)
                                if cnt > 0:
                                    records.append((year, state, district, crime, cnt))
                            except (TypeError, ValueError):
                                pass
        if records:
            cur.executemany(
                "INSERT OR REPLACE INTO crime_statistics (year, state, district, crime_type, case_count) VALUES (?,?,?,?,?)",
                records
            )
            conn.commit()

    # Load property_crime_statistics if empty
    cur.execute("SELECT COUNT(*) FROM property_crime_statistics")
    if cur.fetchone()[0] == 0:
        import csv, os
        data_dir = os.path.join(BASE_DIR, "archive")
        prop_file = os.path.join(data_dir, "10_Property_stolen_and_recovered.csv")
        if os.path.exists(prop_file):
            agg = {}
            with open(prop_file, newline='', encoding='utf-8-sig', errors='ignore') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    state = (row.get("Area_Name") or "").strip()
                    if not state or "TOTAL" in state.upper():
                        continue
                    try:
                        stolen = int(row.get("Cases_Property_Stolen") or 0)
                        recovered = int(row.get("Cases_Property_Recovered") or 0)
                    except (TypeError, ValueError):
                        continue
                    if state not in agg:
                        agg[state] = {"stolen": 0, "recovered": 0}
                    agg[state]["stolen"] += stolen
                    agg[state]["recovered"] += recovered
            for state, val in agg.items():
                cur.execute(
                    "INSERT OR REPLACE INTO property_crime_statistics (state, stolen_cases, recovered_cases) VALUES (?,?,?)",
                    (state, val["stolen"], val["recovered"])
                )
            conn.commit()

    # Load arrest_statistics if empty
    cur.execute("SELECT COUNT(*) FROM arrest_statistics")
    if cur.fetchone()[0] == 0:
        import csv, glob, os
        pattern = os.path.join(data_dir, "*_Persons_arrested_and_their_disposal_*.csv")
        agg = {}
        for file_path in glob.glob(pattern):
            with open(file_path, newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Column names differ across files; try several variants
                    head = row.get("CRIME HEAD") or row.get("Crime Head") or row.get("Crime Head ")
                    arrested = int(row.get("Persons arrested during the year")
                                      or row.get("Persons arrested during the year_Total")
                                      or 0)
                    convicted = int(row.get("Persons convicted")
                                      or row.get("Persons convicted_Total")
                                      or 0)
                    acquitted = int(row.get("Persons acquitted")
                                      or row.get("Persons acquitted_Total")
                                      or 0)
                    if not head:
                        continue
                    if head not in agg:
                        agg[head] = {"arrested": 0, "convicted": 0, "acquitted": 0}
                    agg[head]["arrested"] += arrested
                    agg[head]["convicted"] += convicted
                    agg[head]["acquitted"] += acquitted
        for head, vals in agg.items():
            conn.execute(
                "INSERT INTO arrest_statistics (crime_head, persons_arrested, persons_convicted, persons_acquitted) VALUES (?,?,?,?)",
                (head, vals["arrested"], vals["convicted"], vals["acquitted"])
            )

    # Load women_crime_statistics if empty
    cur.execute("SELECT COUNT(*) FROM women_crime_statistics")
    if cur.fetchone()[0] == 0:
        import csv, glob, os
        pattern = os.path.join(data_dir, "42_District_wise_crimes_committed_against_women_*.csv")
        agg = {}
        for file_path in glob.glob(pattern):
            with open(file_path, newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    for col, val in row.items():
                        if col in ("STATE/UT", "DISTRICT", "Year"):
                            continue
                        crime_type = col.strip()
                        try:
                            count = int(val)
                        except Exception:
                            continue
                        agg[crime_type] = agg.get(crime_type, 0) + count
        for crime_type, total in agg.items():
            conn.execute(
                "INSERT INTO women_crime_statistics (crime_type, case_count) VALUES (?,?)",
                (crime_type, total)
            )

    # Load children_crime_statistics if empty
    cur.execute("SELECT COUNT(*) FROM children_crime_statistics")
    if cur.fetchone()[0] == 0:
        import csv, glob, os
        pattern = os.path.join(data_dir, "03_District_wise_crimes_committed_against_children_*.csv")
        agg = {}
        for file_path in glob.glob(pattern):
            with open(file_path, newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    for col, val in row.items():
                        if col in ("STATE/UT", "DISTRICT", "Year"):
                            continue
                        crime_type = col.strip()
                        try:
                            count = int(val)
                        except Exception:
                            continue
                        agg[crime_type] = agg.get(crime_type, 0) + count
        for crime_type, total in agg.items():
            conn.execute(
                "INSERT INTO children_crime_statistics (crime_type, case_count) VALUES (?,?)",
                (crime_type, total)
            )

    conn.commit()
    conn.close()


# Base Layout & Navigation Bar
HTML_NAVBAR = """
<nav class="navbar navbar-expand-lg sticky-top shadow-sm" style="background-color: #8b5cf6; border-bottom: 2px solid #ec4899;">
  <div class="container-fluid px-4">
    <a class="navbar-brand d-flex align-items-center gap-2 fw-bold" href="/" style="color: #ffffff; font-family: 'Times New Roman', Times, serif; font-size: 1.2rem;">
      <span class="fs-4">🛡️</span> CRIME MANAGEMENT PORTAL
    </a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" style="border-color: #ec4899;">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
        <li class="nav-item"><a class="nav-link" href="/" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Dashboard</a></li>

        <li class="nav-item"><a class="nav-link" href="/analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Analytics &amp; Charts</a></li>
        <li class="nav-item"><a class="nav-link" href="/women-children-analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Women &amp; Children</a></li>
        <li class="nav-item"><a class="nav-link" href="/property-arrest-analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Property &amp; Arrests</a></li>
        <li class="nav-item"><a class="nav-link" href="/police-stations" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Police Stations</a></li>
        <li class="nav-item"><a class="nav-link" href="/police-station-map" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Station Map</a></li>
        <li class="nav-item"><a class="nav-link" href="/fir-management" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">FIR Management</a></li>
        <li class="nav-item"><a class="nav-link" href="/criminal-records" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Criminal Records</a></li>
        <li class="nav-item"><a class="nav-link" href="/case-files" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Case Files</a></li>
        <li class="nav-item"><a class="nav-link" href="/crime-patterns" style="color: #fce7f3; font-weight: bold; font-family: 'Times New Roman', Times, serif;">🔗 Pattern Detector</a></li>
      </ul>
      <span class="badge p-2" style="background-color: #ec4899; color: #ffffff; font-family: 'Times New Roman', Times, serif;">NCRB / Kaggle Dataset</span>
    </div>
  </div>
</nav>
"""

HTML_LAYOUT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Crime Management Portal - Kaggle/NCRB Statistics</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { font-family: 'Times New Roman', Times, serif !important; }
        body { background-color: #ffffff; color: #1a1a1a; }
        h1, h2, h3, h4, h5, h6 { color: #5b21b6; }
        .card { background-color: #f8f9fa; border: 1px solid #dee2e6; color: #1a1a1a; border-radius: 10px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); }
        .table { color: #1a1a1a; }
        .table thead th { background-color: #ede9fe; color: #4c1d95; border-bottom: 2px solid #8b5cf6; }
        .table tbody tr:hover { background-color: #fdf2f8; }
        .table-dark { background-color: #f8f9fa !important; color: #1a1a1a !important; border-color: #dee2e6 !important; }
        .table-dark td, .table-dark th { background-color: transparent !important; color: #1a1a1a !important; }
        .nav-link:hover { color: #fce7f3 !important; }
        .stats-card { background: linear-gradient(135deg, #faf5ff 0%, #f3e8ff 100%); border-left: 4px solid #8b5cf6; }
        .source-badge { font-size: 0.8rem; background: #8b5cf6; color: #ffffff; border-radius: 20px; padding: 4px 12px; }
        .form-select, .form-control { background-color: #ffffff; color: #1a1a1a; border: 1px solid #adb5bd; }
        .form-select:focus, .form-control:focus { background-color: #ffffff; color: #1a1a1a; border-color: #8b5cf6; box-shadow: 0 0 0 2px rgba(139,92,246,0.2); }
        .btn-outline-warning { border-color: #ec4899; color: #ec4899; }
        .btn-outline-warning:hover { background-color: #ec4899; color: #ffffff; }
        .badge.bg-secondary { background-color: #6c757d !important; color: #ffffff !important; }
        .badge.bg-info { background-color: #8b5cf6 !important; color: #ffffff !important; }
        .badge.bg-success { background-color: #2d6a4f !important; color: #ffffff !important; }
        .badge.bg-danger { background-color: #ec4899 !important; color: #ffffff !important; }
        .badge.bg-warning { background-color: #f59e0b !important; color: #ffffff !important; }
        .badge.bg-primary { background-color: #8b5cf6 !important; color: #ffffff !important; }
        .text-warning { color: #ec4899 !important; }
        .text-info { color: #8b5cf6 !important; }
        .text-danger { color: #ec4899 !important; }
        .text-success { color: #2d6a4f !important; }
        .text-secondary { color: #555555 !important; }
        .text-muted { color: #777777 !important; }
        .text-light { color: #1a1a1a !important; }
        .btn-warning { background-color: #ec4899; border-color: #ec4899; color: #ffffff; }
        .btn-warning:hover { background-color: #db2777; border-color: #db2777; color: #ffffff; }
        .btn-primary { background-color: #8b5cf6; border-color: #8b5cf6; color: #ffffff; }
        .btn-primary:hover { background-color: #7c3aed; border-color: #7c3aed; color: #ffffff; }
        .btn-outline-light { border-color: #8b5cf6; color: #6d28d9; }
        .btn-outline-light:hover { background-color: #ede9fe; color: #4c1d95; }
        .btn-outline-info { border-color: #8b5cf6; color: #8b5cf6; }
        .btn-outline-info:hover { background-color: #ede9fe; color: #4c1d95; }
        .btn-outline-danger { border-color: #ec4899; color: #ec4899; }
        .btn-outline-danger:hover { background-color: #fce7f3; color: #db2777; }
        .btn-outline-success { border-color: #2d6a4f; color: #2d6a4f; }
        .btn-outline-success:hover { background-color: #d4edda; color: #000000; }
        .btn-outline-secondary { border-color: #6c757d; color: #6c757d; }
        .btn-outline-secondary:hover { background-color: #e2e3e5; color: #000000; }
        .btn-outline-primary { border-color: #8b5cf6; color: #7c3aed; }
        .btn-outline-primary:hover { background-color: #ede9fe; color: #4c1d95; }
        .list-group-item { background-color: #f8f9fa; color: #1a1a1a; border-color: #dee2e6; }
        .border-secondary { border-color: #dee2e6 !important; }
        a { color: #7c3aed; }
        a:hover { color: #ec4899; }
        footer { background-color: #f8f9fa; color: #555555; border-top: 1px solid #dee2e6 !important; }
        .pagination .page-link { background-color: #f8f9fa; color: #7c3aed; border-color: #dee2e6; }
        .pagination .page-link:hover { background-color: #ede9fe; color: #4c1d95; }
    </style>
</head>
<body style="background-color: #ffffff;">
    """ + HTML_NAVBAR + """
    <div class="container-fluid px-4 py-4">
        {{ content | safe }}
    </div>
    <footer class="text-center py-3 mt-5" style="background-color: #f8f9fa; border-top: 1px solid #dee2e6;">
        <small style="color: #555555;">Data Source: Kaggle / NCRB Crime Statistics Dataset (2001-2014) | Crime Management Portal</small>
    </footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""


# DASHBOARD ROUTE
@app.route('/')
def dashboard():
    conn = get_db_connection()
    try:
        total_cases = conn.execute("SELECT SUM(case_count) FROM crime_statistics").fetchone()[0] or 0
        total_records = conn.execute("SELECT COUNT(*) FROM crime_statistics").fetchone()[0] or 0
        states_count = conn.execute("SELECT COUNT(DISTINCT state) FROM crime_statistics").fetchone()[0] or 0
        districts_count = conn.execute("SELECT COUNT(DISTINCT district) FROM crime_statistics").fetchone()[0] or 0
        categories_count = conn.execute("SELECT COUNT(DISTINCT crime_type) FROM crime_statistics").fetchone()[0] or 0
        
        min_yr = conn.execute("SELECT MIN(year) FROM crime_statistics").fetchone()[0] or 2001
        max_yr = conn.execute("SELECT MAX(year) FROM crime_statistics").fetchone()[0] or 2014

        # Top Crime Category
        top_cat_row = conn.execute("""
            SELECT crime_type, SUM(case_count) as total 
            FROM crime_statistics 
            GROUP BY crime_type 
            ORDER BY total DESC LIMIT 1
        """).fetchone()
        top_cat = top_cat_row['crime_type'] if top_cat_row else "N/A"
        top_cat_val = top_cat_row['total'] if top_cat_row else 0

        # Top State
        top_state_row = conn.execute("""
            SELECT state, SUM(case_count) as total 
            FROM crime_statistics 
            GROUP BY state 
            ORDER BY total DESC LIMIT 1
        """).fetchone()
        top_state = top_state_row['state'] if top_state_row else "N/A"
        top_state_val = top_state_row['total'] if top_state_row else 0

        # Highest Crime Year
        top_yr_row = conn.execute("""
            SELECT year, SUM(case_count) as total 
            FROM crime_statistics 
            GROUP BY year 
            ORDER BY total DESC LIMIT 1
        """).fetchone()
        top_yr = top_yr_row['year'] if top_yr_row else "N/A"
        top_yr_val = top_yr_row['total'] if top_yr_row else 0

    except Exception as e:
        print(f"Error fetching stats: {e}")
        total_cases = total_records = states_count = districts_count = categories_count = 0
        min_yr, max_yr = 2001, 2014
        top_cat = top_state = top_yr = "N/A"
        top_cat_val = top_state_val = top_yr_val = 0

    body = f"""
    <div class="row g-4 mb-4">
        <div class="col-md-12">
            <div class="p-4 rounded-3 card shadow-sm text-center" style="background: linear-gradient(135deg, #ede9fe 0%, #fdf2f8 100%); border: 2px solid #ec4899;">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <span class="source-badge">Official NCRB / Kaggle Crime Dataset</span>
                    <span class="small fw-semibold" style="color: #6d28d9;">Years Covered: {min_yr} – {max_yr}</span>
                </div>
                <h1 class="display-6 fw-bold" style="color: #ec4899;">National Crime Management Portal</h1>
                <p class="lead mb-3" style="color: #4c1d95;">Live Dynamic Insights from 35+ Million Real NCRB Recorded Crime Cases</p>
                <div class="d-flex justify-content-center gap-3">
                    <a href="/crime-statistics" class="btn btn-warning fw-bold px-4 shadow-sm">🔍 Search Crime Records</a>
                    <a href="/analytics" class="btn btn-primary fw-bold px-4 shadow-sm">📊 Interactive Visual Analytics</a>
                    <a href="/women-children-analytics" class="btn btn-outline-primary fw-bold px-4 shadow-sm" style="background-color: #ffffff;">👧 Women & Children Reports</a>
                </div>
            </div>
        </div>
    </div>

    <div class="row g-4 mb-4">
        <div class="col-md-3">
            <div class="card stats-card p-3 shadow-sm text-center">
                <h6 class="text-uppercase text-secondary small">Total Recorded Cases</h6>
                <span class="fs-2 fw-bold text-info">{total_cases:,}</span>
                <small class="text-muted">From {total_records:,} stat entries</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #ec4899;">
                <h6 class="text-uppercase text-secondary small">States & UTs</h6>
                <span class="fs-2 fw-bold text-danger">{states_count}</span>
                <small class="text-muted">{districts_count} Districts Covered</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #f59e0b;">
                <h6 class="text-uppercase text-secondary small">Crime Categories</h6>
                <span class="fs-2 fw-bold text-warning">{categories_count}</span>
                <small class="text-muted">Normalized IPC Categories</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #10b981;">
                <h6 class="text-uppercase text-secondary small">Highest Crime State</h6>
                <span class="fs-4 fw-bold text-success">{top_state}</span>
                <small class="text-muted">{top_state_val:,} Total Cases</small>
            </div>
        </div>
    </div>

    <div class="row g-4">
        <div class="col-12">
            <div class="card p-4">
                <h5 class="text-warning mb-3">📌 Key Dataset Highlights</h5>
                <ul class="list-group list-group-flush bg-transparent">
                    <li class="list-group-item bg-transparent border-secondary d-flex justify-content-between" style="color: #1a1a1a;">
                        <span>Most Common Crime Category:</span>
                        <strong class="text-info">{top_cat} ({top_cat_val:,})</strong>
                    </li>
                    <li class="list-group-item bg-transparent border-secondary d-flex justify-content-between" style="color: #1a1a1a;">
                        <span>Peak Crime Year:</span>
                        <strong class="text-warning">{top_yr} ({top_yr_val:,} cases)</strong>
                    </li>
                    <li class="list-group-item bg-transparent border-secondary d-flex justify-content-between" style="color: #1a1a1a;">
                        <span>Primary Source:</span>
                        <span class="badge bg-secondary">NCRB District-Wise IPC Datasets</span>
                    </li>
                    <li class="list-group-item bg-transparent border-secondary d-flex justify-content-between" style="color: #1a1a1a;">
                        <span>Specialized Modules:</span>
                        <span>Women, Children, Property, Arrests</span>
                    </li>
                </ul>
            </div>
        </div>
    </div>
    """
    return render_template_string(HTML_LAYOUT, content=body)


# CRIME STATISTICS & FILTER ROUTE
@app.route('/crime-statistics')
def crime_statistics():
    conn = get_db_connection()
    
    # Selected filters
    selected_state = request.args.get('state', '').strip()
    selected_district = request.args.get('district', '').strip()
    selected_year = request.args.get('year', '').strip()
    selected_crime = request.args.get('crime_type', '').strip()
    
    page = int(request.args.get('page', 1))
    per_page = 50
    offset = (page - 1) * per_page

    # Fetch filter dropdown choices
    states = [r[0] for r in conn.execute("SELECT DISTINCT state FROM crime_statistics ORDER BY state").fetchall()]
    years = [r[0] for r in conn.execute("SELECT DISTINCT year FROM crime_statistics ORDER BY year DESC").fetchall()]
    crimes = [r[0] for r in conn.execute("SELECT DISTINCT crime_type FROM crime_statistics ORDER BY crime_type").fetchall()]

    districts_query = "SELECT DISTINCT district FROM crime_statistics"
    if selected_state:
        districts_query += f" WHERE state = '{selected_state}'"
    districts = [r[0] for r in conn.execute(districts_query + " ORDER BY district").fetchall()]

    # Build filtered query
    where_clauses = []
    params = []

    if selected_state:
        where_clauses.append("state = ?")
        params.append(selected_state)
    if selected_district:
        where_clauses.append("district = ?")
        params.append(selected_district)
    if selected_year:
        where_clauses.append("year = ?")
        params.append(int(selected_year))
    if selected_crime:
        where_clauses.append("crime_type = ?")
        params.append(selected_crime)

    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    # Count total results
    count_sql = f"SELECT COUNT(*) FROM crime_statistics{where_sql}"
    total_matches = conn.execute(count_sql, params).fetchone()[0]

    # Fetch page items
    data_sql = f"""
        SELECT state, district, year, crime_type, case_count, source 
        FROM crime_statistics
        {where_sql}
        ORDER BY case_count DESC, year DESC, state, district
        LIMIT {per_page} OFFSET {offset}
    """
    rows = conn.execute(data_sql, params).fetchall()

    # Total cases matching filter
    total_cases_sql = f"SELECT SUM(case_count) FROM crime_statistics{where_sql}"
    sum_cases = conn.execute(total_cases_sql, params).fetchone()[0] or 0

    # Build Table HTML
    if rows:
        rows_html = "".join([f"""
        <tr>
            <td class="fw-bold text-warning">{r['state']}</td>
            <td>{r['district']}</td>
            <td><span class="badge bg-secondary">{r['year']}</span></td>
            <td><span class="badge bg-info text-dark">{r['crime_type']}</span></td>
            <td class="fw-bold text-danger fs-6">{r['case_count']:,}</td>
            <td><span class="source-badge">{r['source']}</span></td>
        </tr>
        """ for r in rows])
    else:
        rows_html = """
        <tr>
            <td colspan="6" class="text-center py-5 text-muted fs-5">
                ⚠️ No records found for the selected filters. Please adjust your search criteria.
            </td>
        </tr>
        """

    # Build State/District/Year/Crime select options
    state_opts = "".join([f'<option value="{s}" {"selected" if s==selected_state else ""}>{s}</option>' for s in states])
    dist_opts = "".join([f'<option value="{d}" {"selected" if d==selected_district else ""}>{d}</option>' for d in districts])
    year_opts = "".join([f'<option value="{y}" {"selected" if str(y)==selected_year else ""}>{y}</option>' for y in years])
    crime_opts = "".join([f'<option value="{c}" {"selected" if c==selected_crime else ""}>{c}</option>' for c in crimes])

    total_pages = (total_matches + per_page - 1) // per_page if total_matches > 0 else 1

    body = f"""
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2 class="text-warning m-0">🔍 Kaggle/NCRB Crime Statistics Explorer</h2>
        <span class="source-badge">Data Source: Kaggle / NCRB Dataset</span>
    </div>

    <div class="card p-4 mb-4">
        <form method="GET" action="/crime-statistics" class="row g-3">
            <div class="col-md-3">
                <label class="form-label text-secondary small fw-bold">State / UT</label>
                <select name="state" class="form-select" onchange="this.form.submit()">
                    <option value="">-- All States --</option>
                    {state_opts}
                </select>
            </div>
            <div class="col-md-3">
                <label class="form-label text-secondary small fw-bold">District</label>
                <select name="district" class="form-select">
                    <option value="">-- All Districts --</option>
                    {dist_opts}
                </select>
            </div>
            <div class="col-md-2">
                <label class="form-label text-secondary small fw-bold">Year</label>
                <select name="year" class="form-select">
                    <option value="">-- All Years --</option>
                    {year_opts}
                </select>
            </div>
            <div class="col-md-3">
                <label class="form-label text-secondary small fw-bold">Crime Category</label>
                <select name="crime_type" class="form-select">
                    <option value="">-- All Crime Categories --</option>
                    {crime_opts}
                </select>
            </div>
            <div class="col-md-1 d-flex align-items-end">
                <button type="submit" class="btn btn-warning w-100 fw-bold">Filter</button>
            </div>
        </form>
    </div>

    <div class="card p-4">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h5 class="text-info m-0">
                Matching Statistics: <span class="fw-bold" style="color: #1a1a1a;">{total_matches:,} Entries</span> 
                (<span class="text-danger fw-bold">{sum_cases:,} Total Cases</span>)
            </h5>
            <a href="/crime-statistics" class="btn btn-outline-secondary btn-sm">Reset Filters</a>
        </div>
        <div class="table-responsive">
            <table class="table table-dark table-hover align-middle">
                <thead>
                    <tr>
                        <th>State / UT</th>
                        <th>District</th>
                        <th>Year</th>
                        <th>Crime Category</th>
                        <th>Reported Cases</th>
                        <th>Source</th>
                    </tr>
                </thead>
                <tbody>{rows_html}</tbody>
            </table>
        </div>

        <div class="d-flex justify-content-between align-items-center mt-3">
            <small class="text-secondary">Page {page} of {total_pages}</small>

            <nav>
                <ul class="pagination pagination-sm m-0">
                    <li class="page-item {'disabled' if page <= 1 else ''}">
                        <a class="page-link" href="/crime-statistics?state={selected_state}&district={selected_district}&year={selected_year}&crime_type={selected_crime}&page={page-1}">Previous</a>
                    </li>
                    <li class="page-item {'disabled' if page >= total_pages else ''}">
                        <a class="page-link" href="/crime-statistics?state={selected_state}&district={selected_district}&year={selected_year}&crime_type={selected_crime}&page={page+1}">Next</a>
                    </li>
                </ul>
            </nav>
        </div>
    </div>
    """
    return render_template_string(HTML_LAYOUT, content=body)


# INTERACTIVE ANALYTICS & CHARTS ROUTE
@app.route('/analytics')
def analytics():
    conn = get_db_connection()
    
    # 1. Yearly Trend
    years_data = conn.execute("""
        SELECT year, SUM(case_count) as total 
        FROM crime_statistics 
        GROUP BY year 
        ORDER BY year
    """).fetchall()
    year_labels = [str(r['year']) for r in years_data]
    year_vals = [r['total'] for r in years_data]

    # 2. Top 10 States
    states_data = conn.execute("""
        SELECT state, SUM(case_count) as total 
        FROM crime_statistics 
        GROUP BY state 
        ORDER BY total DESC LIMIT 10
    """).fetchall()
    state_labels = [r['state'] for r in states_data]
    state_vals = [r['total'] for r in states_data]

    # 3. Top 10 Crime Categories
    cats_data = conn.execute("""
        SELECT crime_type, SUM(case_count) as total 
        FROM crime_statistics 
        WHERE crime_type != 'TOTAL'
        GROUP BY crime_type 
        ORDER BY total DESC LIMIT 10
    """).fetchall()
    cat_labels = [r['crime_type'] for r in cats_data]
    cat_vals = [r['total'] for r in cats_data]

    body = f"""
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2 class="text-info m-0">📊 Interactive Crime Analytics & Trends</h2>
        <span class="source-badge">Data Source: Kaggle / NCRB Dataset</span>
    </div>

    <div class="row g-4 mb-4">
        <div class="col-md-8">
            <div class="card p-4">
                <h5 class="text-warning mb-3">📈 National Crime Trend Over Years (2001 - 2014)</h5>
                <canvas id="yearlyTrendChart" height="140"></canvas>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card p-4">
                <h5 class="text-danger mb-3">🧩 Top Crime Categories</h5>
                <canvas id="categoryPieChart" height="280"></canvas>
            </div>
        </div>
    </div>

    <div class="row g-4">
        <div class="col-md-12">
            <div class="card p-4">
                <h5 class="text-success mb-3">🏛️ Top 10 States by Total Recorded Crimes</h5>
                <canvas id="stateBarChart" height="100"></canvas>
            </div>
        </div>
    </div>

    <script>
        // 1. Line Chart: Yearly Trend
        new Chart(document.getElementById('yearlyTrendChart'), {{
            type: 'line',
            data: {{
                labels: {year_labels},
                datasets: [{{
                    label: 'Total Recorded Crimes',
                    data: {year_vals},
                    borderColor: '#8b5cf6',
                    backgroundColor: 'rgba(139, 92, 246, 0.12)',
                    fill: true,
                    tension: 0.3
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ labels: {{ color: '#1a1a1a', font: {{ weight: 'bold' }} }} }} }},
                scales: {{
                    x: {{ ticks: {{ color: '#555555' }}, grid: {{ color: 'rgba(0,0,0,0.06)' }} }},
                    y: {{ ticks: {{ color: '#555555' }}, grid: {{ color: 'rgba(0,0,0,0.06)' }} }}
                }}
            }}
        }});

        // 2. Pie Chart: Category Distribution
        new Chart(document.getElementById('categoryPieChart'), {{
            type: 'doughnut',
            data: {{
                labels: {cat_labels},
                datasets: [{{
                    data: {cat_vals},
                    backgroundColor: ['#ec4899', '#8b5cf6', '#10b981', '#f59e0b', '#a855f7', '#06b6d4', '#84cc16', '#6366f1', '#14b8a6', '#f43f5e']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#1a1a1a', font: {{ size: 10, weight: 'bold' }} }} }} }}
            }}
        }});

        // 3. Bar Chart: Top States
        new Chart(document.getElementById('stateBarChart'), {{
            type: 'bar',
            data: {{
                labels: {state_labels},
                datasets: [{{
                    label: 'Total Crime Cases',
                    data: {state_vals},
                    backgroundColor: '#8b5cf6'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ labels: {{ color: '#1a1a1a', font: {{ weight: 'bold' }} }} }} }},
                scales: {{
                    x: {{ ticks: {{ color: '#555555' }}, grid: {{ color: 'rgba(0,0,0,0.06)' }} }},
                    y: {{ ticks: {{ color: '#555555' }}, grid: {{ color: 'rgba(0,0,0,0.06)' }} }}
                }}
            }}
        }});
    </script>
    """
    return render_template_string(HTML_LAYOUT, content=body)


# WOMEN & CHILDREN ANALYTICS ROUTE
@app.route('/women-children-analytics')
def women_children_analytics():
    conn = get_db_connection()

    # Women crime totals by category
    women_cats = conn.execute("""
        SELECT crime_type, SUM(case_count) as total 
        FROM women_crime_statistics 
        GROUP BY crime_type 
        ORDER BY total DESC
    """).fetchall()

    # Children crime totals by category
    child_cats = conn.execute("""
        SELECT crime_type, SUM(case_count) as total 
        FROM children_crime_statistics 
        GROUP BY crime_type 
        ORDER BY total DESC
    """).fetchall()

    women_rows = "".join([f"<tr><td>{w['crime_type']}</td><td class='fw-bold text-danger'>{w['total']:,}</td></tr>" for w in women_cats])
    child_rows = "".join([f"<tr><td>{c['crime_type']}</td><td class='fw-bold text-warning'>{c['total']:,}</td></tr>" for c in child_cats])

    body = f"""
    <h2 class="text-danger mb-4">👧 Crimes Against Women & Children Statistics</h2>
    <div class="row g-4">
        <div class="col-md-6">
            <div class="card p-4">
                <h4 class="text-danger mb-3">👩 Crimes Against Women (Category Breakdown)</h4>
                <div class="table-responsive">
                    <table class="table table-dark table-hover align-middle">
                        <thead><tr><th>Category</th><th>Total Reported Cases</th></tr></thead>
                        <tbody>{women_rows}</tbody>
                    </table>
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="card p-4">
                <h4 class="text-warning mb-3">👶 Crimes Against Children (Category Breakdown)</h4>
                <div class="table-responsive">
                    <table class="table table-dark table-hover align-middle">
                        <thead><tr><th>Category</th><th>Total Reported Cases</th></tr></thead>
                        <tbody>{child_rows}</tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    """
    return render_template_string(HTML_LAYOUT, content=body)


# PROPERTY & ARREST ANALYTICS ROUTE
@app.route('/property-arrest-analytics')
def property_arrest_analytics():
    conn = get_db_connection()

    prop_data = conn.execute("""
        SELECT state, SUM(stolen_cases) as stolen, SUM(recovered_cases) as recovered 
        FROM property_crime_statistics 
        GROUP BY state 
        ORDER BY stolen DESC LIMIT 15
    """).fetchall()

    arrest_data = conn.execute("""
        SELECT crime_head, SUM(persons_arrested) as arrested, SUM(persons_convicted) as convicted, SUM(persons_acquitted) as acquitted 
        FROM arrest_statistics 
        GROUP BY crime_head 
        ORDER BY arrested DESC LIMIT 15
    """).fetchall()

    # Top recovered cases per state
    recovered_top_data = conn.execute("""
        SELECT state, SUM(recovered_cases) as recovered
        FROM property_crime_statistics
        GROUP BY state
        ORDER BY recovered DESC LIMIT 15
    """).fetchall()
    recovered_top_rows = "".join([f"<tr><td class='fw-bold text-info'>{p['state']}</td><td class='text-success'>{p['recovered']:,}</td></tr>" for p in recovered_top_data])
    prop_rows = "".join([f"<tr><td class='fw-bold text-warning'>{p['state']}</td><td class='text-danger'>{p['stolen']:,}</td><td class='text-success'>{p['recovered']:,}</td></tr>" for p in prop_data])
    arrest_rows = "".join([f"<tr><td>{a['crime_head']}</td><td class='text-warning'>{a['arrested']:,}</td><td class='text-success'>{a['convicted']:,}</td><td class='text-danger'>{a['acquitted']:,}</td></tr>" for a in arrest_data])

    body = f"""
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2 class="text-info m-0">💰 Property Crimes & Police Arrest Statistics</h2>
        <span class="source-badge">Data Source: Kaggle / NCRB Dataset</span>
    </div>
    <div class="row g-4 mb-4">
        <div class="col-md-6">
            <div class="card p-4 h-100">
                <h4 class="text-warning mb-3">🏡 Stolen vs Recovered Property (Top States)</h4>
                <div class="table-responsive">
                    <table class="table table-hover align-middle">
                        <thead><tr><th>State / UT</th><th>Stolen Cases</th><th>Recovered Cases</th></tr></thead>
                        <tbody>{prop_rows}</tbody>
                    </table>
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="card p-4 h-100">
                <h4 class="text-info mb-3">🏆 Top States by Recovered Property</h4>
                <div class="table-responsive">
                    <table class="table table-hover align-middle">
                        <thead><tr><th>State / UT</th><th>Recovered Cases</th></tr></thead>
                        <tbody>{recovered_top_rows}</tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    <div class="row g-4">
        <div class="col-12">
            <div class="card p-4">
                <h4 class="text-info mb-3">⚖️ Arrests, Convictions & Acquittals</h4>
                <div class="table-responsive">
                    <table class="table table-hover align-middle">
                        <thead><tr><th>Crime Head</th><th>Arrested</th><th>Convicted</th><th>Acquitted</th></tr></thead>
                        <tbody>{arrest_rows}</tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    """
    return render_template_string(HTML_LAYOUT, content=body)


# --- Status option sets shared by the operational modules ---
FIR_STATUSES = ["Pending", "Under Investigation", "Chargesheet Filed", "Closed"]
CASE_STATUSES = ["Active", "Under Trial", "Closed", "Dismissed"]
CRIMINAL_STATUSES = ["Wanted", "Arrested", "Convicted", "Released", "Absconding"]


def _options_html(items, current):
    return "".join(
        f'<option value="{item}"{" selected" if item == current else ""}>{item}</option>'
        for item in items
    )


def _table_exists(conn, table_name):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,)
    ).fetchone() is not None


def _load_police_stations_geojson():
        with open(POLICE_STATIONS_GEOJSON, 'r', encoding='utf-8') as file:
                return json.load(file)


def _station_options(stations, placeholder='Station'):
    options = [f'<option value="">{escape(placeholder)}</option>']
    options.extend(
        f'<option value="{station["station_id"]}">{escape(station["station_name"])}</option>'
        for station in stations
    )
    if os.path.exists(POLICE_STATIONS_GEOJSON):
        reference_stations = _load_police_stations_geojson().get('features', [])
        options.append('<option disabled>--- Reference stations ---</option>')
        options.extend(
            f'<option value="geo:{properties.get("ps_cd")}">'
            f'{escape(properties.get("ps") or "Police Station")} '
            f'({escape(properties.get("district") or "")}, {escape(properties.get("state") or "")})</option>'
            for feature in reference_stations
            if (properties := feature.get('properties', {})).get('ps_cd')
        )
    return ''.join(options)


def _resolve_station_id(conn, raw_station_id):
    if not raw_station_id or not raw_station_id.startswith('geo:'):
        return raw_station_id
    station_code = raw_station_id.removeprefix('geo:')
    data = _load_police_stations_geojson()
    properties = next(
        (feature.get('properties', {}) for feature in data.get('features', [])
         if str(feature.get('properties', {}).get('ps_cd')) == station_code),
        None
    )
    if not properties:
        raise ValueError('Selected reference police station was not found')
    station_name = f"{properties.get('ps', 'Police Station')} ({properties.get('state', 'India')})"
    existing = conn.execute(
        'SELECT station_id FROM police_stations WHERE station_name = ?', (station_name,)
    ).fetchone()
    if existing:
        return existing['station_id']
    cursor = conn.execute(
        """INSERT INTO police_stations
           (station_name, address, city, state, contact_number)
           VALUES (?, ?, ?, ?, ?)""",
        (station_name, properties.get('district') or 'Reference location',
         properties.get('district') or 'Reference location',
         properties.get('state') or 'India', 'GeoJSON reference')
    )
    return cursor.lastrowid


@app.route('/api/police-stations')
def api_police_stations():
        if not os.path.exists(POLICE_STATIONS_GEOJSON):
                return jsonify({'error': 'Police station GeoJSON file is not available'}), 404
        return jsonify(_load_police_stations_geojson())


@app.route('/police-station-map')
def police_station_map():
        if not os.path.exists(POLICE_STATIONS_GEOJSON):
                content = "<h2 class='text-info'>Police Station Map</h2><p>The station GeoJSON file is not available.</p>"
                return render_template_string(HTML_LAYOUT, content=content), 404

        body = """
        <div class="d-flex justify-content-between align-items-center mb-3">
                <div>
                        <h2 class="text-info mb-1">India Police Station Map</h2>
                        <p class="text-muted mb-0">Reference locations from the local GeoJSON dataset.</p>
                </div>
                <span id="station-count" class="source-badge">Loading stations...</span>
        </div>
        <div class="card p-2"><div id="station-map" style="height: 70vh; min-height: 480px;"></div></div>
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
        <script>
            const map = L.map('station-map').setView([22.5, 82.5], 5);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: '&copy; OpenStreetMap contributors'
            }).addTo(map);
            fetch('/api/police-stations')
                .then(response => response.json())
                .then(data => {
                    const features = data.features || [];
                    document.getElementById('station-count').textContent = `${features.length.toLocaleString()} stations`;
                    const layer = L.geoJSON(data, {
                        pointToLayer: (feature, latlng) => L.circleMarker(latlng, {
                            radius: 4, color: '#ec4899', fillColor: '#8b5cf6', fillOpacity: 0.8
                        }),
                        onEachFeature: (feature, layer) => {
                            const properties = feature.properties || {};
                            layer.bindPopup(`<strong>${properties.ps || 'Police Station'}</strong><br>${properties.district || ''}, ${properties.state || ''}`);
                        }
                    }).addTo(map);
                    if (features.length) map.fitBounds(layer.getBounds(), {padding: [20, 20]});
                })
                .catch(() => { document.getElementById('station-count').textContent = 'Unable to load stations'; });
        </script>
        """
        return render_template_string(HTML_LAYOUT, content=body)


# OPERATIONAL MODULES
@app.route('/police-stations')
def police_stations():
    conn = get_db_connection()
    stations = conn.execute("SELECT * FROM police_stations ORDER BY station_id DESC").fetchall()
    officers = conn.execute("""
        SELECT o.*, s.station_name 
        FROM police_officers o 
        LEFT JOIN police_stations s ON o.station_id = s.station_id
        ORDER BY o.officer_id DESC
    """).fetchall()
    dataset_summary = conn.execute("""
        SELECT state, COUNT(DISTINCT district) AS districts,
               SUM(case_count) AS reported_cases, MAX(year) AS latest_year
        FROM crime_statistics
        GROUP BY state ORDER BY reported_cases DESC LIMIT 10
    """).fetchall() if _table_exists(conn, 'crime_statistics') else []
    conn.close()

    geojson_stations = []
    if os.path.exists(POLICE_STATIONS_GEOJSON):
        geojson_data = _load_police_stations_geojson()
        geojson_stations = [feature.get('properties', {}) for feature in geojson_data.get('features', [])]
    
    stations_html = "".join([f"""
    <tr>
        <td>{s['station_id']}</td>
        <td class="fw-bold text-warning">{s['station_name']}</td>
        <td>{s['address']}, {s['city']}, {s['state']}</td>
        <td>{s['contact_number']}</td>
    </tr>
    """ for s in stations]) or "<tr><td colspan='4' class='text-center text-muted py-4'>No operational police stations added yet.</td></tr>"

    officers_html = "".join([f"""
    <tr>
        <td><span class="badge bg-secondary">{o['badge_number']}</span></td>
        <td class="fw-bold">{o['name']}</td>
        <td><span class="badge bg-info text-dark">{o['rank']}</span></td>
        <td>{o['station_name'] or 'Unassigned'}</td>
        <td>{o['phone']}</td>
        <td>{o['email']}</td>
    </tr>
    """ for o in officers]) or "<tr><td colspan='6' class='text-center text-muted py-4'>No operational police officers registered yet.</td></tr>"

    dataset_rows = "".join([f"""
    <tr><td class="fw-bold text-warning">{s['state']}</td><td>{s['districts']}</td>
        <td>{s['reported_cases']:,}</td><td>{s['latest_year']}</td></tr>
    """ for s in dataset_summary]) or "<tr><td colspan='4' class='text-center text-muted py-4'>Run the dataset import to show NCRB coverage.</td></tr>"
    station_options = _station_options(stations)
    geojson_rows = "".join([f"""
    <tr><td class="fw-bold text-warning">{station.get('ps') or 'Police Station'}</td>
        <td>{station.get('district') or 'N/A'}</td><td>{station.get('state') or 'N/A'}</td>
        <td>{station.get('latitude')}, {station.get('longitude')}</td></tr>
    """ for station in geojson_stations[:100]]) or "<tr><td colspan='4' class='text-center text-muted py-4'>Police station GeoJSON not available.</td></tr>"

    body = f"""
    <h2 class="text-warning mb-3">🏢 Police Stations & Officer Directory</h2>
    <div class="card p-4 mb-4">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <div><h4 class="text-info m-0">Police Station Reference Data</h4>
            <small class="text-muted">{len(geojson_stations):,} locations from the downloaded GeoJSON dataset</small></div>
            <a href="/police-station-map" class="btn btn-outline-info btn-sm">Open Station Map</a>
        </div>
        <div class="table-responsive"><table class="table table-dark table-hover align-middle">
            <thead><tr><th>Station Name</th><th>District</th><th>State / UT</th><th>Coordinates</th></tr></thead>
            <tbody>{geojson_rows}</tbody>
        </table></div>
        <small class="text-muted">Showing the first 100 reference locations. These records are not operational station accounts.</small>
    </div>
    <div class="card p-4 mb-4">
        <div class="d-flex justify-content-between align-items-center mb-3"><h4 class="text-info m-0">Operational Police Precincts</h4><a href="/police-stations#add-station" class="btn btn-warning btn-sm">Add Station</a></div>
        <div class="table-responsive">
            <table class="table table-dark table-hover align-middle">
                <thead><tr><th>ID</th><th>Station Name</th><th>Address</th><th>Contact Number</th></tr></thead>
                <tbody>{stations_html}</tbody>
            </table>
        </div>
    </div>

    <div class="card p-4 mb-4">
        <h4 class="text-info mb-3">NCRB Dataset Coverage by State</h4>
        <div class="table-responsive"><table class="table table-dark table-hover align-middle">
            <thead><tr><th>State / UT</th><th>Districts</th><th>Reported Cases</th><th>Latest Year</th></tr></thead>
            <tbody>{dataset_rows}</tbody>
        </table></div>
    </div>

    <div class="card p-4 mb-4" id="add-station">
        <h4 class="text-info mb-3">Add Police Station</h4>
        <form method="POST" action="/police-stations/add" class="row g-2">
            <div class="col-md-3"><input class="form-control" name="station_name" placeholder="Station name" required></div>
            <div class="col-md-3"><input class="form-control" name="address" placeholder="Address" required></div>
            <div class="col-md-2"><input class="form-control" name="city" placeholder="City" required></div>
            <div class="col-md-2"><input class="form-control" name="state" placeholder="State" required></div>
            <div class="col-md-2"><input class="form-control" name="contact_number" placeholder="Contact number" required></div>
            <div class="col-12"><button type="submit" class="btn btn-warning">Add Station</button></div>
        </form>
    </div>

    <div class="card p-4">
        <div class="d-flex justify-content-between align-items-center mb-3"><h4 class="text-info m-0">Deputed Police Officers</h4><a href="/police-stations#add-officer" class="btn btn-warning btn-sm">Add Officer</a></div>
        <div class="table-responsive">
            <table class="table table-dark table-hover align-middle">
                <thead><tr><th>Badge No</th><th>Officer Name</th><th>Rank</th><th>Station</th><th>Phone</th><th>Email</th></tr></thead>
                <tbody>{officers_html}</tbody>
            </table>
        </div>
    </div>

    <div class="card p-4 mt-4" id="add-officer">
        <h4 class="text-info mb-3">Add Police Officer</h4>
        <form method="POST" action="/police-stations/add-officer" class="row g-2">
            <div class="col-md-2"><input class="form-control" name="name" placeholder="Name" required></div>
            <div class="col-md-2"><input class="form-control" name="rank" placeholder="Rank" required></div>
            <div class="col-md-2"><input class="form-control" name="badge_number" placeholder="Badge number" required></div>
            <div class="col-md-2"><input class="form-control" name="phone" placeholder="Phone" required></div>
            <div class="col-md-2"><input type="email" class="form-control" name="email" placeholder="Email" required></div>
            <div class="col-md-2"><select class="form-select" name="station_id" required>{station_options}</select></div>
            <div class="col-12"><button type="submit" class="btn btn-warning">Add Officer</button></div>
        </form>
    </div>
    """
    return render_template_string(HTML_LAYOUT, content=body)


@app.route('/police-stations/add', methods=['POST'])
def add_police_station():
    conn = get_db_connection()
    conn.execute("INSERT INTO police_stations (station_name, address, city, state, contact_number) VALUES (?, ?, ?, ?, ?)",
                 (request.form['station_name'], request.form['address'], request.form['city'], request.form['state'], request.form['contact_number']))
    conn.commit()
    conn.close()
    return redirect('/police-stations')


@app.route('/police-stations/add-officer', methods=['POST'])
def add_police_officer():
    conn = get_db_connection()
    station_id = _resolve_station_id(conn, request.form['station_id'])
    conn.execute("INSERT INTO police_officers (name, rank, badge_number, phone, email, station_id) VALUES (?, ?, ?, ?, ?, ?)",
                 (request.form['name'], request.form['rank'], request.form['badge_number'], request.form['phone'], request.form['email'], station_id))
    conn.commit()
    conn.close()
    return redirect('/police-stations')


@app.route('/fir-management')
def fir_management():
    conn = get_db_connection()
    firs = conn.execute("""
        SELECT f.*, c.crime_type, v.name as victim_name, s.station_name 
        FROM FIR f
        LEFT JOIN crimes c ON f.crime_id = c.crime_id
        LEFT JOIN victims v ON f.victim_id = v.victim_id
        LEFT JOIN police_stations s ON f.station_id = s.station_id
        ORDER BY f.fir_id DESC
    """).fetchall()
    stations = conn.execute("SELECT * FROM police_stations ORDER BY station_name").fetchall()
    crime_categories = conn.execute("""
        SELECT crime_type, SUM(case_count) AS total
        FROM crime_statistics GROUP BY crime_type ORDER BY total DESC LIMIT 10
    """).fetchall() if _table_exists(conn, 'crime_statistics') else []
    conn.close()

    firs_html = "".join([f"""
    <tr>
        <td><span class="badge bg-warning text-dark fw-bold">{f['fir_number']}</span></td>
        <td>{f['crime_type']}</td>
        <td>{f['victim_name']}</td>
        <td>{f['station_name']}</td>
        <td>{f['filing_date']}</td>
        <td><form method="POST" action="/fir-management/{f['fir_id']}/status" class="d-flex gap-1"><select name="status" class="form-select form-select-sm">{_options_html(FIR_STATUSES, f['status'])}</select><button class="btn btn-sm btn-outline-primary">Update</button></form></td>
    </tr>
    """ for f in firs]) or "<tr><td colspan='6' class='text-center text-muted py-4'>No individual FIR records filed yet. Analytical crime statistics are managed in <a href='/crime-statistics'>Crime Statistics</a>.</td></tr>"
    category_rows = "".join(f"<tr><td>{c['crime_type']}</td><td class='fw-bold text-danger'>{c['total']:,}</td></tr>" for c in crime_categories) or "<tr><td colspan='2' class='text-center text-muted'>Run the dataset import to show categories.</td></tr>"
    station_options = _station_options(stations, 'Select police station')
    category_options = "".join(f'<option value="{c["crime_type"]}">' for c in crime_categories)

    body = f"""
    <h2 class="text-warning mb-3">📄 FIR (First Information Report) Registry</h2>
    <div class="card p-4 mb-4">
        <div class="table-responsive">
            <table class="table table-dark table-hover align-middle">
                <thead><tr><th>FIR Number</th><th>Crime Type</th><th>Complainant/Victim</th><th>Police Station</th><th>Filing Date</th><th>Status</th></tr></thead>
                <tbody>{firs_html}</tbody>
            </table>
        </div>
    </div>

    <div class="row g-4">
        <div class="col-lg-7"><div class="card p-4">
            <h4 class="text-info mb-3">NCRB Crime Categories Reference</h4>
            <div class="table-responsive"><table class="table table-dark table-hover"><thead><tr><th>Crime Category</th><th>Reported Cases</th></tr></thead><tbody>{category_rows}</tbody></table></div>
        </div></div>
        <div class="col-lg-5"><div class="card p-4">
            <h4 class="text-info mb-3">File New FIR</h4>
            <form method="POST" action="/fir-management/add">
                <input class="form-control mb-2" name="crime_type" list="crime-categories" placeholder="Crime type" required><datalist id="crime-categories">{category_options}</datalist>
                <textarea class="form-control mb-2" name="crime_description" placeholder="Crime description" rows="2" required></textarea>
                <div class="row g-2 mb-2"><div class="col"><input type="date" class="form-control" name="crime_date" required></div><div class="col"><input type="time" class="form-control" name="crime_time"></div></div>
                <input class="form-control mb-2" name="location" placeholder="Location" required>
                <div class="row g-2 mb-2"><div class="col"><input class="form-control" name="city" placeholder="City" required></div><div class="col"><input class="form-control" name="state" placeholder="State" required></div></div>
                <select class="form-select mb-3" name="severity"><option>Minor</option><option selected>Major</option><option>Critical</option></select>
                <input class="form-control mb-2" name="victim_name" placeholder="Victim / complainant name" required>
                <div class="row g-2 mb-2"><div class="col"><input type="number" min="0" class="form-control" name="victim_age" placeholder="Age"></div><div class="col"><select class="form-select" name="victim_gender"><option>Male</option><option>Female</option><option>Other</option></select></div></div>
                <input class="form-control mb-2" name="victim_phone" placeholder="Victim phone" required><input class="form-control mb-2" name="victim_address" placeholder="Victim address">
                <input class="form-control mb-2" name="fir_number" placeholder="FIR number" required><select class="form-select mb-2" name="station_id" required>{station_options}</select>
                <input type="date" class="form-control mb-2" name="filing_date" required><textarea class="form-control mb-3" name="fir_description" placeholder="FIR narrative" rows="2" required></textarea>
                <button type="submit" class="btn btn-warning w-100">File FIR</button>
            </form>
        </div></div>
    </div>
    """
    return render_template_string(HTML_LAYOUT, content=body)


@app.route('/fir-management/add', methods=['POST'])
def add_fir():
    conn = get_db_connection()
    cur = conn.cursor()
    station_id = _resolve_station_id(conn, request.form['station_id'])
    cur.execute("INSERT INTO crimes (crime_type, description, crime_date, crime_time, location, city, state, severity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (request.form['crime_type'], request.form['crime_description'], request.form['crime_date'], request.form.get('crime_time') or None,
                 request.form['location'], request.form['city'], request.form['state'], request.form['severity']))
    crime_id = cur.lastrowid
    cur.execute("INSERT INTO victims (name, age, gender, address, phone) VALUES (?, ?, ?, ?, ?)",
                (request.form['victim_name'], request.form.get('victim_age') or None, request.form.get('victim_gender', 'Other'), request.form.get('victim_address'), request.form['victim_phone']))
    victim_id = cur.lastrowid
    cur.execute("INSERT INTO FIR (fir_number, crime_id, victim_id, station_id, filing_date, description) VALUES (?, ?, ?, ?, ?, ?)",
                (request.form['fir_number'], crime_id, victim_id, station_id, request.form['filing_date'], request.form['fir_description']))
    conn.commit()
    conn.close()
    return redirect('/fir-management')


@app.route('/fir-management/<int:fir_id>/status', methods=['POST'])
def update_fir_status(fir_id):
    conn = get_db_connection()
    conn.execute("UPDATE FIR SET status = ? WHERE fir_id = ?", (request.form['status'], fir_id))
    conn.commit()
    conn.close()
    return redirect('/fir-management')


@app.route('/criminal-records')
def criminal_records():
    conn = get_db_connection()
    criminals = conn.execute("SELECT * FROM criminals ORDER BY criminal_id DESC").fetchall()
    arrest_context = conn.execute("""
        SELECT crime_head, SUM(persons_arrested) AS arrested, SUM(persons_convicted) AS convicted
        FROM arrest_statistics GROUP BY crime_head ORDER BY arrested DESC LIMIT 10
    """).fetchall() if _table_exists(conn, 'arrest_statistics') else []
    conn.close()
    
    criminals_html = "".join([f"""
    <tr>
        <td>#{cr['criminal_id']}</td>
        <td class="fw-bold text-danger">{cr['name']}</td>
        <td>{cr['alias'] or 'N/A'}</td>
        <td>{cr['gender']}</td>
        <td>{cr['identification_details'] or 'N/A'}</td>
        <td><form method="POST" action="/criminal-records/{cr['criminal_id']}/status" class="d-flex gap-1"><select name="status" class="form-select form-select-sm">{_options_html(CRIMINAL_STATUSES, cr['status'])}</select><button class="btn btn-sm btn-outline-primary">Update</button></form></td>
    </tr>
    """ for cr in criminals]) or "<tr><td colspan='6' class='text-center text-muted py-4'>No individual criminal dossiers registered. View overall arrest numbers in <a href='/property-arrest-analytics'>Arrest Statistics</a>.</td></tr>"
    arrest_rows = "".join(f"<tr><td>{a['crime_head']}</td><td>{a['arrested']:,}</td><td>{a['convicted']:,}</td></tr>" for a in arrest_context) or "<tr><td colspan='3' class='text-center text-muted'>Run the dataset import to show arrest context.</td></tr>"

    body = f"""
    <h2 class="text-danger mb-3">👤 Criminal Record Dossiers</h2>
    <div class="card p-4 mb-4">
        <div class="table-responsive">
            <table class="table table-dark table-hover align-middle">
                <thead><tr><th>ID</th><th>Name</th><th>Alias</th><th>Gender</th><th>Identification Details</th><th>Status</th></tr></thead>
                <tbody>{criminals_html}</tbody>
            </table>
        </div>
    </div>
    <div class="row g-4"><div class="col-lg-7"><div class="card p-4"><h4 class="text-info mb-3">NCRB Arrest Context</h4><div class="table-responsive"><table class="table table-dark table-hover"><thead><tr><th>Crime Head</th><th>Arrested</th><th>Convicted</th></tr></thead><tbody>{arrest_rows}</tbody></table></div></div></div>
    <div class="col-lg-5"><div class="card p-4"><h4 class="text-info mb-3">Add Criminal Record</h4><form method="POST" action="/criminal-records/add"><input class="form-control mb-2" name="name" placeholder="Full name" required><input class="form-control mb-2" name="alias" placeholder="Alias"><div class="row g-2 mb-2"><div class="col"><input type="date" class="form-control" name="date_of_birth"></div><div class="col"><select class="form-select" name="gender"><option>Male</option><option>Female</option><option>Other</option></select></div></div><input class="form-control mb-2" name="address" placeholder="Address"><input class="form-control mb-2" name="phone" placeholder="Phone"><input class="form-control mb-2" name="identification_details" placeholder="Identification details"><select class="form-select mb-3" name="status">{_options_html(CRIMINAL_STATUSES, 'Wanted')}</select><button type="submit" class="btn btn-warning w-100">Add Criminal Record</button></form></div></div></div>
    """
    return render_template_string(HTML_LAYOUT, content=body)


@app.route('/criminal-records/add', methods=['POST'])
def add_criminal():
    conn = get_db_connection()
    conn.execute("INSERT INTO criminals (name, alias, date_of_birth, gender, address, phone, identification_details, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                 (request.form['name'], request.form.get('alias') or None, request.form.get('date_of_birth') or None, request.form.get('gender', 'Other'), request.form.get('address'), request.form.get('phone'), request.form.get('identification_details'), request.form.get('status', 'Wanted')))
    conn.commit()
    conn.close()
    return redirect('/criminal-records')


@app.route('/criminal-records/<int:criminal_id>/status', methods=['POST'])
def update_criminal_status(criminal_id):
    conn = get_db_connection()
    conn.execute("UPDATE criminals SET status = ? WHERE criminal_id = ?", (request.form['status'], criminal_id))
    conn.commit()
    conn.close()
    return redirect('/criminal-records')


@app.route('/case-files')
def case_files():
    conn = get_db_connection()
    cases = conn.execute("""
        SELECT c.*, f.fir_number, po.name as officer_name 
        FROM cases c
        LEFT JOIN FIR f ON c.fir_id = f.fir_id
        LEFT JOIN police_officers po ON c.investigating_officer_id = po.officer_id
        ORDER BY c.case_id DESC
    """).fetchall()
    open_firs = conn.execute("SELECT fir_id, fir_number FROM FIR WHERE fir_id NOT IN (SELECT fir_id FROM cases)").fetchall()
    officers = conn.execute("SELECT * FROM police_officers ORDER BY name").fetchall()
    dataset_years = conn.execute("SELECT year, SUM(case_count) AS total FROM crime_statistics GROUP BY year ORDER BY year").fetchall() if _table_exists(conn, 'crime_statistics') else []
    conn.close()

    cases_html = "".join([f"""
    <tr>
        <td><span class="badge bg-primary fw-bold">{cs['case_number']}</span></td>
        <td>{cs['fir_number']}</td>
        <td>{cs['officer_name'] or 'Unassigned'}</td>
        <td><span class="badge bg-warning text-dark">{cs['priority']}</span></td>
        <td><form method="POST" action="/case-files/{cs['case_id']}/status" class="d-flex gap-1"><select name="case_status" class="form-select form-select-sm">{_options_html(CASE_STATUSES, cs['case_status'])}</select><button class="btn btn-sm btn-outline-primary">Update</button></form></td>
        <td>{cs['start_date']}</td>
        <td>{cs['remarks'] or ''}</td>
    </tr>
    """ for cs in cases]) or "<tr><td colspan='7' class='text-center text-muted py-4'>No active individual court cases registered. Overall statistical reports are available in <a href='/analytics'>Analytics</a>.</td></tr>"
    year_rows = "".join(f"<tr><td>{y['year']}</td><td>{y['total']:,}</td></tr>" for y in dataset_years) or "<tr><td colspan='2' class='text-center text-muted'>Run the dataset import to show yearly context.</td></tr>"
    fir_options = "".join(f'<option value="{f["fir_id"]}">{f["fir_number"]}</option>' for f in open_firs) or '<option value="" disabled selected>No unassigned FIRs</option>'
    officer_options = "".join(f'<option value="{o["officer_id"]}">{o["name"]} ({o["rank"]})</option>' for o in officers) or '<option value="">Unassigned</option>'

    body = f"""
    <h2 class="text-info mb-3">⚖️ Active & Closed Case Files</h2>
    <div class="card p-4 mb-4">
        <div class="table-responsive">
            <table class="table table-dark table-hover align-middle">
                <thead><tr><th>Case Number</th><th>FIR Ref</th><th>Investigating Officer</th><th>Priority</th><th>Status</th><th>Start Date</th><th>Remarks</th></tr></thead>
                <tbody>{cases_html}</tbody>
            </table>
        </div>
    </div>
    <div class="row g-4"><div class="col-lg-7"><div class="card p-4"><h4 class="text-info mb-3">NCRB Yearly Reference</h4><div class="table-responsive"><table class="table table-dark table-hover"><thead><tr><th>Year</th><th>Reported Cases</th></tr></thead><tbody>{year_rows}</tbody></table></div></div></div>
    <div class="col-lg-5"><div class="card p-4"><h4 class="text-info mb-3">Open New Case File</h4><form method="POST" action="/case-files/add"><input class="form-control mb-2" name="case_number" placeholder="Case number" required><select class="form-select mb-2" name="fir_id" required>{fir_options}</select><select class="form-select mb-2" name="investigating_officer_id">{officer_options}</select><div class="row g-2 mb-2"><div class="col"><select class="form-select" name="priority"><option>Low</option><option selected>Medium</option><option>High</option></select></div><div class="col"><input type="date" class="form-control" name="start_date" required></div></div><textarea class="form-control mb-3" name="remarks" placeholder="Remarks" rows="2"></textarea><button type="submit" class="btn btn-warning w-100">Open Case</button></form></div></div></div>
    """
    return render_template_string(HTML_LAYOUT, content=body)


@app.route('/case-files/add', methods=['POST'])
def add_case():
    conn = get_db_connection()
    conn.execute("INSERT INTO cases (case_number, fir_id, investigating_officer_id, priority, start_date, remarks) VALUES (?, ?, ?, ?, ?, ?)",
                 (request.form['case_number'], request.form['fir_id'], request.form.get('investigating_officer_id') or None, request.form.get('priority', 'Medium'), request.form['start_date'], request.form.get('remarks')))
    conn.commit()
    conn.close()
    return redirect('/case-files')


@app.route('/case-files/<int:case_id>/status', methods=['POST'])
def update_case_status(case_id):
    conn = get_db_connection()
    status = request.form['case_status']
    if status == 'Closed':
        conn.execute("UPDATE cases SET case_status = ?, closing_date = ? WHERE case_id = ?", (status, datetime.date.today().isoformat(), case_id))
    else:
        conn.execute("UPDATE cases SET case_status = ? WHERE case_id = ?", (status, case_id))
    conn.commit()
    conn.close()
    return redirect('/case-files')


# REST API ENDPOINTS
@app.route('/api/stats')
def api_stats():
    conn = get_db_connection()
    try:
        stats = {
            "dataset_source": "Kaggle / NCRB Crime Statistics Dataset (2001-2014)",
            "total_crime_cases": conn.execute("SELECT SUM(case_count) FROM crime_statistics").fetchone()[0],
            "total_stat_entries": conn.execute("SELECT COUNT(*) FROM crime_statistics").fetchone()[0],
            "states_and_uts": conn.execute("SELECT COUNT(DISTINCT state) FROM crime_statistics").fetchone()[0],
            "districts": conn.execute("SELECT COUNT(DISTINCT district) FROM crime_statistics").fetchone()[0],
            "years_range": [
                conn.execute("SELECT MIN(year) FROM crime_statistics").fetchone()[0],
                conn.execute("SELECT MAX(year) FROM crime_statistics").fetchone()[0]
            ],
            "crime_categories": conn.execute("SELECT COUNT(DISTINCT crime_type) FROM crime_statistics").fetchone()[0]
        }
    except Exception as e:
        stats = {"error": str(e)}
    return jsonify(stats)


@app.route('/api/districts')
def api_districts():
    state = request.args.get('state', '').strip()
    if not state:
        return jsonify([])
    conn = get_db_connection()
    districts = get_districts_for_state(conn, state)
    conn.close()
    return jsonify(districts)


@app.route('/crime-patterns', methods=['GET'])
def crime_patterns():
    conn = get_db_connection()
    try:
        filter_opts = get_filter_options(conn)
    except Exception as e:
        conn.close()
        body = f'<div class="alert alert-danger">Error loading filters: {escape(str(e))}</div>'
        return render_template_string(HTML_LAYOUT, content=body)

    crimes  = filter_opts.get('crimes', [])
    states  = filter_opts.get('states', [])
    years   = filter_opts.get('years', list(range(2001, 2014)))

    # Form values with defaults
    sel_crime    = request.args.get('crime_type', 'THEFT')
    sel_state    = request.args.get('state',      'MAHARASHTRA')
    sel_district = request.args.get('district',   '')
    sel_sy       = int(request.args.get('start_year', 2001))
    sel_ey       = int(request.args.get('end_year',   2013))
    submitted    = 'crime_type' in request.args

    # Build district dropdown options via JS; pre-populate if state selected
    districts_for_selected = get_districts_for_state(conn, sel_state) if sel_state else []

    # ── Crime dropdown ──────────────────────────────────────────────────────
    crime_opts = ''.join(
        f'<option value="{c}" {"selected" if c == sel_crime else ""}>{c}</option>'
        for c in crimes
    )
    state_opts = ''.join(
        f'<option value="{s}" {"selected" if s == sel_state else ""}>{s}</option>'
        for s in states
    )
    district_opts = '<option value="">All Districts (State-level)</option>' + ''.join(
        f'<option value="{d}" {"selected" if d == sel_district else ""}>{d}</option>'
        for d in districts_for_selected
    )
    year_opts_s = ''.join(
        f'<option value="{y}" {"selected" if y == sel_sy else ""}>{y}</option>'
        for y in years
    )
    year_opts_e = ''.join(
        f'<option value="{y}" {"selected" if y == sel_ey else ""}>{y}</option>'
        for y in years
    )

    # ── Run analysis only when form submitted ───────────────────────────────
    results_html = ''
    if submitted:
        try:
            data = run_full_analysis(conn, sel_crime, sel_state, sel_district, sel_sy, sel_ey)
            results_html = _build_pattern_results(data, sel_crime, sel_state, sel_district)
        except Exception as e:
            results_html = f'<div class="alert alert-danger mt-3"><b>Analysis error:</b> {escape(str(e))}</div>'

    conn.close()

    body = f"""
<div class="container-fluid py-4">
  <div class="row mb-4">
    <div class="col-12">
      <h2 style="color:#5b21b6;">🔗 AI-Powered Crime Pattern &amp; Similarity Detector</h2>
      <p class="text-muted">Analyze historical crime trends, detect anomalies, find similar crime patterns across regions, and identify clusters — powered by real NCRB/Kaggle data (2001–2013).</p>
    </div>
  </div>

  <!-- Filter Form -->
  <div class="card mb-4 p-4" style="border-left:4px solid #8b5cf6;">
    <form method="GET" action="/crime-patterns" id="patternForm">
      <div class="row g-3 align-items-end">
        <div class="col-md-3">
          <label class="form-label fw-bold">Crime Type</label>
          <select class="form-select" name="crime_type" id="crimeType">{crime_opts}</select>
        </div>
        <div class="col-md-3">
          <label class="form-label fw-bold">State / UT</label>
          <select class="form-select" name="state" id="stateSelect" onchange="loadDistricts()">{state_opts}</select>
        </div>
        <div class="col-md-2">
          <label class="form-label fw-bold">District</label>
          <select class="form-select" name="district" id="districtSelect">{district_opts}</select>
        </div>
        <div class="col-md-1">
          <label class="form-label fw-bold">From</label>
          <select class="form-select" name="start_year">{year_opts_s}</select>
        </div>
        <div class="col-md-1">
          <label class="form-label fw-bold">To</label>
          <select class="form-select" name="end_year">{year_opts_e}</select>
        </div>
        <div class="col-md-2">
          <button type="submit" class="btn w-100" style="background:#8b5cf6;color:#fff;">🔍 Analyze</button>
        </div>
      </div>
    </form>
  </div>

  {results_html}
</div>

<script>
function loadDistricts() {{
  var state = document.getElementById('stateSelect').value;
  var sel   = document.getElementById('districtSelect');
  sel.innerHTML = '<option value="">Loading...</option>';
  fetch('/api/districts?state=' + encodeURIComponent(state))
    .then(r => r.json())
    .then(function(districts) {{
      sel.innerHTML = '<option value="">All Districts (State-level)</option>';
      districts.forEach(function(d) {{
        var opt = document.createElement('option');
        opt.value = d; opt.textContent = d;
        sel.appendChild(opt);
      }});
    }})
    .catch(function() {{ sel.innerHTML = '<option value="">All Districts (State-level)</option>'; }});
}}
</script>
"""
    return render_template_string(HTML_LAYOUT, content=body)


def _build_pattern_results(data, crime_type, state, district):
    """Build the HTML results section from run_full_analysis() output."""
    if data.get('error'):
        return f'<div class="alert alert-warning mt-3">⚠️ {escape(data["error"])}</div>'

    trend    = data.get('trend', {})
    spikes   = data.get('spikes', [])
    similar  = data.get('similarity_rankings', [])
    clusters = data.get('clusters', {})
    insights = data.get('ai_insights', [])
    series   = data.get('target_series', {})
    comp_ser = data.get('comparison_series', {})

    location_label = f"{state}" + (f" / {district}" if district else " (State-level)")

    # ── Trend Card ──────────────────────────────────────────────────────────
    direction = trend.get('direction', 'N/A')
    net_pct   = trend.get('net_change_pct', 0)
    peak_yr   = trend.get('peak_year', 'N/A')
    low_yr    = trend.get('lowest_year', 'N/A')
    slope     = trend.get('slope', 0)

    dir_color  = '#2d6a4f' if direction == 'Increasing' else ('#ec4899' if direction == 'Decreasing' else '#8b5cf6')
    trend_badge = f'<span class="badge" style="background:{dir_color};font-size:1rem;">{direction}</span>'

    trend_html = f"""
<div class="card mb-4 p-4">
  <h5 style="color:#5b21b6;">📈 Trend Analysis — {escape(crime_type)} in {escape(location_label)}</h5>
  <div class="row text-center mt-3">
    <div class="col-md-3"><div class="p-3 rounded" style="background:#faf5ff;">
      <div style="font-size:1.8rem;">{trend_badge}</div><small class="text-muted">Overall Trend</small></div></div>
    <div class="col-md-3"><div class="p-3 rounded" style="background:#faf5ff;">
      <div style="font-size:1.8rem;font-weight:bold;color:#5b21b6;">{net_pct:+.1f}%</div><small class="text-muted">Net Change</small></div></div>
    <div class="col-md-3"><div class="p-3 rounded" style="background:#faf5ff;">
      <div style="font-size:1.8rem;font-weight:bold;color:#5b21b6;">{peak_yr}</div><small class="text-muted">Peak Year</small></div></div>
    <div class="col-md-3"><div class="p-3 rounded" style="background:#faf5ff;">
      <div style="font-size:1.8rem;font-weight:bold;color:#5b21b6;">{low_yr}</div><small class="text-muted">Lowest Year</small></div></div>
  </div>
</div>"""

    # ── Spikes / Drops ──────────────────────────────────────────────────────
    spike_items = ''
    for sp in spikes:
        ev_type  = sp.get('event', 'spike')
        yr       = sp.get('year', '')
        pct      = sp.get('change_pct', 0)
        prev_val = sp.get('prev_value', 0)
        cur_val  = sp.get('value', 0)
        icon = '🔺' if ev_type == 'spike' else '🔻'
        col  = '#ec4899' if ev_type == 'spike' else '#8b5cf6'
        spike_items += f'<div class="d-flex align-items-center mb-2 p-2 rounded" style="background:#fff0f6;border-left:4px solid {col};">{icon} <b class="ms-2">{yr}</b>: {ev_type.capitalize()} of <b>{pct:+.1f}%</b> &nbsp;<span class="text-muted">({int(prev_val):,} → {int(cur_val):,} cases)</span></div>'

    spikes_html = f"""
<div class="card mb-4 p-4">
  <h5 style="color:#5b21b6;">⚡ Anomaly & Spike Detection</h5>
  {''.join([spike_items]) if spikes else '<p class="text-muted">No significant anomalies detected in the selected range.</p>'}
</div>"""

    # ── Yearly trend chart + top similar overlay ────────────────────────────
    years_sorted = sorted(series.keys())
    labels_js = str(years_sorted)
    target_js  = str([series.get(y, 0) for y in years_sorted])

    # Pick top 3 similar for overlay
    top3_datasets = ''
    palette = ['#ec4899', '#f59e0b', '#10b981']
    for idx, sim in enumerate(similar[:3]):
        loc_name = sim.get('location', '')
        s_data   = comp_ser.get(loc_name, {})
        vals     = [s_data.get(y, 0) for y in years_sorted]
        color    = palette[idx]
        top3_datasets += f""",
      {{
        label: '{escape(loc_name)} ({sim.get("score_pct", 0):.1f}%)',
        data: {vals},
        borderColor: '{color}',
        backgroundColor: 'transparent',
        borderWidth: 1.5,
        borderDash: [5,3],
        pointRadius: 3
      }}"""

    trend_chart_html = f"""
<div class="card mb-4 p-4">
  <h5 style="color:#5b21b6;">📊 Yearly Crime Trend Chart</h5>
  <canvas id="trendChart" height="100"></canvas>
</div>
<script>
new Chart(document.getElementById('trendChart'), {{
  type: 'line',
  data: {{
    labels: {labels_js},
    datasets: [
      {{
        label: '{escape(location_label)}',
        data: {target_js},
        borderColor: '#8b5cf6',
        backgroundColor: 'rgba(139,92,246,0.08)',
        borderWidth: 2.5,
        fill: true,
        pointRadius: 4
      }}{top3_datasets}
    ]
  }},
  options: {{
    responsive: true,
    plugins: {{
      legend: {{ labels: {{ color: '#1a1a1a' }} }},
      title: {{ display: false }}
    }},
    scales: {{
      x: {{ ticks: {{ color: '#1a1a1a' }} }},
      y: {{ ticks: {{ color: '#1a1a1a' }} }}
    }}
  }}
}});
</script>"""

    # ── Similarity Table ────────────────────────────────────────────────────
    sim_rows = ''
    for rank, sim in enumerate(similar[:15], 1):
        loc      = sim.get('location', '')
        score    = sim.get('score_pct', 0)
        pattern  = sim.get('pattern', 'N/A')
        bar_w    = int(score)
        bar_col  = '#2d6a4f' if score >= 75 else ('#f59e0b' if score >= 50 else '#ec4899')
        medal    = ['🥇', '🥈', '🥉'][rank - 1] if rank <= 3 else str(rank)
        sim_rows += f"""
<tr>
  <td class="text-center">{medal}</td>
  <td><b>{escape(loc)}</b></td>
  <td>
    <div style="background:#ede9fe;border-radius:4px;height:14px;width:100%;">
      <div style="background:{bar_col};width:{bar_w}%;height:14px;border-radius:4px;"></div>
    </div>
    <small>{score:.1f}%</small>
  </td>
  <td><span class="badge" style="background:#8b5cf6;">{escape(pattern)}</span></td>
</tr>"""

    # Similarity bar chart (top 8)
    sim_labels = str([s.get('location','') for s in similar[:8]])
    sim_scores = str([round(s.get('score_pct', 0), 1) for s in similar[:8]])
    sim_colors_js = str(['#2d6a4f' if s.get('score_pct',0)>=75 else ('#f59e0b' if s.get('score_pct',0)>=50 else '#ec4899') for s in similar[:8]])

    if sim_rows:
        sim_table_content = f'''<table class="table table-hover"><thead><tr><th>#</th><th>Region</th><th style="width:30%">Similarity Score</th><th>Pattern</th></tr></thead><tbody>{sim_rows}</tbody></table>'''
        sim_chart_content = f'''<canvas id="simBarChart" height="80"></canvas>'''
        sim_script_content = f'''<script>new Chart(document.getElementById("simBarChart"), {{ type:"bar", data:{{ labels:{sim_labels}, datasets:[{{ label:"Similarity %", data:{sim_scores}, backgroundColor:{sim_colors_js} }}] }}, options:{{ indexAxis:"y", responsive:true, plugins:{{ legend:{{ display:false }} }}, scales:{{ x:{{ max:100, ticks:{{ color:"#1a1a1a" }} }}, y:{{ ticks:{{ color:"#1a1a1a" }} }} }} }} }});</script>'''
    else:
        sim_table_content = '<p class="text-muted">Not enough data to compute similarity rankings.</p>'
        sim_chart_content = ''
        sim_script_content = ''

    similarity_html = f"""
<div class="card mb-4 p-4">
  <h5 style="color:#5b21b6;">🔁 Similarity Rankings (Pearson Correlation)</h5>
  <p class="text-muted small">Regions with the most similar crime trend <i>shapes</i> to {escape(location_label)}. Score = correlation mapped 0–100%.</p>
  {sim_table_content}
  {sim_chart_content}
</div>
{sim_script_content}"""

    # ── Cluster Cards ───────────────────────────────────────────────────────
    cluster_cards = ''
    cluster_meta = [
        ('high_volume_high_growth',   'High Volume + High Growth',   '🔴', '#fee2e2', '#dc2626'),
        ('high_volume_low_growth',    'High Volume + Stable/Slow',   '🟠', '#fff7ed', '#ea580c'),
        ('low_volume_high_growth',    'Low Volume + High Growth',    '🟡', '#fefce8', '#ca8a04'),
        ('low_volume_low_growth',     'Low Volume + Low Activity',   '🟢', '#f0fdf4', '#16a34a'),
    ]
    for key, label, icon, bg, border in cluster_meta:
        members = clusters.get(key, [])
        badges  = ' '.join(f'<span class="badge me-1" style="background:{border};font-size:0.75rem;">{escape(m)}</span>' for m in members)
        cluster_cards += f"""
<div class="col-md-6 mb-3">
  <div class="card h-100 p-3" style="border-left:4px solid {border};background:{bg};">
    <h6 style="color:{border};">{icon} {label}</h6>
    <p class="text-muted small mb-2">{len(members)} region(s)</p>
    <div>{badges if badges else '<span class="text-muted small">No regions in this cluster</span>'}</div>
  </div>
</div>"""

    clusters_html = f"""
<div class="card mb-4 p-4">
  <h5 style="color:#5b21b6;">🗺️ Crime Clusters — {escape(crime_type)}</h5>
  <p class="text-muted small">Regions grouped by crime volume &amp; growth trend across the selected period.</p>
  <div class="row">{cluster_cards}</div>
</div>"""

    # ── AI Insights ─────────────────────────────────────────────────────────
    insight_type_style = {
        'warning':  ('⚠️', '#fef9c3', '#ca8a04'),
        'danger':   ('🚨', '#fee2e2', '#dc2626'),
        'success':  ('✅', '#f0fdf4', '#16a34a'),
        'info':     ('💡', '#eff6ff', '#2563eb'),
        'primary':  ('📌', '#f5f3ff', '#7c3aed'),
    }
    insight_items = ''
    for ins in insights:
        itype = ins.get('type', 'info')
        itext = ins.get('text', '')
        icon_d, bg_d, col_d = insight_type_style.get(itype, ('💡', '#eff6ff', '#2563eb'))
        insight_items += f'<div class="d-flex align-items-start mb-3 p-3 rounded" style="background:{bg_d};border-left:4px solid {col_d};">{icon_d}<span class="ms-2">{escape(itext)}</span></div>'

    insights_html = f"""
<div class="card mb-4 p-4">
  <h5 style="color:#5b21b6;">🤖 AI Insights</h5>
  {insight_items if insight_items else '<p class="text-muted">No insights generated.</p>'}
</div>"""

    return trend_html + spikes_html + trend_chart_html + similarity_html + clusters_html + insights_html


if __name__ == '__main__':
    init_db()
    print("Starting Crime Management Portal (Kaggle/NCRB Version) on http://127.0.0.1:5051")
    app.run(host='0.0.0.0', port=5051, debug=True)