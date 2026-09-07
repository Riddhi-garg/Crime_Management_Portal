"""
Crime Management Portal - Application Entry Point & Web Server
Integrated with Real Kaggle/NCRB Crime Statistics Dataset (2001-2014)
"""

import os
import sqlite3
import datetime
from flask import Flask, render_template_string, request, jsonify, redirect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'crms-kaggle-ncrb-key-2026'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
DB_PATH = os.path.join(DATA_DIR, 'crms.db')


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

    conn.commit()
    conn.close()


# Base Layout & Navigation Bar
HTML_NAVBAR = """
<nav class="navbar navbar-expand-lg sticky-top shadow-sm" style="background-color: #1a1a2e; border-bottom: 2px solid #c0392b;">
  <div class="container-fluid px-4">
    <a class="navbar-brand d-flex align-items-center gap-2 fw-bold" href="/" style="color: #f0c040; font-family: 'Times New Roman', Times, serif; font-size: 1.2rem;">
      <span class="fs-4">🛡️</span> CRIME MANAGEMENT PORTAL
    </a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" style="border-color: #c0392b;">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
        <li class="nav-item"><a class="nav-link" href="/" style="color: #e0e0e0; font-family: 'Times New Roman', Times, serif;">Dashboard</a></li>
        <li class="nav-item"><a class="nav-link" href="/crime-statistics" style="color: #e0e0e0; font-family: 'Times New Roman', Times, serif;">Crime Statistics &amp; Search</a></li>
        <li class="nav-item"><a class="nav-link" href="/analytics" style="color: #e0e0e0; font-family: 'Times New Roman', Times, serif;">Analytics &amp; Charts</a></li>
        <li class="nav-item"><a class="nav-link" href="/women-children-analytics" style="color: #e0e0e0; font-family: 'Times New Roman', Times, serif;">Women &amp; Children</a></li>
        <li class="nav-item"><a class="nav-link" href="/property-arrest-analytics" style="color: #e0e0e0; font-family: 'Times New Roman', Times, serif;">Property &amp; Arrests</a></li>
        <li class="nav-item"><a class="nav-link" href="/police-stations" style="color: #e0e0e0; font-family: 'Times New Roman', Times, serif;">Police Stations</a></li>
        <li class="nav-item"><a class="nav-link" href="/police-infrastructure" style="color: #e0e0e0; font-family: 'Times New Roman', Times, serif;">Police Infrastructure</a></li>
        <li class="nav-item"><a class="nav-link" href="/fir-management" style="color: #e0e0e0; font-family: 'Times New Roman', Times, serif;">FIR Management</a></li>
        <li class="nav-item"><a class="nav-link" href="/criminal-records" style="color: #e0e0e0; font-family: 'Times New Roman', Times, serif;">Criminal Records</a></li>
        <li class="nav-item"><a class="nav-link" href="/case-files" style="color: #e0e0e0; font-family: 'Times New Roman', Times, serif;">Case Files</a></li>
      </ul>
    <span class="badge p-2" style="background-color: #c0392b; font-family: 'Times New Roman', Times, serif;">NCRB / Dataful Datasets</span>
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
        h1, h2, h3, h4, h5, h6 { color: #1a1a2e; }
        .card { background-color: #f8f9fa; border: 1px solid #dee2e6; color: #1a1a1a; border-radius: 10px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); }
        .table { color: #1a1a1a; }
        .table thead th { background-color: #e8eaf0; color: #000000; border-bottom: 2px solid #1a1a2e; }
        .table tbody tr:hover { background-color: #f0f4ff; }
        .table-dark { background-color: #f8f9fa !important; color: #1a1a1a !important; border-color: #dee2e6 !important; }
        .table-dark td, .table-dark th { background-color: transparent !important; color: #1a1a1a !important; }
        .nav-link:hover { color: #c0392b !important; }
        .stats-card { background: linear-gradient(135deg, #f0f4ff 0%, #e8eeff 100%); border-left: 4px solid #1a1a2e; }
        .source-badge { font-size: 0.8rem; background: #1a1a2e; color: #f0c040; border-radius: 20px; padding: 4px 12px; }
        .form-select, .form-control { background-color: #ffffff; color: #1a1a1a; border: 1px solid #adb5bd; }
        .form-select:focus, .form-control:focus { background-color: #ffffff; color: #1a1a1a; border-color: #1a1a2e; box-shadow: 0 0 0 2px rgba(26,26,46,0.15); }
        .btn-outline-warning { border-color: #c0392b; color: #c0392b; }
        .btn-outline-warning:hover { background-color: #c0392b; color: #000000; }
        .badge.bg-secondary { background-color: #6c757d !important; color: #000000 !important; }
        .badge.bg-info { background-color: #0077b6 !important; color: #000000 !important; }
        .badge.bg-success { background-color: #2d6a4f !important; color: #000000 !important; }
        .badge.bg-danger { background-color: #c0392b !important; color: #000000 !important; }
        .badge.bg-warning { background-color: #e67e22 !important; color: #000000 !important; }
        .badge.bg-primary { background-color: #1a1a2e !important; color: #000000 !important; }
        .text-warning { color: #c0392b !important; }
        .text-info { color: #0077b6 !important; }
        .text-danger { color: #c0392b !important; }
        .text-success { color: #2d6a4f !important; }
        .text-secondary { color: #555555 !important; }
        .text-muted { color: #777777 !important; }
        .text-light { color: #1a1a1a !important; }
        .btn-warning { background-color: #c0392b; border-color: #c0392b; color: #000000; }
        .btn-warning:hover { background-color: #a93226; border-color: #a93226; color: #000000; }
        .btn-primary { background-color: #1a1a2e; border-color: #1a1a2e; color: #000000; }
        .btn-primary:hover { background-color: #2c2c4e; border-color: #2c2c4e; color: #000000; }
        .btn-outline-light { border-color: #1a1a2e; color: #1a1a2e; }
        .btn-outline-light:hover { background-color: #e8eaf0; color: #000000; }
        .btn-outline-info { border-color: #0077b6; color: #0077b6; }
        .btn-outline-info:hover { background-color: #d0eaf8; color: #000000; }
        .btn-outline-danger { border-color: #c0392b; color: #c0392b; }
        .btn-outline-danger:hover { background-color: #fde8e8; color: #000000; }
        .btn-outline-success { border-color: #2d6a4f; color: #2d6a4f; }
        .btn-outline-success:hover { background-color: #d4edda; color: #000000; }
        .btn-outline-secondary { border-color: #6c757d; color: #6c757d; }
        .btn-outline-secondary:hover { background-color: #e2e3e5; color: #000000; }
        .btn-outline-primary { border-color: #1a1a2e; color: #1a1a2e; }
        .btn-outline-primary:hover { background-color: #e8eaf0; color: #000000; }
        .list-group-item { background-color: #f8f9fa; color: #1a1a1a; border-color: #dee2e6; }
        .border-secondary { border-color: #dee2e6 !important; }
        a { color: #0077b6; }
        a:hover { color: #c0392b; }
        footer { background-color: #f8f9fa; color: #555555; border-top: 1px solid #dee2e6 !important; }
        .pagination .page-link { background-color: #f8f9fa; color: #1a1a2e; border-color: #dee2e6; }
        .pagination .page-link:hover { background-color: #e8eaf0; color: #000000; }
    </style>
</head>
<body style="background-color: #ffffff;">
    """ + HTML_NAVBAR + """
    <div class="container-fluid px-4 py-4">
        {{ content | safe }}
    </div>
    <footer class="text-center py-3 mt-5" style="background-color: #f8f9fa; border-top: 1px solid #dee2e6;">
        <small style="color: #555555;">Data Source: Kaggle / NCRB and Dataful / BPRD datasets | Crime Management Portal</small>
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
            <div class="p-4 rounded-3 card shadow-sm text-center bg-dark border-warning">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <span class="source-badge">Official NCRB / Kaggle Crime Dataset</span>
                    <span class="text-secondary small">Years Covered: {min_yr} – {max_yr}</span>
                </div>
                <h1 class="display-6 text-warning fw-bold">National Crime Management Portal</h1>
                <p class="lead text-secondary mb-3">Live Dynamic Insights from 35+ Million Real NCRB Recorded Crime Cases</p>
                <div class="d-flex justify-content-center gap-3">
                    <a href="/crime-statistics" class="btn btn-warning fw-bold px-4">🔍 Search Crime Records</a>
                    <a href="/analytics" class="btn btn-primary fw-bold px-4">📊 Interactive Visual Analytics</a>
                    <a href="/women-children-analytics" class="btn btn-outline-light px-4">👧 Women & Children Reports</a>
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
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #ef4444;">
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
        <div class="col-md-6">
            <div class="card p-4 h-100">
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
        <div class="col-md-6">
            <div class="card p-4 h-100">
                <h5 class="text-info mb-3">⚡ Quick Portal Navigation</h5>
                <div class="d-grid gap-2">
                    <a href="/crime-statistics" class="btn btn-outline-warning text-start py-2">🔍 District & State Multi-Filter Query Engine</a>
                    <a href="/analytics" class="btn btn-outline-primary text-start py-2">📈 Interactive State & Yearly Trend Charts</a>
                    <a href="/women-children-analytics" class="btn btn-outline-danger text-start py-2">👩 Women & Children Protection Reports</a>
                    <a href="/property-arrest-analytics" class="btn btn-outline-success text-start py-2">💰 Property Recovery & Police Arrest Rates</a>
                    <a href="/api/stats" class="btn btn-outline-secondary text-start py-2" target="_blank">🔗 Access REST API Statistics Endpoint</a>
                </div>
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
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.15)',
                    fill: true,
                    tension: 0.3
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ labels: {{ color: '#f8fafc' }} }} }},
                scales: {{
                    x: {{ ticks: {{ color: '#cbd5e1' }}, grid: {{ color: '#334155' }} }},
                    y: {{ ticks: {{ color: '#cbd5e1' }}, grid: {{ color: '#334155' }} }}
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
                    backgroundColor: ['#ef4444', '#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16', '#6366f1', '#14b8a6']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#f8fafc', font: {{ size: 10 }} }} }} }}
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
                    backgroundColor: '#3b82f6'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ labels: {{ color: '#f8fafc' }} }} }},
                scales: {{
                    x: {{ ticks: {{ color: '#cbd5e1' }}, grid: {{ color: '#334155' }} }},
                    y: {{ ticks: {{ color: '#cbd5e1' }}, grid: {{ color: '#334155' }} }}
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

    prop_rows = "".join([f"<tr><td class='fw-bold text-warning'>{p['state']}</td><td class='text-danger'>{p['stolen']:,}</td><td class='text-success'>{p['recovered']:,}</td></tr>" for p in prop_data])
    arrest_rows = "".join([f"<tr><td>{a['crime_head']}</td><td class='text-warning'>{a['arrested']:,}</td><td class='text-success'>{a['convicted']:,}</td><td class='text-danger'>{a['acquitted']:,}</td></tr>" for a in arrest_data])

    body = f"""
    <h2 class="text-success mb-4">💰 Property Crimes & Police Arrest Statistics</h2>
    <div class="row g-4">
        <div class="col-md-6">
            <div class="card p-4">
                <h4 class="text-warning mb-3">🏡 Stolen vs Recovered Property (Top States)</h4>
                <div class="table-responsive">
                    <table class="table table-dark table-hover align-middle">
                        <thead><tr><th>State / UT</th><th>Stolen Cases</th><th>Recovered Cases</th></tr></thead>
                        <tbody>{prop_rows}</tbody>
                    </table>
                </div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="card p-4">
                <h4 class="text-info mb-3">⚖️ Arrests, Convictions & Acquittals</h4>
                <div class="table-responsive">
                    <table class="table table-dark table-hover align-middle">
                        <thead><tr><th>Crime Head</th><th>Arrested</th><th>Convicted</th><th>Acquitted</th></tr></thead>
                        <tbody>{arrest_rows}</tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    """
    return render_template_string(HTML_LAYOUT, content=body)


@app.route('/police-infrastructure')
def police_infrastructure():
    conn = get_db_connection()
    if not _table_exists(conn, 'police_infrastructure_statistics'):
        conn.close()
        return render_template_string(
            HTML_LAYOUT,
            content="<h2 class='text-info'>Police Infrastructure</h2><p>Run the dataset import to load Dataful dataset 20145.</p>"
        )

    rows = conn.execute("""
        SELECT state, station_or_outpost, station_or_outpost_type,
               SUM(CASE WHEN category = 'Actual' THEN value ELSE 0 END) AS actual,
               SUM(CASE WHEN category = 'Sanctioned' THEN value ELSE 0 END) AS sanctioned
        FROM police_infrastructure_statistics
        GROUP BY state, station_or_outpost, station_or_outpost_type
        ORDER BY state, station_or_outpost, station_or_outpost_type
    """).fetchall()
    conn.close()

    table_rows = ''.join(
        f"<tr><td>{row['state']}</td><td>{row['station_or_outpost']}</td>"
        f"<td>{row['station_or_outpost_type']}</td><td>{row['sanctioned']:,}</td>"
        f"<td>{row['actual']:,}</td></tr>"
        for row in rows
    ) or "<tr><td colspan='5' class='text-center text-muted py-4'>No Dataful police infrastructure records loaded.</td></tr>"

    body = f"""
    <h2 class="text-info mb-2">Police Stations &amp; Outposts</h2>
    <p class="text-muted">Dataful dataset 20145, sourced from the Bureau of Police Research and Development.</p>
    <div class="card p-4"><div class="table-responsive"><table class="table table-dark table-hover align-middle">
        <thead><tr><th>State / UT</th><th>Asset</th><th>Region</th><th>Sanctioned</th><th>Actual</th></tr></thead>
        <tbody>{table_rows}</tbody>
    </table></div></div>
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
    station_options = "".join(f'<option value="{s["station_id"]}">{s["station_name"]}</option>' for s in stations)

    body = f"""
    <h2 class="text-warning mb-3">🏢 Police Stations & Officer Directory</h2>
    <div class="card p-4 mb-4">
        <div class="d-flex justify-content-between align-items-center mb-3"><h4 class="text-info m-0">Police Precincts</h4><a href="/police-stations#add-station" class="btn btn-warning btn-sm">Add Station</a></div>
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
            <div class="col-md-2"><select class="form-select" name="station_id" required><option value="">Station</option>{station_options}</select></div>
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
    conn.execute("INSERT INTO police_officers (name, rank, badge_number, phone, email, station_id) VALUES (?, ?, ?, ?, ?, ?)",
                 (request.form['name'], request.form['rank'], request.form['badge_number'], request.form['phone'], request.form['email'], request.form['station_id']))
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
    station_options = "".join(f'<option value="{s["station_id"]}">{s["station_name"]}</option>' for s in stations) or '<option value="" disabled selected>Add a police station first</option>'
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
    cur.execute("INSERT INTO crimes (crime_type, description, crime_date, crime_time, location, city, state, severity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (request.form['crime_type'], request.form['crime_description'], request.form['crime_date'], request.form.get('crime_time') or None,
                 request.form['location'], request.form['city'], request.form['state'], request.form['severity']))
    crime_id = cur.lastrowid
    cur.execute("INSERT INTO victims (name, age, gender, address, phone) VALUES (?, ?, ?, ?, ?)",
                (request.form['victim_name'], request.form.get('victim_age') or None, request.form.get('victim_gender', 'Other'), request.form.get('victim_address'), request.form['victim_phone']))
    victim_id = cur.lastrowid
    cur.execute("INSERT INTO FIR (fir_number, crime_id, victim_id, station_id, filing_date, description) VALUES (?, ?, ?, ?, ?, ?)",
                (request.form['fir_number'], crime_id, victim_id, request.form['station_id'], request.form['filing_date'], request.form['fir_description']))
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
            "dataset_source": "Kaggle / NCRB Crime Statistics and Dataful / BPRD datasets",
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
        if _table_exists(conn, 'police_infrastructure_statistics'):
            stats["police_infrastructure_records"] = conn.execute(
                "SELECT COUNT(*) FROM police_infrastructure_statistics"
            ).fetchone()[0]
            stats["police_infrastructure_source"] = "Dataful/BPRD Dataset 20145"
    except Exception as e:
        stats = {"error": str(e)}
    return jsonify(stats)


if __name__ == '__main__':
    init_db()
    print("Starting Crime Management Portal (Kaggle/NCRB Version) on http://127.0.0.1:5050")
    app.run(host='0.0.0.0', port=5050, debug=True)