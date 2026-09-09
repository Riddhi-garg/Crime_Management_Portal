"""
Crime Management Portal - Application Entry Point & Web Server
Integrated with Real Kaggle/NCRB Crime Statistics Dataset (2001-2014)
"""

import os
import json
import sqlite3
import datetime
from datetime import timedelta
import secrets
import smtplib
from email.mime.text import MIMEText
from functools import wraps
from html import escape
from flask import Flask, render_template_string, request, jsonify, redirect, flash, url_for, send_from_directory, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from crime_pattern_analysis import get_filter_options, get_districts_for_state, run_full_analysis

# The four account types the portal issues logins to. Every users.role value
# must be one of these; the login/registration flow only ever assigns one of
# these four.
ROLES = ['Citizen', 'Police', 'Court', 'District Magistrate']

# Which of the four roles may reach which write actions. View-only pages are
# open to any signed-in user regardless of role.
ROLE_PERMISSIONS = {
    'add_police_station':   ['Police', 'District Magistrate'],
    'add_police_officer':   ['Police', 'District Magistrate'],
    'add_fir':               ['Citizen', 'Police', 'District Magistrate'],
    'update_fir_status':     ['Police', 'District Magistrate'],
    'add_criminal':          ['Police', 'District Magistrate'],
    'update_criminal_status':['Police', 'District Magistrate'],
    'add_case':               ['Court', 'Police', 'District Magistrate'],
    'update_case_status':     ['Court', 'District Magistrate'],
}

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


def get_role_dashboard_url(role):
    """Return the dedicated landing dashboard route for a given user role."""
    mapping = {
        'Citizen': '/dashboard/citizen',
        'Police': '/dashboard/police',
        'Court': '/dashboard/court',
        'District Magistrate': '/dashboard/district-magistrate'
    }
    return mapping.get(role, '/')


def send_email(to_email, subject, body):
    """
    Send an email via SMTP if configured via environment variables.
    Otherwise, log the complete email with verification link to console as a safe fallback.
    """
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASSWORD') or os.environ.get('SMTP_PASS')

    if smtp_host and smtp_user and smtp_pass:
        try:
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = smtp_user
            msg['To'] = to_email
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            print(f"[EMAIL] Verification email sent to {to_email} via SMTP ({smtp_host}).")
            return True
        except Exception as e:
            print(f"[EMAIL ERROR] SMTP delivery failed: {e}. Falling back to console dispatch.")

    # Safe fallback: Print email details to console/log
    print("\n" + "=" * 70)
    print(f"[EMAIL NOTIFICATION - CONSOLE FALLBACK]")
    print(f"To: {to_email}")
    print(f"Subject: {subject}")
    print("-" * 70)
    print(body)
    print("=" * 70 + "\n")
    return True


def render_page(content, status_code=200):
    """Render a page inside the shared layout, injecting the signed-in user
    (if any) so the navbar can show who's logged in and display role-specific links."""
    role = session.get('role')
    html = render_template_string(
        HTML_LAYOUT,
        content=content,
        current_user_name=session.get('full_name'),
        current_user_role=role,
        role_dashboard_url=get_role_dashboard_url(role) if role else '/',
    )
    return (html, status_code) if status_code != 200 else html


def login_required(view_func):
    """Redirect anonymous visitors to /login, preserving where they were headed."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login', next=request.path))
        return view_func(*args, **kwargs)
    return wrapped


def roles_required(*allowed_roles):
    """Restrict a view to specific roles; anonymous users go to /login first."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not session.get('user_id'):
                return redirect(url_for('login', next=request.path))
            if session.get('role') not in allowed_roles:
                return render_page(
                    f"""<div class="alert alert-danger mt-4">
                        Your account role ({escape(session.get('role', ''))}) does not have
                        permission to perform this action. This action is limited to:
                        {escape(', '.join(allowed_roles))}.
                    </div>""",
                    403,
                )
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


@app.before_request
def _require_login_globally():
    """Gate every route except public authentication endpoints and static assets."""
    public_endpoints = {'login', 'logout', 'signup', 'verify_email', 'resend_verification', 'static'}
    if request.endpoint in public_endpoints or request.endpoint is None:
        return None
    if not session.get('user_id'):
        return redirect(url_for('login', next=request.path))
    return None


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
        role TEXT NOT NULL DEFAULT 'Citizen',
        full_name TEXT NOT NULL,
        email TEXT UNIQUE,
        email_verified INTEGER DEFAULT 0,
        verification_token TEXT,
        token_expiry TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Schema migration for existing users table
    cursor.execute("PRAGMA table_info(users)")
    existing_cols = [row[1] for row in cursor.fetchall()]
    if 'email_verified' not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0")
    if 'verification_token' not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN verification_token TEXT")
    if 'token_expiry' not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN token_expiry TIMESTAMP")

    # Seed one login per role the first time the app runs. Passwords are
    # hashed with werkzeug's default (PBKDF2) — never stored in plain text.
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_accounts = [
            # (full_name, email, temporary password, role)
            ("Citizen Portal Account",        "citizen@crms.gov.in",     "Citizen@123",     "Citizen"),
            ("Police Station Account",        "police@crms.gov.in",      "Police@123",      "Police"),
            ("District Court Account",        "court@crms.gov.in",       "Court@123",       "Court"),
            ("District Magistrate Account",   "magistrate@crms.gov.in",  "Magistrate@123",  "District Magistrate"),
        ]
        for full_name, email, temp_password, role in default_accounts:
            cursor.execute(
                "INSERT INTO users (username, password, role, full_name, email, email_verified) VALUES (?, ?, ?, ?, ?, 1)",
                (email, generate_password_hash(temp_password), role, full_name, email)
            )
        conn.commit()
    else:
        # Ensure seeded default accounts are marked email_verified = 1
        default_emails = ["citizen@crms.gov.in", "police@crms.gov.in", "court@crms.gov.in", "magistrate@crms.gov.in"]
        for email in default_emails:
            cursor.execute("UPDATE users SET email_verified = 1 WHERE lower(email) = ?", (email.lower(),))
        conn.commit()

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
<nav class="navbar navbar-expand-lg sticky-top shadow-sm" style="background-color: #374151; border-bottom: 2px solid #D6cfc4;">
  <div class="container-fluid px-4">
    <a class="navbar-brand d-flex align-items-center gap-2 fw-bold" href="{{ role_dashboard_url or '/' }}" style="color: #ffffff; font-family: 'Times New Roman', Times, serif; font-size: 1.2rem;">
      CRIME MANAGEMENT PORTAL
    </a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" style="border-color: #D6cfc4;">
      <span class="navbar-toggler-icon" style="filter: invert(1);"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
        <li class="nav-item"><a class="nav-link" href="{{ role_dashboard_url or '/' }}" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Dashboard</a></li>

        {% if current_user_role == 'Citizen' %}
          <li class="nav-item"><a class="nav-link" href="/fir-management" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">File / Track FIR</a></li>
          <li class="nav-item"><a class="nav-link" href="/police-stations" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Police Stations</a></li>
          <li class="nav-item"><a class="nav-link" href="/police-station-map" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Station Map</a></li>
          <li class="nav-item"><a class="nav-link" href="/crime-statistics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Crime Statistics</a></li>
          <li class="nav-item"><a class="nav-link" href="/analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Analytics &amp; Charts</a></li>
          <li class="nav-item"><a class="nav-link" href="/women-children-analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Women &amp; Children</a></li>

        {% elif current_user_role == 'Police' %}
          <li class="nav-item"><a class="nav-link" href="/fir-management" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">FIR Management</a></li>
          <li class="nav-item"><a class="nav-link" href="/criminal-records" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Criminal Records</a></li>
          <li class="nav-item"><a class="nav-link" href="/case-files" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Case Files</a></li>
          <li class="nav-item"><a class="nav-link" href="/police-stations" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Police Stations</a></li>
          <li class="nav-item"><a class="nav-link" href="/police-station-map" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Station Map</a></li>
          <li class="nav-item"><a class="nav-link" href="/crime-patterns" style="color: #D6cfc4; font-weight: bold; font-family: 'Times New Roman', Times, serif;">Pattern Detector</a></li>
          <li class="nav-item"><a class="nav-link" href="/analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Analytics &amp; Charts</a></li>

        {% elif current_user_role == 'Court' %}
          <li class="nav-item"><a class="nav-link" href="/case-files" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Case Files</a></li>
          <li class="nav-item"><a class="nav-link" href="/fir-management" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">FIR Records</a></li>
          <li class="nav-item"><a class="nav-link" href="/criminal-records" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Criminal Records</a></li>
          <li class="nav-item"><a class="nav-link" href="/property-arrest-analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Property &amp; Arrests</a></li>
          <li class="nav-item"><a class="nav-link" href="/crime-statistics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Crime Statistics</a></li>
          <li class="nav-item"><a class="nav-link" href="/analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Analytics &amp; Charts</a></li>

        {% elif current_user_role == 'District Magistrate' %}
          <li class="nav-item"><a class="nav-link" href="/fir-management" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">FIR Management</a></li>
          <li class="nav-item"><a class="nav-link" href="/criminal-records" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Criminal Records</a></li>
          <li class="nav-item"><a class="nav-link" href="/case-files" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Case Files</a></li>
          <li class="nav-item"><a class="nav-link" href="/police-stations" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Police Stations</a></li>
          <li class="nav-item"><a class="nav-link" href="/crime-patterns" style="color: #D6cfc4; font-weight: bold; font-family: 'Times New Roman', Times, serif;">Pattern Detector</a></li>
          <li class="nav-item"><a class="nav-link" href="/analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Analytics &amp; Charts</a></li>
          <li class="nav-item"><a class="nav-link" href="/women-children-analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Women &amp; Children</a></li>
          <li class="nav-item"><a class="nav-link" href="/property-arrest-analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Property &amp; Arrests</a></li>

        {% else %}
          <li class="nav-item"><a class="nav-link" href="/analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Analytics &amp; Charts</a></li>
          <li class="nav-item"><a class="nav-link" href="/women-children-analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Women &amp; Children</a></li>
          <li class="nav-item"><a class="nav-link" href="/property-arrest-analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Property &amp; Arrests</a></li>
          <li class="nav-item"><a class="nav-link" href="/police-stations" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Police Stations</a></li>
          <li class="nav-item"><a class="nav-link" href="/police-station-map" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Station Map</a></li>
          <li class="nav-item"><a class="nav-link" href="/fir-management" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">FIR Management</a></li>
          <li class="nav-item"><a class="nav-link" href="/criminal-records" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Criminal Records</a></li>
          <li class="nav-item"><a class="nav-link" href="/case-files" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Case Files</a></li>
          <li class="nav-item"><a class="nav-link" href="/crime-patterns" style="color: #D6cfc4; font-weight: bold; font-family: 'Times New Roman', Times, serif;">Pattern Detector</a></li>
        {% endif %}
      </ul>
      {% if current_user_name %}
      <span class="d-flex align-items-center gap-2" style="font-family: 'Times New Roman', Times, serif;">
        <span class="small" style="color: #D6cfc4;">{{ current_user_name }} &middot; <strong>{{ current_user_role }}</strong></span>
        <a href="/logout" class="btn btn-sm btn-outline-light">Sign Out</a>
      </span>
      {% endif %}
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
        h1, h2, h3, h4, h5, h6 { color: #1f2937; }
        .card { background-color: #f8f9fa; border: 1px solid #dee2e6; color: #1a1a1a; border-radius: 10px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); }
        .table { color: #1a1a1a; }
        .table thead th { background-color: #e5e7eb; color: #1f2937; border-bottom: 2px solid #9ca3af; }
        .table tbody tr:hover { background-color: #f3f4f6; }
        .table-dark { background-color: #f8f9fa !important; color: #1a1a1a !important; border-color: #dee2e6 !important; }
        .table-dark td, .table-dark th { background-color: transparent !important; color: #1a1a1a !important; }
        .nav-link:hover { color: #D6cfc4 !important; }
        .stats-card { background: linear-gradient(135deg, #f9fafb 0%, #f3f4f6 100%); border-left: 4px solid #4b5563; }
        .source-badge { font-size: 0.8rem; background: #4b5563; color: #ffffff; border-radius: 20px; padding: 4px 12px; }
        .form-select, .form-control { background-color: #ffffff; color: #1a1a1a; border: 1px solid #adb5bd; }
        .form-select:focus, .form-control:focus { background-color: #ffffff; color: #1a1a1a; border-color: #4b5563; box-shadow: 0 0 0 2px rgba(75,85,99,0.2); }
        .btn-outline-warning { border-color: #4b5563; color: #1f2937; }
        .btn-outline-warning:hover { background-color: #4b5563; color: #ffffff; }
        .badge.bg-secondary { background-color: #6c757d !important; color: #ffffff !important; }
        .badge.bg-info { background-color: #4b5563 !important; color: #ffffff !important; }
        .badge.bg-success { background-color: #2d6a4f !important; color: #ffffff !important; }
        .badge.bg-danger { background-color: #991b1b !important; color: #ffffff !important; }
        .badge.bg-warning { background-color: #d97706 !important; color: #ffffff !important; }
        .badge.bg-primary { background-color: #374151 !important; color: #ffffff !important; }
        .text-warning { color: #854d0e !important; }
        .text-info { color: #374151 !important; }
        .text-danger { color: #991b1b !important; }
        .text-success { color: #2d6a4f !important; }
        .text-secondary { color: #555555 !important; }
        .text-muted { color: #777777 !important; }
        .text-light { color: #1a1a1a !important; }
        .btn-warning { background-color: #D6cfc4; border-color: #b8b1a5; color: #1f2937; }
        .btn-warning:hover { background-color: #c5bdae; border-color: #a8a094; color: #111827; }
        .btn-primary { background-color: #374151; border-color: #374151; color: #ffffff; }
        .btn-primary:hover { background-color: #1f2937; border-color: #1f2937; color: #ffffff; }
        .btn-outline-light { border-color: #D6cfc4; color: #D6cfc4; }
        .btn-outline-light:hover { background-color: #D6cfc4; color: #1f2937; }
        .btn-outline-info { border-color: #4b5563; color: #4b5563; }
        .btn-outline-info:hover { background-color: #e5e7eb; color: #1f2937; }
        .btn-outline-danger { border-color: #991b1b; color: #991b1b; }
        .btn-outline-danger:hover { background-color: #fee2e2; color: #7f1d1d; }
        .btn-outline-success { border-color: #2d6a4f; color: #2d6a4f; }
        .btn-outline-success:hover { background-color: #d4edda; color: #000000; }
        .btn-outline-secondary { border-color: #6c757d; color: #6c757d; }
        .btn-outline-secondary:hover { background-color: #e2e3e5; color: #000000; }
        .btn-outline-primary { border-color: #4b5563; color: #374151; }
        .btn-outline-primary:hover { background-color: #e5e7eb; color: #111827; }
        .list-group-item { background-color: #f8f9fa; color: #1a1a1a; border-color: #dee2e6; }
        .border-secondary { border-color: #dee2e6 !important; }
        a { color: #374151; }
        a:hover { color: #111827; }
        footer { background-color: #f8f9fa; color: #555555; border-top: 1px solid #dee2e6 !important; }
        .pagination .page-link { background-color: #f8f9fa; color: #374151; border-color: #dee2e6; }
        .pagination .page-link:hover { background-color: #e5e7eb; color: #111827; }
    </style>
</head>
<body style="background-color: #ffffff;">
    """ + HTML_NAVBAR + """
    <div class="container-fluid px-4 py-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert alert-{{ category if category != 'message' else 'info' }} alert-dismissible fade show" role="alert">
                {{ message | safe }}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
              </div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        {{ content | safe }}
    </div>
    <footer class="text-center py-3 mt-5" style="background-color: #f8f9fa; border-top: 1px solid #dee2e6;">
        <small style="color: #555555;">Data Source: Kaggle / NCRB Crime Statistics Dataset (2001-2014) | Crime Management Portal</small>
    </footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""


# AUTHENTICATION
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET' and session.get('user_id'):
        return redirect(get_role_dashboard_url(session.get('role')))
    error = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE lower(email) = ?", (email,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            if not user['email_verified']:
                error = 'Your email address is not verified yet. Please check your inbox or <a href="/resend-verification" class="alert-link text-decoration-underline">click here to resend the verification email</a>.'
            else:
                session.clear()
                session['user_id'] = user['user_id']
                session['role'] = user['role']
                session['full_name'] = user['full_name']
                session['email'] = user['email']
                next_url = request.args.get('next')
                if next_url and next_url.startswith('/') and not next_url.startswith('//'):
                    return redirect(next_url)
                return redirect(get_role_dashboard_url(user['role']))
        else:
            error = "No account matches that email address and password."

    error_html = f'<div class="alert alert-danger py-2">{error}</div>' if error else ''
    content = f"""
    <div class="row justify-content-center">
      <div class="col-md-5 col-lg-4">
        <div class="card p-4 shadow-sm mt-5">
          <h3 class="text-center mb-1" style="color: #1f2937;">Crime Management Portal</h3>
          <p class="text-center text-muted mb-4">Sign in with your registered account</p>
          {error_html}
          <form method="POST">
            <div class="mb-3">
              <label class="form-label fw-semibold">Email address</label>
              <input type="email" name="email" class="form-control" placeholder="name@example.com" required autofocus>
            </div>
            <div class="mb-3">
              <label class="form-label fw-semibold">Password</label>
              <input type="password" name="password" class="form-control" placeholder="Password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100 py-2">Sign In</button>
          </form>

          <div class="text-center mt-3 pt-2 border-top">
            <p class="mb-1 small text-muted">Don't have an account yet?</p>
            <a href="/signup" class="btn btn-sm btn-outline-primary fw-semibold w-100 mb-2">Create New Account</a>
            <a href="/resend-verification" class="small text-muted text-decoration-none">Resend Email Verification</a>
          </div>

          <hr class="my-3">
          <p class="small text-muted mb-1 fw-semibold">Portal Account Types:</p>
          <ul class="small text-muted mb-0 ps-3">
            <li><strong>Citizen</strong> — file and track personal FIRs</li>
            <li><strong>Police</strong> — FIRs, criminal records, stations</li>
            <li><strong>Court</strong> — case files, hearings, judicial oversight</li>
            <li><strong>District Magistrate</strong> — executive law & order oversight</li>
          </ul>
        </div>
      </div>
    </div>
    """
    return render_template_string(HTML_LAYOUT, content=content, current_user_name=None, current_user_role=None)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET' and session.get('user_id'):
        return redirect(get_role_dashboard_url(session.get('role')))
    error = None
    form_data = {'full_name': '', 'email': '', 'role': 'Citizen'}
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        role = request.form.get('role', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        form_data = {'full_name': full_name, 'email': email, 'role': role}

        if not full_name or not email or not password or not confirm_password or not role:
            error = "All fields are required."
        elif role not in ROLES:
            error = f"Invalid role selected. Must be one of: {', '.join(ROLES)}."
        elif '@' not in email or '.' not in email.split('@')[-1]:
            error = "Please enter a valid email address."
        elif len(password) < 6:
            error = "Password must be at least 6 characters long."
        elif password != confirm_password:
            error = "Passwords do not match."
        else:
            conn = get_db_connection()
            existing = conn.execute("SELECT user_id FROM users WHERE lower(email) = ?", (email,)).fetchone()
            if existing:
                conn.close()
                error = "An account with that email address already exists. Please sign in or use another email."
            else:
                verification_token = secrets.token_urlsafe(32)
                token_expiry = (datetime.datetime.now() + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
                pwd_hash = generate_password_hash(password)
                conn.execute(
                    """
                    INSERT INTO users (username, password, role, full_name, email, email_verified, verification_token, token_expiry)
                    VALUES (?, ?, ?, ?, ?, 0, ?, ?)
                    """,
                    (email, pwd_hash, role, full_name, email, verification_token, token_expiry)
                )
                conn.commit()
                conn.close()

                verify_url = request.url_root.rstrip('/') + url_for('verify_email', token=verification_token)
                email_body = f"""Hello {full_name},

Thank you for registering on the Crime Management Portal.

Please verify your email address to activate your {role} account by clicking the link below (valid for 24 hours):

{verify_url}

If you did not register for an account, you can safely ignore this message.

Crime Management Portal
National Crime Records System
"""
                send_email(to_email=email, subject="Verify your Crime Management Portal account", body=email_body)
                flash("Registration successful! A verification link has been sent to your email. Please verify before signing in.", "success")
                return redirect(url_for('login'))

    error_html = f'<div class="alert alert-danger py-2">{escape(error)}</div>' if error else ''
    role_options = "".join([
        f'<option value="{r}" {"selected" if r == form_data.get("role") else ""}>{r}</option>'
        for r in ROLES
    ])

    content = f"""
    <div class="row justify-content-center">
      <div class="col-md-6 col-lg-5">
        <div class="card p-4 shadow-sm mt-4">
          <h3 class="text-center mb-1" style="color: #1f2937;">Create an Account</h3>
          <p class="text-center text-muted mb-4">Register for Crime Management Portal Access</p>
          {error_html}
          <form method="POST">
            <div class="mb-3">
              <label class="form-label fw-semibold">Full Name</label>
              <input type="text" name="full_name" class="form-control" placeholder="e.g. Rajesh Sharma" value="{escape(form_data.get('full_name', ''))}" required autofocus>
            </div>
            <div class="mb-3">
              <label class="form-label fw-semibold">Email Address</label>
              <input type="email" name="email" class="form-control" placeholder="name@example.com" value="{escape(form_data.get('email', ''))}" required>
            </div>
            <div class="mb-3">
              <label class="form-label fw-semibold">Account Role</label>
              <select name="role" class="form-select" required>
                {role_options}
              </select>
              <div class="form-text text-muted">Select role: Citizen, Police, Court, or District Magistrate.</div>
            </div>
            <div class="row">
              <div class="col-md-6 mb-3">
                <label class="form-label fw-semibold">Password</label>
                <input type="password" name="password" class="form-control" placeholder="At least 6 chars" required>
              </div>
              <div class="col-md-6 mb-3">
                <label class="form-label fw-semibold">Confirm Password</label>
                <input type="password" name="confirm_password" class="form-control" placeholder="Confirm password" required>
              </div>
            </div>
            <button type="submit" class="btn btn-primary w-100 py-2 mt-2">Create Account</button>
          </form>
          <hr class="my-3">
          <div class="text-center">
            <span class="text-muted small">Already have an account?</span>
            <a href="/login" class="fw-semibold small ms-1">Sign In</a>
          </div>
        </div>
      </div>
    </div>
    """
    return render_template_string(HTML_LAYOUT, content=content, current_user_name=None, current_user_role=None)


@app.route('/verify-email/<token>')
def verify_email(token):
    token = (token or '').strip()
    if not token:
        flash("Invalid verification link.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE verification_token = ?", (token,)).fetchone()
    if not user:
        conn.close()
        flash("Invalid or already used verification link. If you need a new link, please request one below.", "danger")
        return redirect(url_for('resend_verification'))

    # Check token expiry if set
    if user['token_expiry']:
        try:
            expiry = datetime.datetime.strptime(user['token_expiry'], '%Y-%m-%d %H:%M:%S')
            if datetime.datetime.now() > expiry:
                conn.close()
                flash("This verification link has expired (24-hour validity). Please enter your email below to request a new link.", "warning")
                return redirect(url_for('resend_verification'))
        except Exception:
            pass

    conn.execute(
        "UPDATE users SET email_verified = 1, verification_token = NULL, token_expiry = NULL WHERE user_id = ?",
        (user['user_id'],)
    )
    conn.commit()
    conn.close()

    flash("Your email address has been successfully verified! You may now sign in.", "success")
    return redirect(url_for('login'))


@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'GET' and session.get('user_id'):
        return redirect(get_role_dashboard_url(session.get('role')))
    error = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            error = "Please provide your registered email address."
        else:
            conn = get_db_connection()
            user = conn.execute("SELECT * FROM users WHERE lower(email) = ?", (email,)).fetchone()
            if not user:
                conn.close()
                flash("If an account exists with that email address, a verification link has been dispatched.", "info")
                return redirect(url_for('login'))

            if user['email_verified']:
                conn.close()
                flash("This account is already verified. Please sign in with your credentials.", "info")
                return redirect(url_for('login'))

            new_token = secrets.token_urlsafe(32)
            token_expiry = (datetime.datetime.now() + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
            conn.execute(
                "UPDATE users SET verification_token = ?, token_expiry = ? WHERE user_id = ?",
                (new_token, token_expiry, user['user_id'])
            )
            conn.commit()
            conn.close()

            verify_url = request.url_root.rstrip('/') + url_for('verify_email', token=new_token)
            email_body = f"""Hello {user['full_name']},

A request was received to resend your Crime Management Portal verification link.

Please click the link below to verify your email and activate your {user['role']} account (valid for 24 hours):

{verify_url}

If you did not request this, you can safely ignore this email.

Crime Management Portal
National Crime Records System
"""
            send_email(to_email=user['email'], subject="Verify your Crime Management Portal account", body=email_body)
            flash("A fresh verification link has been sent to your email address.", "success")
            return redirect(url_for('login'))

    error_html = f'<div class="alert alert-danger py-2">{escape(error)}</div>' if error else ''
    content = f"""
    <div class="row justify-content-center">
      <div class="col-md-5 col-lg-4">
        <div class="card p-4 shadow-sm mt-5">
          <h3 class="text-center mb-1" style="color: #1f2937;">Resend Verification</h3>
          <p class="text-center text-muted mb-4">Enter your email to receive a new verification link</p>
          {error_html}
          <form method="POST">
            <div class="mb-3">
              <label class="form-label fw-semibold">Email address</label>
              <input type="email" name="email" class="form-control" placeholder="name@example.com" required autofocus>
            </div>
            <button type="submit" class="btn btn-primary w-100 py-2">Send Verification Link</button>
          </form>
          <hr class="my-3">
          <div class="d-flex justify-content-between small">
            <a href="/login" class="fw-semibold">Back to Sign In</a>
            <a href="/signup" class="text-muted">Create Account</a>
          </div>
        </div>
      </div>
    </div>
    """
    return render_template_string(HTML_LAYOUT, content=content, current_user_name=None, current_user_role=None)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# DASHBOARD ROUTE (Redirects to role-specific landing page)
@app.route('/')
def dashboard():
    role = session.get('role')
    return redirect(get_role_dashboard_url(role))


# NATIONAL DATASET OVERVIEW
@app.route('/dataset-overview')
def dataset_overview():
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
    finally:
        conn.close()

    body = f"""
    <div class="row g-4 mb-4">
        <div class="col-md-12">
            <div class="p-4 rounded-3 card shadow-sm text-center" style="background: #f9fafb; border: 2px solid #D6cfc4;">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <span class="source-badge">Official NCRB / Kaggle Crime Dataset</span>
                    <span class="small fw-semibold" style="color: #374151;">Years Covered: {min_yr} – {max_yr}</span>
                </div>
                <h1 class="display-6 fw-bold" style="color: #1f2937;">National Crime Management Portal</h1>
                <p class="lead mb-3" style="color: #4b5563;">Live Dynamic Insights from 35+ Million Real NCRB Recorded Crime Cases</p>
                <div class="d-flex justify-content-center gap-3">
                    <a href="/crime-statistics" class="btn btn-warning fw-bold px-4 shadow-sm">Search Crime Records</a>
                    <a href="/analytics" class="btn btn-primary fw-bold px-4 shadow-sm">Interactive Visual Analytics</a>
                    <a href="/women-children-analytics" class="btn btn-outline-primary fw-bold px-4 shadow-sm" style="background-color: #ffffff;">Women &amp; Children Reports</a>
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
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #4b5563;">
                <h6 class="text-uppercase text-secondary small">States &amp; UTs</h6>
                <span class="fs-2 fw-bold text-danger">{states_count}</span>
                <small class="text-muted">{districts_count} Districts Covered</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #6b7280;">
                <h6 class="text-uppercase text-secondary small">Crime Categories</h6>
                <span class="fs-2 fw-bold text-warning">{categories_count}</span>
                <small class="text-muted">Normalized IPC Categories</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #2d6a4f;">
                <h6 class="text-uppercase text-secondary small">Highest Crime State</h6>
                <span class="fs-4 fw-bold text-success">{top_state}</span>
                <small class="text-muted">{top_state_val:,} Total Cases</small>
            </div>
        </div>
    </div>

    <div class="row g-4">
        <div class="col-12">
            <div class="card p-4">
                <h5 class="text-secondary mb-3">Key Dataset Highlights</h5>
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
    return render_page(body)


# ROLE DASHBOARD: CITIZEN
@app.route('/dashboard/citizen')
@login_required
def citizen_dashboard():
    full_name = session.get('full_name', 'Citizen')
    conn = get_db_connection()

    # Query FIRs filed by or associated with this citizen
    firs = conn.execute("""
        SELECT f.fir_id, f.fir_number, f.filing_date, f.status, f.description,
               c.crime_type, c.location, ps.station_name, ps.contact_number
        FROM FIR f
        LEFT JOIN victims v ON f.victim_id = v.victim_id
        LEFT JOIN crimes c ON f.crime_id = c.crime_id
        LEFT JOIN police_stations ps ON f.station_id = ps.station_id
        WHERE lower(v.name) = lower(?)
        ORDER BY f.filing_date DESC
    """, (full_name,)).fetchall()

    total_firs = len(firs)
    pending_firs = sum(1 for f in firs if f['status'] in ('Pending', 'Investigating', 'Active', 'Reported'))
    resolved_firs = sum(1 for f in firs if f['status'] in ('Resolved', 'Closed', 'Disposed'))

    # Nearby police stations for emergency contact
    stations = conn.execute("SELECT station_name, city, state, contact_number FROM police_stations LIMIT 5").fetchall()
    conn.close()

    fir_rows = ""
    if firs:
        for f in firs:
            status_badge = "bg-warning text-dark" if f['status'] == 'Pending' else ("bg-success" if f['status'] in ('Closed', 'Resolved') else "bg-secondary")
            fir_rows += f"""
            <tr>
                <td class="fw-bold">{escape(f['fir_number'] or '')}</td>
                <td>{escape(f['filing_date'] or '')}</td>
                <td>{escape(f['crime_type'] or 'General Complaint')}</td>
                <td>{escape(f['station_name'] or 'Central Station')}</td>
                <td><span class="badge {status_badge}">{escape(f['status'] or 'Pending')}</span></td>
                <td><small class="text-muted">{escape((f['description'] or '')[:60])}{'...' if len(f['description'] or '') > 60 else ''}</small></td>
            </tr>
            """
    else:
        fir_rows = """
        <tr>
            <td colspan="6" class="text-center text-muted py-4">
                You have not filed any complaints or FIRs under this name yet.<br>
                <a href="/fir-management" class="btn btn-sm btn-primary mt-2">File an Official FIR Complaint</a>
            </td>
        </tr>
        """

    station_rows = ""
    for s in stations:
        station_rows += f"""
        <li class="list-group-item d-flex justify-content-between align-items-center bg-transparent">
            <div>
                <strong>{escape(s['station_name'])}</strong><br>
                <small class="text-muted">{escape(s['city'])}, {escape(s['state'])}</small>
            </div>
            <a href="tel:{escape(s['contact_number'])}" class="btn btn-sm btn-outline-primary">{escape(s['contact_number'])}</a>
        </li>
        """

    body = f"""
    <div class="row g-4 mb-4">
        <div class="col-12">
            <div class="p-4 rounded-3 card shadow-sm" style="background: #f9fafb; border: 2px solid #D6cfc4;">
                <div class="d-flex flex-wrap justify-content-between align-items-center gap-3">
                    <div>
                        <span class="badge bg-secondary mb-2">Citizen Services Portal</span>
                        <h2 class="fw-bold mb-1" style="color: #1f2937;">Welcome, {escape(full_name)}</h2>
                        <p class="text-muted mb-0">Track filed FIRs, submit new complaints, access police station contacts and explore public safety analytics.</p>
                    </div>
                    <div class="d-flex flex-wrap gap-2">
                        <a href="/fir-management" class="btn btn-primary fw-semibold">File a New FIR</a>
                        <a href="/police-station-map" class="btn btn-outline-primary fw-semibold">Station Map</a>
                        <a href="/crime-statistics" class="btn btn-outline-secondary fw-semibold">Safety Trends</a>
                        <a href="/dataset-overview" class="btn btn-warning fw-semibold">National Overview</a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="row g-4 mb-4">
        <div class="col-md-4">
            <div class="card stats-card p-3 shadow-sm text-center">
                <h6 class="text-uppercase text-secondary small">My Registered FIRs</h6>
                <span class="fs-2 fw-bold text-info">{total_firs}</span>
                <small class="text-muted">Total recorded under your profile</small>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #d97706;">
                <h6 class="text-uppercase text-secondary small">Pending / Active</h6>
                <span class="fs-2 fw-bold text-warning">{pending_firs}</span>
                <small class="text-muted">Currently undergoing investigation</small>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #2d6a4f;">
                <h6 class="text-uppercase text-secondary small">Resolved / Closed</h6>
                <span class="fs-2 fw-bold text-success">{resolved_firs}</span>
                <small class="text-muted">Completed case proceedings</small>
            </div>
        </div>
    </div>

    <div class="row g-4">
        <div class="col-lg-8">
            <div class="card shadow-sm p-3">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="fw-bold mb-0" style="color: #1f2937;">My Filed Complaints &amp; FIR Records</h5>
                    <a href="/fir-management" class="btn btn-sm btn-outline-primary">View All Records</a>
                </div>
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0">
                        <thead>
                            <tr>
                                <th>FIR Number</th>
                                <th>Filing Date</th>
                                <th>Crime Type</th>
                                <th>Police Station</th>
                                <th>Status</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {fir_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="col-lg-4">
            <div class="card shadow-sm p-3 mb-4">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="fw-bold mb-0" style="color: #1f2937;">Station Directory</h5>
                    <a href="/police-stations" class="small">All Stations</a>
                </div>
                <ul class="list-group list-group-flush">
                    {station_rows if station_rows else '<li class="list-group-item text-muted">No station records found.</li>'}
                </ul>
            </div>

            <div class="card shadow-sm p-3" style="background-color: #f8f9fa;">
                <h6 class="fw-bold mb-2" style="color: #1f2937;">Citizen Legal Protections</h6>
                <ul class="small text-muted ps-3 mb-0">
                    <li>Every citizen is entitled to a free, signed copy of their registered FIR.</li>
                    <li>Zero FIRs may be registered at any station regardless of territorial jurisdiction.</li>
                    <li>All sensitive complaints concerning women and children receive priority processing.</li>
                </ul>
            </div>
        </div>
    </div>
    """
    return render_page(body)


# ROLE DASHBOARD: POLICE
@app.route('/dashboard/police')
@roles_required('Police', 'District Magistrate')
def police_dashboard():
    conn = get_db_connection()
    total_firs = conn.execute("SELECT COUNT(*) FROM FIR").fetchone()[0]
    pending_firs = conn.execute("SELECT COUNT(*) FROM FIR WHERE status != 'Closed'").fetchone()[0]
    active_cases = conn.execute("SELECT COUNT(*) FROM cases WHERE case_status = 'Active'").fetchone()[0]
    wanted_criminals = conn.execute("SELECT COUNT(*) FROM criminals WHERE status = 'Wanted'").fetchone()[0]
    total_stations = conn.execute("SELECT COUNT(*) FROM police_stations").fetchone()[0]

    recent_firs = conn.execute("""
        SELECT f.fir_id, f.fir_number, f.filing_date, f.status, f.description,
               c.crime_type, ps.station_name
        FROM FIR f
        LEFT JOIN crimes c ON f.crime_id = c.crime_id
        LEFT JOIN police_stations ps ON f.station_id = ps.station_id
        ORDER BY f.filing_date DESC LIMIT 5
    """).fetchall()

    active_cases_list = conn.execute("""
        SELECT c.case_id, c.case_number, c.priority, c.case_status, c.start_date,
               po.name as officer_name, po.badge_number
        FROM cases c
        LEFT JOIN police_officers po ON c.investigating_officer_id = po.officer_id
        WHERE c.case_status = 'Active'
        ORDER BY c.start_date DESC LIMIT 5
    """).fetchall()

    wanted_suspects = conn.execute("""
        SELECT criminal_id, name, alias, status, identification_details
        FROM criminals
        WHERE status = 'Wanted'
        LIMIT 5
    """).fetchall()
    conn.close()

    fir_rows = ""
    for f in recent_firs:
        status_badge = "bg-warning text-dark" if f['status'] == 'Pending' else ("bg-success" if f['status'] == 'Closed' else "bg-secondary")
        fir_rows += f"""
        <tr>
            <td class="fw-bold"><a href="/fir-management">{escape(f['fir_number'] or '')}</a></td>
            <td>{escape(f['filing_date'] or '')}</td>
            <td>{escape(f['crime_type'] or 'N/A')}</td>
            <td>{escape(f['station_name'] or 'Station')}</td>
            <td><span class="badge {status_badge}">{escape(f['status'] or 'Pending')}</span></td>
        </tr>
        """

    case_rows = ""
    for c in active_cases_list:
        p_badge = "bg-danger" if c['priority'] == 'High' else ("bg-warning text-dark" if c['priority'] == 'Medium' else "bg-secondary")
        case_rows += f"""
        <tr>
            <td class="fw-bold"><a href="/case-files">{escape(c['case_number'] or '')}</a></td>
            <td><span class="badge {p_badge}">{escape(c['priority'] or 'Normal')}</span></td>
            <td>{escape(c['officer_name'] or 'Unassigned')}</td>
            <td>{escape(c['start_date'] or '')}</td>
        </tr>
        """

    wanted_rows = ""
    for w in wanted_suspects:
        wanted_rows += f"""
        <li class="list-group-item d-flex justify-content-between align-items-center bg-transparent">
            <div>
                <strong>{escape(w['name'])}</strong>
                {f'<span class="text-muted small"> (Alias: {escape(w["alias"])})</span>' if w['alias'] else ''}<br>
                <small class="text-muted">{escape(w['identification_details'] or 'No details on record')}</small>
            </div>
            <span class="badge bg-danger">Wanted</span>
        </li>
        """

    body = f"""
    <div class="row g-4 mb-4">
        <div class="col-12">
            <div class="p-4 rounded-3 card shadow-sm" style="background: #f9fafb; border: 2px solid #D6cfc4;">
                <div class="d-flex flex-wrap justify-content-between align-items-center gap-3">
                    <div>
                        <span class="badge bg-secondary mb-2">Law Enforcement Command</span>
                        <h2 class="fw-bold mb-1" style="color: #1f2937;">Police Operations Dashboard</h2>
                        <p class="text-muted mb-0">Operational control for FIR registration, investigative case tracking, suspect identification, and station management.</p>
                    </div>
                    <div class="d-flex flex-wrap gap-2">
                        <a href="/fir-management" class="btn btn-primary fw-semibold">Register FIR</a>
                        <a href="/criminal-records" class="btn btn-outline-primary fw-semibold">Criminal Records</a>
                        <a href="/case-files" class="btn btn-outline-primary fw-semibold">Case Files</a>
                        <a href="/crime-patterns" class="btn btn-warning fw-semibold">Pattern Detector</a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="row g-4 mb-4">
        <div class="col-md-3">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #d97706;">
                <h6 class="text-uppercase text-secondary small">Open / Pending FIRs</h6>
                <span class="fs-2 fw-bold text-warning">{pending_firs}</span>
                <small class="text-muted">Out of {total_firs} total registered</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stats-card p-3 shadow-sm text-center">
                <h6 class="text-uppercase text-secondary small">Active Cases</h6>
                <span class="fs-2 fw-bold text-info">{active_cases}</span>
                <small class="text-muted">Under investigation</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #991b1b;">
                <h6 class="text-uppercase text-secondary small">Wanted Suspects</h6>
                <span class="fs-2 fw-bold text-danger">{wanted_criminals}</span>
                <small class="text-muted">Active warrants logged</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #2d6a4f;">
                <h6 class="text-uppercase text-secondary small">Police Stations</h6>
                <span class="fs-2 fw-bold text-success">{total_stations}</span>
                <small class="text-muted"><a href="/police-station-map" class="text-success text-decoration-none">Open Map View</a></small>
            </div>
        </div>
    </div>

    <div class="row g-4">
        <div class="col-lg-6">
            <div class="card shadow-sm p-3">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="fw-bold mb-0" style="color: #1f2937;">Recent FIR Activity</h5>
                    <a href="/fir-management" class="btn btn-sm btn-outline-primary">Manage All FIRs</a>
                </div>
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0">
                        <thead>
                            <tr>
                                <th>FIR Number</th>
                                <th>Date</th>
                                <th>Crime Head</th>
                                <th>Station</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {fir_rows if fir_rows else '<tr><td colspan="5" class="text-center text-muted">No FIRs logged yet.</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="col-lg-6">
            <div class="card shadow-sm p-3">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="fw-bold mb-0" style="color: #1f2937;">Active Investigative Cases</h5>
                    <a href="/case-files" class="btn btn-sm btn-outline-primary">Manage Cases</a>
                </div>
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0">
                        <thead>
                            <tr>
                                <th>Case Number</th>
                                <th>Priority</th>
                                <th>Investigator</th>
                                <th>Initiated</th>
                            </tr>
                        </thead>
                        <tbody>
                            {case_rows if case_rows else '<tr><td colspan="4" class="text-center text-muted">No active cases logged.</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="col-12">
            <div class="card shadow-sm p-3">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="fw-bold mb-0" style="color: #1f2937;">Most Wanted Suspects</h5>
                    <a href="/criminal-records" class="btn btn-sm btn-outline-primary">Criminal Database</a>
                </div>
                <ul class="list-group list-group-flush">
                    {wanted_rows if wanted_rows else '<li class="list-group-item text-muted">No active wanted notices.</li>'}
                </ul>
            </div>
        </div>
    </div>
    """
    return render_page(body)


# ROLE DASHBOARD: COURT
@app.route('/dashboard/court')
@roles_required('Court', 'District Magistrate')
def court_dashboard():
    conn = get_db_connection()
    total_cases = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    active_trials = conn.execute("SELECT COUNT(*) FROM cases WHERE case_status = 'Active'").fetchone()[0]
    closed_cases = conn.execute("SELECT COUNT(*) FROM cases WHERE case_status = 'Closed'").fetchone()[0]

    arrest_summary = conn.execute("""
        SELECT SUM(persons_arrested) as arrested,
               SUM(persons_convicted) as convicted,
               SUM(persons_acquitted) as acquitted
        FROM arrest_statistics
    """).fetchone()

    total_convicted = arrest_summary['convicted'] or 0
    total_acquitted = arrest_summary['acquitted'] or 0
    total_disposed = total_convicted + total_acquitted
    conviction_pct = round((total_convicted / total_disposed * 100), 1) if total_disposed > 0 else 0.0

    pending_cases = conn.execute("""
        SELECT c.case_id, c.case_number, c.case_status, c.priority, c.start_date, c.remarks,
               f.fir_number, po.name as officer_name
        FROM cases c
        LEFT JOIN FIR f ON c.fir_id = f.fir_id
        LEFT JOIN police_officers po ON c.investigating_officer_id = po.officer_id
        ORDER BY c.start_date DESC LIMIT 8
    """).fetchall()

    top_charges = conn.execute("""
        SELECT crime_head, persons_arrested, persons_convicted, persons_acquitted
        FROM arrest_statistics
        ORDER BY (persons_convicted + persons_acquitted) DESC LIMIT 5
    """).fetchall()
    conn.close()

    case_rows = ""
    for c in pending_cases:
        p_badge = "bg-danger" if c['priority'] == 'High' else ("bg-warning text-dark" if c['priority'] == 'Medium' else "bg-secondary")
        status_badge = "bg-info" if c['case_status'] == 'Active' else ("bg-success" if c['case_status'] == 'Closed' else "bg-secondary")
        case_rows += f"""
        <tr>
            <td class="fw-bold"><a href="/case-files">{escape(c['case_number'] or '')}</a></td>
            <td><a href="/fir-management">{escape(c['fir_number'] or 'N/A')}</a></td>
            <td><span class="badge {p_badge}">{escape(c['priority'] or 'Normal')}</span></td>
            <td><span class="badge {status_badge}">{escape(c['case_status'] or 'Active')}</span></td>
            <td>{escape(c['officer_name'] or 'Unassigned')}</td>
            <td>{escape(c['start_date'] or '')}</td>
            <td><small class="text-muted">{escape(c['remarks'] or 'Under Judicial Review')}</small></td>
        </tr>
        """

    disposition_rows = ""
    for ch in top_charges:
        tot = (ch['persons_convicted'] or 0) + (ch['persons_acquitted'] or 0)
        c_rate = round((ch['persons_convicted'] / tot * 100), 1) if tot > 0 else 0.0
        disposition_rows += f"""
        <tr>
            <td class="fw-semibold">{escape(ch['crime_head'])}</td>
            <td class="text-end">{ch['persons_arrested']:,}</td>
            <td class="text-end text-success fw-bold">{ch['persons_convicted']:,}</td>
            <td class="text-end text-secondary">{ch['persons_acquitted']:,}</td>
            <td class="text-end"><span class="badge bg-secondary">{c_rate}%</span></td>
        </tr>
        """

    body = f"""
    <div class="row g-4 mb-4">
        <div class="col-12">
            <div class="p-4 rounded-3 card shadow-sm" style="background: #f9fafb; border: 2px solid #D6cfc4;">
                <div class="d-flex flex-wrap justify-content-between align-items-center gap-3">
                    <div>
                        <span class="badge bg-secondary mb-2">Judicial Administration</span>
                        <h2 class="fw-bold mb-1" style="color: #1f2937;">District Court Case Proceedings Dashboard</h2>
                        <p class="text-muted mb-0">Court docket tracking, hearing status management, prosecution evidence review, and judicial disposition metrics.</p>
                    </div>
                    <div class="d-flex flex-wrap gap-2">
                        <a href="/case-files" class="btn btn-primary fw-semibold">Case File Proceedings</a>
                        <a href="/fir-management" class="btn btn-outline-primary fw-semibold">FIR Evidence</a>
                        <a href="/criminal-records" class="btn btn-outline-primary fw-semibold">Criminal Records</a>
                        <a href="/property-arrest-analytics" class="btn btn-warning fw-semibold">Arrests &amp; Convictions</a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="row g-4 mb-4">
        <div class="col-md-3">
            <div class="card stats-card p-3 shadow-sm text-center">
                <h6 class="text-uppercase text-secondary small">Cases Pending Hearing / Trial</h6>
                <span class="fs-2 fw-bold text-info">{active_trials}</span>
                <small class="text-muted">Active in court proceedings</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #2d6a4f;">
                <h6 class="text-uppercase text-secondary small">Disposed / Closed Cases</h6>
                <span class="fs-2 fw-bold text-success">{closed_cases}</span>
                <small class="text-muted">Final judgements rendered</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #4b5563;">
                <h6 class="text-uppercase text-secondary small">Total Docketed Cases</h6>
                <span class="fs-2 fw-bold text-secondary">{total_cases}</span>
                <small class="text-muted">Total judicial registry</small>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #d97706;">
                <h6 class="text-uppercase text-secondary small">National Conviction Rate</h6>
                <span class="fs-2 fw-bold text-warning">{conviction_pct}%</span>
                <small class="text-muted">Based on official trial records</small>
            </div>
        </div>
    </div>

    <div class="row g-4 mb-4">
        <div class="col-12">
            <div class="card shadow-sm p-3">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="fw-bold mb-0" style="color: #1f2937;">Active Judicial Case Files</h5>
                    <a href="/case-files" class="btn btn-sm btn-outline-primary">Manage Case Dockets</a>
                </div>
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0">
                        <thead>
                            <tr>
                                <th>Case Number</th>
                                <th>Associated FIR</th>
                                <th>Priority</th>
                                <th>Status</th>
                                <th>Investigator</th>
                                <th>Initiated</th>
                                <th>Remarks / Notes</th>
                            </tr>
                        </thead>
                        <tbody>
                            {case_rows if case_rows else '<tr><td colspan="7" class="text-center text-muted">No judicial cases on docket.</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <div class="row g-4">
        <div class="col-12">
            <div class="card shadow-sm p-3">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="fw-bold mb-0" style="color: #1f2937;">Trial &amp; Disposition Trends by Crime Category</h5>
                    <a href="/property-arrest-analytics" class="small">Full Analytics</a>
                </div>
                <div class="table-responsive">
                    <table class="table table-sm table-hover align-middle mb-0">
                        <thead>
                            <tr>
                                <th>Crime Category</th>
                                <th class="text-end">Arrested</th>
                                <th class="text-end">Convicted</th>
                                <th class="text-end">Acquitted</th>
                                <th class="text-end">Conviction Rate</th>
                            </tr>
                        </thead>
                        <tbody>
                            {disposition_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    """
    return render_page(body)


# ROLE DASHBOARD: DISTRICT MAGISTRATE
@app.route('/dashboard/district-magistrate')
@roles_required('District Magistrate')
def magistrate_dashboard():
    conn = get_db_connection()
    total_firs = conn.execute("SELECT COUNT(*) FROM FIR").fetchone()[0]
    total_cases = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    total_criminals = conn.execute("SELECT COUNT(*) FROM criminals").fetchone()[0]
    total_stations = conn.execute("SELECT COUNT(*) FROM police_stations").fetchone()[0]
    active_cases = conn.execute("SELECT COUNT(*) FROM cases WHERE case_status = 'Active'").fetchone()[0]
    pending_firs = conn.execute("SELECT COUNT(*) FROM FIR WHERE status != 'Closed'").fetchone()[0]

    arrest_summary = conn.execute("""
        SELECT SUM(persons_arrested) as arrested,
               SUM(persons_convicted) as convicted,
               SUM(persons_acquitted) as acquitted
        FROM arrest_statistics
    """).fetchone()

    total_convicted = arrest_summary['convicted'] or 0
    total_acquitted = arrest_summary['acquitted'] or 0
    total_disposed = total_convicted + total_acquitted
    conviction_pct = round((total_convicted / total_disposed * 100), 1) if total_disposed > 0 else 0.0

    recent_firs = conn.execute("""
        SELECT f.fir_id, f.fir_number, f.filing_date, f.status, f.description,
               c.crime_type, ps.station_name
        FROM FIR f
        LEFT JOIN crimes c ON f.crime_id = c.crime_id
        LEFT JOIN police_stations ps ON f.station_id = ps.station_id
        ORDER BY f.filing_date DESC LIMIT 5
    """).fetchall()

    recent_cases = conn.execute("""
        SELECT c.case_number, c.case_status, c.priority, c.start_date,
               po.name as officer_name
        FROM cases c
        LEFT JOIN police_officers po ON c.investigating_officer_id = po.officer_id
        ORDER BY c.start_date DESC LIMIT 5
    """).fetchall()

    conn.close()

    fir_rows = ""
    for f in recent_firs:
        status_badge = "bg-warning text-dark" if f['status'] == 'Pending' else ("bg-success" if f['status'] == 'Closed' else "bg-secondary")
        fir_rows += f"""
        <tr>
            <td class="fw-bold"><a href="/fir-management">{escape(f['fir_number'] or '')}</a></td>
            <td>{escape(f['filing_date'] or '')}</td>
            <td>{escape(f['crime_type'] or 'N/A')}</td>
            <td>{escape(f['station_name'] or 'Station')}</td>
            <td><span class="badge {status_badge}">{escape(f['status'] or 'Pending')}</span></td>
        </tr>
        """

    case_rows = ""
    for c in recent_cases:
        p_badge = "bg-danger" if c['priority'] == 'High' else ("bg-warning text-dark" if c['priority'] == 'Medium' else "bg-secondary")
        case_rows += f"""
        <tr>
            <td class="fw-bold"><a href="/case-files">{escape(c['case_number'] or '')}</a></td>
            <td><span class="badge {p_badge}">{escape(c['priority'] or 'Normal')}</span></td>
            <td>{escape(c['case_status'] or 'Active')}</td>
            <td>{escape(c['officer_name'] or 'Unassigned')}</td>
            <td>{escape(c['start_date'] or '')}</td>
        </tr>
        """

    body = f"""
    <div class="row g-4 mb-4">
        <div class="col-12">
            <div class="p-4 rounded-3 card shadow-sm" style="background: #f9fafb; border: 2px solid #D6cfc4;">
                <div class="d-flex flex-wrap justify-content-between align-items-center gap-3">
                    <div>
                        <span class="badge bg-secondary mb-2">Executive Law &amp; Order Oversight</span>
                        <h2 class="fw-bold mb-1" style="color: #1f2937;">District Magistrate Command Console</h2>
                        <p class="text-muted mb-0">District administrative authority: cross-departmental supervision across Police Stations, FIR Registrations, Criminal Surveillance, and Court Proceedings.</p>
                    </div>
                    <div class="d-flex flex-wrap gap-2">
                        <a href="/fir-management" class="btn btn-primary fw-semibold">FIR Control</a>
                        <a href="/case-files" class="btn btn-outline-primary fw-semibold">Case Dockets</a>
                        <a href="/criminal-records" class="btn btn-outline-primary fw-semibold">Criminal Profiles</a>
                        <a href="/crime-patterns" class="btn btn-outline-primary fw-semibold">Pattern Detector</a>
                        <a href="/dataset-overview" class="btn btn-warning fw-semibold">National Overview</a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="row g-4 mb-4">
        <div class="col-md">
            <div class="card stats-card p-3 shadow-sm text-center">
                <h6 class="text-uppercase text-secondary small">Police Stations</h6>
                <span class="fs-2 fw-bold text-info">{total_stations}</span>
                <small class="text-muted">In district jurisdiction</small>
            </div>
        </div>
        <div class="col-md">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #d97706;">
                <h6 class="text-uppercase text-secondary small">Total Registered FIRs</h6>
                <span class="fs-2 fw-bold text-warning">{total_firs}</span>
                <small class="text-muted">{pending_firs} pending resolution</small>
            </div>
        </div>
        <div class="col-md">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #4b5563;">
                <h6 class="text-uppercase text-secondary small">Active Cases</h6>
                <span class="fs-2 fw-bold text-secondary">{active_cases}</span>
                <small class="text-muted">Under active inquiry</small>
            </div>
        </div>
        <div class="col-md">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #991b1b;">
                <h6 class="text-uppercase text-secondary small">Known Criminals</h6>
                <span class="fs-2 fw-bold text-danger">{total_criminals}</span>
                <small class="text-muted">On judicial watch</small>
            </div>
        </div>
        <div class="col-md">
            <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color: #2d6a4f;">
                <h6 class="text-uppercase text-secondary small">Conviction Rate</h6>
                <span class="fs-2 fw-bold text-success">{conviction_pct}%</span>
                <small class="text-muted">Judicial conviction metric</small>
            </div>
        </div>
    </div>

    <div class="row g-4">
        <div class="col-lg-6">
            <div class="card shadow-sm p-3">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="fw-bold mb-0" style="color: #1f2937;">Jurisdictional FIR Registrations</h5>
                    <a href="/fir-management" class="btn btn-sm btn-outline-primary">All FIRs</a>
                </div>
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0">
                        <thead>
                            <tr>
                                <th>FIR Number</th>
                                <th>Filing Date</th>
                                <th>Crime Head</th>
                                <th>Station</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {fir_rows if fir_rows else '<tr><td colspan="5" class="text-center text-muted">No FIRs logged yet.</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="col-lg-6">
            <div class="card shadow-sm p-3">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="fw-bold mb-0" style="color: #1f2937;">Case Investigation Oversight</h5>
                    <a href="/case-files" class="btn btn-sm btn-outline-primary">All Cases</a>
                </div>
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0">
                        <thead>
                            <tr>
                                <th>Case Number</th>
                                <th>Priority</th>
                                <th>Status</th>
                                <th>Investigator</th>
                                <th>Initiated</th>
                            </tr>
                        </thead>
                        <tbody>
                            {case_rows if case_rows else '<tr><td colspan="5" class="text-center text-muted">No active cases.</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    """
    return render_page(body)


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
        SELECT state, district, year, crime_type, case_count 
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
            <td class="fw-bold text-secondary">{r['state']}</td>
            <td>{r['district']}</td>
            <td><span class="badge bg-secondary">{r['year']}</span></td>
            <td><span class="badge bg-info text-dark">{r['crime_type']}</span></td>
            <td class="fw-bold text-danger fs-6">{r['case_count']:,}</td>
            <td><span class="source-badge">NCRB Record</span></td>
        </tr>
        """ for r in rows])
    else:
        rows_html = """
        <tr>
            <td colspan="6" class="text-center py-5 text-muted fs-5">
                No records found for the selected filters. Please adjust your search criteria.
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
        <h2 class="text-secondary m-0">Kaggle/NCRB Crime Statistics Explorer</h2>
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
    return render_page(body)


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
        <h2 class="text-secondary m-0">Interactive Crime Analytics &amp; Trends</h2>
        <span class="source-badge">Data Source: Kaggle / NCRB Dataset</span>
    </div>

    <div class="row g-4 mb-4">
        <div class="col-md-8">
            <div class="card p-4">
                <h5 class="text-secondary mb-3">National Crime Trend Over Years (2001 - 2014)</h5>
                <canvas id="yearlyTrendChart" height="140"></canvas>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card p-4">
                <h5 class="text-secondary mb-3">Top Crime Categories</h5>
                <canvas id="categoryPieChart" height="280"></canvas>
            </div>
        </div>
    </div>

    <div class="row g-4">
        <div class="col-md-12">
            <div class="card p-4">
                <h5 class="text-secondary mb-3">Top 10 States by Total Recorded Crimes</h5>
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
                    borderColor: '#374151',
                    backgroundColor: 'rgba(55, 65, 81, 0.12)',
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
                    backgroundColor: ['#374151', '#4b5563', '#6b7280', '#9ca3af', '#b8b1a5', '#1f2937', '#111827', '#2d6a4f', '#d97706', '#991b1b']
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
                    backgroundColor: '#4b5563'
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
    return render_page(body)


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
    <h2 class="text-secondary mb-4">Crimes Against Women &amp; Children Statistics</h2>
    <div class="row g-4">
        <div class="col-md-6">
            <div class="card p-4">
                <h4 class="text-secondary mb-3">Crimes Against Women (Category Breakdown)</h4>
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
                <h4 class="text-secondary mb-3">Crimes Against Children (Category Breakdown)</h4>
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
    return render_page(body)


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
        <h2 class="text-secondary m-0">Property Crimes &amp; Police Arrest Statistics</h2>
        <span class="source-badge">Data Source: Kaggle / NCRB Dataset</span>
    </div>
    <div class="row g-4 mb-4">
        <div class="col-md-6">
            <div class="card p-4 h-100">
                <h4 class="text-secondary mb-3">Stolen vs Recovered Property (Top States)</h4>
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
                <h4 class="text-secondary mb-3">Top States by Recovered Property</h4>
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
                <h4 class="text-secondary mb-3">Arrests, Convictions &amp; Acquittals</h4>
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
    return render_page(body)


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
                return render_page(content), 404

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
                            radius: 4, color: '#D6cfc4', fillColor: '#374151', fillOpacity: 0.8
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
        return render_page(body)


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
    <h2 class="text-warning mb-3">Police Stations & Officer Directory</h2>
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
    return render_page(body)


@app.route('/police-stations/add', methods=['POST'])
@roles_required(*ROLE_PERMISSIONS['add_police_station'])
def add_police_station():
    conn = get_db_connection()
    conn.execute("INSERT INTO police_stations (station_name, address, city, state, contact_number) VALUES (?, ?, ?, ?, ?)",
                 (request.form['station_name'], request.form['address'], request.form['city'], request.form['state'], request.form['contact_number']))
    conn.commit()
    conn.close()
    return redirect('/police-stations')


@app.route('/police-stations/add-officer', methods=['POST'])
@roles_required(*ROLE_PERMISSIONS['add_police_officer'])
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
    <h2 class="text-secondary mb-3">FIR (First Information Report) Registry</h2>
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
    return render_page(body)


@app.route('/fir-management/add', methods=['POST'])
@roles_required(*ROLE_PERMISSIONS['add_fir'])
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
@roles_required(*ROLE_PERMISSIONS['update_fir_status'])
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
    <h2 class="text-secondary mb-3">Criminal Record Dossiers</h2>
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
    return render_page(body)


@app.route('/criminal-records/add', methods=['POST'])
@roles_required(*ROLE_PERMISSIONS['add_criminal'])
def add_criminal():
    conn = get_db_connection()
    conn.execute("INSERT INTO criminals (name, alias, date_of_birth, gender, address, phone, identification_details, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                 (request.form['name'], request.form.get('alias') or None, request.form.get('date_of_birth') or None, request.form.get('gender', 'Other'), request.form.get('address'), request.form.get('phone'), request.form.get('identification_details'), request.form.get('status', 'Wanted')))
    conn.commit()
    conn.close()
    return redirect('/criminal-records')


@app.route('/criminal-records/<int:criminal_id>/status', methods=['POST'])
@roles_required(*ROLE_PERMISSIONS['update_criminal_status'])
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
    <h2 class="text-secondary mb-3">Active &amp; Closed Case Files</h2>
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
    return render_page(body)


@app.route('/case-files/add', methods=['POST'])
@roles_required(*ROLE_PERMISSIONS['add_case'])
def add_case():
    conn = get_db_connection()
    conn.execute("INSERT INTO cases (case_number, fir_id, investigating_officer_id, priority, start_date, remarks) VALUES (?, ?, ?, ?, ?, ?)",
                 (request.form['case_number'], request.form['fir_id'], request.form.get('investigating_officer_id') or None, request.form.get('priority', 'Medium'), request.form['start_date'], request.form.get('remarks')))
    conn.commit()
    conn.close()
    return redirect('/case-files')


@app.route('/case-files/<int:case_id>/status', methods=['POST'])
@roles_required(*ROLE_PERMISSIONS['update_case_status'])
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
        return render_page(body)

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
      <h2 style="color: #1f2937;">AI-Powered Crime Pattern &amp; Similarity Detector</h2>
      <p class="text-muted">Analyze historical crime trends, detect anomalies, find similar crime patterns across regions, and identify clusters — powered by real NCRB/Kaggle data (2001–2013).</p>
    </div>
  </div>

  <!-- Filter Form -->
  <div class="card mb-4 p-4" style="border-left: 4px solid #374151;">
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
          <button type="submit" class="btn btn-primary w-100">Analyze</button>
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
    return render_page(body)


def _build_pattern_results(data, crime_type, state, district):
    """Build the HTML results section from run_full_analysis() output."""
    if data.get('error'):
        return f'<div class="alert alert-warning mt-3">{escape(data["error"])}</div>'

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

    dir_color  = '#2d6a4f' if direction == 'Increasing' else ('#991b1b' if direction == 'Decreasing' else '#374151')
    trend_badge = f'<span class="badge" style="background:{dir_color};font-size:1rem;">{direction}</span>'

    trend_html = f"""
<div class="card mb-4 p-4">
  <h5 style="color: #1f2937;">Trend Analysis — {escape(crime_type)} in {escape(location_label)}</h5>
  <div class="row text-center mt-3">
    <div class="col-md-3"><div class="p-3 rounded" style="background: #f3f4f6;">
      <div style="font-size:1.8rem;">{trend_badge}</div><small class="text-muted">Overall Trend</small></div></div>
    <div class="col-md-3"><div class="p-3 rounded" style="background: #f3f4f6;">
      <div style="font-size:1.8rem;font-weight:bold;color: #1f2937;">{net_pct:+.1f}%</div><small class="text-muted">Net Change</small></div></div>
    <div class="col-md-3"><div class="p-3 rounded" style="background: #f3f4f6;">
      <div style="font-size:1.8rem;font-weight:bold;color: #1f2937;">{peak_yr}</div><small class="text-muted">Peak Year</small></div></div>
    <div class="col-md-3"><div class="p-3 rounded" style="background: #f3f4f6;">
      <div style="font-size:1.8rem;font-weight:bold;color: #1f2937;">{low_yr}</div><small class="text-muted">Lowest Year</small></div></div>
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
        tag  = '[Spike]' if ev_type == 'spike' else '[Drop]'
        col  = '#991b1b' if ev_type == 'spike' else '#374151'
        spike_items += f'<div class="d-flex align-items-center mb-2 p-2 rounded" style="background: #f9fafb; border-left: 4px solid {col};"><span class="badge bg-secondary me-2">{tag}</span> <b class="ms-1">{yr}</b>: {ev_type.capitalize()} of <b>{pct:+.1f}%</b> &nbsp;<span class="text-muted">({int(prev_val):,} → {int(cur_val):,} cases)</span></div>'

    spikes_html = f"""
<div class="card mb-4 p-4">
  <h5 style="color: #1f2937;">Anomaly &amp; Spike Detection</h5>
  {''.join([spike_items]) if spikes else '<p class="text-muted">No significant anomalies detected in the selected range.</p>'}
</div>"""

    # ── Yearly trend chart + top similar overlay ────────────────────────────
    years_sorted = sorted(series.keys())
    labels_js = str(years_sorted)
    target_js  = str([series.get(y, 0) for y in years_sorted])

    # Pick top 3 similar for overlay
    top3_datasets = ''
    palette = ['#D6cfc4', '#d97706', '#2d6a4f']
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
  <h5 style="color: #1f2937;">Yearly Crime Trend Chart</h5>
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
        borderColor: '#374151',
        backgroundColor: 'rgba(55,65,81,0.08)',
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
        bar_col  = '#2d6a4f' if score >= 75 else ('#d97706' if score >= 50 else '#4b5563')
        rank_badge = f'#{rank}'
        sim_rows += f"""
<tr>
  <td class="text-center fw-bold">{rank_badge}</td>
  <td><b>{escape(loc)}</b></td>
  <td>
    <div style="background: #e5e7eb; border-radius: 4px; height: 14px; width: 100%;">
      <div style="background:{bar_col}; width:{bar_w}%; height: 14px; border-radius: 4px;"></div>
    </div>
    <small>{score:.1f}%</small>
  </td>
  <td><span class="badge bg-secondary">{escape(pattern)}</span></td>
</tr>"""

    # Similarity bar chart (top 8)
    sim_labels = str([s.get('location','') for s in similar[:8]])
    sim_scores = str([round(s.get('score_pct', 0), 1) for s in similar[:8]])
    sim_colors_js = str(['#2d6a4f' if s.get('score_pct',0)>=75 else ('#d97706' if s.get('score_pct',0)>=50 else '#4b5563') for s in similar[:8]])

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
  <h5 style="color: #1f2937;">Similarity Rankings (Pearson Correlation)</h5>
  <p class="text-muted small">Regions with the most similar crime trend <i>shapes</i> to {escape(location_label)}. Score = correlation mapped 0–100%.</p>
  {sim_table_content}
  {sim_chart_content}
</div>
{sim_script_content}"""

    # ── Cluster Cards ───────────────────────────────────────────────────────
    cluster_cards = ''
    cluster_meta = [
        ('high_volume_high_growth',   'High Volume + High Growth',   '#991b1b', '#fee2e2'),
        ('high_volume_low_growth',    'High Volume + Stable/Slow',   '#ea580c', '#fff7ed'),
        ('low_volume_high_growth',    'Low Volume + High Growth',    '#ca8a04', '#fefce8'),
        ('low_volume_low_growth',     'Low Volume + Low Activity',   '#16a34a', '#f0fdf4'),
    ]
    for key, label, border, bg in cluster_meta:
        members = clusters.get(key, [])
        badges  = ' '.join(f'<span class="badge me-1" style="background:{border};font-size:0.75rem;">{escape(m)}</span>' for m in members)
        cluster_cards += f"""
<div class="col-md-6 mb-3">
  <div class="card h-100 p-3" style="border-left: 4px solid {border}; background: {bg};">
    <h6 style="color:{border};">{label}</h6>
    <p class="text-muted small mb-2">{len(members)} region(s)</p>
    <div>{badges if badges else '<span class="text-muted small">No regions in this cluster</span>'}</div>
  </div>
</div>"""

    clusters_html = f"""
<div class="card mb-4 p-4">
  <h5 style="color: #1f2937;">Crime Clusters — {escape(crime_type)}</h5>
  <p class="text-muted small">Regions grouped by crime volume &amp; growth trend across the selected period.</p>
  <div class="row">{cluster_cards}</div>
</div>"""

    # ── AI Insights ─────────────────────────────────────────────────────────
    insight_type_style = {
        'warning':  ('#fef9c3', '#ca8a04', '[Warning]'),
        'danger':   ('#fee2e2', '#dc2626', '[Alert]'),
        'success':  ('#f0fdf4', '#16a34a', '[Resolved]'),
        'info':     ('#eff6ff', '#2563eb', '[Insight]'),
        'primary':  ('#f9fafb', '#374151', '[Key]'),
    }
    insight_items = ''
    for ins in insights:
        itype = ins.get('type', 'info')
        itext = ins.get('text', '')
        bg_d, col_d, tag = insight_type_style.get(itype, ('#eff6ff', '#2563eb', '[Insight]'))
        insight_items += f'<div class="d-flex align-items-start mb-3 p-3 rounded" style="background:{bg_d};border-left:4px solid {col_d};"><span class="badge bg-secondary me-2">{tag}</span><span class="ms-1">{escape(itext)}</span></div>'

    insights_html = f"""
<div class="card mb-4 p-4">
  <h5 style="color: #1f2937;">AI Insights</h5>
  {insight_items if insight_items else '<p class="text-muted">No insights generated.</p>'}
</div>"""

    return trend_html + spikes_html + trend_chart_html + similarity_html + clusters_html + insights_html


if __name__ == '__main__':
    init_db()
    print("Starting Crime Management Portal (Kaggle/NCRB Version) on http://127.0.0.1:5051")
    app.run(host='0.0.0.0', port=5051, debug=True)