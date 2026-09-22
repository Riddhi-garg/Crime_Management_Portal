"""
Crime Management Portal - Application Entry Point & Web Server
Integrated with Real Kaggle/NCRB Crime Statistics Dataset (2001-2014)
"""
import os
import re
import json
import hashlib
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
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv not installed – environment variables must be set manually
    pass

from crime_pattern_analysis import get_filter_options, get_districts_for_state, run_full_analysis


# The two account types the portal issues logins to. Every users.role value
# must be one of these; the login/registration flow only ever assigns one of
# these two.
ROLES = ['Citizen', 'Police']

# Which of the two roles may reach which write actions. View-only pages are
# open to any signed-in user regardless of role.
ROLE_PERMISSIONS = {
    'add_police_station':    ['Police'],
    'add_police_officer':    ['Police'],
    'add_fir':               ['Citizen', 'Police'],
    'update_fir_status':     ['Police'],
    'add_criminal':          ['Police'],
    'update_criminal_status':['Police'],
    'add_case':              ['Police'],
    'update_case_status':    ['Police'],
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
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB limit


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
        'Court': '/dashboard/police',
        'District Magistrate': '/dashboard/police'
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
    public_endpoints = {'login', 'logout', 'signup', 'verify_email', 'resend_verification', 'verify_otp', 'resend_otp', 'static'}
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
        otp_code TEXT,
        otp_expires_at TEXT,
        otp_attempts INTEGER DEFAULT 0,
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
    if 'otp_code' not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN otp_code TEXT")
    if 'otp_expires_at' not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN otp_expires_at TEXT")
    if 'otp_attempts' not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN otp_attempts INTEGER DEFAULT 0")
    if 'aadhaar_hash' not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN aadhaar_hash TEXT")
    if 'aadhaar_last4' not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN aadhaar_last4 TEXT")
    if 'police_station_id' not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN police_station_id INTEGER")

    # Seed one login per role the first time the app runs. Passwords are
    # hashed with werkzeug's default (PBKDF2) — never stored in plain text.
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_accounts = [
            # (full_name, email, temporary password, role)
            ("Citizen Portal Account",        "citizen@crms.gov.in",     "Citizen@123",     "Citizen"),
            ("Police Station Account",        "police@crms.gov.in",      "Police@123",      "Police"),
        ]
        for full_name, email, temp_password, role in default_accounts:
            cursor.execute(
                "INSERT INTO users (username, password, role, full_name, email, email_verified) VALUES (?, ?, ?, ?, ?, 1)",
                (email, generate_password_hash(temp_password), role, full_name, email)
            )
        conn.commit()
    else:
        # Ensure seeded default accounts are marked email_verified = 1
        default_emails = ["citizen@crms.gov.in", "police@crms.gov.in"]
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
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cbi_firs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rc_number TEXT UNIQUE NOT NULL,
        fir_number TEXT,
        fir_date DATE,
        title_or_subject TEXT,
        pdf_url TEXT NOT NULL,
        source_page_url TEXT NOT NULL DEFAULT 'https://cbi.gov.in/view-fir',
        first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Additional tables for analytics
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ncrb_crime_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        year INTEGER NOT NULL,
        state TEXT NOT NULL,
        district TEXT NOT NULL,
        crime_category TEXT NOT NULL,
        crime_type TEXT NOT NULL,
        reported_cases INTEGER NOT NULL,
        other_fields TEXT,
        UNIQUE(year, state, district, crime_category, crime_type)
    );
    """)
    # Flexible table for arbitrary NCRB CSV imports
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ncrb_raw_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_file TEXT NOT NULL,
        table_name TEXT,
        row_hash TEXT UNIQUE,
        raw_data TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

    # Auto-synchronize official NCRB CSV files from ncrb/ folder
    try:
        from import_ncrb_data import sync_ncrb_csvs
        sync_ncrb_csvs(conn)
    except Exception as e:
        print(f"[WARN] Could not auto-sync NCRB CSV directory: {e}")

    # Auto-synchronize genuine public CBI data from data/cbi/ folder if present
    try:
        from import_cbi_data import sync_all_cbi_files
        sync_all_cbi_files(conn)
    except Exception as e:
        print(f"[WARN] Could not auto-sync CBI directory: {e}")

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
          <li class="nav-item"><a class="nav-link" href="/fir-management" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">FIR Management System</a></li>
          <li class="nav-item"><a class="nav-link" href="/police-stations" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Police Stations</a></li>
          <li class="nav-item"><a class="nav-link" href="/crime-statistics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Crime Statistics</a></li>
          <li class="nav-item"><a class="nav-link" href="/analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Analytics &amp; Charts</a></li>
          <li class="nav-item"><a class="nav-link" href="/women-children-analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Women &amp; Children</a></li>

        {% elif current_user_role == 'Police' %}
          <li class="nav-item"><a class="nav-link" href="/fir-management" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">FIR Management System</a></li>
          <li class="nav-item"><a class="nav-link" href="/criminal-records" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Criminal Records</a></li>
          <li class="nav-item"><a class="nav-link" href="/case-files" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Case Files</a></li>
          <li class="nav-item"><a class="nav-link" href="/police-stations" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Police Stations</a></li>
          <li class="nav-item"><a class="nav-link" href="/crime-patterns" style="color: #D6cfc4; font-weight: bold; font-family: 'Times New Roman', Times, serif;">Pattern Detector</a></li>
          <li class="nav-item"><a class="nav-link" href="/crime-statistics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Crime Statistics</a></li>
          <li class="nav-item"><a class="nav-link" href="/analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Analytics &amp; Charts</a></li>
          <li class="nav-item"><a class="nav-link" href="/women-children-analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Women &amp; Children</a></li>
          <li class="nav-item"><a class="nav-link" href="/property-arrest-analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Property &amp; Arrests</a></li>

        {% else %}
          <li class="nav-item"><a class="nav-link" href="/fir-management" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">FIR Management System</a></li>
          <li class="nav-item"><a class="nav-link" href="/analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Analytics &amp; Charts</a></li>
          <li class="nav-item"><a class="nav-link" href="/women-children-analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Women &amp; Children</a></li>
          <li class="nav-item"><a class="nav-link" href="/property-arrest-analytics" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Property &amp; Arrests</a></li>
          <li class="nav-item"><a class="nav-link" href="/police-stations" style="color: #ffffff; font-family: 'Times New Roman', Times, serif;">Police Stations</a></li>
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
                flash("Please verify your email first. Enter the 6-digit code sent to your inbox.", "warning")
                return redirect(url_for('verify_otp', email=user['email']))
            else:
                session.clear()
                session['user_id'] = user['user_id']
                session['role'] = user['role']
                session['full_name'] = user['full_name']
                session['email'] = user['email']
                session['police_station_id'] = user['police_station_id'] if 'police_station_id' in user.keys() else None
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
            <a href="/verify-otp" class="small text-muted text-decoration-none">Enter Verification Code (OTP)</a>
          </div>

          <hr class="my-3">
          <p class="small text-muted mb-1 fw-semibold">Portal Account Types:</p>
          <ul class="small text-muted mb-0 ps-3">
            <li><strong>Citizen</strong> — file and track personal FIRs, check case status</li>
            <li><strong>Police</strong> — FIRs, criminal records, cases, stations, analytics</li>
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
                otp = f"{secrets.randbelow(1000000):06d}"
                otp_expires_at = (datetime.datetime.now() + timedelta(minutes=10)).isoformat()
                pwd_hash = generate_password_hash(password)
                conn.execute(
                    """
                    INSERT INTO users (username, password, role, full_name, email, email_verified,
                                       otp_code, otp_expires_at, otp_attempts)
                    VALUES (?, ?, ?, ?, ?, 0, ?, ?, 0)
                    """,
                    (email, pwd_hash, role, full_name, email, otp, otp_expires_at)
                )
                conn.commit()
                conn.close()

                email_body = f"""Hello {full_name},

Thank you for registering on the Crime Management Portal.

Your 6-digit verification code (OTP) is:

  {otp}

This code is valid for 10 minutes. Enter it on the verification page to activate your {role} account.

If you did not register for an account, you can safely ignore this message.

Crime Management Portal
National Crime Records System
"""
                send_email(to_email=email, subject="Your Crime Management Portal verification code", body=email_body)
                flash("Registration successful! A 6-digit verification code has been sent to your email.", "success")
                return redirect(url_for('verify_otp', email=email))

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
              <div class="form-text text-muted">Select role: Citizen or Police.</div>
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

# OTP verification routes

def verify_otp():
    email = request.args.get('email') or request.form.get('email')
    if request.method == 'GET':
        if not email:
            flash('Email parameter is required for OTP verification.', 'danger')
            return redirect(url_for('login'))
        # Render OTP input form
        content = f"""<div class=\"row justify-content-center\">
          <div class=\"col-md-5 col-lg-4\">
            <div class=\"card p-4 shadow-sm mt-5\">
              <h3 class=\"text-center mb-1\" style=\"color: #1f2937;\">Enter Verification Code</h3>
              <p class=\"text-center text-muted mb-4\">A 6‑digit code was sent to <strong>{escape(email)}</strong></p>
              <form method=\"POST\">
                <input type=\"hidden\" name=\"email\" value=\"{escape(email)}\">
                <div class=\"mb-3\">
                  <label class=\"form-label fw-semibold\">Verification Code</label>
                  <input type=\"text\" name=\"otp\" class=\"form-control\" placeholder=\"123456\" required>
                </div>
                <button type=\"submit\" class=\"btn btn-primary w-100 py-2\">Verify</button>
              </form>
            </div>
          </div>
        </div>"""
        return render_template_string(HTML_LAYOUT, content=content, current_user_name=None, current_user_role=None)

    # POST – verify OTP
    otp_input = request.form.get('otp', '').strip()
    if not email or not otp_input:
        flash('Missing email or OTP.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE lower(email) = ?", (email.lower(),)).fetchone()
    if not user:
        conn.close()
        flash('User not found.', 'danger')
        return redirect(url_for('signup'))

    # Check expiry and attempts
    now = datetime.datetime.now()
    try:
        expires_at = datetime.datetime.fromisoformat(user['otp_expires_at']) if user['otp_expires_at'] else None
    except Exception:
        expires_at = None

    if expires_at is None or now > expires_at:
        conn.close()
        flash('OTP has expired. Please request a new code.', 'warning')
        return redirect(url_for('resend_otp', email=email))

    if user['otp_attempts'] >= 5:
        conn.close()
        flash('Maximum verification attempts exceeded. Please request a new code.', 'warning')
        return redirect(url_for('resend_otp', email=email))

    if otp_input == user['otp_code']:
        # Successful verification
        conn.execute(
            "UPDATE users SET email_verified = 1, otp_code = NULL, otp_expires_at = NULL, otp_attempts = 0 WHERE user_id = ?",
            (user['user_id'],)
        )
        conn.commit()
        conn.close()
        flash('Your email has been verified. You may now sign in.', 'success')
        return redirect(url_for('login'))
    else:
        # Increment attempts
        conn.execute(
            "UPDATE users SET otp_attempts = otp_attempts + 1 WHERE user_id = ?",
            (user['user_id'],)
        )
        conn.commit()
        conn.close()
        flash('Invalid verification code. Please try again.', 'danger')
        return redirect(url_for('verify_otp', email=email))



@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email') or request.form.get('email')

    # Show OTP page
    if request.method == 'GET':
        if not email:
            flash('Email parameter is required for OTP verification.', 'danger')
            return redirect(url_for('login'))

        content = f"""
        <div class="row justify-content-center">
          <div class="col-md-5 col-lg-4">
            <div class="card p-4 shadow-sm mt-5">
              <h3 class="text-center mb-1" style="color: #1f2937;">
                Enter Verification Code
              </h3>

              <p class="text-center text-muted mb-4">
                A 6-digit code was sent to
                <strong>{escape(email)}</strong>
              </p>

              <form method="POST">
                <input type="hidden" name="email" value="{escape(email)}">

                <div class="mb-3">
                  <label class="form-label fw-semibold">
                    Verification Code
                  </label>

                  <input
                    type="text"
                    name="otp"
                    class="form-control"
                    placeholder="123456"
                    required
                  >
                </div>

                <button type="submit"
                        class="btn btn-primary w-100 py-2">
                  Verify
                </button>
              </form>

              <div class="text-center mt-3">
                <a href="{url_for('resend_otp', email=email)}"
                   class="btn btn-link">
                  Didn't receive the code? Resend OTP
                </a>
              </div>

            </div>
          </div>
        </div>
        """

        return render_template_string(
            HTML_LAYOUT,
            content=content,
            current_user_name=None,
            current_user_role=None
        )

    # Verify submitted OTP
    otp_input = request.form.get('otp', '').strip()

    if not email or not otp_input:
        flash('Missing email or OTP.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()

    user = conn.execute(
        "SELECT * FROM users WHERE lower(email) = ?",
        (email.lower(),)
    ).fetchone()

    if not user:
        conn.close()
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    expires_at = None

    if user['otp_expires_at']:
        try:
            expires_at = datetime.datetime.fromisoformat(
                user['otp_expires_at']
            )
        except Exception:
            expires_at = None

    # Check expiry
    if expires_at and datetime.datetime.now() > expires_at:
        conn.close()
        flash('OTP has expired. Please request a new one.', 'warning')
        return redirect(url_for('resend_otp', email=email))

    # Check attempt limit
    if user['otp_attempts'] >= 5:
        conn.close()
        flash('Too many incorrect attempts. Please request a new OTP.', 'danger')
        return redirect(url_for('resend_otp', email=email))

    # Correct OTP
    if otp_input == user['otp_code']:

        conn.execute(
            """
            UPDATE users
            SET email_verified = 1,
                otp_code = NULL,
                otp_expires_at = NULL,
                otp_attempts = 0
            WHERE user_id = ?
            """,
            (user['user_id'],)
        )

        conn.commit()
        conn.close()

        flash('Email verified successfully! You can now log in.', 'success')

        return redirect(url_for('login'))

    # Incorrect OTP
    conn.execute(
        """
        UPDATE users
        SET otp_attempts = otp_attempts + 1
        WHERE user_id = ?
        """,
        (user['user_id'],)
    )

    conn.commit()
    conn.close()

    flash('Incorrect verification code. Please try again.', 'danger')

    return redirect(url_for('verify_otp', email=email))


@app.route('/resend-otp')
def resend_otp():

    email = request.args.get('email')

    if not email:
        flash('Email is required to resend OTP.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()

    user = conn.execute(
        "SELECT * FROM users WHERE lower(email) = ?",
        (email.lower(),)
    ).fetchone()

    if not user:
        conn.close()
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    # Generate new OTP
    new_otp = f"{secrets.randbelow(1000000):06d}"

    # OTP expires in 10 minutes
    expires_at = (
        datetime.datetime.now()
        + timedelta(minutes=10)
    ).isoformat()

    # Save new OTP
    conn.execute(
        """
        UPDATE users
        SET otp_code = ?,
            otp_expires_at = ?,
            otp_attempts = 0
        WHERE user_id = ?
        """,
        (new_otp, expires_at, user['user_id'])
    )

    conn.commit()
    conn.close()

    # Email message
    email_body = f"""Hello {user['full_name']},

Your new 6-digit verification code (OTP) is:

{new_otp}

This code is valid for 10 minutes.

Enter it on the verification page to activate your account.

If you did not request this, you can safely ignore this message.

Crime Management Portal
"""

    # Send OTP email
    send_email(
        to_email=user['email'],
        subject="Your Crime Management Portal verification code",
        body=email_body
    )

    flash(
        'A new verification code has been sent to your email.',
        'success'
    )

    return redirect(
        url_for('verify_otp', email=email)
    )

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
@roles_required('Citizen')
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

    user_id = session.get('user_id')
    user_row = conn.execute("SELECT aadhaar_hash, aadhaar_last4 FROM users WHERE user_id = ?", (user_id,)).fetchone()
    aadhaar_linked = bool(user_row and user_row['aadhaar_hash'])
    aadhaar_last4 = user_row['aadhaar_last4'] if (user_row and user_row['aadhaar_last4']) else ""
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
                <a href="/fir-management" class="btn btn-sm btn-primary mt-2">Access FIR Management System</a>
            </td>
        </tr>
        """

    aadhaar_badge = f'<span class="badge bg-success"><i class="bi bi-shield-check"></i> Identity Linked (XXXX-XXXX-{escape(aadhaar_last4)})</span>' if aadhaar_linked else '<span class="badge bg-warning text-dark"><i class="bi bi-exclamation-triangle"></i> Aadhaar Not Linked</span>'

    linking_html = ""
    if not aadhaar_linked:
        linking_html = f"""
        <div class="alert alert-warning mb-3">
            Your citizen profile is not linked to an Aadhaar identifier. Please contact the authorized department or link your Aadhaar below to verify your citizen identity.
        </div>
        <div class="card bg-light p-3 border mb-3" style="max-width: 520px;">
            <h6 class="fw-bold mb-1 text-dark">Verify Citizen Identity (Link Aadhaar)</h6>
            <p class="small text-muted mb-2">Link your 12-digit Aadhaar number to enable case status lookup for your portal account.</p>
            <form id="link-aadhaar-form" onsubmit="linkAadhaar(event)">
                <div class="input-group mb-2">
                    <input type="password" class="form-control" id="link_aadhaar_input" placeholder="Enter 12-digit Aadhaar Number" pattern="\\d{{12}}" maxlength="12" title="Must be exactly 12 digits" required autocomplete="off">
                    <button class="btn btn-dark" type="submit">Verify &amp; Link</button>
                </div>
            </form>
            <div id="link-aadhaar-status"></div>
        </div>
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
                        <a href="/fir-management" class="btn btn-primary fw-semibold">FIR Management System</a>
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
            <div class="card shadow-sm p-3 h-100">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="fw-bold mb-0" style="color: #1f2937;">My Filed Complaints &amp; FIR Records</h5>
                    <a href="/fir-management" class="btn btn-sm btn-outline-primary">FIR Management System</a>
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
            <div class="card shadow-sm p-4 h-100 d-flex flex-column justify-content-between" style="background-color: #ffffff; border-left: 4px solid #0d6efd;">
                <div>
                    <h5 class="fw-bold mb-2" style="color: #1f2937;">Station Map</h5>
                    <p class="text-muted small mb-3">Find nearby police stations and view their locations.</p>
                </div>
                <div>
                    <a href="/police-station-map" class="btn btn-outline-primary w-100 fw-semibold">View Station Map</a>
                </div>
            </div>
        </div>
    </div>

    <div class="row g-4 mt-1 mb-4">
        <div class="col-12">
            <div class="card shadow-sm p-4" style="border-left: 4px solid #1f2937;">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <h5 class="fw-bold mb-0" style="color: #1f2937;">Check Case Status</h5>
                    {aadhaar_badge}
                </div>
                <p class="text-muted small mb-3">
                    Check official case records and proceedings associated with your authenticated portal profile.
                    <span class="d-block mt-1 text-secondary" style="font-size: 0.82rem;">
                        <strong>Privacy Notice:</strong> The Aadhaar identifier is cryptographically hashed (SHA-256) and strictly utilized as an internal portal identifier. This system does NOT connect to UIDAI servers and does not query national criminal databases.
                    </span>
                </p>

                {linking_html}

                <form id="aadhaar-form" onsubmit="lookupCaseStatus(event)">
                    <div class="input-group mb-2" style="max-width: 440px;">
                        <input type="password" class="form-control" id="aadhaar_input" placeholder="Enter Aadhaar Number" pattern="\\d{{12}}" maxlength="12" title="Must be exactly 12 digits" required autocomplete="off">
                        <button class="btn btn-primary" type="submit">Check Case Status</button>
                    </div>
                    <small class="text-muted">Enter your 12-digit Aadhaar number to verify identity and retrieve records.</small>
                </form>
                <div id="case-status-results"></div>
            </div>
        </div>
    </div>
    
    <script>
    function escapeHtml(str) {{
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }}

    function linkAadhaar(event) {{
        event.preventDefault();
        const input = document.getElementById('link_aadhaar_input');
        const aadhaar = input ? input.value.trim() : '';
        const statusDiv = document.getElementById('link-aadhaar-status');
        statusDiv.innerHTML = '<span class="text-muted small">Verifying and hashing identifier...</span>';

        fetch('/api/citizen/link-aadhaar', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
            body: 'aadhaar=' + encodeURIComponent(aadhaar)
        }})
        .then(res => res.json())
        .then(data => {{
            if (data.error) {{
                statusDiv.innerHTML = '<div class="alert alert-danger small mt-2 py-2 mb-0">' + escapeHtml(data.error) + '</div>';
            }} else {{
                statusDiv.innerHTML = '<div class="alert alert-success small mt-2 py-2 mb-0">' + escapeHtml(data.message) + ' (Identifier: ' + escapeHtml(data.aadhaar_masked) + ')</div>';
                setTimeout(function() {{ window.location.reload(); }}, 1200);
            }}
        }})
        .catch(err => {{
            statusDiv.innerHTML = '<div class="alert alert-danger small mt-2 py-2 mb-0">An error occurred during identity verification.</div>';
        }});
    }}

    function lookupCaseStatus(event) {{
        event.preventDefault();
        const input = document.getElementById('aadhaar_input');
        const aadhaar = input ? input.value.trim() : '';
        const resultsDiv = document.getElementById('case-status-results');
        resultsDiv.innerHTML = '<span class="text-muted small">Verifying identifier and retrieving authorized records...</span>';

        fetch('/api/citizen/case-status', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
            body: 'aadhaar=' + encodeURIComponent(aadhaar)
        }})
        .then(response => response.json().then(data => ({{ ok: response.ok, body: data }})))
        .then(res => {{
            const data = res.body;
            if (data.error) {{
                resultsDiv.innerHTML = '<div class="alert alert-danger mt-3">' + escapeHtml(data.error) + '</div>';
                return;
            }}

            if (data.message && (!data.records || data.records.length === 0)) {{
                resultsDiv.innerHTML = '<div class="alert alert-info mt-3">' + escapeHtml(data.message) + '</div>';
                return;
            }}

            if (!data.records || data.records.length === 0) {{
                resultsDiv.innerHTML = '<div class="alert alert-info mt-3">No matching case records were found in this portal.</div>';
                return;
            }}

            let html = '<div class="card bg-light border p-3 mt-3 shadow-sm">';
            html += '<div class="d-flex justify-content-between align-items-center mb-2 border-bottom pb-2">';
            html += '<h6 class="fw-bold mb-0 text-dark">Case Status</h6>';
            html += '<span class="badge bg-secondary font-monospace">Aadhaar: ' + escapeHtml(data.aadhaar_masked || 'XXXX-XXXX-****') + '</span>';
            html += '</div>';

            html += '<div class="alert alert-secondary small py-2 mb-3"><i class="bi bi-info-circle"></i> Note: An FIR or case record is a formal record of proceedings and does not determine or imply guilt.</div>';

            html += '<div class="table-responsive"><table class="table table-bordered table-hover align-middle mb-0 bg-white"><thead><tr class="table-light text-secondary small">' +
                    '<th>Case/FIR Number</th><th>Police Station</th><th>Offence</th>' +
                    '<th>FIR Date</th><th>Investigation Status</th><th>Court Status</th>' +
                    '<th>Last Updated</th></tr></thead><tbody>';

            data.records.forEach(r => {{
                html += '<tr>' +
                        '<td class="fw-bold">' + escapeHtml(r.case_fir_number || r.fir_number || 'N/A') + '</td>' +
                        '<td>' + escapeHtml(r.station_name || 'N/A') + '</td>' +
                        '<td>' + escapeHtml(r.offence || 'N/A') + '</td>' +
                        '<td>' + escapeHtml(r.fir_date || 'N/A') + '</td>' +
                        '<td><span class="badge bg-primary">' + escapeHtml(r.investigation_status || 'FIR Registered') + '</span></td>' +
                        '<td><span class="badge bg-secondary">' + escapeHtml(r.court_status || 'Pending') + '</span></td>' +
                        '<td><small class="text-muted">' + escapeHtml(r.last_updated || 'N/A') + '</small></td>' +
                        '</tr>';
            }});
            html += '</tbody></table></div></div>';
            resultsDiv.innerHTML = html;
        }})
        .catch(err => {{
            resultsDiv.innerHTML = '<div class="alert alert-danger mt-3">An error occurred while fetching case status.</div>';
        }});
    }}
    </script>
    """
    return render_page(body)


@app.route('/api/citizen/link-aadhaar', methods=['POST'])
@login_required
@roles_required('Citizen')
def api_citizen_link_aadhaar():
    raw_aadhaar = request.form.get('aadhaar', '').strip()
    normalized = re.sub(r'[\s\-]', '', raw_aadhaar)
    if not normalized.isdigit() or len(normalized) != 12:
        return jsonify({'error': 'Invalid Aadhaar format. Must be exactly 12 digits.'}), 400

    user_id = session.get('user_id')
    aadhaar_hash = hashlib.sha256(normalized.encode('utf-8')).hexdigest()
    aadhaar_last4 = normalized[-4:]

    conn = get_db_connection()
    existing = conn.execute(
        "SELECT user_id FROM users WHERE aadhaar_hash = ? AND user_id != ?",
        (aadhaar_hash, user_id)
    ).fetchone()
    if existing:
        conn.close()
        return jsonify({'error': 'This Aadhaar identifier is already linked to another portal account.'}), 409

    conn.execute(
        "UPDATE users SET aadhaar_hash = ?, aadhaar_last4 = ? WHERE user_id = ?",
        (aadhaar_hash, aadhaar_last4, user_id)
    )
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'message': 'Citizen identity verified and Aadhaar identifier linked successfully.',
        'aadhaar_masked': f"XXXX-XXXX-{aadhaar_last4}"
    })


@app.route('/api/citizen/case-status', methods=['POST'])
@login_required
@roles_required('Citizen')

def api_citizen_case_status():
    raw_aadhaar = request.form.get('aadhaar', '').strip()
    normalized = re.sub(r'[\s\-]', '', raw_aadhaar)
    if not normalized.isdigit() or len(normalized) != 12:
        return jsonify({'error': 'Invalid Aadhaar format. Must be exactly 12 digits.'}), 400

    user_id = session.get('user_id')
    # Ensure the citizen has a linked Aadhaar (security requirement)
    conn = get_db_connection()
    user_row = conn.execute(
        "SELECT user_id, full_name, aadhaar_hash, aadhaar_last4 FROM users WHERE user_id = ?",
        (user_id,)
    ).fetchone()
    if not user_row:
        conn.close()
        return jsonify({'error': 'User not found.'}), 404
    if not user_row['aadhaar_hash']:
        conn.close()
        return jsonify({
            'error': 'Your citizen profile is not linked to an Aadhaar identifier. Please contact the authorized department.'
        }), 400

    # Compute hash of entered Aadhaar and masked version for response
    entered_hash = hashlib.sha256(normalized.encode('utf-8')).hexdigest()
    masked_aadhaar = f"XXXX-XXXX-{normalized[-4:]}"

    # Ensure FIR table has test-only column; ignore if exists
    try:
        conn.execute('ALTER TABLE FIR ADD COLUMN aadhaar_hash TEXT')
        conn.commit()
    except Exception:
        pass

    # Query FIR / cases linked via Aadhaar hash
    query = """
        SELECT f.fir_number,
               c.case_number,
               ps.station_name,
               cr.crime_type AS offence,
               f.filing_date AS fir_date,
               f.status AS investigation_status,
               c.case_status AS court_status,
               COALESCE(c.created_at, f.filing_date) AS last_updated
        FROM FIR f
        LEFT JOIN cases c ON f.fir_id = c.fir_id
        JOIN crimes cr ON f.crime_id = cr.crime_id
        JOIN police_stations ps ON f.station_id = ps.station_id
        WHERE f.aadhaar_hash = ?
        ORDER BY f.filing_date DESC
    """
    records = conn.execute(query, (entered_hash,)).fetchall()
    conn.close()

    if not records:
        return jsonify({
            'success': True,
            'message': 'No matching case records were found in this portal.',
            'aadhaar_masked': masked_aadhaar,
            'records': []
        })

    formatted_records = []
    for r in records:
        inv_status = r['investigation_status'] or 'Under Investigation'
        court_stat = r['court_status'] or 'Pending'
        formatted_records.append({
            'case_fir_number': r['case_number'] if r['case_number'] else (r['fir_number'] or 'N/A'),
            'fir_number': r['fir_number'] or 'N/A',
            'case_number': r['case_number'] or 'N/A',
            'station_name': r['station_name'] or 'N/A',
            'offence': r['offence'] or 'N/A',
            'fir_date': r['fir_date'] or 'N/A',
            'investigation_status': inv_status,
            'court_status': court_stat,
            'last_updated': r['last_updated'] or 'N/A'
        })

    return jsonify({
        'success': True,
        'aadhaar_masked': masked_aadhaar,
        'records': formatted_records
    })

# POLICE STATION CASE SEARCH API
@app.route('/api/police/station-cases', methods=['GET'])
@roles_required('Police', 'District Magistrate')
def api_police_station_cases():
    """
    Search portal FIR/case records by police station name.
    CBI records (cbi_firs) are NOT included because branch/location fields
    are entirely NULL in the imported dataset — no station-level data exists
    to perform an honest match.
    """
    query = request.args.get('station', '').strip()
    if not query:
        return jsonify({'error': 'Please enter a station name to search.'}), 400

    # Normalise: strip extra spaces, collapse whitespace, upper
    import re as _re
    norm_query = _re.sub(r'\s+', ' ', query).upper()

    # Reject single-word generic terms that would match too broadly
    # (e.g. "Delhi" must not return every station in Delhi)
    generic_terms = {'DELHI', 'MUMBAI', 'INDIA', 'POLICE', 'STATION', 'NORTH', 'SOUTH', 'EAST', 'WEST', 'CENTRAL'}
    if norm_query in generic_terms:
        return jsonify({'error': 'Search term too generic. Please enter a specific station name.'}), 400

    conn = get_db_connection()

    # --- Fetch all portal stations for autocomplete + fuzzy name resolution ---
    all_stations = conn.execute(
        "SELECT station_id, station_name, city, state FROM police_stations"
    ).fetchall()

    # Find matching stations: the normalised station_name must CONTAIN the
    # normalised query as a substring (not just city/state).
    def _norm(s):
        return _re.sub(r'\s+', ' ', (s or '').upper()).strip()

    matched_stations = [
        s for s in all_stations
        if norm_query in _norm(s['station_name'])
    ]

    # --- Requesting officer's own station context ---
    officer_station_id = session.get('police_station_id')

    # --- Portal FIR results ---
    fir_results = []
    case_results = []

    for st in matched_stations:
        sid = st['station_id']

        # Access control: if officer has an assigned station, they may only
        # view portal operational records for their own station.
        # Public CBI records have no such restriction (see below).
        if officer_station_id and sid != officer_station_id:
            # Officer is not authorised to view another station's operational records
            continue

        firs = conn.execute("""
            SELECT f.fir_id, f.fir_number, f.filing_date, f.status, f.description,
                   c.crime_type, ps.station_name, ps.city, ps.state
            FROM FIR f
            LEFT JOIN crimes c ON f.crime_id = c.crime_id
            LEFT JOIN police_stations ps ON f.station_id = ps.station_id
            WHERE f.station_id = ?
            ORDER BY f.filing_date DESC
        """, (sid,)).fetchall()

        for f in firs:
            fir_results.append({
                'type': 'Portal FIR',
                'fir_id': f['fir_id'],
                'ref_number': f['fir_number'],
                'date': f['filing_date'],
                'offence': f['crime_type'] or 'N/A',
                'station': f['station_name'],
                'city': f['city'],
                'state': f['state'],
                'status': f['status'],
                'description': f['description'],
                'detail_url': '/fir-management',
                'pdf_url': None,
                'source': 'Portal FIR Database'
            })

        cases = conn.execute("""
            SELECT cs.case_id, cs.case_number, cs.case_status, cs.priority,
                   cs.start_date, cs.remarks,
                   f.fir_number,
                   ps.station_name, ps.city, ps.state,
                   po.name as officer_name
            FROM cases cs
            JOIN FIR f ON cs.fir_id = f.fir_id
            LEFT JOIN police_stations ps ON f.station_id = ps.station_id
            LEFT JOIN police_officers po ON cs.investigating_officer_id = po.officer_id
            WHERE f.station_id = ?
            ORDER BY cs.start_date DESC
        """, (sid,)).fetchall()

        for c in cases:
            case_results.append({
                'type': 'Portal Case',
                'case_id': c['case_id'],
                'ref_number': c['case_number'],
                'date': c['start_date'],
                'offence': f"FIR #{c['fir_number']}",
                'station': c['station_name'],
                'city': c['city'],
                'state': c['state'],
                'status': c['case_status'],
                'description': c['remarks'] or '',
                'officer': c['officer_name'] or 'Unassigned',
                'detail_url': '/case-files',
                'pdf_url': None,
                'source': 'Portal Case Database'
            })

    # --- CBI records: include those with matching branch or location ---
    cbi_results = []
    cbi_count = 0
    cbi_note = ''
    if _table_exists(get_db_connection(), 'cbi_firs'):
        conn_cbi = get_db_connection()
        for st in matched_stations:
            rows = conn_cbi.execute(
                """
                SELECT id, rc_number, fir_number, title_or_subject AS offence, fir_date,
                       COALESCE(branch, location) AS station, status, pdf_url
                FROM cbi_firs
                WHERE (branch IS NOT NULL AND LOWER(branch) = LOWER(?))
                   OR (location IS NOT NULL AND LOWER(location) = LOWER(?))
                """,
                (st['station_name'], st['station_name'])
            ).fetchall()
            for r in rows:
                cbi_results.append({
                    'type': 'CBI PUBLIC',
                    'ref_number': r['rc_number'] or r['fir_number'],
                    'date': r['fir_date'],
                    'offence': r['offence'],
                    'station': r['station'],
                    'status': r['status'],
                    'detail_url': r['pdf_url'] or '#',
                    'pdf_url': r['pdf_url'],
                    'source': 'CBI PUBLIC'
                })
        cbi_count = len(cbi_results)
        conn_cbi.close()
    else:
        cbi_note = ('CBI public records (cbi_firs) imported from cbi.gov.in do not contain '
                    'police station field data (branch and location are not populated in the '
                    'current dataset). No CBI records can be reliably linked to a specific '
                    'police station.')

    conn.close()

    station_names = [_norm(s['station_name']) for s in matched_stations]

    return jsonify({
        'searched_query': query,
        'matched_station_names': station_names,
        'portal_fir_count': len(fir_results),
        'portal_case_count': len(case_results),
        'cbi_count': cbi_count,
        'cbi_note': cbi_note,
        'total_results': len(fir_results) + len(case_results) + cbi_count,
        'fir_results': fir_results,
        'case_results': case_results,
        'cbi_results': cbi_results,
        'restricted': bool(officer_station_id and matched_stations and all(
            s['station_id'] != officer_station_id for s in matched_stations
        ))
    })


# AUTOCOMPLETE: list all station names for the search box
@app.route('/api/police/stations-list', methods=['GET'])
@roles_required('Police', 'District Magistrate')
def api_police_stations_list():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT station_id, station_name, city, state FROM police_stations ORDER BY station_name"
    ).fetchall()
    conn.close()
    return jsonify([
        {'id': r['station_id'], 'name': r['station_name'],
         'city': r['city'], 'state': r['state']}
        for r in rows
    ])


# ROLE DASHBOARD: POLICE
@app.route('/dashboard/police')
@roles_required('Police', 'District Magistrate')
def police_dashboard():
    conn = get_db_connection()
    station_id = session.get('police_station_id')

    if station_id:
        total_firs = conn.execute("SELECT COUNT(*) FROM FIR WHERE station_id = ?", (station_id,)).fetchone()[0]
        pending_firs = conn.execute("SELECT COUNT(*) FROM FIR WHERE status != 'Closed' AND station_id = ?", (station_id,)).fetchone()[0]
        active_cases = conn.execute("SELECT COUNT(*) FROM cases c JOIN FIR f ON c.fir_id = f.fir_id WHERE c.case_status = 'Active' AND f.station_id = ?", (station_id,)).fetchone()[0]
        wanted_criminals = conn.execute("SELECT COUNT(*) FROM criminals WHERE status = 'Wanted'").fetchone()[0]
        total_stations = conn.execute("SELECT COUNT(*) FROM police_stations").fetchone()[0]

        recent_firs = conn.execute("""
            SELECT f.fir_id, f.fir_number, f.filing_date, f.status, f.description,
                   c.crime_type, ps.station_name
            FROM FIR f
            LEFT JOIN crimes c ON f.crime_id = c.crime_id
            LEFT JOIN police_stations ps ON f.station_id = ps.station_id
            WHERE f.station_id = ?
            ORDER BY f.filing_date DESC LIMIT 5
        """, (station_id,)).fetchall()

        active_cases_list = conn.execute("""
            SELECT c.case_id, c.case_number, c.priority, c.case_status, c.start_date,
                   po.name as officer_name, po.badge_number
            FROM cases c
            JOIN FIR f ON c.fir_id = f.fir_id
            LEFT JOIN police_officers po ON c.investigating_officer_id = po.officer_id
            WHERE c.case_status = 'Active' AND f.station_id = ?
            ORDER BY c.start_date DESC LIMIT 5
        """, (station_id,)).fetchall()
    else:
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

    cbi_count = 0
    if _table_exists(conn, 'cbi_firs'):
        cbi_count = conn.execute("SELECT COUNT(*) FROM cbi_firs").fetchone()[0]

    # Officer's assigned station name
    officer_station_name = ''
    if station_id:
        row = conn.execute("SELECT station_name FROM police_stations WHERE station_id = ?", (station_id,)).fetchone()
        if row:
            officer_station_name = row['station_name']

    # All station names for autocomplete
    all_station_names = conn.execute("SELECT station_name FROM police_stations ORDER BY station_name").fetchall()
    station_options_html = ''
    for sn in all_station_names:
        station_options_html += f'<option value="{escape(sn["station_name"])}">'

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
                        <a href="/fir-management" class="btn btn-primary fw-semibold">FIR Management System</a>
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
                <small class="text-muted">Operational network</small>
            </div>
        </div>
    </div>

    <!-- POLICE STATION CASE SEARCH -->
    <div class="row g-4 mb-4">
        <div class="col-12">
            <div class="card shadow-sm p-4" style="border-left: 4px solid #0d6efd;">
                <h5 class="fw-bold mb-3" style="color: #1f2937;">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="#0d6efd" class="bi bi-search me-2" viewBox="0 0 16 16"><path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85zm-5.598 1.1a5.5 5.5 0 1 1 0-11 5.5 5.5 0 0 1 0 11z"/></svg>
                    Search Cases by Police Station
                </h5>
                {'<div class="alert alert-info d-flex align-items-center mb-3 py-2" style="border-left: 4px solid #0d6efd;"><div><strong>My Police Station:</strong> ' + escape(officer_station_name) + ' <button class="btn btn-sm btn-primary ms-3" onclick="stationSearchAutoFill()">View Cases for My Station</button></div></div>' if officer_station_name else '<div class="alert alert-secondary mb-3 py-2"><small>No police station assigned to your account. Use the search below to look up any station.</small></div>'}
                <div class="row g-2 align-items-end">
                    <div class="col-md-8">
                        <label for="stationSearchInput" class="form-label text-muted small mb-1">Enter Police Station Name</label>
                        <input type="text" class="form-control" id="stationSearchInput" placeholder="e.g. Crossing Republic" list="stationSuggestions" autocomplete="off">
                        <datalist id="stationSuggestions">{station_options_html}</datalist>
                    </div>
                    <div class="col-md-4 d-grid">
                        <button class="btn btn-primary fw-semibold" onclick="searchStationCases()">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-search me-1" viewBox="0 0 16 16"><path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85zm-5.598 1.1a5.5 5.5 0 1 1 0-11 5.5 5.5 0 0 1 0 11z"/></svg>
                            Search
                        </button>
                    </div>
                </div>
                <div id="stationSearchResults" class="mt-3"></div>
            </div>
        </div>
    </div>

    <script>
    function stationSearchAutoFill() {{
        var input = document.getElementById('stationSearchInput');
        input.value = {f'"{escape(officer_station_name)}"' if officer_station_name else '""'};
        searchStationCases();
    }}

    function searchStationCases() {{
        var query = document.getElementById('stationSearchInput').value.trim();
        var resultsDiv = document.getElementById('stationSearchResults');
        if (!query) {{
            resultsDiv.innerHTML = '<div class="alert alert-warning py-2">Please enter a station name to search.</div>';
            return;
        }}
        resultsDiv.innerHTML = '<div class="text-center py-3"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Searching...</span></div><p class="text-muted mt-2">Searching records...</p></div>';

        fetch('/api/police/station-cases?station=' + encodeURIComponent(query))
        .then(function(resp) {{ return resp.json(); }})
        .then(function(data) {{
            if (data.error) {{
                resultsDiv.innerHTML = '<div class="alert alert-danger py-2">' + data.error + '</div>';
                return;
            }}
            if (data.restricted) {{
                resultsDiv.innerHTML = '<div class="alert alert-warning py-2">Access restricted: You may only view operational records for your assigned police station.</div>';
                return;
            }}

            var html = '';

            // Summary header
            var stationLabel = data.matched_station_names.length > 0 ? data.matched_station_names.join(', ') : data.searched_query;
            html += '<div class="card p-3 mb-3" style="background: #f0f9ff; border: 1px solid #bae6fd;">';
            html += '<div class="row text-center">';
            html += '<div class="col-md-3"><h6 class="text-muted small text-uppercase">Station</h6><strong>' + stationLabel + '</strong></div>';
            html += '<div class="col-md-3"><h6 class="text-muted small text-uppercase">Portal FIRs</h6><span class="fs-4 fw-bold text-primary">' + data.portal_fir_count + '</span></div>';
            html += '<div class="col-md-3"><h6 class="text-muted small text-uppercase">Portal Cases</h6><span class="fs-4 fw-bold text-info">' + data.portal_case_count + '</span></div>';
            html += '<div class="col-md-3"><h6 class="text-muted small text-uppercase">Total Results</h6><span class="fs-4 fw-bold text-dark">' + data.total_results + '</span></div>';
            html += '</div></div>';

            // CBI data note
            if (data.cbi_note) {{
                html += '<div class="alert alert-secondary py-2 small"><strong>CBI Records:</strong> ' + data.cbi_note + '</div>';
            }}

            // Results table
            if (data.total_results > 0) {{
                html += '<div class="table-responsive"><table class="table table-hover align-middle mb-0">';
                html += '<thead><tr><th>Case/FIR No.</th><th>Date</th><th>Offence / Subject</th><th>Station</th><th>Status</th><th>Source</th><th>Actions</th></tr></thead><tbody>';

                // FIR results
                for (var i = 0; i < data.fir_results.length; i++) {{
                    var r = data.fir_results[i];
                    var statusCls = r.status === 'Closed' ? 'bg-success' : (r.status === 'Pending' ? 'bg-warning text-dark' : 'bg-secondary');
                    html += '<tr>';
                    html += '<td class="fw-bold">' + (r.ref_number || 'N/A') + '</td>';
                    html += '<td>' + (r.date || 'N/A') + '</td>';
                    html += '<td>' + (r.offence || 'N/A') + (r.description ? '<br><small class="text-muted">' + r.description + '</small>' : '') + '</td>';
                    html += '<td>' + (r.station || 'N/A') + '</td>';
                    html += '<td><span class="badge ' + statusCls + '">' + (r.status || 'N/A') + '</span></td>';
                    html += '<td><span class="badge bg-primary">' + r.source + '</span></td>';
                    html += '<td><a href="' + r.detail_url + '" class="btn btn-sm btn-outline-primary">View Details</a></td>';
                    html += '</tr>';
                }}

                // Case results
                for (var j = 0; j < data.case_results.length; j++) {{
                    var c = data.case_results[j];
                    var cStatusCls = c.status === 'Active' ? 'bg-info' : (c.status === 'Closed' ? 'bg-success' : 'bg-secondary');
                    html += '<tr>';
                    html += '<td class="fw-bold">' + (c.ref_number || 'N/A') + '</td>';
                    html += '<td>' + (c.date || 'N/A') + '</td>';
                    html += '<td>' + (c.offence || 'N/A') + '</td>';
                    html += '<td>' + (c.station || 'N/A') + '</td>';
                    html += '<td><span class="badge ' + cStatusCls + '">' + (c.status || 'N/A') + '</span></td>';
                    html += '<td><span class="badge bg-info">' + c.source + '</span></td>';
                    html += '<td><a href="' + c.detail_url + '" class="btn btn-sm btn-outline-primary">View Details</a></td>';
                    html += '</tr>';
                }}

                html += '</tbody></table></div>';
            }} else if (data.matched_station_names.length === 0) {{
                html += '<div class="alert alert-warning py-2">No police station found matching "<strong>' + data.searched_query + '</strong>". Please check the station name and try again.</div>';
            }} else {{
                html += '<div class="alert alert-info py-2">No FIR or case records found for <strong>' + stationLabel + '</strong>.</div>';
            }}

            resultsDiv.innerHTML = html;
        }})
        .catch(function(err) {{
            resultsDiv.innerHTML = '<div class="alert alert-danger py-2">Error searching: ' + err.message + '</div>';
        }});
    }}

    // Allow pressing Enter in the search field
    document.getElementById('stationSearchInput').addEventListener('keypress', function(e) {{
        if (e.key === 'Enter') {{ searchStationCases(); }}
    }});
    </script>

    <div class="row g-4">
        <div class="col-lg-6">
            <div class="card shadow-sm p-3">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="fw-bold mb-0" style="color: #1f2937;">Recent FIR Activity</h5>
                    <a href="/fir-management" class="btn btn-sm btn-outline-primary">FIR Management System</a>
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

        <div class="col-lg-8">
            <div class="card shadow-sm p-3 h-100">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="fw-bold mb-0" style="color: #1f2937;">Most Wanted Suspects</h5>
                    <a href="/criminal-records" class="btn btn-sm btn-outline-primary">Criminal Database</a>
                </div>
                <ul class="list-group list-group-flush">
                    {wanted_rows if wanted_rows else '<li class="list-group-item text-muted">No active wanted notices.</li>'}
                </ul>
            </div>
        </div>

        <div class="col-lg-4">
            <div class="card shadow-sm p-4 h-100 d-flex flex-column justify-content-between" style="background-color: #ffffff; border-left: 4px solid #0d6efd;">
                <div>
                    <h5 class="fw-bold mb-2" style="color: #1f2937;">Station Map</h5>
                    <p class="text-muted small mb-3">Find nearby police stations and view their locations.</p>
                </div>
                <div>
                    <a href="/police-station-map" class="btn btn-outline-primary w-100 fw-semibold">View Station Map</a>
                </div>
            </div>
        </div>
    </div>
    """
    return render_page(body)


# ROLE DASHBOARD: COURT
@app.route('/dashboard/court')
@roles_required('Police', 'Court', 'District Magistrate')
def court_dashboard():
    return redirect(url_for('police_dashboard'))
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
                        <a href="/fir-management" class="btn btn-outline-primary fw-semibold">FIR Management System</a>
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
@roles_required('Police', 'Court', 'District Magistrate')
def magistrate_dashboard():
    return redirect(url_for('police_dashboard'))
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
                        <a href="/fir-management" class="btn btn-primary fw-semibold">FIR Management System</a>
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
                    <a href="/fir-management" class="btn btn-sm btn-outline-primary">FIR Management System</a>
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
@login_required
def fir_management():
    """FIR Management System – Central portal interface powered by official NCRB Crime & Incident data."""
    import math
    from collections import OrderedDict

    search_q = request.args.get('q', '').strip()
    filter_file = request.args.get('source_file', '').strip()
    page = max(1, int(request.args.get('page', 1)))
    per_page = 25

    conn = get_db_connection()
    cur = conn.cursor()

    # Distinct source files for dropdown
    all_files = [r[0] for r in cur.execute(
        "SELECT DISTINCT source_file FROM ncrb_raw_data ORDER BY source_file"
    ).fetchall()]

    # WHERE clause
    params = []
    where_clauses = []
    if filter_file:
        where_clauses.append("source_file = ?")
        params.append(filter_file)
    if search_q:
        where_clauses.append("raw_data LIKE ?")
        params.append(f"%{search_q}%")
    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    total_rows = cur.execute(f"SELECT COUNT(*) FROM ncrb_raw_data {where_sql}", params).fetchone()[0]
    offset = (page - 1) * per_page
    db_rows = cur.execute(
        f"SELECT source_file, table_name, raw_data FROM ncrb_raw_data {where_sql} ORDER BY source_file, id LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()

    # Global totals (unfiltered)
    total_all = cur.execute("SELECT COUNT(*) FROM ncrb_raw_data").fetchone()[0]
    distinct_files = cur.execute("SELECT COUNT(DISTINCT source_file) FROM ncrb_raw_data").fetchone()[0]
    conn.close()

    # Group rows by source_file
    grouped = OrderedDict()
    for r in db_rows:
        sf = r['source_file']
        if sf not in grouped:
            grouped[sf] = {'rows': []}
        grouped[sf]['rows'].append(json.loads(r['raw_data']))

    # Official table descriptions
    TABLE_DESCRIPTIONS = {
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
    TABLE_ICONS = {
        'NCRB_ADSI_2023_Table_1A.3_2.csv':          '&#128663;',
        'NCRB_ADSI_2023_Table_1A.3_2 (1).csv':      '&#128663;',
        'NCRB_ADSI_2023_Table_1.11.csv':            '&#128293;',
        'NCRB_ADSI_2023_Table_2.4.csv':              '&#128202;',
        'NCRB_ADSI_2023_Table_2.6.csv':              '&#128084;',
        'NCRB_ADSI_2023_Table_2.12.csv':             '&#9888;',
        'AkolaPolice2025_0_1.csv':                   '&#128110;',
        'All_India_Index_Upto_Apr25.csv':            '&#128200;',
        'All_India_Index_Upto_Jan25.csv':            '&#128200;',
        'Rajya_Sabha_Session_234_AU2375_1.csv':     '&#127757;',
        'Rajya_Sabha_Session_237_AU1971_1.1.csv':   '&#128103;',
        'rs_session240_au2685_1.1.csv':             '&#128203;',
        'rs_session_239_AU1970_1.2.csv':            '&#128105;',
    }

    def is_num(v):
        try:
            s = str(v).replace(',', '').replace('NA', '').strip()
            if not s:
                return False
            float(s)
            return True
        except (ValueError, TypeError):
            return False

    # Build per-table sections
    sections_html = ''
    all_chart_js = ''
    chart_idx = 0

    for sf, data in grouped.items():
        rows_list = data['rows']
        if not rows_list:
            continue
        title = TABLE_DESCRIPTIONS.get(sf) or data.get('table_name') or sf.replace('.csv', '').replace('_', ' ').title()
        icon = TABLE_ICONS.get(sf, '&#128200;')
        headers = list(rows_list[0].keys())
        label_col = headers[1] if len(headers) > 1 else headers[0]
        numeric_cols = [h for h in headers if h not in ('Sl. No.', 'SL', label_col) and
                        any(is_num(r.get(h, '')) for r in rows_list)]

        # Table header
        header_cells = ''.join(
            f'<th style="white-space:nowrap; background:#e5e7eb; color:#1f2937;">{escape(h)}</th>'
            for h in headers
        )

        # Table body
        body_rows = ''
        for row in rows_list:
            cells = ''
            for h in headers:
                val = row.get(h, '')
                is_num_cell = h in numeric_cols and is_num(val)
                style = ' style="text-align:right; font-weight:600; color:#374151;"' if is_num_cell else ''
                cells += f'<td{style}>{escape(str(val))}</td>'
            body_rows += f'<tr>{cells}</tr>'

        # Bar chart for primary numeric column
        chart_html = ''
        if numeric_cols:
            chart_col = numeric_cols[0]
            chart_labels, chart_vals = [], []
            for row in rows_list[:30]:
                lbl = str(row.get(label_col, ''))[:40]
                raw_v = str(row.get(chart_col, '')).replace(',', '').strip()
                try:
                    chart_labels.append(lbl)
                    chart_vals.append(float(raw_v))
                except ValueError:
                    chart_labels.append(lbl)
                    chart_vals.append(0)

            cid = f'firChart{chart_idx}'
            chart_idx += 1
            chart_html = f'''
            <div class="mt-3 px-3 pb-3">
              <h6 class="text-muted mb-2" style="font-size:0.85rem;">{escape(chart_col)} — Graphical Distribution</h6>
              <canvas id="{cid}" height="90"></canvas>
            </div>'''
            all_chart_js += f'''
            new Chart(document.getElementById('{cid}'), {{
                type: 'bar',
                data: {{
                    labels: {json.dumps(chart_labels)},
                    datasets: [{{
                        label: {json.dumps(chart_col)},
                        data: {json.dumps(chart_vals)},
                        backgroundColor: 'rgba(75,85,99,0.75)',
                        borderColor: '#374151',
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{ legend: {{ display: false }} }},
                    scales: {{
                        x: {{ ticks: {{ maxRotation: 45, font: {{ size: 9, family: "'Times New Roman', serif" }} }} }},
                        y: {{ beginAtZero: true, ticks: {{ font: {{ size: 9 }} }} }}
                    }}
                }}
            }});'''

        sections_html += f'''
        <div class="card shadow-sm mb-4" style="border-left: 4px solid #D6cfc4;">
          <div class="card-header d-flex justify-content-between align-items-center"
               style="background:#f3f4f6; border-bottom:1px solid #dee2e6;">
            <span style="color:#1f2937; font-weight:700; font-size:1rem;">
              {icon}&nbsp; {escape(title)}
            </span>
            <span class="badge bg-secondary">{len(rows_list)} records</span>
          </div>
          <div class="card-body p-0">
            <div class="table-responsive">
              <table class="table table-sm table-hover align-middle mb-0"
                     style="font-size:0.84rem;">
                <thead><tr>{header_cells}</tr></thead>
                <tbody>{body_rows}</tbody>
              </table>
            </div>
            {chart_html}
          </div>
        </div>'''

    # File filter dropdown options
    file_options = '<option value="">All Source Tables</option>'
    for f in all_files:
        sel = ' selected' if f == filter_file else ''
        lbl = TABLE_DESCRIPTIONS.get(f) or f.replace('.csv', '').replace('_', ' ').title()
        lbl = lbl[:75]
        file_options += f'<option value="{escape(f)}"{sel}>{escape(lbl)}</option>'

    # Pagination
    total_pages = max(1, math.ceil(total_rows / per_page))
    def pg_link(p, lbl=None):
        txt = lbl or str(p)
        dis = ' disabled' if p < 1 or p > total_pages else ''
        act = ' active' if p == page else ''
        sf_param = f'&source_file={escape(filter_file)}' if filter_file else ''
        q_param = f'&q={escape(search_q)}' if search_q else ''
        return f'<li class="page-item{dis}{act}"><a class="page-link" href="?page={p}{sf_param}{q_param}">{txt}</a></li>'

    pag_items = pg_link(page - 1, '&laquo;')
    for p in range(max(1, page - 2), min(total_pages, page + 2) + 1):
        pag_items += pg_link(p)
    pag_items += pg_link(page + 1, '&raquo;')

    pagination_html = f'''
    <nav aria-label="FIR pagination" class="mt-2">
      <ul class="pagination justify-content-center">{pag_items}</ul>
      <p class="text-center text-muted small">
        Showing {offset + 1}–{min(offset + per_page, total_rows)} of {total_rows} records
      </p>
    </nav>''' if total_pages > 1 else ''

    no_data = f'''
    <div class="card shadow-sm p-4 text-center" style="border-left:4px solid #D6cfc4;">
      <p class="text-muted mb-2">No records found matching your search query.</p>
      <a href="/fir-management" class="btn btn-outline-secondary btn-sm">Clear Filters</a>
    </div>''' if not grouped else ''

    chart_script = f'<script>{all_chart_js}</script>' if all_chart_js else ''

    body = f'''
    <!-- Main header banner -->
    <div class="row g-4 mb-4">
      <div class="col-12">
        <div class="p-4 rounded-3 card shadow-sm" style="background:#f9fafb; border:2px solid #D6cfc4;">
          <div class="d-flex flex-wrap justify-content-between align-items-center gap-3">
            <div>
              <span class="badge bg-secondary mb-2">Central Crime Registry</span>
              <h2 class="fw-bold mb-1" style="color:#1f2937;">
                FIR Management System
              </h2>
              <p class="text-muted mb-0">
                Official National Crime Records Bureau (NCRB) repository &amp; First Information incident data across Accidental Deaths &amp; Suicides in India (ADSI). Real imported official records.
              </p>
            </div>
            <div class="d-flex flex-wrap gap-2">
              <a href="/fir-management" class="btn btn-outline-secondary btn-sm fw-semibold">Reset Filters</a>
              <a href="/crime-statistics" class="btn btn-warning fw-semibold btn-sm">Crime Statistics</a>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Summary stat cards -->
    <div class="row g-4 mb-4">
      <div class="col-md-3 col-6">
        <div class="card stats-card p-3 shadow-sm text-center">
          <h6 class="text-uppercase text-secondary small">Total Records</h6>
          <span class="fs-2 fw-bold text-info">{total_all}</span>
          <br><small class="text-muted">Imported NCRB entries</small>
        </div>
      </div>
      <div class="col-md-3 col-6">
        <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color:#2d6a4f;">
          <h6 class="text-uppercase text-secondary small">NCRB Source Tables</h6>
          <span class="fs-2 fw-bold text-success">{distinct_files}</span>
          <br><small class="text-muted">Active datasets</small>
        </div>
      </div>
      <div class="col-md-3 col-6">
        <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color:#d97706;">
          <h6 class="text-uppercase text-secondary small">Publication Year</h6>
          <span class="fs-2 fw-bold text-warning">2023</span>
          <br><small class="text-muted">Government of India</small>
        </div>
      </div>
      <div class="col-md-3 col-6">
        <div class="card stats-card p-3 shadow-sm text-center" style="border-left-color:#991b1b;">
          <h6 class="text-uppercase text-secondary small">Report Series</h6>
          <span class="fs-2 fw-bold text-danger">NCRB ADSI</span>
          <br><small class="text-muted">Official Gazette Data</small>
        </div>
      </div>
    </div>

    <!-- Filter & Search card -->
    <div class="card shadow-sm p-3 mb-4">
      <form method="GET" class="row g-2 align-items-end">
        <div class="col-md-5">
          <label class="form-label fw-semibold small" style="color:#4b5563;">Filter by NCRB Source Table</label>
          <select name="source_file" class="form-select form-select-sm"
                  onchange="this.form.submit()">
            {file_options}
          </select>
        </div>
        <div class="col-md-5">
          <label class="form-label fw-semibold small" style="color:#4b5563;">Search Within Incident Records</label>
          <input type="text" name="q" value="{escape(search_q)}"
                 class="form-control form-control-sm"
                 placeholder="e.g. Two-Wheeler, Hanging, Bankruptcy, Profession, Cause...">
        </div>
        <div class="col-md-2 d-flex gap-1">
          <button type="submit" class="btn btn-primary btn-sm flex-grow-1">Search</button>
          <a href="/fir-management" class="btn btn-outline-secondary btn-sm">&#x2715;</a>
        </div>
      </form>
    </div>

    <!-- Per-table data sections -->
    {sections_html or no_data}

    {pagination_html}
    {chart_script}
    '''
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
    search_q = request.args.get('q', '').strip()
    filter_source = request.args.get('source', '').strip()

    conn = get_db_connection()
    cur = conn.cursor()

    # 1. Fetch public CBI cases (if cbi_firs table exists)
    cbi_rows = []
    if _table_exists(conn, 'cbi_firs'):
        # Use actual DB columns — DO NOT hardcode values that override real data.
        # Fields that are NULL in DB display as "Not available" in the UI.
        # location, branch, fir_number, fir_date, offence are genuinely NULL
        # in the current dataset (the CBI index page did not provide them).
        cbi_sql = """
            SELECT
                id,
                rc_number AS case_number,
                fir_number,
                COALESCE(offence, title_or_subject) AS title_offence,
                fir_date AS case_date,
                agency,
                location,
                branch,
                status,
                pdf_url,
                source_page_url,
                source,
                'Public CBI Case' AS source_type,
                'cbi' AS source_key
            FROM cbi_firs
        """
        cbi_params = []
        cbi_clauses = []
        if search_q:
            cbi_clauses.append("(rc_number LIKE ? OR fir_number LIKE ? OR title_or_subject LIKE ? OR offence LIKE ? OR location LIKE ? OR branch LIKE ?)")
            q_pat = f"%{search_q}%"
            cbi_params.extend([q_pat, q_pat, q_pat, q_pat, q_pat, q_pat])
        if cbi_clauses:
            cbi_sql += " WHERE " + " AND ".join(cbi_clauses)
        cbi_sql += " ORDER BY id DESC"
        cbi_rows = cur.execute(cbi_sql, cbi_params).fetchall()

    # 2. Fetch portal registered cases
    reg_rows = []
    reg_sql = """
        SELECT 
            c.case_id AS id,
            c.case_number,
            f.fir_number,
            COALESCE(cr.crime_type, f.description, 'Not available') AS title_offence,
            COALESCE(c.start_date, f.filing_date, 'Not available') AS case_date,
            COALESCE(ps.station_name, 'Not available') AS agency,
            COALESCE(cr.city || ', ' || cr.state, ps.city || ', ' || ps.state, 'Not available') AS location,
            c.case_status AS status,
            c.priority,
            NULL AS pdf_url,
            NULL AS source_page_url,
            'Portal Registered Case' AS source_type,
            'registered' AS source_key,
            po.name AS officer_name,
            c.remarks
        FROM cases c
        LEFT JOIN FIR f ON c.fir_id = f.fir_id
        LEFT JOIN crimes cr ON f.crime_id = cr.crime_id
        LEFT JOIN police_stations ps ON f.station_id = ps.station_id
        LEFT JOIN police_officers po ON c.investigating_officer_id = po.officer_id
    """
    reg_params = []
    reg_clauses = []
    if search_q:
        reg_clauses.append("(c.case_number LIKE ? OR f.fir_number LIKE ? OR cr.crime_type LIKE ? OR cr.city LIKE ? OR cr.state LIKE ?)")
        q_pat = f"%{search_q}%"
        reg_params.extend([q_pat, q_pat, q_pat, q_pat, q_pat])
    if reg_clauses:
        reg_sql += " WHERE " + " AND ".join(reg_clauses)
    reg_sql += " ORDER BY c.case_id DESC"
    reg_rows = cur.execute(reg_sql, reg_params).fetchall()

    # Apply source filter if selected
    if filter_source == 'cbi':
        combined_cases = [dict(r) for r in cbi_rows]
    elif filter_source == 'registered':
        combined_cases = [dict(r) for r in reg_rows]
    else:
        combined_cases = [dict(r) for r in cbi_rows] + [dict(r) for r in reg_rows]

    dataset_years = conn.execute("SELECT year, SUM(case_count) AS total FROM crime_statistics GROUP BY year ORDER BY year").fetchall() if _table_exists(conn, 'crime_statistics') else []
    conn.close()

    # Build table rows
    cases_html = ""
    for cs in combined_cases:
        is_cbi = cs.get('source_key') == 'cbi'
        src_badge = '<span class="badge bg-primary">Public CBI Case</span>' if is_cbi else '<span class="badge bg-secondary">Portal Registered</span>'
        
        pdf_btn = ''
        if cs.get('pdf_url'):
            url = cs['pdf_url']
            if is_cbi and not url.startswith('https://cbi.gov.in/'):
                pass # Security: only allow official CBI domain for CBI records
            else:
                pdf_btn = f'<a href="{escape(url)}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-outline-danger ms-1" title="View Official FIR PDF">View</a>'
        
        fir_display = escape(cs['fir_number']) if cs.get('fir_number') else '<span class="text-muted small">Not available</span>'
        offence_display = escape(cs['title_offence']) if cs.get('title_offence') else '<span class="text-muted small">Not available</span>'
        date_display = escape(str(cs['case_date'])) if cs.get('case_date') else '<span class="text-muted small">Not available</span>'
        
        agency_str = escape(cs['agency']) if cs.get('agency') else ''
        if is_cbi and cs.get('branch'):
            agency_str += f" - {escape(cs['branch'])}"
        agency_display = agency_str if agency_str else '<span class="text-muted small">Not available</span>'
        
        location_display = escape(cs['location']) if cs.get('location') else '<span class="text-muted small">Not available</span>'

        if is_cbi:
            status_display = f'<span class="badge bg-info text-dark">{escape(cs["status"])}</span>'
        else:
            status_display = f"""
            <form method="POST" action="/case-files/{cs['id']}/status" class="d-flex gap-1">
                <select name="case_status" class="form-select form-select-sm">
                    {_options_html(CASE_STATUSES, cs['status'])}
                </select>
                <button class="btn btn-sm btn-outline-primary">Update</button>
            </form>"""

        cases_html += f"""
        <tr>
            <td class="fw-bold" style="color: #1f2937;">{escape(cs['case_number'])}</td>
            <td>{fir_display}</td>
            <td>{offence_display}</td>
            <td>{date_display}</td>
            <td>{agency_display}</td>
            <td>{location_display}</td>
            <td>{status_display}</td>
            <td>{src_badge}{pdf_btn}</td>
        </tr>
        """

    if not cases_html:
        cases_html = """
        <tr>
            <td colspan="8" class="text-center py-5 text-muted">
                <div class="mb-2" style="font-size: 1.15rem; color: #374151; font-weight: 600;">No Case Files Available</div>
                <p class="mb-1" style="font-size: 0.88rem; color: #6b7280;">No public CBI case records or registered court cases match the current query.</p>
                <p class="small text-muted mb-0">Public CBI FIR records will automatically display here when synchronized via the CBI feed.</p>
            </td>
        </tr>
        """

    year_rows = "".join(f"<tr><td>{y['year']}</td><td>{y['total']:,}</td></tr>" for y in dataset_years) or "<tr><td colspan='2' class='text-center text-muted'>Run the dataset import to show yearly context.</td></tr>"
    reset_btn = f'<a href="/case-files" class="btn btn-outline-secondary">Reset</a>' if (search_q or filter_source) else ''

    body = f"""
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h2 style="color: #1f2937; font-family: 'Times New Roman', Times, serif; font-weight: bold;">Case Files &amp; Judicial Oversight</h2>
        <span class="badge bg-secondary fs-6">{len(combined_cases)} Total Cases</span>
    </div>

    <!-- Data Classification & Source Distinction Banner -->
    <div class="card mb-4 p-3 shadow-sm" style="background-color: #f9fafb; border-left: 4px solid #374151; border-color: #dee2e6;">
        <h6 class="fw-bold mb-1" style="color: #1f2937;">Data Classification &amp; Authority Notice</h6>
        <p class="small mb-0" style="color: #4b5563;">
            &bull; <strong>Public CBI Cases:</strong> Individual Regular Cases (RCs) and public FIR records sourced from the Central Bureau of Investigation.<br>
            &bull; <strong>Portal Registered Cases:</strong> Individual case files linked to verified departmental FIR registrations.<br>
            &bull; <strong>Official NCRB Statistics:</strong> Aggregated annual crime statistics compiled at the national/state/district level (available in <a href="/fir-management" class="fw-bold" style="color: #1f2937; text-decoration: underline;">FIR Management</a> and <a href="/analytics" class="fw-bold" style="color: #1f2937; text-decoration: underline;">Analytics</a>).
        </p>
    </div>

    <!-- Search & Filter Bar -->
    <div class="card p-3 mb-4 shadow-sm" style="border: 1px solid #D6cfc4;">
        <form method="GET" action="/case-files" class="row g-2 align-items-center">
            <div class="col-md-5">
                <input type="text" name="q" value="{escape(search_q)}" class="form-control" placeholder="Search by Case/RC number, FIR number, offence, or location...">
            </div>
            <div class="col-md-4">
                <select name="source" class="form-select">
                    <option value="">All Sources (CBI &amp; Registered)</option>
                    <option value="cbi" {'selected' if filter_source == 'cbi' else ''}>Public CBI Cases</option>
                    <option value="registered" {'selected' if filter_source == 'registered' else ''}>Portal Registered Cases</option>
                </select>
            </div>
            <div class="col-md-3 d-flex gap-2">
                <button type="submit" class="btn text-white fw-semibold w-100" style="background-color: #374151;">Filter Cases</button>
                {reset_btn}
            </div>
        </form>
    </div>

    <!-- Case Files Table -->
    <div class="card p-0 mb-4 shadow-sm" style="border: 1px solid #D6cfc4;">
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0" style="font-size: 0.88rem;">
                <thead style="background-color: #e5e7eb; color: #1f2937;">
                    <tr>
                        <th>Case / RC Number</th>
                        <th>FIR Number</th>
                        <th>Crime / Offence</th>
                        <th>Date</th>
                        <th>Agency / Station</th>
                        <th>Location</th>
                        <th>Status</th>
                        <th>Source</th>
                    </tr>
                </thead>
                <tbody>{cases_html}</tbody>
            </table>
        </div>
    </div>

    <div class="row g-4">
        <div class="col-12">
            <div class="card p-4 shadow-sm" style="border: 1px solid #D6cfc4;">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5 class="mb-0" style="color: #1f2937; font-weight: bold;">NCRB Yearly Context (Aggregated Reference)</h5>
                    <span class="badge bg-secondary">Official NCRB Annual Data</span>
                </div>
                <p class="small text-muted mb-3">Historical national crime incidence totals compiled from NCRB official publications (2001–2013). These aggregate statistics provide background context and are distinct from individual Case/FIR files.</p>
                <div class="table-responsive">
                    <table class="table table-sm table-hover mb-0">
                        <thead style="background-color: #f3f4f6;"><tr><th>Year</th><th>Total Recorded Cases</th></tr></thead>
                        <tbody>{year_rows}</tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
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

    # Crime dropdown 
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

    # Run analysis only when form submitted 
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
      <p class="text-muted">Analyze historical crime trends, detect anomalies, find similar crime patterns across regions, and categorize regions — powered by real NCRB/Kaggle data (2001–2013).</p>
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
    similar  = data.get('similarities', [])
    clusters = data.get('clusters', {})
    insights = data.get('insights', [])
    # run_full_analysis returns 'years' (list) and 'counts' (list); reconstruct dict
    _years   = data.get('years', [])
    _counts  = data.get('counts', [])
    series   = dict(zip(_years, _counts)) if _years else {}
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
        ev_type  = sp.get('type', 'Spike')
        yr       = sp.get('year', '')
        pct      = sp.get('pct_change', 0)
        prev_val = sp.get('prev_val', 0)
        cur_val  = sp.get('curr_val', 0)
        tag  = '[Spike]' if ev_type == 'Spike' else '[Drop]'
        col  = '#991b1b' if ev_type == 'Spike' else '#374151'
        spike_items += f'<div class="d-flex align-items-center mb-2 p-2 rounded" style="background: #f9fafb; border-left: 4px solid {col};"><span class="badge bg-secondary me-2">{tag}</span> <b class="ms-1">{yr}</b>: {ev_type} of <b>{pct:+.1f}%</b> &nbsp;<span class="text-muted">({int(prev_val):,} → {int(cur_val):,} cases)</span></div>'

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
        # comp_ser values might be lists; handle both dict and list
        if isinstance(s_data, list):
            vals = s_data + [0] * max(0, len(years_sorted) - len(s_data))
            vals = vals[:len(years_sorted)]
        else:
            vals = [s_data.get(y, 0) for y in years_sorted]
        color    = palette[idx]
        top3_datasets += f""",
      {{
        label: '{escape(loc_name)} ({sim.get("score", 0):.1f}%)',
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

    
    # ── Region Cards ────────────────────────────────────────────────────────
    badge_colors = {
        'danger': '#dc2626',
        'success': '#16a34a',
        'primary': '#2563eb',
        'warning': '#d97706',
    }
    cluster_cards = ''
    # clusters dict keys are descriptive names; each value contains members list
    for key, meta in clusters.items():
        label = key.replace("Cluster", "Region")
        border = badge_colors.get(meta.get('badge'), '#2563eb')
        desc = meta.get('description', '')
        members = meta.get('members', [])
        badges = ' '.join(f'<span class="badge me-1 mb-1" style="background: #f3f4f6; color: #000000; border: 1px solid #cbd5e1; font-size: 0.75rem; font-weight: 600; padding: 4px 8px;">{escape(m)}</span>' for m in members)
        cluster_cards += f"""
<div class="col-md-6 mb-3">
  <div class="card h-100 p-3" style="border-left: 4px solid {border}; background: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
    <h6 style="color: #000000; font-weight: 700;">{escape(label)}</h6>
    <p class="small mb-1" style="color: #4b5563;">{escape(desc)}</p>
    <p class="small mb-2" style="color: #000000; font-weight: 600;">{len(members)} region(s)</p>
    <div>{badges if badges else '<span class="small" style="color: #000000;">No regions found</span>'}</div>
  </div>
</div>"""
    
    clusters_html = f"""
<div class="card mb-4 p-4">
  <h5 style="color: #000000; font-weight: 700;">Region — {escape(crime_type)}</h5>
  <p class="small" style="color: #374151;">Regions grouped by crime volume &amp; growth trend across the selected period.</p>
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


# FIR Search Feature
@app.route('/search-fir', methods=['GET', 'POST'])
@login_required
def search_fir():
    if request.method == 'POST':
        fir_number = request.form.get('fir_number', '').strip()
        conn = get_db_connection()
        fir = conn.execute("SELECT fir_number FROM FIR WHERE fir_number = ?", (fir_number,)).fetchone()
        conn.close()
        if fir:
            return redirect(url_for('fir_details', fir_number=fir['fir_number']))
        else:
            return render_page('''
            <h3 class="text-danger">FIR not found in the available database.</h3>
            <a href="/search-fir" class="btn btn-primary mt-3">Search Again</a>
            ''')
    # GET request – show search form
    form_html = '''
    <h3 class="mb-4">Search FIR by Number</h3>
    <form method="POST" action="/search-fir" class="row g-3">
        <div class="col-auto">
            <input type="text" name="fir_number" placeholder="Enter FIR Number" class="form-control" required>
        </div>
        <div class="col-auto">
            <button type="submit" class="btn btn-primary">Search</button>
        </div>
    </form>
    '''
    return render_page(form_html)

@app.route('/fir/<fir_number>')
@login_required
def fir_details(fir_number):
    conn = get_db_connection()
    fir = conn.execute('''
        SELECT f.*, c.crime_type, c.description AS crime_desc,
               v.name AS victim_name, v.age AS victim_age, v.gender AS victim_gender,
               v.address AS victim_address, v.phone AS victim_phone,
               s.station_name, s.station_address
        FROM FIR f
        LEFT JOIN crimes c ON f.crime_id = c.crime_id
        LEFT JOIN victims v ON f.victim_id = v.victim_id
        LEFT JOIN police_stations s ON f.station_id = s.station_id
        WHERE f.fir_number = ?
    ''', (fir_number,)).fetchone()
    conn.close()
    if not fir:
        return render_page('''
        <h3 class="text-danger">FIR not found in the available database.</h3>
        <a href="/search-fir" class="btn btn-primary mt-3">Search FIR</a>
        ''', 404)
    details_html = f'''<h3 class="mb-4">FIR Details: {fir["fir_number"]}</h3>
    <table class="table table-bordered">
        <tr><th>FIR Number</th><td>{fir["fir_number"]}</td></tr>
        <tr><th>Filing Date</th><td>{fir["filing_date"]}</td></tr>
        <tr><th>Status</th><td>{fir["status"]}</td></tr>
        <tr><th>Crime Type</th><td>{fir.get("crime_type", "")}</td></tr>
        <tr><th>Crime Description</th><td>{fir.get("crime_desc", "")}</td></tr>
        <tr><th>Victim Name</th><td>{fir.get("victim_name", "")}</td></tr>
        <tr><th>Victim Age</th><td>{fir.get("victim_age", "")}</td></tr>
        <tr><th>Victim Gender</th><td>{fir.get("victim_gender", "")}</td></tr>
        <tr><th>Victim Phone</th><td>{fir.get("victim_phone", "")}</td></tr>
        <tr><th>Victim Address</th><td>{fir.get("victim_address", "")}</td></tr>
        <tr><th>Police Station</th><td>{fir.get("station_name", "")}</td></tr>
        <tr><th>Station Address</th><td>{fir.get("station_address", "")}</td></tr>
        <tr><th>FIR Description</th><td>{fir.get("description", "")}</td></tr>
    </table>
    <a href="/search-fir" class="btn btn-secondary mt-3">Search Another FIR</a>
    '''
    return render_page(details_html)

@app.route('/recent-firs')
@login_required
def recent_firs():
    conn = get_db_connection()
    firs = conn.execute("SELECT fir_number, filing_date FROM FIR ORDER BY filing_date DESC LIMIT 10").fetchall()
    conn.close()
    rows = ''
    for f in firs:
        rows += f'''<tr>
            <td><a href="/fir/{{escape(f["fir_number"])}}">{{escape(f["fir_number"])}}</a></td>
            <td>{{escape(f["filing_date"])}}</td>
        </tr>'''
    body = f'''<h3 class="mb-4">Recent FIRs</h3>
    <table class="table table-hover">
        <thead><tr><th>FIR Number</th><th>Filing Date</th></tr></thead>
        <tbody>{rows if rows else '<tr><td colspan="2" class="text-center text-muted">No FIR records found.</td></tr>'}</tbody>
    </table>'''
    return render_page(body)

# ---------------------------------------------------------------------
# NCRB Data Import (Admin) and Browsing
# ---------------------------------------------------------------------
@app.route('/admin/ncrb-import', methods=['GET', 'POST'])
@login_required
@roles_required('Police')
def ncrb_import():
    """Upload CSV/XLSX official NCRB dataset and import into ncrb_crime_data table.
    The admin can upload a file; the server will parse, clean, and insert rows.
    Duplicate (year,state,district,crime_category,crime_type) rows are ignored via UNIQUE constraint.
    """
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        filename = secure_filename(file.filename)
        ext = os.path.splitext(filename)[1].lower()
        if ext not in {'.csv', '.xlsx'}:
            flash('Unsupported file type. Use CSV or XLSX.', 'danger')
            return redirect(request.url)
        tmp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(tmp_path)
        inserted = 0
        skipped = 0
        errors = []
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            if ext == '.csv':
                import csv
                with open(tmp_path, newline='', encoding='utf-8-sig', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    for row_num, row in enumerate(reader, start=2):
                        year = row.get('Year') or row.get('YEAR')
                        state = row.get('State/UT') or row.get('STATE/UT') or row.get('State')
                        district = row.get('District')
                        if not year or not state or not district:
                            skipped += 1
                            continue
                        try:
                            year = int(year)
                        except ValueError:
                            skipped += 1
                            continue
                        state = state.strip().title()
                        district = district.strip().title()
                        for col, val in row.items():
                            if col in ('Year','YEAR','State/UT','STATE/UT','State','District'):
                                continue
                            if not val:
                                continue
                            try:
                                cases = int(val)
                            except ValueError:
                                continue
                            if cases <= 0:
                                continue
                            crime_type = col.strip()
                            crime_category = 'IPC'
                            try:
                                cur.execute(
                                    "INSERT OR IGNORE INTO ncrb_crime_data (year, state, district, crime_category, crime_type, reported_cases) VALUES (?,?,?,?,?,?)",
                                    (year, state, district, crime_category, crime_type, cases)
                                )
                                inserted += cur.rowcount
                            except Exception as e:
                                errors.append(f'Row {row_num}: {e}')
            else:
                try:
                    import openpyxl
                except ImportError:
                    flash('openpyxl not installed – cannot process XLSX files.', 'danger')
                    return redirect(request.url)
                wb = openpyxl.load_workbook(tmp_path, data_only=True)
                ws = wb.active
                headers = [c.value for c in next(ws.iter_rows(min_row=1, max_row=1))]
                for idx, row in enumerate(ws.iter_rows(min_row=2), start=2):
                    row_dict = {headers[i]: row[i].value for i in range(len(headers))}
                    year = row_dict.get('Year') or row_dict.get('YEAR')
                    state = row_dict.get('State/UT') or row_dict.get('STATE/UT') or row_dict.get('State')
                    district = row_dict.get('District')
                    if not year or not state or not district:
                        skipped += 1
                        continue
                    try:
                        year = int(year)
                    except ValueError:
                        skipped += 1
                        continue
                    state = str(state).strip().title()
                    district = str(district).strip().title()
                    for col, val in row_dict.items():
                        if col in ('Year','YEAR','State/UT','STATE/UT','State','District'):
                            continue
                        if val is None:
                            continue
                        try:
                            cases = int(val)
                        except ValueError:
                            continue
                        if cases <= 0:
                            continue
                        crime_type = str(col).strip()
                        crime_category = 'IPC'
                        try:
                            cur.execute(
                                "INSERT OR IGNORE INTO ncrb_crime_data (year, state, district, crime_category, crime_type, reported_cases) VALUES (?,?,?,?,?,?)",
                                (year, state, district, crime_category, crime_type, cases)
                            )
                            inserted += cur.rowcount
                        except Exception as e:
                            errors.append(f'Row {idx}: {e}')
            conn.commit()
            flash(f'Import completed – inserted: {inserted}, skipped: {skipped}.', 'success')
            if errors:
                flash('Some rows produced errors – see server log.', 'warning')
        finally:
            conn.close()
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        return redirect(url_for('ncrb_browse'))
    # GET – show upload form
    form_html = '''
    <h3 class="mb-4">Import Official NCRB Data</h3>
    <form method="POST" enctype="multipart/form-data" class="row g-3">
        <div class="col-auto">
            <input type="file" name="file" class="form-control" accept=".csv,.xlsx" required>
        </div>
        <div class="col-auto">
            <button type="submit" class="btn btn-primary">Upload</button>
        </div>
    </form>
    '''
    return render_page(form_html)

@app.route('/ncrb-data')
@login_required
def ncrb_browse():
    """Redirect legacy /ncrb-data endpoint to the new FIR Management System."""
    return redirect(url_for('fir_management', **request.args))

if __name__ == '__main__':
    init_db()
    
    # Auto-seed test citizen data so the user just runs app.py
    try:
        import seed_test_citizens
        seed_test_citizens.seed()
        print("Auto-seeded test citizen accounts.")
    except Exception as e:
        print(f"[WARN] Failed to auto-seed test citizens: {e}")
        
    print("Starting Crime Management Portal (Kaggle/NCRB Version) on http://127.0.0.1:5051")
    app.run(host='0.0.0.0', port=5051, debug=True)