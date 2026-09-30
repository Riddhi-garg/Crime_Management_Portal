#!/usr/bin/env python3
"""Seed script to insert synthetic test police stations and FIR records for the Police Dashboard.

- Adds six test stations (if they do not already exist).
- Inserts twelve test FIR records, two per station.
- Uses placeholder entries for required foreign‑key tables (crimes, victims) when needed.
- Marks records as TEST DATA via the station name prefix "Test ".
- Does NOT modify any genuine records or CBI data.
- Idempotent – running the script multiple times will not create duplicates.

Run with:
    python seed_test_police_stations.py
"""

import sys
import sqlite3
from pathlib import Path

# Import the Flask app's DB helper (assumes the project root is on PYTHONPATH)
try:
    from Crime_Management_Portal.app import get_db_connection
except ImportError:
    # When the script is executed from the project root, add the package path manually.
    sys.path.append(str(Path(__file__).parent / "Crime_Management_Portal"))
    from Crime_Management_Portal.app import get_db_connection

# ---------------------------------------------------------------------------
# Configuration – test data definitions
# ---------------------------------------------------------------------------
TEST_STATIONS = [
    {"name": "Test Central Police Station", "city": "Test City", "state": "Uttar Pradesh", "contact": "000-000-0000"},
    {"name": "Test Cyber Crime Police Station", "city": "Test City", "state": "Uttar Pradesh", "contact": "000-000-0001"},
    {"name": "Test North Police Station", "city": "Test City", "state": "Uttar Pradesh", "contact": "000-000-0002"},
    {"name": "Test South Police Station", "city": "Test City", "state": "Uttar Pradesh", "contact": "000-000-0003"},
    {"name": "Test Women Police Station", "city": "Test City", "state": "Uttar Pradesh", "contact": "000-000-0004"},
    {"name": "Test Rural Police Station", "city": "Test District", "state": "Uttar Pradesh", "contact": "000-000-0005"},
]

# Each entry is (station_name, fir_number, crime, filing_date, status)
TEST_FIRS = [
    # Test Central Police Station
    ("Test Central Police Station", "FIR-TEST-ST-001", "Theft", "2026-01-10", "Pending"),
    ("Test Central Police Station", "FIR-TEST-ST-002", "Burglary", "2026-02-12", "Under Investigation"),
    # Test Cyber Crime Police Station
    ("Test Cyber Crime Police Station", "FIR-TEST-ST-003", "Cyber Fraud", "2026-01-20", "Pending"),
    ("Test Cyber Crime Police Station", "FIR-TEST-ST-004", "Online Financial Fraud", "2026-03-01", "Closed"),
    # Test North Police Station
    ("Test North Police Station", "FIR-TEST-ST-005", "Vehicle Theft", "2026-02-05", "Under Investigation"),
    ("Test North Police Station", "FIR-TEST-ST-006", "Assault", "2026-03-15", "Pending"),
    # Test South Police Station
    ("Test South Police Station", "FIR-TEST-ST-007", "Property Dispute", "2026-01-25", "Pending"),
    ("Test South Police Station", "FIR-TEST-ST-008", "Criminal Trespass", "2026-03-10", "Closed"),
    # Test Women Police Station
    ("Test Women Police Station", "FIR-TEST-ST-009", "Harassment", "2026-02-18", "Under Investigation"),
    ("Test Women Police Station", "FIR-TEST-ST-010", "Domestic Dispute", "2026-03-20", "Pending"),
    # Test Rural Police Station
    ("Test Rural Police Station", "FIR-TEST-ST-011", "Theft", "2026-01-30", "Closed"),
    ("Test Rural Police Station", "FIR-TEST-ST-012", "Property Damage", "2026-02-28", "Pending"),
]

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def ensure_crime(conn: sqlite3.Connection, crime_name: str) -> int:
    """Return a crime_id for *crime_name*, inserting a placeholder row if necessary.
    The *crimes* table has columns (crime_id, crime_type, description)."""
    row = conn.execute("SELECT crime_id FROM crimes WHERE crime_type = ?", (crime_name,)).fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        "INSERT INTO crimes (crime_type, description) VALUES (?, ?)",
        (crime_name, "TEST DATA ONLY - Placeholder for police dashboard testing."),
    )
    return cur.lastrowid


def ensure_victim(conn: sqlite3.Connection) -> int:
    """Create a generic dummy victim and return its id.
    The *victims* table is required for the FIR foreign‑key constraint.
    We reuse a single dummy victim for all test FIRs."""
    row = conn.execute("SELECT victim_id FROM victims LIMIT 1").fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        "INSERT INTO victims (name, gender, age, address) VALUES (?, ?, ?, ?)",
        ("Test Victim", "Other", 30, "Test Address"),
    )
    return cur.lastrowid


def get_station_id(conn: sqlite3.Connection, name: str) -> int:
    row = conn.execute("SELECT station_id FROM police_stations WHERE station_name = ?", (name,)).fetchone()
    if row:
        return row[0]
    raise ValueError(f"Station '{name}' not found – this should never happen after insertion.")

# ---------------------------------------------------------------------------
# Main seeding logic
# ---------------------------------------------------------------------------

def main():
    conn = get_db_connection()
    try:
        # 1. Insert test stations (idempotent)
        for st in TEST_STATIONS:
            exists = conn.execute(
                "SELECT 1 FROM police_stations WHERE station_name = ?", (st["name"],)
            ).fetchone()
            if not exists:
                conn.execute(
                    "INSERT INTO police_stations (station_name, address, city, state, contact_number) VALUES (?, ?, ?, ?, ?)",
                    (
                        st["name"],
                        f"{st['name']} – TEST ADDRESS",
                        st["city"],
                        st["state"],
                        st["contact"],
                    ),
                )
                print(f"Inserted test station: {st['name']}")
            else:
                print(f"Test station already exists: {st['name']}")

        # 2. Prepare supporting data (crime & victim placeholders)
        victim_id = ensure_victim(conn)

        # 3. Insert test FIRs (idempotent based on FIR number)
        for station_name, fir_no, crime_name, filing_date, status in TEST_FIRS:
            exists = conn.execute("SELECT 1 FROM FIR WHERE fir_number = ?", (fir_no,)).fetchone()
            if exists:
                print(f"FIR already exists: {fir_no}")
                continue
            station_id = get_station_id(conn, station_name)
            crime_id = ensure_crime(conn, crime_name)
            conn.execute(
                "INSERT INTO FIR (fir_number, crime_id, victim_id, station_id, filing_date, description, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    fir_no,
                    crime_id,
                    victim_id,
                    station_id,
                    filing_date,
                    "TEST DATA ONLY - Synthetic record created for Police Dashboard testing.",
                    status,
                ),
            )
            print(f"Inserted FIR {fir_no} for station {station_name}")

        conn.commit()
        print("\nSeeding complete.")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
