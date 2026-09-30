#!/usr/bin/env python3
"""
refresh_cbi_location_date.py

Fetches the official CBI View FIR page (https://cbi.gov.in/view-fir) and
updates ONLY the fir_date and location columns for EXISTING cbi_firs records.

- Does NOT insert new records.
- Does NOT modify rc_number or pdf_url.
- Does NOT fabricate data — only uses actual CBI source values.
- Stops gracefully if the CBI site becomes unavailable.
"""

import urllib.request
import ssl
import re
import sqlite3
import os
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "crms.db"
OFFICIAL_FIR_URL = "https://cbi.gov.in/view-fir"

def fetch_page(url, timeout=30):
    """Fetch a URL and return the HTML content."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/120.0.0.0 Safari/537.36",
    }
    req = urllib.request.Request(url, headers=headers)
    resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
    return resp.read().decode('utf-8', errors='ignore')


def parse_cbi_table(html):
    """Parse CBI View FIR HTML table rows and extract (rc_number, location, date)."""
    records = []
    # Match table rows with class rgRow or rgAltRow
    row_pat = re.compile(
        r'<tr[^>]*class=[\'"](?:rgRow|rgAltRow)[\'"][^>]*>(.*?)</tr>',
        re.DOTALL | re.I
    )
    for row_html in row_pat.findall(html):
        tds = re.findall(r'<td[^>]*>(.*?)</td>', row_html, re.DOTALL | re.I)
        if len(tds) < 5:
            continue

        # Column 1 (index 1): Location Of Registration
        loc = re.sub(r'<span[^>]*class=[\'"]visible-xs[\'"]>.*?</span>', '', tds[1],
                     flags=re.DOTALL | re.I)
        loc = re.sub(r'<[^>]+>', '', loc).strip()
        # Strip mobile-responsive column label prefix if present
        loc = re.sub(r'^Location\s*Of\s*Registration\s*', '', loc, flags=re.I).strip()

        # Column 2 (index 2): Regular Case No. (with PDF link)
        link = re.search(r'<a[^>]*href=[\'"]([^\'"]+)[\'"][^>]*>(.*?)</a>', tds[2], re.I)
        if not link:
            continue
        rc = re.sub(r'<[^>]+>', '', link.group(2)).strip()

        # Column 4 (index 4): Date of Registration
        date = re.sub(r'<span[^>]*class=[\'"]visible-xs[\'"]>.*?</span>', '', tds[4],
                      flags=re.DOTALL | re.I)
        date = re.sub(r'<[^>]+>', '', date).strip()
        # Strip mobile-responsive column label prefix if present
        date = re.sub(r'^Date\s*of\s*Registration\s*', '', date, flags=re.I).strip()

        if rc:
            records.append({
                "rc_number": rc,
                "location": loc if loc else None,
                "fir_date": date if date else None,
            })
    return records


def main():
    print("=" * 70)
    print("CBI LOCATION & DATE REFRESH")
    print("=" * 70)
    print(f"Database: {DB_PATH}")
    print(f"Source:   {OFFICIAL_FIR_URL}")
    print()

    # Verify database exists
    if not DB_PATH.exists():
        print(f"ERROR: Database not found at {DB_PATH}")
        sys.exit(1)

    # Count existing records
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    total_before = conn.execute("SELECT COUNT(*) FROM cbi_firs").fetchone()[0]
    print(f"Existing CBI records in database: {total_before}")
    print()

    # Step 1: Fetch the CBI page
    print("[1/3] Fetching official CBI View FIR page...")
    try:
        html = fetch_page(OFFICIAL_FIR_URL)
        print(f"      Page fetched successfully ({len(html):,} bytes)")
    except Exception as e:
        print(f"ERROR: Could not fetch CBI page: {e}")
        print("STOPPING. No records were modified.")
        conn.close()
        sys.exit(1)

    # Step 2: Parse the table
    print("[2/3] Parsing CBI table rows...")
    scraped = parse_cbi_table(html)
    print(f"      Extracted {len(scraped)} records from the page")
    if not scraped:
        print("WARNING: No records parsed. The page format may have changed or the site returned an error page.")
        print("STOPPING. No records were modified.")
        conn.close()
        sys.exit(1)

    # Show a few examples
    print()
    print("      Sample records from CBI source:")
    for r in scraped[:5]:
        print(f"        RC: {r['rc_number']:25s}  Location: {r['location'] or '(empty)':30s}  Date: {r['fir_date'] or '(empty)'}")
    print()

    # Step 3: Update existing database records
    print("[3/3] Updating existing database records...")
    updated_location = 0
    updated_date = 0
    matched = 0
    not_in_db = 0

    for rec in scraped:
        rc = rec["rc_number"]
        # Check if this RC exists in the database
        existing = conn.execute(
            "SELECT id, fir_date, location FROM cbi_firs WHERE rc_number = ?",
            (rc,)
        ).fetchone()

        if not existing:
            not_in_db += 1
            continue

        matched += 1
        updates = []
        params = []

        # Only update fir_date if currently NULL and source has a value
        if rec["fir_date"] and (not existing["fir_date"]):
            updates.append("fir_date = ?")
            params.append(rec["fir_date"])
            updated_date += 1

        # Only update location if currently NULL and source has a value
        if rec["location"] and (not existing["location"]):
            updates.append("location = ?")
            params.append(rec["location"])
            updated_location += 1

        if updates:
            updates.append("last_seen_at = CURRENT_TIMESTAMP")
            sql = f"UPDATE cbi_firs SET {', '.join(updates)} WHERE id = ?"
            params.append(existing["id"])
            conn.execute(sql, params)

    conn.commit()

    # Verification
    total_after = conn.execute("SELECT COUNT(*) FROM cbi_firs").fetchone()[0]
    has_date = conn.execute("SELECT COUNT(*) FROM cbi_firs WHERE fir_date IS NOT NULL AND fir_date != ''").fetchone()[0]
    has_location = conn.execute("SELECT COUNT(*) FROM cbi_firs WHERE location IS NOT NULL AND location != ''").fetchone()[0]
    missing_date = total_after - has_date
    missing_location = total_after - has_location

    # Show sample updated records
    print()
    print("      Sample updated records:")
    samples = conn.execute(
        "SELECT rc_number, fir_date, location FROM cbi_firs WHERE fir_date IS NOT NULL AND location IS NOT NULL LIMIT 5"
    ).fetchall()
    for s in samples:
        print(f"        RC: {s['rc_number']:25s}  Date: {s['fir_date']:15s}  Location: {s['location']}")

    conn.close()

    # Final report
    print()
    print("=" * 70)
    print("REFRESH COMPLETE — AUDIT REPORT")
    print("=" * 70)
    print(f"1. Records in DB before update:     {total_before}")
    print(f"2. Records in DB after update:      {total_after}")
    print(f"3. Records scraped from CBI source: {len(scraped)}")
    print(f"4. Records matched to existing DB:  {matched}")
    print(f"5. Scraped but NOT in DB (skipped):  {not_in_db}")
    print(f"6. Location fields populated:       {updated_location}")
    print(f"7. Date fields populated:           {updated_date}")
    print(f"8. Total with Location now:         {has_location}")
    print(f"9. Total with Date now:             {has_date}")
    print(f"10. Still missing Location:          {missing_location}")
    print(f"11. Still missing Date:              {missing_date}")
    print(f"12. New records created:             0 (update-only mode)")
    print(f"13. RC numbers changed:              0")
    print(f"14. PDF URLs changed:                0")
    print("=" * 70)


if __name__ == "__main__":
    main()
