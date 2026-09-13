"""
cbi_integration/scraper.py

Fetches the CBI "View FIR" listing page and extracts individual FIR records.

IMPORTANT — READ BEFORE RUNNING
--------------------------------
1. cbi.gov.in's robots.txt disallows automated crawling of parts of the
   site. Public FIRs are published there under a Supreme Court directive
   (2016) and are meant to be publicly viewable, but you should still:
     - Keep request frequency low (this script defaults to once every
       few hours, not every few minutes).
     - Set a real, identifying User-Agent (done below).
     - Check CBI's Terms of Use before deploying this anywhere beyond a
       local/academic project.

2. I could not fetch cbi.gov.in/view-fir directly (blocked for automated
   tools), so I don't know its exact HTML structure. The parsing function
   below is a TEMPLATE with the shape CBI's page is publicly known to
   have (a listing of RC numbers + PDF links), but you MUST verify and
   adjust the CSS selectors marked with "ADJUST ME" for the actual page.

HOW TO FIND THE REAL SELECTORS
-------------------------------
1. Open https://cbi.gov.in/view-fir in Chrome/Firefox.
2. Right-click a row in the FIR table/list -> "Inspect".
3. Note the tag + class/id of:
     - the repeating row/card element (ROW_SELECTOR)
     - the element holding the RC number / FIR number text
     - the <a> tag whose href points to the PDF (usually ends in .pdf)
     - the element holding the date, if shown
4. Paste those into the constants below.
5. If the page loads results via JavaScript (check: view page source and
   see if the FIR list is actually present in the raw HTML, not just in
   dev tools after rendering), requests+BeautifulSoup won't see it and
   you'll need Selenium/Playwright instead — let me know and I'll adapt
   this to that.
"""

import re
import logging
from datetime import datetime
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

CBI_FIR_PAGE_URL = "https://cbi.gov.in/view-fir"

HEADERS = {
    # Identify yourself honestly — don't spoof a browser UA to evade blocking.
    "User-Agent": "CrimeManagementPortal-AcademicProject/1.0 (contact: your-email@example.com)"
}

REQUEST_TIMEOUT = 15  # seconds


class CBIScraperError(Exception):
    pass


def fetch_fir_listing_html(url: str = CBI_FIR_PAGE_URL) -> str:
    """Downloads the raw HTML of the FIR listing page."""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        raise CBIScraperError(f"Failed to fetch {url}: {e}") from e


def parse_fir_listing(html: str, base_url: str = CBI_FIR_PAGE_URL) -> list[dict]:
    """
    Parses the FIR listing HTML into a list of dicts:
        {rc_number, fir_number, fir_date, title_or_subject, pdf_url}

    ADJUST ME: the selectors below are placeholders. Replace them once
    you've inspected the live page.
    """
    soup = BeautifulSoup(html, "html.parser")
    results = []

    # ADJUST ME: selector for each repeating FIR row/card.
    # Common patterns: "table tr", "div.fir-row", "li.fir-item"
    rows = soup.select("table tr")  # <-- placeholder

    for row in rows:
        # Skip header rows with no links
        pdf_link = row.find("a", href=re.compile(r"\.pdf$", re.IGNORECASE))
        if not pdf_link:
            continue

        pdf_url = urljoin(base_url, pdf_link["href"])

        # RC number is usually embedded in the PDF filename, e.g.
        # https://cbi.gov.in/assets/files/fir/RC0782017E0007.pdf
        rc_match = re.search(r"([A-Z]{2}\d+[A-Z]\d+)", pdf_url)
        rc_number = rc_match.group(1) if rc_match else pdf_url.rsplit("/", 1)[-1]

        # ADJUST ME: pull the visible text cells for FIR number / date / title
        cells = [c.get_text(strip=True) for c in row.find_all(["td", "span", "div"])]
        row_text = " | ".join(c for c in cells if c)

        fir_number = _extract_fir_number(row_text)
        fir_date = _extract_date(row_text)

        results.append(
            {
                "rc_number": rc_number,
                "fir_number": fir_number,
                "fir_date": fir_date,
                "title_or_subject": row_text[:500] if row_text else None,
                "pdf_url": pdf_url,
            }
        )

    return results


def _extract_fir_number(text: str) -> str | None:
    # ADJUST ME once you know the real label format, e.g. "FIR No: 12/2024"
    m = re.search(r"FIR\s*No\.?\s*[:\-]?\s*([A-Za-z0-9/\-]+)", text, re.IGNORECASE)
    return m.group(1) if m else None


def _extract_date(text: str) -> "datetime.date | None":
    # Tries a couple of common Indian date formats: dd/mm/yyyy, dd-mm-yyyy
    m = re.search(r"(\d{1,2})[/\-](\d{1,2})[/\-](\d{4})", text)
    if not m:
        return None
    day, month, year = map(int, m.groups())
    try:
        return datetime(year, month, day).date()
    except ValueError:
        return None


def get_current_firs() -> list[dict]:
    """Convenience wrapper: fetch + parse in one call."""
    html = fetch_fir_listing_html()
    return parse_fir_listing(html)