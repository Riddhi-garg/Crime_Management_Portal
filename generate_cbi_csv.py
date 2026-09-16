#!/usr/bin/env python3
import urllib.request, ssl, csv, re, os
from urllib.parse import urlparse

OFFICIAL_FIR_URL = "https://cbi.gov.in/view-fir"
# fetch page
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
headers = {"User-Agent": "Mozilla/5.0"}
req = urllib.request.Request(OFFICIAL_FIR_URL, headers=headers)
html = urllib.request.urlopen(req, context=ctx, timeout=30).read().decode('utf-8', errors='ignore')

row_pat = re.compile(r'<tr[^>]*class=[\'\"](?:rgRow|rgAltRow)[\'\"][^>]*>(.*?)</tr>', re.DOTALL|re.I)
rows = row_pat.findall(html)
records = []
for row in rows:
    tds = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL|re.I)
    if len(tds) < 5:
        continue
    # location (strip visible-xs span)
    loc = re.sub(r'<span[^>]*class=[\'\"]visible-xs[\'\"]>.*?</span>', '', tds[1], flags=re.DOTALL|re.I)
    loc = re.sub(r'<[^>]+>', '', loc).strip()
    # RC & PDF link
    link = re.search(r'<a[^>]*href=[\'\"]([^\'\"]+)[\'\"][^>]*>(.*?)</a>', tds[2], re.I)
    if not link:
        continue
    pdf_url = link.group(1).strip()
    rc = re.sub(r'<[^>]+>', '', link.group(2)).strip()
    # date
    date = re.sub(r'<span[^>]*class=[\'\"]visible-xs[\'\"]>.*?</span>', '', tds[4], flags=re.DOTALL|re.I)
    date = re.sub(r'<[^>]+>', '', date).strip()
    # Append record with available fields; others left empty
    records.append({
        "rc_number": rc,
        "fir_number": "",
        "fir_date": date,
        "title_or_subject": "",
        "offence": "",
        "branch": "",
        "location": loc,
        "status": "Under Investigation",
        "pdf_url": pdf_url,
    })

csv_path = os.path.abspath("data/cbi/cbi_firs.csv")
os.makedirs(os.path.dirname(csv_path), exist_ok=True)
with open(csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["rc_number","fir_number","fir_date","title_or_subject","offence","branch","location","status","pdf_url"])
    writer.writeheader()
    writer.writerows(records)
print(f"CSV written to {csv_path}, records: {len(records)}")
