import sqlite3
import requests
import io
import re

import pdfplumber

def extract_info_from_pdf(pdf_bytes):
    text = ""
    try:
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
    except Exception as e:
        return {"error": f"PDF parse error: {e}"}

    if not text.strip():
        return {"error": "No text extracted (could be scanned/image-only PDF)."}

    # Let's return the first 1500 chars to analyze the format.
    return {"text": text[:1500]}

def main():
    conn = sqlite3.connect('data/crms.db')
    conn.row_factory = sqlite3.Row
    
    rows = conn.execute("SELECT id, rc_number, pdf_url FROM cbi_firs WHERE pdf_url IS NOT NULL LIMIT 5").fetchall()
    
    for r in rows:
        rc = r['rc_number']
        url = r['pdf_url']
        print(f"--- RC: {rc} ---")
        try:
            resp = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            resp.raise_for_status()
            
            res = extract_info_from_pdf(resp.content)
            if "error" in res:
                print(f"FAILED: {res['error']}")
            else:
                print("TEXT EXTRACT:")
                print(res["text"])
                print("TEXT END\n")
                
        except Exception as e:
            print(f"Download/Process Error: {e}")

if __name__ == "__main__":
    main()
