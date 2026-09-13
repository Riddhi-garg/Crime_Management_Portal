"""
cbi_integration/sync.py

Compares freshly scraped FIRs against what's already in the DB and
inserts new ones / updates the "last_seen_at" timestamp on existing ones.
"""

import logging

from .models import db, CBIFir
from .scraper import get_current_firs, CBIScraperError

logger = logging.getLogger(__name__)


def sync_cbi_firs(app=None) -> dict:
    """
    Runs one sync cycle. Returns a summary dict:
        {"fetched": N, "new": N, "updated": N, "errors": N}

    If `app` (a Flask app) is passed, this wraps the DB work in its
    app context — needed when called from a background scheduler thread
    that has no request context.
    """
    summary = {"fetched": 0, "new": 0, "updated": 0, "errors": 0}

    def _do_sync():
        try:
            firs = get_current_firs()
        except CBIScraperError as e:
            logger.error("CBI sync failed: %s", e)
            summary["errors"] += 1
            return

        summary["fetched"] = len(firs)

        for fir_data in firs:
            existing = CBIFir.query.filter_by(rc_number=fir_data["rc_number"]).first()
            if existing:
                # Already have it — just bump last_seen_at (handled by onupdate)
                existing.pdf_url = fir_data["pdf_url"]
                summary["updated"] += 1
            else:
                new_fir = CBIFir(
                    rc_number=fir_data["rc_number"],
                    fir_number=fir_data.get("fir_number"),
                    fir_date=fir_data.get("fir_date"),
                    title_or_subject=fir_data.get("title_or_subject"),
                    pdf_url=fir_data["pdf_url"],
                    source_page_url="https://cbi.gov.in/view-fir",
                )
                db.session.add(new_fir)
                summary["new"] += 1

        db.session.commit()
        logger.info("CBI sync complete: %s", summary)

    if app is not None:
        with app.app_context():
            _do_sync()
    else:
        _do_sync()

    return summary