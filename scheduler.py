"""
cbi_integration/scheduler.py

Runs sync_cbi_firs() automatically on a schedule, in the background,
inside your existing Flask app process. No separate worker needed —
good fit for a student/academic project.

For a production system you'd normally use Celery beat instead, but
APScheduler is far less setup for this scale.
"""

import atexit
import logging

from apscheduler.schedulers.background import BackgroundScheduler

try:
    from sync import sync_cbi_firs
except ImportError:
    from .sync import sync_cbi_firs

logger = logging.getLogger(__name__)

_scheduler = None


def init_cbi_scheduler(app, interval_hours: int = 6):
    """
    Call this once from your Flask app factory / main app.py, after the
    app and db are created:

        from cbi_integration.scheduler import init_cbi_scheduler
        init_cbi_scheduler(app, interval_hours=6)

    `interval_hours=6` means it re-checks CBI's page 4x/day. Keep this
    modest — there's no benefit to polling more often than CBI actually
    publishes new FIRs, and it's kinder to their servers.
    """
    global _scheduler
    if _scheduler is not None:
        return _scheduler  # already started (avoids double-init on reload)

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        func=lambda: sync_cbi_firs(app=app),
        trigger="interval",
        hours=interval_hours,
        id="cbi_fir_sync",
        next_run_time=None,  # set below to run once shortly after startup
        misfire_grace_time=3600,
    )
    _scheduler.start()

    # Run an initial sync 30 seconds after startup, not instantly, so the
    # app finishes booting first.
    from datetime import datetime, timedelta
    _scheduler.modify_job("cbi_fir_sync", next_run_time=datetime.now() + timedelta(seconds=30))

    atexit.register(lambda: _scheduler.shutdown(wait=False))
    logger.info("CBI FIR scheduler started (every %s hours)", interval_hours)
    return _scheduler