"""
FIR model for storing CBI FIR records.

--- DJANGO USERS ---
If your project is actually Django, translate this to:

    from django.db import models

    class CBIFir(models.Model):
        rc_number = models.CharField(max_length=100, unique=True)
        fir_number = models.CharField(max_length=50, blank=True, null=True)
        fir_date = models.DateField(blank=True, null=True)
        title_or_subject = models.CharField(max_length=500, blank=True, null=True)
        pdf_url = models.URLField(max_length=500)
        source_page_url = models.URLField(max_length=500)
        first_seen_at = models.DateTimeField(auto_now_add=True)
        last_seen_at = models.DateTimeField(auto_now=True)

        class Meta:
            ordering = ["-fir_date"]

    Then run: python manage.py makemigrations && python manage.py migrate

--- FLASK / SQLAlchemy (used below) ---
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class CBIFir(db.Model):
    __tablename__ = "cbi_firs"

    id = db.Column(db.Integer, primary_key=True)

    # RC number (Regular Case number) is CBI's own unique case identifier,
    # e.g. "RC0782017E0007" — use this as the dedup key, NOT the FIR number,
    # since FIR numbers repeat across years/branches but RC numbers don't.
    rc_number = db.Column(db.String(100), unique=True, nullable=False, index=True)

    fir_number = db.Column(db.String(50), nullable=True)
    fir_date = db.Column(db.Date, nullable=True)
    title_or_subject = db.Column(db.String(500), nullable=True)

    pdf_url = db.Column(db.String(500), nullable=False)
    source_page_url = db.Column(db.String(500), nullable=False)

    first_seen_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "rc_number": self.rc_number,
            "fir_number": self.fir_number,
            "fir_date": self.fir_date.isoformat() if self.fir_date else None,
            "title_or_subject": self.title_or_subject,
            "pdf_url": self.pdf_url,
            "first_seen_at": self.first_seen_at.isoformat() if self.first_seen_at else None,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
        }