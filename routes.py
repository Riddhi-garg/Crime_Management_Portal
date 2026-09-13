"""
cbi_integration/routes.py

A Flask blueprint you can register in your main app:

    from cbi_integration.routes import cbi_bp
    app.register_blueprint(cbi_bp, url_prefix="/cbi-firs")

Endpoints:
    GET  /cbi-firs/           -> list synced FIRs (JSON)
    POST /cbi-firs/sync-now   -> trigger an immediate manual sync
"""

from flask import Blueprint, jsonify, current_app

from .models import CBIFir
from .sync import sync_cbi_firs

cbi_bp = Blueprint("cbi_firs", __name__)


@cbi_bp.route("/", methods=["GET"])
def list_firs():
    firs = CBIFir.query.order_by(CBIFir.fir_date.desc().nullslast()).all()
    return jsonify([f.to_dict() for f in firs])


@cbi_bp.route("/sync-now", methods=["POST"])
def sync_now():
    summary = sync_cbi_firs(app=current_app._get_current_object())
    return jsonify({"status": "ok", "summary": summary})