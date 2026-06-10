from __future__ import annotations
import json, os, zipfile
from datetime import datetime
from io import BytesIO
from pathlib import Path
from flask import current_app
from .models import Settings, SignalArchive, Unit, User, Broadcast

def backup_folder(app=None) -> str:
    app = app or current_app
    folder = os.path.join(app.instance_path, "backups")
    os.makedirs(folder, exist_ok=True)
    return folder

def _serialize_users():
    return [{"id": u.id, "service_number": u.service_number, "full_name": u.full_name, "rank": u.rank, "specialty": u.specialty, "role": u.role, "unit_id": u.unit_id, "clearance_level": u.clearance_level, "is_active": bool(u.is_active_flag), "created_at": u.created_at.isoformat() if u.created_at else None} for u in User.query.order_by(User.full_name.asc()).all()]

def _serialize_units():
    return [{"id": u.id, "name": u.name, "code": u.code, "level": u.level, "parent_id": u.parent_id, "created_at": u.created_at.isoformat() if u.created_at else None} for u in Unit.query.order_by(Unit.name.asc()).all()]

def _serialize_broadcasts():
    rows = []
    for b in Broadcast.query.order_by(Broadcast.created_at.desc()).all():
        rows.append({"id": b.id, "title": b.title, "priority": b.priority, "status": b.status, "issuer_id": b.issuer_id, "target_scope": b.target_scope, "target_unit_id": b.target_unit_id, "target_level": b.target_level, "requires_ack": bool(b.requires_ack), "originator_number": b.originator_number, "classification": b.security_classification, "precedence_action": b.precedence_action, "precedence_info": b.precedence_info, "msg_from": b.msg_from, "msg_to": b.msg_to, "from_unit_id": b.from_unit_id, "dtg": b.dtg, "message_instruction": b.message_instruction, "file_reference": b.file_reference, "internal_distribution": b.internal_distribution, "released_at": b.released_at.isoformat() if b.released_at else None, "created_at": b.created_at.isoformat() if b.created_at else None, "signed_at": b.signed_at.isoformat() if b.signed_at else None, "signed_by_id": b.signed_by_id, "signature_fingerprint": b.signature_fingerprint, "digital_signature": b.digital_signature, "action_user_ids": b.csv_ids("action_users_csv"), "info_user_ids": b.csv_ids("info_users_csv"), "action_unit_ids": b.csv_ids("action_units_csv"), "info_unit_ids": b.csv_ids("info_units_csv")})
    return rows

def _serialize_archives():
    return [{"id": a.id, "broadcast_id": a.broadcast_id, "file_name": a.file_name, "title": a.title, "signal_number": a.signal_number, "classification": a.classification, "priority": a.priority, "from_unit_text": a.from_unit_text, "sha256": a.sha256, "signature_hash": a.signature_hash, "integrity_status": a.integrity_status, "verified_at": a.verified_at.isoformat() if a.verified_at else None, "export_count": a.export_count, "created_at": a.created_at.isoformat() if a.created_at else None} for a in SignalArchive.query.order_by(SignalArchive.created_at.desc()).all()]

def _serialize_settings():
    s = Settings.get()
    return {"platform_name": s.platform_name, "maintenance_mode": bool(s.maintenance_mode), "maintenance_banner": s.maintenance_banner, "dark_mode_default": bool(s.dark_mode_default), "allowed_extensions": s.allowed_extensions, "storage_backend": s.storage_backend, "retention_days": s.retention_days, "allow_direct_messages": bool(s.allow_direct_messages), "allow_attachments": bool(s.allow_attachments), "max_attachment_mb": s.max_attachment_mb, "session_timeout_minutes": s.session_timeout_minutes, "broadcast_escalation_minutes": s.broadcast_escalation_minutes}

def build_backup_zip_bytes(app=None, include_database=True):
    app = app or current_app
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    name = f"nms_disaster_recovery_{stamp}.zip"
    archive_folder = app.config.get("SIGNAL_ARCHIVE_FOLDER") or os.path.join(app.instance_path, "signal_bank")
    payload = {"generated_at_utc": datetime.utcnow().isoformat() + "Z", "settings": _serialize_settings(), "users": _serialize_users(), "units": _serialize_units(), "broadcasts": _serialize_broadcasts(), "signal_archives": _serialize_archives()}
    mem = BytesIO()
    with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("export/system_export.json", json.dumps(payload, indent=2))
        zf.writestr("export/README.txt", "Disaster recovery export for NMS. Contains system JSON, released signal PDFs, and database snapshot if available.\n")
        if os.path.isdir(archive_folder):
            for file_name in sorted(os.listdir(archive_folder)):
                path = os.path.join(archive_folder, file_name)
                if os.path.isfile(path):
                    zf.write(path, arcname=f"signals/{file_name}")
        if include_database:
            db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
            if db_uri.startswith("sqlite:///"):
                db_path = db_uri.replace("sqlite:///", "", 1)
                if not os.path.isabs(db_path):
                    db_path = os.path.join(app.instance_path, os.path.basename(db_path))
                if os.path.exists(db_path):
                    zf.write(db_path, arcname="database/naf_messaging.db")
    mem.seek(0)
    return mem.read(), name

def ensure_daily_system_backup(app=None):
    app = app or current_app
    folder = backup_folder(app)
    day_key = datetime.utcnow().strftime("%Y%m%d")
    marker = Path(folder) / f"daily_{day_key}.ok"
    if marker.exists():
        return None
    backup_bytes, name = build_backup_zip_bytes(app=app, include_database=True)
    out_path = os.path.join(folder, f"daily_{day_key}_{name}")
    with open(out_path, "wb") as fh:
        fh.write(backup_bytes)
    marker.write_text(datetime.utcnow().isoformat() + "Z", encoding="utf-8")
    return out_path
