import hashlib
import hmac
import json
from datetime import datetime
from flask import current_app, request, has_request_context
from . import db
from .models import AuditEvent, User


def _audit_secret() -> bytes:
    return str(current_app.config.get("SECRET_KEY", "dev-change-me")).encode("utf-8")


def _client_ip() -> str:
    if not has_request_context():
        return "system"
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _user_agent() -> str:
    if not has_request_context():
        return "system"
    return (request.headers.get("User-Agent") or "unknown")[:240]


def _request_meta() -> dict:
    if not has_request_context():
        return {"ip": "system", "device": "system", "path": "system", "method": "system"}
    return {
        "ip": _client_ip(),
        "device": _user_agent(),
        "path": request.path,
        "method": request.method,
    }


def _actor_meta(actor_id) -> dict:
    if not actor_id:
        return {"actor": "System"}
    try:
        u = User.query.get(actor_id)
        if not u:
            return {"actor_id": actor_id, "actor": "Unknown user"}
        return {
            "actor_id": u.id,
            "actor_name": u.full_name,
            "rank": u.rank,
            "service_number": u.service_number,
            "role": u.role,
            "unit": u.unit.name if getattr(u, "unit", None) else "",
            "clearance": u.clearance_level,
        }
    except Exception:
        return {"actor_id": actor_id}


def _normalise_details(details=None, **kwargs) -> str:
    payload = {}
    payload.update(_actor_meta(kwargs.pop("actor_id", None)))
    payload.update(_request_meta())
    if isinstance(details, dict):
        payload.update(details)
    elif details:
        payload["summary"] = str(details)
    payload.update({k: v for k, v in kwargs.items() if v is not None})
    return json.dumps(payload, ensure_ascii=False, default=str)[:500]


def parse_details(details: str) -> dict:
    try:
        return json.loads(details or "{}")
    except Exception:
        return {"summary": details or ""}


def verify_event_hash(ev: AuditEvent) -> bool:
    if not getattr(ev, "event_hash", None):
        return False
    created = ev.created_at or datetime.utcnow()
    payload = f"{ev.actor_id or 0}|{ev.action}|{ev.details or ''}|{created.isoformat()}|{ev.prev_hash or ''}"
    payload_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    expected = hmac.new(_audit_secret(), payload_sha.encode("utf-8"), hashlib.sha256).hexdigest()
    return expected == ev.event_hash and (not ev.payload_sha256 or ev.payload_sha256 == payload_sha)


def log_event(actor_id, action, details=None, **kwargs):
    created = datetime.utcnow()
    kwargs["actor_id"] = actor_id
    detail_text = _normalise_details(details, **kwargs)
    prev = AuditEvent.query.order_by(AuditEvent.id.desc()).first()
    prev_hash = getattr(prev, "event_hash", None)
    payload = f"{actor_id or 0}|{action}|{detail_text or ''}|{created.isoformat()}|{prev_hash or ''}"
    payload_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    event_hash = hmac.new(_audit_secret(), payload_sha.encode("utf-8"), hashlib.sha256).hexdigest()
    ev = AuditEvent(actor_id=actor_id, action=action, details=detail_text, created_at=created, payload_sha256=payload_sha, prev_hash=prev_hash, event_hash=event_hash)
    db.session.add(ev)
    db.session.commit()
    return ev
