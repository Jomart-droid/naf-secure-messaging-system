import os
import uuid
import hashlib
import hmac
import json
import secrets
import string
import html as html_lib
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from collections import OrderedDict
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, current_app, send_from_directory, send_file, Response, jsonify
from flask_login import login_required, current_user
from .. import db, socketio
from werkzeug.utils import secure_filename
import bleach
from bleach.css_sanitizer import CSSSanitizer
from ..models import (
    Channel, Message, MessageType, User, Broadcast, BroadcastAck, Priority, Role, DirectRead, DirectDelivery,
    Settings, Unit, Attachment, BroadcastReceipt, MessageReaction, BroadcastAttachment, ClassificationLevel, SignalArchive, AuditEvent
)
from ..audit import log_event
from ..notify import create_notification
from ..security import require_roles, can_access_classification, can_view_broadcast, can_view_signal_bank, is_signal_delivery_recipient, can_target_scope, can_release_broadcast, can_approve_broadcast, is_explicit_broadcast_recipient, can_create_signal, normalize_unit_appointment, unit_appointment_label, can_direct_message_user, can_external_direct_messages, is_unit_chief_clerk
from ..hierarchy import is_in_subtree, visible_unit_ids_for_user
from ..distribution import distribution_payload, resolve_distribution_unit_ids, build_route_display
from ..unit_workflow import workflow_due_info

bp = Blueprint("msg", __name__, url_prefix="/m")


def _is_recalled_signal(b) -> bool:
    return (getattr(b, "status", "") or "").upper() == "RECALLED" or bool(getattr(b, "recalled_at", None))


def _can_open_signal(user, b):
    """Permit detail view without exposing private workflow items to everyone.

    Released/archived signals follow normal Signal Bank and delivery rules.
    Draft/submitted/approved items are visible only to the drafter and users who
    can manage or validate the release chain. This prevents unfinished signals
    from appearing as operational traffic before authority validation.
    """
    status = (getattr(b, "status", "") or "").upper()
    uid = getattr(user, "id", None)
    if uid and uid in ({getattr(b, "issuer_id", None), getattr(b, "reviewed_by_id", None), getattr(b, "approved_by_id", None), getattr(b, "released_by_id", None), getattr(b, "signed_by_id", None), getattr(b, "release_authority_id", None)} | _unit_workflow_actor_ids(b)):
        return True
    if _can_view_unit_workflow(user, b):
        return True
    if getattr(user, "role", "") in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        return True
    if status in ("DRAFT", "SUBMITTED", "APPROVED") or status in UNIT_WORKFLOW_STATUSES:
        return False
    if status in ("RELEASED", "ARCHIVED", "RECALLED") or _is_recalled_signal(b):
        return can_view_signal_bank(user, b) or can_view_broadcast(user, b, is_in_subtree)
    return can_view_broadcast(user, b, is_in_subtree)


def _block_recalled_signal_action(b, action_label="This action"):
    if _is_recalled_signal(b):
        log_event(current_user.id, "RECALLED_SIGNAL_ACTION_BLOCKED", {
            "target_module": "Signals/Broadcasts",
            "target_id": getattr(b, "id", None),
            "signal_ref": getattr(b, "originator_number", None) or getattr(b, "file_reference", None),
            "blocked_action": action_label,
            "status": "BLOCKED",
        })
        flash(f"{action_label} is disabled because this signal has been recalled.", "warning")
        return True
    return False


def _is_inbox_signal_for_user(user, b):
    """Received Signals/notifications are TO/INFO-specific, not global bank-based.
    Recalled delivered signals must remain visible and clearly marked as RECALLED.
    """
    if getattr(user, "role", "") in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        return True
    if getattr(b, "issuer_id", None) == getattr(user, "id", None):
        return True
    status = (getattr(b, "status", "") or "").upper()
    if status not in {"RELEASED", "RECALLED"}:
        return False
    return is_signal_delivery_recipient(user, b) and can_access_classification(user, getattr(b, "security_classification", None))



def _channel_unit_ids(ch):
    ids = set()
    try:
        ids.update([u.id for u in ch.units])
    except Exception:
        pass
    if getattr(ch, "unit_id", None):
        ids.add(ch.unit_id)
    return ids

def _channel_member_ids(ch):
    ids = set()
    try:
        ids.update([u.id for u in ch.members])
    except Exception:
        pass
    unit_ids = list(_channel_unit_ids(ch))
    if unit_ids:
        ids.update([u.id for u in User.query.filter(User.is_active_flag.is_(True), User.unit_id.in_(unit_ids)).all()])
    return ids

def _can_access_channel(user, ch):
    if getattr(user, "role", "") in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        return True
    if getattr(ch, "created_by_id", None) == getattr(user, "id", None):
        return can_access_classification(user, getattr(ch, "classification_level", None))
    if not can_access_classification(user, getattr(ch, "classification_level", None)):
        return False
    if getattr(user, "id", None) in [u.id for u in getattr(ch, "members", [])]:
        return True
    return bool(getattr(user, "unit_id", None) and getattr(user, "unit_id", None) in _channel_unit_ids(ch))

ALLOWED_EXTENSIONS = {
    "png","jpg","jpeg","gif","webp",
    "pdf","doc","docx","xls","xlsx","ppt","pptx",
    "txt","csv","zip",
    "webm","ogg","mp3","wav","m4a","aac"
}


ALLOWED_RICH_TAGS = [
    "p", "br", "strong", "b", "em", "i", "u", "s",
    "ol", "ul", "li", "blockquote", "code", "pre",
    "table", "thead", "tbody", "tr", "td", "th",
    "h1", "h2", "h3", "h4", "h5", "h6", "a", "span", "div"
]
ALLOWED_RICH_ATTRIBUTES = {
    "a": ["href", "target", "rel"],
    "td": ["colspan", "rowspan"],
    "th": ["colspan", "rowspan"],
    "span": ["style"],
    "div": ["style"],
    "p": ["style"],
}
CSS_SANITIZER = CSSSanitizer(allowed_css_properties=["text-align"])
DANGEROUS_EXTENSIONS = {
    "exe", "msi", "bat", "cmd", "com", "scr", "ps1", "vbs", "js", "jar", "sh", "php", "py", "rb", "dll"
}
CLASSIFICATION_CHOICES = [
    ClassificationLevel.UNCLASSIFIED.value,
    ClassificationLevel.RESTRICTED.value,
    ClassificationLevel.CONFIDENTIAL.value,
    ClassificationLevel.SECRET.value,
    ClassificationLevel.TOP_SECRET.value,
]

RANK_OPTIONS = [
    "ACM", "LAC", "CPL", "SGT", "FS", "WO", "MWO", "AWO",
    "PLT OFFR", "FG OFFR", "FLT LT", "SQN LDR", "WG CDR", "GP CAPT",
    "AIR CDRE", "AVM", "AIR MSHL", "AIR CHIEF MSHL"
]

SIGNAL_TEMPLATES = {
    "OPERATIONAL_ORDER": {"label": "Operational Order", "title": "OPERATIONAL ORDER", "branch_office": "OPS", "precedence_action": "IMMEDIATE", "precedence_info": "PRIORITY", "body": "<p><b>1. Situation:</b> Provide current operational picture.</p><p><b>2. Mission:</b> State the assigned task clearly.</p><p><b>3. Execution:</b> Outline actions, timelines, and responsible elements.</p><p><b>4. Administration / Logistics:</b> State support arrangements.</p><p><b>5. Command / Signal:</b> State reporting chain and communication instructions.</p>"},
    "ADMINISTRATIVE_MESSAGE": {"label": "Administrative Message", "title": "ADMINISTRATIVE MESSAGE", "branch_office": "ADMIN", "precedence_action": "ROUTINE", "precedence_info": "ROUTINE", "body": "<p><b>1. Reference:</b> Quote relevant file or policy.</p><p><b>2. Request / Direction:</b> State the administrative action required.</p><p><b>3. Timeline:</b> State compliance date/time.</p><p><b>4. Remarks:</b> Add clarifications and contact details.</p>"},
    "MOVEMENT_SIGNAL": {"label": "Movement Signal", "title": "MOVEMENT SIGNAL", "branch_office": "MOV", "precedence_action": "PRIORITY", "precedence_info": "ROUTINE", "body": "<p><b>1. Movement Task:</b> State personnel / equipment to move.</p><p><b>2. Origin / Destination:</b> List departure and arrival locations.</p><p><b>3. Date / Time:</b> State movement window and reporting time.</p><p><b>4. Escort / Security:</b> State escort, convoy, or access requirements.</p><p><b>5. Remarks:</b> Add load list, contact, and contingency instructions.</p>"},
    "MAINTENANCE_SIGNAL": {"label": "Maintenance Signal", "title": "MAINTENANCE SIGNAL", "branch_office": "ENGR", "precedence_action": "PRIORITY", "precedence_info": "ROUTINE", "body": "<p><b>1. Equipment / Platform:</b> Identify asset or aircraft.</p><p><b>2. Fault / Inspection Need:</b> Describe issue or maintenance requirement.</p><p><b>3. Required Action:</b> State inspection, repair, replacement, or stand-down direction.</p><p><b>4. Deadline:</b> State completion or report time.</p><p><b>5. Technical Remarks:</b> Add parts, safety, and engineer notes.</p>"},
}

ROUTING_HINT_KEYWORDS = {
    "AIR": ("air", "aircraft", "flight", "sortie", "patrol", "squadron", "wing", "aviation", "training"),
    "LOG": ("logistics", "supply", "stores", "fuel", "transport", "movement", "inventory"),
    "MAINT": ("maintenance", "repair", "inspection", "serviceability", "engine", "spares"),
    "COMM": ("signal", "comms", "communication", "network", "radio", "cis", "ict"),
    "ADMIN": ("admin", "personnel", "leave", "nominal", "welfare", "discipline", "posting"),
}

def _sanitize_rich_text(raw: str) -> str:
    cleaned = bleach.clean(
        raw or "",
        tags=ALLOWED_RICH_TAGS,
        attributes=ALLOWED_RICH_ATTRIBUTES,
        css_sanitizer=CSS_SANITIZER,
        strip=True,
    )
    return bleach.linkify(cleaned)


def _normalize_nbsp_text(value: str) -> str:
    """Convert non-breaking-space entities/characters to ordinary spaces.

    TinyMCE/browser editors may save repeated spaces as &nbsp; or  .
    If those entities are escaped later, the print/PDF output shows NBSP text
    inside the official signal body. This keeps spacing readable without
    leaking HTML entities into the final document.
    """
    text = str(value or "")
    text = text.replace("&NBSP;", " ").replace("&nbsp;", " ").replace("&#160;", " ").replace("&#xA0;", " ")
    try:
        text = html_lib.unescape(text)
    except Exception:
        pass
    return text.replace("\xa0", " ")


def _signal_print_body_html(raw_html: str) -> str:
    """Sanitised, upper-case, print-safe signal body HTML."""
    cleaned = _sanitize_rich_text(_normalize_nbsp_text(raw_html))
    cleaned = _upper_html_text(cleaned)
    return _normalize_nbsp_text(cleaned)


def _broadcast_attachment_rows(broadcast: Broadcast):
    """Return safe attachment metadata for a signal/broadcast."""
    try:
        rows = broadcast.attachments.order_by(BroadcastAttachment.created_at.asc()).all()
    except Exception:
        rows = []
    return rows or []


def _broadcast_attachment_print_block(broadcast: Broadcast) -> str:
    """Render a compact attachment reference for official print/export.

    The printable signal must not list long attachment filenames inside the
    message body because that disturbs pagination and can collide with the
    repeated footer. Full attachment filenames remain available on the signal
    detail page for authorized users. The official form only shows a short
    count summary.
    """
    rows = _broadcast_attachment_rows(broadcast)
    count = len(rows or [])
    if count <= 0:
        return ""
    label = "FILE" if count == 1 else "FILES"
    return f'<p class="attachment-summary"><b>ATTACHMENT(S):</b> {count} {label}</p>'

def _checksum_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def _checksum_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _signature_secret() -> bytes:
    return str(current_app.config.get("SECRET_KEY", "dev-change-me")).encode("utf-8")

def _originator_for(broadcast: Broadcast) -> str:
    source_unit = broadcast.from_unit or (broadcast.issuer.unit if broadcast.issuer else None)
    unit_label = ((source_unit.name if source_unit and source_unit.name else (source_unit.code if source_unit and source_unit.code else "GEN")) or "GEN").strip().upper()
    if broadcast.originator_number:
        existing = str(broadcast.originator_number).strip()
        if existing.startswith(f"{unit_label}/"):
            return existing
    prefix = f"{unit_label}/"
    max_num = 0
    q = Broadcast.query.filter(Broadcast.originator_number.isnot(None))
    if source_unit:
        q = q.filter(Broadcast.from_unit_id == source_unit.id)
    for existing in q.with_entities(Broadcast.originator_number).all():
        value = (existing[0] or "").strip().upper()
        if not value.startswith(prefix):
            continue
        tail = value[len(prefix):].strip()
        if tail.isdigit():
            max_num = max(max_num, int(tail))
    return f"{unit_label}/{max_num + 1:03d}"

def _broadcast_signature_payload(broadcast: Broadcast, include_signature_image_hash: bool = True) -> str:
    rs = _routing_summary(broadcast)
    payload = {
        "id": broadcast.id,
        "title": broadcast.title or "",
        "priority": broadcast.priority or "",
        "classification": broadcast.security_classification or "",
        "originator_number": broadcast.originator_number or "",
        "from": broadcast.msg_from or "",
        "from_unit": rs["from_unit_text"] or "",
        "to": broadcast.msg_to or "",
        "action": rs["action_lines"],
        "info": rs["info_lines"],
        "body": _sanitize_rich_text(broadcast.get_body() or ""),
        "released_at": broadcast.released_at.isoformat() if broadcast.released_at else "",
        "signed_by_id": broadcast.signed_by_id or "",
        "signed_at": broadcast.signed_at.isoformat() if broadcast.signed_at else "",
        "drafter_name": broadcast.drafter_name or "",
        "drafter_rank": getattr(broadcast, "drafter_rank", None) or "",
        "releasing_officer_name": broadcast.releasing_officer_name or "",
        "releasing_signature_rank": broadcast.releasing_signature_rank or "",
        "release_signature_image_sha256": _signature_file_sha256(broadcast) if include_signature_image_hash else "",
        "attachments": [
            {
                "filename": getattr(a, "original_filename", "") or "",
                "sha256": getattr(a, "sha256", "") or "",
                "size_bytes": getattr(a, "size_bytes", 0) or 0,
            }
            for a in _broadcast_attachment_rows(broadcast)
        ],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))

def _sign_broadcast(broadcast: Broadcast, signer_id=None, signed_at=None):
    signer_id = signer_id or broadcast.signed_by_id or broadcast.released_by_id or broadcast.issuer_id
    broadcast.signed_by_id = signer_id
    broadcast.signed_at = signed_at or datetime.utcnow()
    signer = User.query.get(signer_id) if signer_id else None
    if signer:
        if not broadcast.releasing_officer_name:
            broadcast.releasing_officer_name = signer.full_name
        if not broadcast.releasing_signature_rank:
            broadcast.releasing_signature_rank = signer.rank or broadcast.releasing_signature_rank
    payload = _broadcast_signature_payload(broadcast, include_signature_image_hash=True).encode("utf-8")
    sig = hmac.new(_signature_secret(), payload, hashlib.sha256).hexdigest()
    broadcast.digital_signature = sig
    broadcast.signature_fingerprint = sig[:16].upper()
    return sig

def _verify_broadcast_signature(broadcast: Broadcast) -> bool:
    if not broadcast.digital_signature:
        return False
    expected = hmac.new(_signature_secret(), _broadcast_signature_payload(broadcast, include_signature_image_hash=True).encode("utf-8"), hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected, broadcast.digital_signature):
        return True
    # Backward compatibility for signals signed before signature-image hashing was added.
    legacy_expected = hmac.new(_signature_secret(), _broadcast_signature_payload(broadcast, include_signature_image_hash=False).encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(legacy_expected, broadcast.digital_signature)


def _signature_file_sha256(broadcast: Broadcast) -> str:
    filename = getattr(broadcast, "releasing_signature_image", None)
    if not filename:
        return ""
    try:
        path = os.path.join(current_app.config.get("UPLOAD_FOLDER"), filename)
        if not os.path.exists(path):
            return ""
        return _checksum_file(path)
    except Exception:
        current_app.logger.exception("Unable to checksum release signature image")
        return ""


def _save_drawn_signature_image(broadcast: Broadcast, data_uri: str | None) -> str | None:
    """Persist a mouse/touch/stylus signature captured from the release canvas."""
    raw = (data_uri or "").strip()
    if not raw:
        return None
    if not raw.startswith("data:image/") or ";base64," not in raw:
        raise ValueError("Invalid signature image data.")
    header, encoded = raw.split(",", 1)
    mime = header.split(";", 1)[0].replace("data:", "").lower()
    ext_map = {"image/png": "png", "image/jpeg": "jpg", "image/jpg": "jpg", "image/webp": "webp"}
    ext = ext_map.get(mime)
    if ext not in {"png", "jpg", "webp"}:
        raise ValueError("Signature must be PNG, JPG, or WEBP.")
    if len(encoded) > 1_500_000:
        raise ValueError("Signature image is too large. Clear it and sign again.")
    try:
        import base64
        image_bytes = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise ValueError("Signature image could not be decoded.") from exc
    if len(image_bytes) < 500:
        raise ValueError("Signature is empty. Please draw your signature before release.")
    upload_folder = current_app.config.get("UPLOAD_FOLDER")
    os.makedirs(upload_folder, exist_ok=True)
    filename = secure_filename(f"drawn_signature_{broadcast.id}_{uuid.uuid4().hex}.{ext}")
    path = os.path.join(upload_folder, filename)
    with open(path, "wb") as f:
        f.write(image_bytes)
    old = getattr(broadcast, "releasing_signature_image", None)
    broadcast.releasing_signature_image = filename
    if old and old != filename:
        try:
            old_path = os.path.join(upload_folder, old)
            if os.path.exists(old_path):
                os.remove(old_path)
        except Exception:
            current_app.logger.warning("Could not remove previous release signature image", exc_info=True)
    return filename


def _signature_display(broadcast: Broadcast) -> dict:
    full = broadcast.digital_signature or ""
    signer = None
    if getattr(broadcast, "signed_by", None):
        signer = broadcast.signed_by.full_name
    elif getattr(broadcast, "issuer", None):
        signer = broadcast.issuer.full_name
    return {
        "full": full,
        "fingerprint": broadcast.signature_fingerprint or (full[:16].upper() if full else ""),
        "short": (full[:24] + "…") if full and len(full) > 24 else full,
        "signer_name": signer or (broadcast.releasing_officer_name or "—"),
        "signer_rank": broadcast.releasing_signature_rank or "—",
        "signed_at_text": broadcast.signed_at.strftime("%Y-%m-%d %H:%M") + " UTC" if broadcast.signed_at else "Awaiting manual signature",
        "is_signed": bool(broadcast.digital_signature and broadcast.signed_at and broadcast.signed_by_id),
    }


def _can_sign_broadcast(user, broadcast: Broadcast) -> bool:
    """Who can validate final release authority.

    Platform/HQ signals keep the old ADMIN/SUPER_ADMIN release path. Unit
    signals are stricter: they can only reach this final Sign & Release form
    after AO/signatory endorsement and Commander final approval.
    """
    status = (broadcast.status or "").upper()
    if not user:
        return False

    if _broadcast_requires_unit_workflow(broadcast):
        ready, _reason = _unit_workflow_release_ready(broadcast)
        if not ready:
            return False
        if status != "APPROVED_BY_COMMANDER":
            return False
        if user.role in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
            return True
        # For unit-originated signals, final release is the Commander's gate.
        return (
            normalize_unit_appointment(getattr(user, "appointment", None)) == "COMMANDER"
            and getattr(user, "id", None) == getattr(broadcast, "unit_commander_id", None)
        )

    if status not in {"SUBMITTED", "APPROVED", "RELEASED"}:
        return False
    if not can_release_broadcast(user):
        return False
    if user.role in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        return True
    if user.role == Role.COMMANDER.value or normalize_unit_appointment(getattr(user, "appointment", None)) == "COMMANDER":
        return user.id in {broadcast.issuer_id, broadcast.approved_by_id, broadcast.released_by_id, broadcast.release_authority_id, broadcast.current_handler_id}
    return False

def _join_nonempty(values, sep=", ") -> str:
    return sep.join([str(v).strip() for v in values if str(v).strip()])


def _route_label_users(users):
    return [f"{u.full_name}{(' (' + u.unit.code + ')') if getattr(u, 'unit', None) else ''}" for u in users]


def _route_label_units(units):
    return [f"{u.name} ({u.code})" if getattr(u, 'code', None) else u.name for u in units]


def _routing_summary(b: Broadcast):
    routing = _action_info_targets(b)
    action_lines = _route_label_users(routing["action_users"]) + _route_label_units(routing["action_units"])
    info_lines = _route_label_users(routing["info_users"]) + _route_label_units(routing["info_units"])
    return {
        "routing": routing,
        "action_lines": action_lines,
        "info_lines": info_lines,
        "action_text": _join_nonempty(action_lines, "\n"),
        "info_text": _join_nonempty(info_lines, "\n"),
        "from_unit_text": _from_unit_text(b),
    }


def _default_dtg(value=None):
    if value:
        return value
    return datetime.utcnow().strftime("%d%H%MA %b %y").upper()


from zoneinfo import ZoneInfo

NAF_TZ = ZoneInfo("Africa/Lagos")

def _naf_time_stamp(value=None):
    """Compact NAF footer timestamp for Time-In/Out fields."""

    try:
        if value:
            dt = value

            # if datetime already has timezone
            if getattr(dt, "tzinfo", None):
                dt = dt.astimezone(NAF_TZ)

            # assume UTC if timezone missing
            else:
                dt = dt.replace(tzinfo=ZoneInfo("UTC")).astimezone(NAF_TZ)

        else:
            dt = datetime.now(NAF_TZ)

        return dt.strftime("%d %b %y %H:%M").upper()

    except Exception:
        return datetime.now(NAF_TZ).strftime("%d %b %y %H:%M").upper()

def _format_signal_created_time(b):
    """Return the signal creation/submission timestamp for the NAF footer."""
    created = getattr(b, "created_at", None) or getattr(b, "sent_at", None) or datetime.utcnow()
    return _naf_time_stamp(created)


def _format_signal_out_time(value=None):
    """Return the print/export timestamp for the NAF footer."""
    return _naf_time_stamp(value or datetime.utcnow())


def _signal_time_in_out(b, time_out=None):
    """Time-In is signal creation time; Time-Out is print/export time."""
    return f"IN: {_format_signal_created_time(b)}\nOUT: {_format_signal_out_time(time_out)}"


def _visible_text_len(html_text: str) -> int:
    """Return a print-weight estimate based on visible text, not raw HTML."""
    try:
        from bs4 import BeautifulSoup
        return len(BeautifulSoup(str(html_text or ""), "html.parser").get_text(" ", strip=True))
    except Exception:
        return len(str(html_text or ""))


def _wrap_text_as_paragraph(text: str) -> str:
    import html as _html
    return "<p>" + _html.escape(str(text or "").strip()) + "</p>"


def _split_plain_text_for_print(text: str, max_chars: int):
    """Split visible text on paragraph/sentence/word boundaries for print pages."""
    import re
    text = re.sub(r"\s+", " ", str(text or "").replace("\xa0", " ")).strip()
    if not text:
        return []
    chunks = []
    while len(text) > max_chars:
        cut = max_chars
        # Prefer sentence end, then comma/semicolon, then a normal space.
        candidates = [text.rfind(mark, 0, max_chars) for mark in (". ", "; ", ": ", ", ", " ")]
        good = [c for c in candidates if c and c > int(max_chars * 0.62)]
        if good:
            cut = max(good) + (2 if text[max(good):max(good)+2] in ('. ', '; ', ': ', ', ') else 1)
        chunks.append(text[:cut].strip())
        text = text[cut:].strip()
    if text:
        chunks.append(text)
    return chunks


def _paginate_signal_html(body_html, first_page_chars=3000, continuation_chars=5200):
    """Paginate official signal body while preserving rich-text tables.

    Earlier builds converted the body HTML to plain text before pagination. That
    made pasted/inserted tables print as ordinary lines. This version keeps safe
    HTML blocks intact, especially <table>, <tr>, <td> and <th>, while still
    splitting long text on safe boundaries and reserving space for the repeated
    footer.
    """
    import re, html as _html
    from bs4 import BeautifulSoup, NavigableString

    safe_html = _sanitize_rich_text(_normalize_nbsp_text(str(body_html or "").strip()))
    safe_html = _upper_html_text(safe_html)
    safe_html = _normalize_nbsp_text(safe_html)
    if not safe_html.strip():
        return ["<p>&nbsp;</p>"]

    # These line budgets are deliberately conservative because the official
    # footer occupies the lower part of every page. If the form still leaves too
    # much space, tune first_max_lines/cont_max_lines here rather than stripping
    # HTML or tables.
    first_max_lines = 53
    cont_max_lines = 102
    chars_per_line = 104

    def visible_text(fragment):
        try:
            return BeautifulSoup(str(fragment or ""), "html.parser").get_text(" ", strip=True)
        except Exception:
            return bleach.clean(str(fragment or ""), tags=[], strip=True)

    def estimate_text_lines(text):
        text = _normalize_nbsp_text(str(text or "")).strip()
        if not text:
            return 1
        lines = 1
        cur = 0
        for w in text.split():
            wl = len(w)
            if cur and cur + 1 + wl > chars_per_line:
                lines += 1
                cur = wl
            else:
                cur = wl if not cur else cur + 1 + wl
            if wl > chars_per_line:
                lines += max(1, wl // chars_per_line)
                cur = wl % chars_per_line
        return lines

    def estimate_html_lines(fragment):
        frag = str(fragment or "")
        try:
            soup = BeautifulSoup(frag, "html.parser")
            table = soup.find("table") if soup else None
            if table:
                total = 1
                rows = table.find_all("tr")
                for tr in rows:
                    cells = tr.find_all(["td", "th"], recursive=False)
                    if not cells:
                        total += 1
                        continue
                    # Table columns are narrower than body text, so estimate
                    # row height from the fullest cell.
                    col_count = max(1, len(cells))
                    cell_width = max(18, int(chars_per_line / col_count))
                    row_lines = 1
                    for cell in cells:
                        txt = cell.get_text(" ", strip=True)
                        row_lines = max(row_lines, max(1, (len(txt) // cell_width) + 1))
                    total += row_lines + 1
                return max(4, total)
        except Exception:
            pass
        return estimate_text_lines(visible_text(frag)) + 1

    def split_text_to_paragraphs(text, max_lines):
        words = str(text or "").split()
        chunks, cur = [], []
        for w in words:
            test = " ".join(cur + [w])
            if cur and estimate_text_lines(test) + 1 > max_lines:
                chunks.append(" ".join(cur))
                cur = [w]
            else:
                cur.append(w)
        if cur:
            chunks.append(" ".join(cur))
        return [f"<p>{_html.escape(x)}</p>" for x in chunks if x.strip()]

    def split_table_html(table_html, max_lines):
        """Split large tables by row while repeating header rows where possible."""
        try:
            soup = BeautifulSoup(str(table_html or ""), "html.parser")
            table = soup.find("table")
            if not table:
                return [str(table_html)]
            all_rows = table.find_all("tr")
            if not all_rows:
                return [str(table)]
            header_rows = []
            body_rows = []
            for tr in all_rows:
                if tr.find("th") or tr.find_parent("thead"):
                    header_rows.append(str(tr))
                else:
                    body_rows.append(str(tr))
            if not body_rows:
                body_rows = [str(r) for r in all_rows]
                header_rows = []

            def row_lines(row_html):
                return max(1, estimate_html_lines(f"<table>{row_html}</table>") - 2)

            header_cost = sum(row_lines(r) for r in header_rows) + (1 if header_rows else 0)
            chunks, cur_rows, used = [], [], header_cost
            for r in body_rows:
                need = row_lines(r) + 1
                if cur_rows and used + need > max_lines:
                    head = "<thead>" + "".join(header_rows) + "</thead>" if header_rows else ""
                    chunks.append("<table>" + head + "<tbody>" + "".join(cur_rows) + "</tbody></table>")
                    cur_rows, used = [], header_cost
                cur_rows.append(r)
                used += need
            if cur_rows:
                head = "<thead>" + "".join(header_rows) + "</thead>" if header_rows else ""
                chunks.append("<table>" + head + "<tbody>" + "".join(cur_rows) + "</tbody></table>")
            return chunks or [str(table)]
        except Exception:
            return [str(table_html)]

    def blockify_html(html):
        soup = BeautifulSoup(html, "html.parser")
        source_nodes = soup.body.contents if soup.body else soup.contents
        blocks = []
        buffer_text = []

        def flush_text():
            text = " ".join(x.strip() for x in buffer_text if str(x).strip()).strip()
            buffer_text.clear()
            if text:
                # Preserve paragraph-like breaks for plain pasted text.
                for para in re.split(r"\n{2,}", text):
                    para = para.strip()
                    if para:
                        blocks.append(f"<p>{_html.escape(para)}</p>")

        for node in source_nodes:
            if isinstance(node, NavigableString):
                if str(node).strip():
                    buffer_text.append(str(node))
                continue
            name = getattr(node, "name", "")
            if name == "br":
                buffer_text.append("\n")
                continue
            flush_text()
            if name == "table":
                blocks.append(str(node))
            elif name in {"p", "div", "ul", "ol", "blockquote", "pre", "h1", "h2", "h3", "h4", "h5", "h6"}:
                if visible_text(node) or node.find("table"):
                    blocks.append(str(node))
            elif visible_text(node):
                blocks.append(f"<p>{_html.escape(visible_text(node))}</p>")
        flush_text()
        return blocks

    raw_blocks = blockify_html(safe_html)
    if not raw_blocks:
        return ["<p>&nbsp;</p>"]

    # Expand oversize paragraphs/tables into page-safe sub-blocks.
    expanded = []
    for block in raw_blocks:
        try:
            bs = BeautifulSoup(block, "html.parser")
            is_table = bs.find("table") is not None and bs.find("table").name == "table"
        except Exception:
            is_table = False
        line_cost = estimate_html_lines(block)
        max_limit = max(first_max_lines, cont_max_lines)
        if is_table and line_cost > max_limit:
            expanded.extend(split_table_html(block, cont_max_lines - 3))
        elif (not is_table) and line_cost > max_limit:
            expanded.extend(split_text_to_paragraphs(visible_text(block), cont_max_lines - 2))
        else:
            expanded.append(block)

    pages, current, used = [], [], 0
    limit = first_max_lines
    for block in expanded:
        need = estimate_html_lines(block)
        if current and used + need > limit:
            pages.append(current)
            current, used = [], 0
            limit = cont_max_lines
        # If a single block is still too tall, allow it alone on the page. The
        # table CSS uses page-break-inside:auto so browsers can split rows if
        # absolutely necessary.
        current.append(block)
        used += need
    if current:
        pages.append(current)

    html_pages = ["".join(page).strip() for page in pages if "".join(page).strip()]
    return html_pages or ["<p>&nbsp;</p>"]


INFO_ROUTE_MARKER = "__INFO_ROUTE_DISPLAY__="

def _split_internal_distribution(value):
    text = (value or "").strip()
    info_display = None
    if INFO_ROUTE_MARKER in text:
        clean_lines = []
        for line in text.splitlines():
            if line.startswith(INFO_ROUTE_MARKER):
                info_display = line[len(INFO_ROUTE_MARKER):].strip() or None
            else:
                clean_lines.append(line)
        text = "\n".join(clean_lines).strip()
    return text, info_display

def _clean_text(value, fallback="—"):
    value = (value or "").strip()
    return value or fallback


def _upper_plain(value, fallback="—"):
    return _clean_text(_normalize_nbsp_text(value), fallback).upper()


def _format_drafter_display(name, rank=None):
    """Official print display: NAME (RANK). Only the rank is bracketed."""
    clean_name = _upper_plain(name, "")
    clean_rank = _upper_plain(rank, "")
    if clean_name and clean_rank:
        return f"{clean_name} ({clean_rank})"
    return clean_name or clean_rank or "—"


def _upper_html_text(html):
    """Uppercase only visible text inside rich HTML, leaving tags/attributes intact."""
    html = _normalize_nbsp_text(html)
    try:
        soup = BeautifulSoup(html, "html.parser")
        for node in soup.find_all(string=True):
            node.replace_with(str(node).upper())
        return str(soup)
    except Exception:
        return html.upper()


def _message_form_context(b: Broadcast, time_out=None):
    rs = _routing_summary(b)
    sig = _signature_display(b)
    signature_valid = _verify_broadcast_signature(b)
    message_instruction = _clean_text(getattr(b, "message_instruction", None), "")
    file_reference = _clean_text(getattr(b, "file_reference", None) or b.originator_number)
    internal_raw, info_route_display = _split_internal_distribution(getattr(b, "internal_distribution", None))
    internal_distribution = _clean_text(internal_raw or rs["from_unit_text"] or b.msg_from)

    # PRINT/PDF ROUTING FIX:
    # action_units_csv/info_units_csv contain the BACKEND-RESOLVED delivery recipients.
    # The official NAF message form must NOT print those expanded arrays when the
    # drafter selected ALL NAF UNITS, LIST A/B/C/etc, or LESS/EXCLUDE routing.
    # The print form must use only the human routing display labels saved in
    # msg_to and the hidden INFO_ROUTE_MARKER. We fall back to expanded units
    # only for old/legacy signals that do not have saved display labels.
    action_print_lines = [] if (getattr(b, "msg_to", None) or "").strip() else [str(x).upper() for x in (rs["action_lines"] or ["—"])]
    info_print_lines = [str(info_route_display).upper()] if info_route_display else [str(x).upper() for x in (rs["info_lines"] or ["—"])]

    rows = [{
        "drafter_name": _format_drafter_display(b.drafter_name, getattr(b, "drafter_rank", None)),
        "drafter_rank": _upper_plain(getattr(b, "drafter_rank", None), ""),
        "precedence_action": _upper_plain(b.precedence_action or "ROUTINE"),
        "precedence_info": _upper_plain(b.precedence_info),
        "from": _upper_plain(b.msg_from),
        "to": _upper_plain(b.msg_to),
        "branch_office": _upper_plain(b.branch_office),
        "telephone": _upper_plain(b.telephone),
        "dtg": _upper_plain(_default_dtg(b.dtg)),
        "releasing_signature_rank": _upper_plain(b.releasing_signature_rank),
        "releasing_officer_name": _upper_plain(b.releasing_officer_name),
        "security_classification": _upper_plain(b.security_classification or ClassificationLevel.RESTRICTED.value),
        "originator_number": _upper_plain(b.originator_number),
        "from_unit_text": _upper_plain(rs["from_unit_text"]),
        "action_lines": action_print_lines,
        "info_lines": info_print_lines,
        "message_instruction": _upper_plain(message_instruction, ""),
        "internal_distribution": _upper_plain(internal_distribution),
        "file_reference": _upper_plain(file_reference),
        "refers_classified_message": bool(getattr(b, "refers_classified_message", False)),
        "does_not_refer_classified_message": not bool(getattr(b, "refers_classified_message", False)),
        "comms_gen_serial_no": _upper_plain(getattr(b, "comms_gen_serial_no", None) or b.originator_number),
        "sender_receiver_op": _upper_plain(getattr(b, "sender_receiver_op", None)),
        "transmission_system": _upper_plain(getattr(b, "transmission_system", None)),
        "time_in_out": _upper_plain(_signal_time_in_out(b, time_out)),
        "signature_valid": signature_valid,
        "signature_meta": sig,
        "releasing_signature_image": getattr(b, "releasing_signature_image", None),
        "page_label": "1",
        "page_total": "1",
    }]
    return {
        "rows": rows,
        "routing": rs["routing"],
        "signature_valid": signature_valid,
        "signature_meta": sig,
        "from_unit_text": rs["from_unit_text"],
        "action_lines": action_print_lines,
        "info_lines": info_print_lines,
    }


def _from_unit_text(b: Broadcast) -> str:
    if getattr(b, "from_unit", None):
        return b.from_unit.name + (f" ({b.from_unit.code})" if b.from_unit.code else "")
    if b.msg_from:
        return b.msg_from
    if b.issuer and b.issuer.unit:
        return b.issuer.unit.name + (f" ({b.issuer.unit.code})" if b.issuer.unit.code else "")
    return ""

def _selected_ints(name: str):
    vals = request.form.getlist(name)
    out = []
    for v in vals:
        v = str(v).strip()
        if v.isdigit():
            out.append(int(v))
    return out

def _action_info_targets(b: Broadcast):
    return {
        "action_users": User.query.filter(User.id.in_(b.csv_ids("action_users_csv"))).order_by(User.full_name.asc()).all() if b.csv_ids("action_users_csv") else [],
        "info_users": User.query.filter(User.id.in_(b.csv_ids("info_users_csv"))).order_by(User.full_name.asc()).all() if b.csv_ids("info_users_csv") else [],
        "action_units": Unit.query.filter(Unit.id.in_(b.csv_ids("action_units_csv"))).order_by(Unit.name.asc()).all() if b.csv_ids("action_units_csv") else [],
        "info_units": Unit.query.filter(Unit.id.in_(b.csv_ids("info_units_csv"))).order_by(Unit.name.asc()).all() if b.csv_ids("info_units_csv") else [],
    }

def _broadcast_search_results(args, current_user):
    q = (args.get("q") or "").strip()
    classification = (args.get("classification") or "").strip()
    status = (args.get("status") or "").strip()
    priority = (args.get("priority") or "").strip()
    sender = (args.get("sender") or "").strip()
    unit_id = (args.get("unit_id") or "").strip()
    date_from = (args.get("date_from") or "").strip()
    date_to = (args.get("date_to") or "").strip()
    attachment_mode = (args.get("has_attachments") or "").strip()

    bq = Broadcast.query
    if q:
        like = f"%{q}%"
        bq = bq.filter(
            (Broadcast.title.ilike(like)) |
            (Broadcast.msg_from.ilike(like)) |
            (Broadcast.msg_to.ilike(like)) |
            (Broadcast.originator_number.ilike(like)) |
            (Broadcast.security_classification.ilike(like)) |
            (Broadcast.drafter_name.ilike(like)) |
            (Broadcast.releasing_officer_name.ilike(like)) |
            (Broadcast.message_instruction.ilike(like)) |
            (Broadcast.internal_distribution.ilike(like)) |
            (Broadcast.file_reference.ilike(like)) |
            (Broadcast.branch_office.ilike(like)) |
            (Broadcast.telephone.ilike(like)) |
            (Broadcast.dtg.ilike(like))
        )
    if classification:
        bq = bq.filter(Broadcast.security_classification == classification)
    if status:
        bq = bq.filter(Broadcast.status == status)
    if priority:
        bq = bq.filter(Broadcast.priority == priority)
    if sender:
        s_like = f"%{sender}%"
        bq = bq.join(User, Broadcast.issuer_id == User.id).filter(
            (User.full_name.ilike(s_like)) | (User.service_number.ilike(s_like))
        )
    if unit_id.isdigit():
        uid = int(unit_id)
        bq = bq.filter(
            (Broadcast.target_unit_id == uid) |
            (Broadcast.from_unit_id == uid) |
            (Broadcast.action_units_csv.ilike(f"%{uid}%")) |
            (Broadcast.info_units_csv.ilike(f"%{uid}%"))
        )
    if date_from:
        try:
            bq = bq.filter(Broadcast.created_at >= datetime.strptime(date_from, "%Y-%m-%d"))
        except ValueError:
            pass
    if date_to:
        try:
            end = datetime.strptime(date_to, "%Y-%m-%d")
            bq = bq.filter(Broadcast.created_at < end.replace(hour=23, minute=59, second=59, microsecond=999999))
        except ValueError:
            pass
    if attachment_mode == "yes":
        bq = bq.filter(Broadcast.attachments.any())
    elif attachment_mode == "no":
        bq = bq.filter(~Broadcast.attachments.any())

    rows = []
    for b in bq.order_by(Broadcast.created_at.desc()).limit(250).all():
        if _can_open_signal(current_user, b):
            rows.append(b)
    return rows


def _allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    parts = [p.strip().lower() for p in filename.split(".") if p.strip()]
    ext = parts[-1]
    if ext in DANGEROUS_EXTENSIONS or any(p in DANGEROUS_EXTENSIONS for p in parts[:-1]):
        return False
    s = Settings.get()
    allowed = set([e.strip().lower() for e in (getattr(s, "allowed_extensions", "") or "").split(",") if e.strip()])
    if not allowed:
        allowed = ALLOWED_EXTENSIONS
    # Voice notes require audio formats even when an older DB setting still has the previous allow-list.
    allowed = set(allowed) | {"webm", "ogg", "mp3", "wav", "m4a", "aac"}
    return ext in allowed


def _save_attachments(files, message_id: int):
    s = Settings.get()
    if not s.allow_attachments:
        return
    max_bytes = int(s.max_attachment_mb or 10) * 1024 * 1024
    upload_dir = current_app.config.get("UPLOAD_FOLDER")
    for f in files:
        if not f or not getattr(f, "filename", ""):
            continue
        if not _allowed_file(f.filename):
            flash(f"Attachment type not allowed: {f.filename}", "warning")
            continue

        # size check (best-effort)
        f.stream.seek(0, os.SEEK_END)
        size = f.stream.tell()
        f.stream.seek(0)
        if size > max_bytes:
            flash(f"Attachment too large (max {s.max_attachment_mb}MB): {f.filename}", "warning")
            continue

        safe_name = secure_filename(f.filename)
        stored = f"{uuid.uuid4().hex}_{safe_name}" if safe_name else uuid.uuid4().hex
        path = os.path.join(upload_dir, stored)
        f.save(path)

        a = Attachment(
            message_id=message_id,
            uploader_id=current_user.id,
            original_filename=f.filename,
            stored_filename=stored,
            mime_type=getattr(f, "mimetype", None),
            size_bytes=size,
            sha256=_checksum_file(path),
        )
        db.session.add(a)


def _save_broadcast_attachments(files, broadcast_id: int):
    """Persist uploaded files as BroadcastAttachment rows."""
    s = Settings.get()
    if not s.allow_attachments:
        return
    max_bytes = int(s.max_attachment_mb or 10) * 1024 * 1024
    upload_dir = current_app.config.get("UPLOAD_FOLDER")
    for f in files:
        if not f or not getattr(f, "filename", ""):
            continue
        if not _allowed_file(f.filename):
            flash(f"Attachment type not allowed: {f.filename}", "warning")
            continue

        f.stream.seek(0, os.SEEK_END)
        size = f.stream.tell()
        f.stream.seek(0)
        if size > max_bytes:
            flash(f"Attachment too large (max {s.max_attachment_mb}MB): {f.filename}", "warning")
            continue

        safe_name = secure_filename(f.filename)
        stored = f"{uuid.uuid4().hex}_{safe_name}" if safe_name else uuid.uuid4().hex
        path = os.path.join(upload_dir, stored)
        f.save(path)

        a = BroadcastAttachment(
            broadcast_id=broadcast_id,
            uploader_id=current_user.id,
            original_filename=f.filename,
            stored_filename=stored,
            mime_type=getattr(f, "mimetype", None),
            size_bytes=size,
            sha256=_checksum_file(path),
        )
        db.session.add(a)


def _broadcast_targets(b: Broadcast):
    """Return explicit TO/INFO recipients only.

    Signal Bank is global by clearance, but delivery notifications and the
    Received Signals inbox must remain specific to units/users selected under
    ACTION/TO or INFO.
    """
    user_ids = set()

    explicit_user_ids = set(b.csv_ids("action_users_csv")) | set(b.csv_ids("info_users_csv"))
    user_ids.update(uid for uid in explicit_user_ids if uid)

    explicit_unit_ids = set(b.csv_ids("action_units_csv")) | set(b.csv_ids("info_units_csv"))
    if getattr(b, "channel_id", None):
        ch = Channel.query.get(b.channel_id)
        if ch:
            explicit_unit_ids.update(_channel_unit_ids(ch))
            user_ids.update(_channel_member_ids(ch))
    if explicit_unit_ids:
        routed_users = User.query.filter(User.is_active_flag.is_(True), User.unit_id.in_(list(explicit_unit_ids))).all()
        user_ids.update(u.id for u in routed_users)

    if not user_ids:
        return []
    candidates = User.query.filter(User.id.in_(list(user_ids))).all()
    return [u for u in candidates if can_access_classification(u, getattr(b, "security_classification", None))]



UNIT_WORKFLOW_STATUSES = {
    "DRAFT",
    "FORWARDED_TO_AO",
    "RETURNED_BY_AO",
    "APPROVED_BY_AO",
    "FORWARDED_TO_SIGNATORY",
    "SIGNED_BY_SIGNATORY",
    "PENDING_COMMANDER_APPROVAL",
    "RETURNED_BY_COMMANDER",
    "APPROVED_BY_COMMANDER",
}

UNIT_WORKFLOW_LABELS = {
    "DRAFT": "Draft",
    "FORWARDED_TO_AO": "Forwarded to AO",
    "RETURNED_BY_AO": "Returned by AO",
    "APPROVED_BY_AO": "Approved by AO",
    "FORWARDED_TO_SIGNATORY": "Forwarded to Signatory",
    "SIGNED_BY_SIGNATORY": "Signed by Signatory",
    "PENDING_COMMANDER_APPROVAL": "Pending Commander Approval",
    "RETURNED_BY_COMMANDER": "Returned by Commander",
    "APPROVED_BY_COMMANDER": "Approved by Commander",
    "SUBMITTED": "Submitted",
    "APPROVED": "Approved",
    "RELEASED": "Released",
    "RECALLED": "Recalled",
    "ARCHIVED": "Archived",
}


def _unit_officers(unit_id: int | None, appointment_key: str | None = None):
    if not unit_id:
        return []
    q = User.query.filter_by(unit_id=unit_id, is_active_flag=True).order_by(User.rank.asc(), User.full_name.asc())
    users = q.all()
    if appointment_key:
        appointment_key = normalize_unit_appointment(appointment_key)
        users = [u for u in users if normalize_unit_appointment(getattr(u, "appointment", None)) == appointment_key]
    return users


def _first_unit_officer(unit_id: int | None, appointment_key: str | None):
    officers = _unit_officers(unit_id, appointment_key)
    return officers[0] if officers else None


def _unit_workflow_actor_ids(b: Broadcast) -> set[int]:
    ids = {
        getattr(b, "current_handler_id", None),
        getattr(b, "unit_ao_id", None),
        getattr(b, "unit_signatory_id", None),
        getattr(b, "unit_commander_id", None),
        getattr(b, "returned_by_id", None),
    }
    return {int(x) for x in ids if str(x or "").isdigit()}


def _is_unit_internal_workflow_required(user) -> bool:
    """HQ/Admin keep legacy release flow; unit officer accounts enter internal routing."""
    if getattr(user, "role", "") in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        return False
    return bool(getattr(user, "unit_id", None))


def _broadcast_requires_unit_workflow(b: Broadcast) -> bool:
    """True when a signal belongs to the internal unit chain.

    A unit-originated signal must pass Chief Clerk -> AO/signatory -> Commander
    before external release.  This guard is intentionally based on the signal
    record, not just the current user, so AO/signatory/Commander cannot bypass
    the chain by opening the final release form directly.
    """
    if not b:
        return False
    status = (getattr(b, "status", "") or "").upper()
    if status in UNIT_WORKFLOW_STATUSES:
        return True
    if any(getattr(b, attr, None) for attr in ("unit_ao_id", "unit_signatory_id", "unit_commander_id", "routed_to_ao_at", "commander_approved_at")):
        return True
    issuer = getattr(b, "issuer", None)
    if issuer and getattr(issuer, "unit_id", None) and getattr(issuer, "role", "") not in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        return True
    return False


def _unit_workflow_release_ready(b: Broadcast) -> tuple[bool, str]:
    """Validate that a unit signal completed the internal chain before release."""
    if not _broadcast_requires_unit_workflow(b):
        return True, ""
    status = (getattr(b, "status", "") or "").upper()
    if status != "APPROVED_BY_COMMANDER":
        return False, "Unit signal cannot be released until Commander final approval is completed."
    if not getattr(b, "unit_ao_id", None) or not getattr(b, "ao_reviewed_at", None):
        return False, "Unit signal must be reviewed by the Admin Officer before release."
    if not getattr(b, "signatory_signed_at", None) or not getattr(b, "unit_signatory_id", None):
        return False, "Unit signal must be signed/endorsed by AO or selected signatory before release."
    if not getattr(b, "unit_commander_id", None) or not getattr(b, "commander_approved_at", None):
        return False, "Unit signal must be approved by the Commander before release."
    return True, ""


def _initial_unit_workflow_status(user, requested_status: str, now):
    """Return (status, current_handler, ao, signatory, commander, routed_to_ao_at).

    Corrected unit route: Chief Clerk drafts/submits first; submitted unit
    signals always go to the Unit AO. AO/Signatory/Commander must act through
    the workflow controls, not by originating the signal from the composer.
    """
    if requested_status == "DRAFT":
        return "DRAFT", None, None, None, None, None
    if not _is_unit_internal_workflow_required(user):
        return requested_status, None, None, None, None, None

    unit_id = getattr(user, "unit_id", None)
    ao = _first_unit_officer(unit_id, "ADMIN_OFFICER")
    signatory = _first_unit_officer(unit_id, "SIGNATORY_OFFICER")
    commander = _first_unit_officer(unit_id, "COMMANDER")
    return "FORWARDED_TO_AO", ao, ao, signatory, commander, now


def _can_view_unit_workflow(user, b: Broadcast) -> bool:
    if getattr(user, "role", "") in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        return True
    if getattr(user, "id", None) in _unit_workflow_actor_ids(b):
        return True
    if getattr(user, "unit_id", None) and getattr(user, "unit_id", None) == getattr(b, "from_unit_id", None):
        appt = normalize_unit_appointment(getattr(user, "appointment", None))
        return appt in {"ADMIN_OFFICER", "COMMANDER"}
    return False


def _unit_workflow_context(b: Broadcast):
    status = (getattr(b, "status", "") or "").upper()
    handler = getattr(b, "current_handler", None)
    return {
        "status": status,
        "label": UNIT_WORKFLOW_LABELS.get(status, status or "Pending"),
        "is_unit_workflow": status in UNIT_WORKFLOW_STATUSES or bool(getattr(b, "unit_ao_id", None) or getattr(b, "unit_commander_id", None)),
        "handler": handler,
        "handler_label": (f"{handler.rank or ''} {handler.full_name}".strip() if handler else "—"),
        "ao": getattr(b, "unit_ao", None),
        "signatory": getattr(b, "unit_signatory", None),
        "commander": getattr(b, "unit_commander", None),
        "return_reason": getattr(b, "return_reason", None),
    }



def _unit_workflow_items_for_user(user):
    """Return workflow signals grouped for the Unit Workflow Center.

    This intentionally uses visibility helpers instead of a loose unit-only
    query so unfinished signals do not leak outside the proper unit chain.
    """
    q = Broadcast.query.order_by(Broadcast.created_at.desc()).limit(500).all()
    items = [b for b in q if (getattr(b, "status", "") or "").upper() in UNIT_WORKFLOW_STATUSES and _can_open_signal(user, b)]

    uid = getattr(user, "id", None)
    my_action = [b for b in items if getattr(b, "current_handler_id", None) == uid]
    returned = [b for b in items if (getattr(b, "status", "") or "").upper() in {"RETURNED_BY_AO", "RETURNED_BY_COMMANDER"}]
    ready_release = [b for b in items if (getattr(b, "status", "") or "").upper() == "APPROVED_BY_COMMANDER"]
    in_routing = [b for b in items if b not in my_action and b not in returned and b not in ready_release]

    return {
        "all": items,
        "my_action": my_action,
        "returned": returned,
        "ready_release": ready_release,
        "in_routing": in_routing,
    }

def _notify_current_handler(b: Broadcast, title: str, body: str):
    uid = getattr(b, "current_handler_id", None)
    if not uid:
        return
    try:
        create_notification(
            uid,
            "BROADCAST",
            title,
            body,
            link=url_for("msg.broadcast_detail", broadcast_id=b.id),
            thread_type="BROADCAST",
            thread_id=b.id,
        )
        socketio.emit("live_feed_event", {"type": "UNIT_WORKFLOW", "title": title, "body": body, "link": url_for("msg.broadcast_detail", broadcast_id=b.id), "created_at": datetime.utcnow().isoformat()+"Z"}, room=f"user_{uid}")
    except Exception:
        current_app.logger.exception("Could not notify unit workflow handler for signal %s", getattr(b, "id", None))


def _prepare_release_authority(b: Broadcast, actor: User, now=None):
    """Apply final workflow fields before computing the digital signature."""
    now = now or datetime.utcnow()
    if not b.originator_number:
        b.originator_number = _originator_for(b)
    if not b.file_reference:
        b.file_reference = b.originator_number
    if not b.comms_gen_serial_no or str(b.comms_gen_serial_no).strip().upper() == "AUTO":
        b.comms_gen_serial_no = b.originator_number
    b.status = "RELEASED"
    b.submitted_at = b.submitted_at or now
    b.approved_at = b.approved_at or now
    b.released_at = now
    b.reviewed_by_id = b.reviewed_by_id or actor.id
    b.approved_by_id = b.approved_by_id or actor.id
    b.released_by_id = actor.id
    b.release_authority_id = actor.id
    b.release_authority_validated_at = now
    b.ack_deadline_at = _ack_deadline_for(b.precedence_action or b.signal_precedence or "ROUTINE", now) if b.requires_ack else None


def _deliver_released_broadcast(b: Broadcast, actor: User, now=None):
    """Create receipts, notify recipients, and refresh the archive after release."""
    now = now or datetime.utcnow()
    targets = _broadcast_targets(b)
    for u in targets:
        if u.id == actor.id:
            continue
        if not BroadcastReceipt.query.filter_by(broadcast_id=b.id, user_id=u.id).first():
            db.session.add(BroadcastReceipt(broadcast_id=b.id, user_id=u.id))
    if not BroadcastReceipt.query.filter_by(broadcast_id=b.id, user_id=actor.id).first():
        db.session.add(BroadcastReceipt(broadcast_id=b.id, user_id=actor.id, received_at=now, read_at=now))
    db.session.commit()

    notified_user_ids = set()
    payload = {
        "id": b.id,
        "title": b.title,
        "priority": b.priority,
        "classification": b.security_classification,
        "originator_number": b.originator_number,
        "from": b.msg_from,
        "precedence_action": b.precedence_action or b.priority,
        "precedence_info": b.precedence_info or "",
        "requires_ack": bool(b.requires_ack),
        "link": url_for("msg.broadcast_detail", broadcast_id=b.id),
    }
    for u in targets:
        if u.id in notified_user_ids:
            continue
        notified_user_ids.add(u.id)
        socketio.emit("broadcast_new", payload, room=f"user_{u.id}")
        if u.id != actor.id:
            create_notification(
                u.id,
                "BROADCAST",
                f"New signal: {b.title}",
                f"{b.originator_number or ''} · {b.priority} · {b.security_classification or 'RESTRICTED'}",
                link=url_for("msg.broadcast_detail", broadcast_id=b.id),
                thread_type="BROADCAST",
                thread_id=b.id,
            )
    socketio.emit("broadcast_new", payload, room="broadcast_admins")
    socketio.emit("live_feed_event", {"type": "SIGNAL_RELEASED", "title": f"Signal released: {b.originator_number or b.id}", "body": b.title, "link": url_for("msg.broadcast_detail", broadcast_id=b.id), "created_at": datetime.utcnow().isoformat()+"Z"}, room="broadcast_admins")
    try:
        _ensure_signal_archive(b)
    except Exception:
        current_app.logger.exception("Signal archive generation failed for broadcast %s", b.id)


PHASE4_PRECEDENCE_ORDER = ["ROUTINE", "PRIORITY", "IMMEDIATE", "FLASH"]
PHASE4_ACK_MINUTES = {"FLASH": 5, "IMMEDIATE": 15, "PRIORITY": 60, "ROUTINE": 240}


def _normalize_precedence(value: str | None) -> str:
    v = (value or "ROUTINE").strip().upper()
    return v if v in PHASE4_PRECEDENCE_ORDER else "ROUTINE"


def _ack_deadline_for(precedence: str, base=None):
    base = base or datetime.utcnow()
    return base + timedelta(minutes=PHASE4_ACK_MINUTES.get(_normalize_precedence(precedence), 240))


def _workflow_timeline(b: Broadcast):
    events = []
    def add(label, at, actor=None, status="done"):
        if at:
            events.append({"label": label, "at": at, "actor": actor, "status": status})
    add("Drafted", b.created_at, b.issuer.full_name if getattr(b, "issuer", None) else None)
    add("Submitted", b.submitted_at, None)
    add("Forwarded to AO", getattr(b, "routed_to_ao_at", None), getattr(getattr(b, "unit_ao", None), "full_name", None))
    add("AO reviewed", getattr(b, "ao_reviewed_at", None), getattr(getattr(b, "unit_ao", None), "full_name", None))
    add("Forwarded to signatory", getattr(b, "routed_to_signatory_at", None), getattr(getattr(b, "unit_signatory", None), "full_name", None))
    add("Signed/endorsed", getattr(b, "signatory_signed_at", None), getattr(getattr(b, "unit_signatory", None), "full_name", None))
    add("Forwarded to Commander", getattr(b, "routed_to_commander_at", None), getattr(getattr(b, "unit_commander", None), "full_name", None))
    add("Commander approved", getattr(b, "commander_approved_at", None), getattr(getattr(b, "unit_commander", None), "full_name", None))
    add("Returned", getattr(b, "returned_at", None), getattr(getattr(b, "returned_by", None), "full_name", None), "warn")
    add("Approved", b.approved_at, None)
    add("Release authority validated", getattr(b, "release_authority_validated_at", None), getattr(getattr(b, "release_authority", None), "full_name", None))
    add("Released", b.released_at, None)
    add("Recalled", getattr(b, "recalled_at", None), getattr(getattr(b, "recalled_by", None), "full_name", None), "warn")
    if getattr(b, "superseded_by", None):
        add("Superseded", getattr(b.superseded_by, "created_at", None), b.superseded_by.originator_number or f"Signal {b.superseded_by.id}", "warn")
    return events


def _ack_dashboard(b: Broadcast):
    targets = _broadcast_targets(b) if (b.status == "RELEASED" and not _is_recalled_signal(b)) else []
    target_ids = {u.id for u in targets}
    acks = BroadcastAck.query.filter_by(broadcast_id=b.id).all()
    acked_ids = {a.user_id for a in acks if a.acked_at}
    pending_users = [u for u in targets if u.id not in acked_ids]
    total = len(targets)
    acked = len(target_ids & acked_ids)
    rate = round((acked / total) * 100, 1) if total else 0
    overdue = False
    if getattr(b, "ack_deadline_at", None) and b.requires_ack:
        overdue = datetime.utcnow() > b.ack_deadline_at and acked < total
    return {"total": total, "acked": acked, "pending": max(total-acked, 0), "rate": rate, "pending_users": pending_users, "overdue": overdue}


def _can_manage_signal_workflow(user, b: Broadcast) -> bool:
    # Do not tie workflow authority to drafting permission. In the corrected
    # chain, only Chief Clerk drafts, while AO, Signatory and Commander handle
    # review/sign/approval actions.
    if user.role in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        return True
    if getattr(user, "id", None) in ({b.issuer_id, b.approved_by_id, b.released_by_id} | _unit_workflow_actor_ids(b)):
        return True
    return _can_view_unit_workflow(user, b)


def _can_edit_broadcast_signal(user, b: Broadcast) -> bool:
    """Editable signals are unfinished drafts or recalled records under authority control.

    Released/archived signals remain locked. To change one, the releasing authority
    must first recall it, or create an editable correction draft. This keeps the
    operational record disciplined while still allowing real correction workflow.
    """
    if not user or not can_create_signal(user):
        return False
    status = (getattr(b, "status", "") or "").upper()
    if status not in {"DRAFT", "RECALLED", "RETURNED_BY_AO", "RETURNED_BY_COMMANDER"}:
        return False
    if user.role in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        return True
    if user.id == b.issuer_id:
        return True
    return user.role == Role.COMMANDER.value and user.id in {b.issuer_id, b.approved_by_id, b.released_by_id, b.recalled_by_id}


def _remove_signal_archive_file(b: Broadcast):
    """Remove stale archived PDF after an editable correction/recall update."""
    try:
        rec = SignalArchive.query.filter_by(broadcast_id=b.id).first()
        if not rec:
            return
        archive_dir = os.path.join(current_app.instance_path, "signal_bank")
        path = os.path.join(archive_dir, rec.file_name or "")
        if rec.file_name and os.path.exists(path):
            os.remove(path)
        db.session.delete(rec)
    except Exception:
        current_app.logger.exception("Failed removing stale archive for signal %s", getattr(b, "id", None))


def _reset_release_state_for_edit(b: Broadcast):
    """A changed recalled/correction signal must be signed again before release."""
    b.digital_signature = None
    b.signature_fingerprint = None
    b.signed_at = None
    b.signed_by_id = None
    b.released_at = None
    b.released_by_id = None
    b.release_authority_id = None
    b.release_authority_validated_at = None
    b.approved_at = None
    b.approved_by_id = None
    b.reviewed_by_id = None
    b.ack_deadline_at = None
    b.releasing_signature_image = None
    try:
        BroadcastReceipt.query.filter_by(broadcast_id=b.id).delete(synchronize_session=False)
        BroadcastAck.query.filter_by(broadcast_id=b.id).delete(synchronize_session=False)
    except Exception:
        current_app.logger.exception("Failed clearing stale receipts/acks for edited signal %s", getattr(b, "id", None))
    _remove_signal_archive_file(b)



def _autosave_folder() -> str:
    folder = os.path.join(current_app.instance_path, "autosave")
    os.makedirs(folder, exist_ok=True)
    return folder


def _autosave_path(user_id: int) -> str:
    return os.path.join(_autosave_folder(), f"broadcast_{user_id}.json")


def _load_autosave(user_id: int) -> dict:
    path = _autosave_path(user_id)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
            return payload if isinstance(payload, dict) else {}
    except Exception:
        current_app.logger.exception("Failed to load autosave draft for user %s", user_id)
        return {}


def _save_autosave(user_id: int, payload: dict):
    payload = dict(payload or {})
    payload["saved_at"] = datetime.utcnow().isoformat() + "Z"
    with open(_autosave_path(user_id), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return payload


def _clear_autosave(user_id: int):
    path = _autosave_path(user_id)
    if os.path.exists(path):
        os.remove(path)


def _units_payload(units):
    return [{"id": u.id, "name": u.name, "code": u.code, "level": u.level, "haystack": f"{u.name or ''} {u.code or ''} {u.level or ''}".lower()} for u in units]


def _routing_warning_text(title: str, body: str, unit_ids: list[int]):
    text = f"{title or ''} {bleach.clean(body or '', tags=[], strip=True)}".lower().strip()
    if not text or not unit_ids:
        return None
    inferred = None
    for label, keywords in ROUTING_HINT_KEYWORDS.items():
        if any(k in text for k in keywords):
            inferred = label
            break
    if not inferred:
        return None
    selected_units = Unit.query.filter(Unit.id.in_(unit_ids)).all()
    if not selected_units:
        return None
    def match(hay):
        if inferred == "AIR": return any(k in hay for k in ("air", "wing", "sqn", "squadron", "training"))
        if inferred == "LOG": return any(k in hay for k in ("log", "supply", "transport", "movement", "bsg"))
        if inferred == "MAINT": return any(k in hay for k in ("maint", "engineering", "engr", "service"))
        if inferred == "COMM": return any(k in hay for k in ("comm", "cis", "signal", "ict", "network"))
        if inferred == "ADMIN": return any(k in hay for k in ("admin", "personnel", "hq", "headquarters"))
        return False
    if any(match(f"{u.name or ''} {u.code or ''} {u.level or ''}".lower()) for u in selected_units):
        return None
    names = ", ".join([(u.code or u.name or str(u.id)) for u in selected_units[:4]])
    return f"Routing warning: this signal looks {inferred.lower()}-related, but the selected routing is {names}. Review recipients before release."


def _template_payloads():
    return [{"key": key, **value} for key, value in SIGNAL_TEMPLATES.items()]


@bp.post("/broadcasts/autosave")
@login_required
def broadcast_autosave():
    if not can_create_signal(current_user):
        abort(403)
    payload = request.get_json(silent=True) or {}
    allowed = {"template_key","title","priority","precedence_action","precedence_info","security_classification","drafter_name","drafter_rank","telephone","msg_from","from_unit_id","msg_to","branch_office","dtg","releasing_officer_name","releasing_signature_rank","message_instruction","file_reference","internal_distribution","refers_classified_message","comms_gen_serial_no","sender_receiver_op","transmission_system","time_in_out","action_user_ids","info_user_ids","action_unit_ids","info_unit_ids","body","target_scope","target_unit_id","target_level","requires_ack","workflow_action"}
    clean = {k: payload.get(k) for k in allowed if k in payload}
    saved = _save_autosave(current_user.id, clean)
    return {"ok": True, "saved_at": saved.get("saved_at")}


@bp.post("/broadcasts/autosave/clear")
@login_required
def broadcast_autosave_clear():
    if not can_create_signal(current_user):
        abort(403)
    _clear_autosave(current_user.id)
    return {"ok": True}

@bp.get("/channels")
@login_required
def channel_list():
    all_channels = Channel.query.order_by(Channel.created_at.desc()).all()
    channels = [c for c in all_channels if _can_access_channel(current_user, c)]
    return render_template("messaging/channels.html", channels=channels)

@bp.route("/channels/<int:channel_id>", methods=["GET","POST"])
@login_required
def channel_view(channel_id):
    ch = Channel.query.get_or_404(channel_id)
    if not _can_access_channel(current_user, ch):
        abort(403)

    may_create_signal = can_create_signal(current_user)
    if request.method == "POST":
        if not may_create_signal:
            abort(403)
        body = request.form.get("body","").strip()
        files = request.files.getlist("attachments") if request.files else []
        if body or any(getattr(f, "filename", "") for f in files):
            m = Message(msg_type=MessageType.CHANNEL.value, sender_id=current_user.id, channel_id=ch.id, body_enc=b"")
            m.set_body(body or "[attachment]")
            db.session.add(m); db.session.commit()

            _save_attachments(files, m.id)
            db.session.commit()

            # Real-time: notify channel room
            payload = {"id": m.id, "created_at": m.created_at.isoformat(), "sender_id": m.sender_id, "sender_name": current_user.full_name, "sender_rank": current_user.rank or "", "sender_unit": current_user.unit.code if current_user.unit else "", "channel_id": ch.id, "body": m.get_body(), "link": url_for("msg.channel_view", channel_id=ch.id)}
            socketio.emit("channel_message", payload, room=f"channel_{ch.id}")
            socketio.emit("live_feed_event", {"type": "CHANNEL_MESSAGE", "title": f"New channel update: {ch.name}", "body": m.get_body()[:140], "link": url_for("msg.channel_view", channel_id=ch.id), "created_at": datetime.utcnow().isoformat()+"Z"}, room="broadcast_admins")
            # Notify channel members (except sender)
            try:
                for uid in _channel_member_ids(ch):
                    u = User.query.get(uid)
                    if u and u.id != current_user.id:
                        create_notification(u.id, "CHANNEL_MESSAGE", f"New message in #{ch.name}", (m.get_body()[:120] + ("…" if len(m.get_body())>120 else "")),
                                            link=url_for("msg.channel_view", channel_id=ch.id), thread_type="CHANNEL", thread_id=ch.id)
            except Exception:
                pass
            log_event(current_user.id, "MSG_SENT_CHANNEL", f"channel:{ch.id}")
        return redirect(url_for("msg.channel_view", channel_id=ch.id))

    messages = Message.query.filter_by(channel_id=ch.id).order_by(Message.created_at.asc()).limit(200).all()
    channel_signals = Broadcast.query.filter(Broadcast.channel_id == ch.id, Broadcast.status.in_(["RELEASED", "ARCHIVED", "RECALLED"])).order_by(Broadcast.created_at.desc()).limit(50).all()
    channel_signals = [b for b in channel_signals if can_view_signal_bank(current_user, b)]
    return render_template("messaging/channel_view.html", ch=ch, messages=messages, channel_signals=channel_signals)



def _unit_internal_contacts_for_user(user):
    """Return active officers in the same unit for the Unit Internal Messages page."""
    unit_id = getattr(user, "unit_id", None)
    if not unit_id:
        return []
    return (
        User.query
        .filter(User.unit_id == unit_id, User.is_active_flag == True, User.id != user.id)
        .order_by(User.appointment.asc(), User.rank.asc(), User.full_name.asc())
        .all()
    )


def _unit_dm_unread_counts(user, contacts):
    """Unread direct messages from contacts inside the current unit only."""
    contact_ids = {u.id for u in contacts}
    if not contact_ids:
        return {}
    unread_by_user = {}
    inbound = Message.query.filter(
        Message.msg_type == MessageType.DIRECT.value,
        Message.recipient_id == user.id,
        Message.sender_id.in_(contact_ids)
    ).order_by(Message.created_at.desc()).limit(300).all()
    for m in inbound:
        if not DirectRead.query.filter_by(user_id=user.id, message_id=m.id).first():
            unread_by_user[m.sender_id] = unread_by_user.get(m.sender_id, 0) + 1
    return unread_by_user


@bp.route("/direct", methods=["GET"])
@login_required
def direct_list():
    """Officer-to-officer direct messages.

    Internal Unit Messages remains the same-unit workspace. This page now
    explicitly supports Commander/HQ external coordination while preventing
    normal unit officers from silently messaging outside their unit.
    """
    all_users = User.query.filter(User.is_active_flag == True).order_by(User.full_name.asc()).all()
    users = [u for u in all_users if can_direct_message_user(current_user, u)]
    allow_external_dm = can_external_direct_messages(current_user)

    # Per-user unread counts (messages addressed to me)
    unread_by_user = {}
    inbound = Message.query.filter(
        Message.msg_type==MessageType.DIRECT.value,
        Message.recipient_id==current_user.id
    ).order_by(Message.created_at.desc()).limit(500).all()

    for m in inbound:
        if not DirectRead.query.filter_by(user_id=current_user.id, message_id=m.id).first():
            unread_by_user[m.sender_id] = unread_by_user.get(m.sender_id, 0) + 1

    my_unit_id = getattr(current_user, "unit_id", None)
    contact_sections = OrderedDict([
        ("my_unit", {"title": "My Unit", "hint": "Internal officers in your unit", "users": []}),
        ("unit_commanders", {"title": "Other Unit Commanders", "hint": "Commanders available for unit-to-unit coordination", "users": []}),
        ("hq", {"title": "HQ / Admin", "hint": "HQ administrators and super administrators", "users": []}),
        ("others", {"title": "Other Authorised Officers", "hint": "Other reachable officers outside your unit", "users": []}),
    ])
    for u in users:
        if getattr(u, "unit_id", None) and getattr(u, "unit_id", None) == my_unit_id:
            contact_sections["my_unit"]["users"].append(u)
        elif getattr(u, "role", "") in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
            contact_sections["hq"]["users"].append(u)
        elif getattr(u, "role", "") == Role.COMMANDER.value or normalize_unit_appointment(getattr(u, "appointment", None)) == "COMMANDER":
            contact_sections["unit_commanders"]["users"].append(u)
        else:
            contact_sections["others"]["users"].append(u)

    return render_template(
        "messaging/direct_list.html",
        users=users,
        contact_sections=contact_sections,
        unread_by_user=unread_by_user,
        allow_external_dm=allow_external_dm,
    )




@bp.route("/direct/unit", methods=["GET"])
@login_required
def unit_direct_list():
    if not getattr(current_user, "unit_id", None):
        flash("Your account is not attached to a unit, so unit internal messages are not available.", "warning")
        return redirect(url_for("msg.direct_list"))
    contacts = _unit_internal_contacts_for_user(current_user)
    unread_by_user = _unit_dm_unread_counts(current_user, contacts)
    return render_template(
        "messaging/unit_direct_list.html",
        users=contacts,
        unread_by_user=unread_by_user,
        unit=current_user.unit,
    )


@bp.route("/direct/<int:user_id>", methods=["GET","POST"])
@login_required
def direct_view(user_id):
    other = User.query.get_or_404(user_id)
    if not can_direct_message_user(current_user, other):
        log_event(current_user.id, "DIRECT_MESSAGE_ACCESS_DENIED", {
            "target_module": "Direct Messages",
            "target_id": other.id,
            "recipient": other.service_number,
            "recipient_unit_id": getattr(other, "unit_id", None),
            "sender_unit_id": getattr(current_user, "unit_id", None),
            "status": "DENIED",
        })
        abort(403)
    if request.method == "POST":
        if not Settings.get().allow_direct_messages:
            flash("Direct messages are disabled by policy.", "danger")
            return redirect(url_for("msg.direct_view", user_id=other.id))
        body = request.form.get("body","").strip()
        files = request.files.getlist("attachments") if request.files else []
        voice_file = request.files.get("voice_message") if request.files else None
        if voice_file and getattr(voice_file, "filename", ""):
            files.append(voice_file)
            body = body or "[voice message]"
        if body or any(getattr(f, "filename", "") for f in files):
            m = Message(msg_type=MessageType.DIRECT.value, sender_id=current_user.id, recipient_id=other.id, body_enc=b"")
            m.set_body(body or "[attachment]")
            db.session.add(m); db.session.commit()

            _save_attachments(files, m.id)

            delivered_now = False
            try:
                from ..sockets import USER_SIDS
                delivered_now = bool(USER_SIDS.get(other.id))
            except Exception:
                delivered_now = False
            if delivered_now and not DirectDelivery.query.filter_by(user_id=other.id, message_id=m.id).first():
                db.session.add(DirectDelivery(user_id=other.id, message_id=m.id))
            db.session.commit()

            # Real-time: notify both participants via their private rooms.
            # The link is recipient-aware so popups open the correct conversation on each side.
            attachments_payload = []
            try:
                attachments_payload = [
                    {
                        "id": a.id,
                        "name": a.original_filename,
                        "mime_type": a.mime_type or "",
                        "size_bytes": a.size_bytes or 0,
                        "url": url_for("msg.download_attachment", attachment_id=a.id),
                    }
                    for a in m.attachments.order_by(Attachment.created_at.asc()).all()
                ]
            except Exception:
                attachments_payload = []
            payload = {
                "id": m.id,
                "created_at": m.created_at.isoformat(),
                "sender_id": m.sender_id,
                "sender_name": current_user.full_name,
                "sender_role": current_user.role,
                "recipient_id": other.id,
                "recipient_name": other.full_name,
                "body": m.get_body(),
                "status": "delivered" if delivered_now else "sent",
                "attachments": attachments_payload,
                "link": url_for("msg.direct_view", user_id=current_user.id),
            }
            sender_payload = dict(payload)
            sender_payload["link"] = url_for("msg.direct_view", user_id=other.id)
            socketio.emit("direct_message", payload, room=f"user_{other.id}")
            socketio.emit("direct_message", sender_payload, room=f"user_{current_user.id}")
            if delivered_now:
                socketio.emit("direct_delivery", {"recipient_id": other.id, "message_ids": [m.id], "delivered_at": datetime.utcnow().isoformat()+"Z"}, room=f"user_{current_user.id}")
            create_notification(other.id, "DIRECT_MESSAGE", f"New message from {current_user.full_name}", (m.get_body()[:120] + ("…" if len(m.get_body())>120 else "")), link=url_for("msg.direct_view", user_id=current_user.id), thread_type="DIRECT", thread_id=current_user.id)
            if getattr(current_user, "unit_id", None) and getattr(current_user, "unit_id", None) == getattr(other, "unit_id", None):
                log_event(current_user.id, "UNIT_INTERNAL_DIRECT_MESSAGE_SENT", {
                    "target_module": "Unit Direct Messages",
                    "target_id": other.id,
                    "recipient": other.service_number,
                    "unit_id": current_user.unit_id,
                    "status": "SUCCESS",
                })
            else:
                log_event(current_user.id, "EXTERNAL_DIRECT_MESSAGE_SENT" if getattr(current_user, "unit_id", None) != getattr(other, "unit_id", None) else "MSG_SENT_DIRECT", {
                    "target_module": "Direct Messages",
                    "target_id": other.id,
                    "recipient": other.service_number,
                    "recipient_unit_id": getattr(other, "unit_id", None),
                    "sender_unit_id": getattr(current_user, "unit_id", None),
                    "status": "SUCCESS",
                })
            if request.headers.get("X-Requested-With") == "XMLHttpRequest" or "application/json" in (request.headers.get("Accept") or ""):
                return jsonify({"ok": True, "message": sender_payload})
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or "application/json" in (request.headers.get("Accept") or ""):
            return jsonify({"ok": False, "error": "Message body or attachment required."}), 400
        return redirect(url_for("msg.direct_view", user_id=other.id))

    messages = Message.query.filter(
        (Message.msg_type==MessageType.DIRECT.value) &
        (
            ((Message.sender_id==current_user.id) & (Message.recipient_id==other.id)) |
            ((Message.sender_id==other.id) & (Message.recipient_id==current_user.id))
        )
    ).order_by(Message.created_at.asc()).limit(200).all()

    # Mark inbound messages as delivered/read when this conversation is opened.
    unread_inbound = [m for m in messages if m.sender_id == other.id and m.recipient_id == current_user.id]
    newly_delivered = []
    newly_read = []
    for m in unread_inbound:
        if not DirectDelivery.query.filter_by(user_id=current_user.id, message_id=m.id).first():
            db.session.add(DirectDelivery(user_id=current_user.id, message_id=m.id))
            newly_delivered.append(m.id)
        if not DirectRead.query.filter_by(user_id=current_user.id, message_id=m.id).first():
            db.session.add(DirectRead(user_id=current_user.id, message_id=m.id))
            newly_read.append(m.id)
    if newly_delivered or newly_read:
        db.session.commit()
        try:
            if newly_delivered:
                socketio.emit("direct_delivery", {"recipient_id": current_user.id, "message_ids": newly_delivered, "delivered_at": datetime.utcnow().isoformat()+"Z"}, room=f"user_{other.id}")
            if newly_read:
                socketio.emit("direct_read", {"reader_id": current_user.id, "reader_name": current_user.full_name, "thread_user_id": other.id, "message_ids": newly_read, "read_at": datetime.utcnow().isoformat()+"Z"}, room=f"user_{other.id}")
        except Exception:
            pass

    delivered_ids = {r.message_id for r in DirectDelivery.query.filter_by(user_id=other.id).filter(DirectDelivery.message_id.in_([m.id for m in messages if m.sender_id == current_user.id])).all()}
    read_ids = {r.message_id for r in DirectRead.query.filter_by(user_id=other.id).filter(DirectRead.message_id.in_([m.id for m in messages if m.sender_id == current_user.id])).all()}

    return render_template("messaging/direct_view.html", other=other, messages=messages, delivered_ids=delivered_ids, read_ids=read_ids)


@bp.get("/attachments/<int:attachment_id>/download")
@login_required
def download_attachment(attachment_id):
    a = Attachment.query.get_or_404(attachment_id)
    m = Message.query.get_or_404(a.message_id)

    # Authorization: must be a participant (direct) or have channel access
    if m.msg_type == MessageType.DIRECT.value:
        if current_user.id not in (m.sender_id, m.recipient_id):
            abort(403)
    elif m.msg_type == MessageType.CHANNEL.value:
        # Basic channel access: unit scope check aligns with channel_view
        ch = Channel.query.get(m.channel_id)
        if not ch:
            abort(404)
        if ch.scope == "UNIT" and current_user.role != Role.ADMIN.value:
            if not current_user.unit_id or ch.unit_id != current_user.unit_id:
                abort(403)
    else:
        abort(403)

    log_event(current_user.id, "MESSAGE_ATTACHMENT_DOWNLOADED", f"{attachment_id}:{a.original_filename}")
    upload_dir = current_app.config.get("UPLOAD_FOLDER")
    return send_from_directory(upload_dir, a.stored_filename, as_attachment=True, download_name=a.original_filename)


@bp.get("/broadcasts/<int:broadcast_id>/attachments/<int:attachment_id>/download")
@login_required
def download_broadcast_attachment(broadcast_id, attachment_id):
    a = BroadcastAttachment.query.get_or_404(attachment_id)
    if a.broadcast_id != broadcast_id:
        abort(404)
    b = Broadcast.query.get_or_404(broadcast_id)

    if not _can_open_signal(current_user, b):
        abort(403)
    if _block_recalled_signal_action(b, "Attachment download"):
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))

    log_event(current_user.id, "BROADCAST_ATTACHMENT_DOWNLOADED", f"{broadcast_id}:{attachment_id}")
    upload_dir = current_app.config.get("UPLOAD_FOLDER")
    return send_from_directory(upload_dir, a.stored_filename, as_attachment=True, download_name=a.original_filename)


@bp.get("/unit-workflow")
@login_required
def unit_workflow_center():
    if not can_create_signal(current_user) and not getattr(current_user, "unit_id", None) and getattr(current_user, "role", "") not in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        abort(403)
    groups = _unit_workflow_items_for_user(current_user)
    stats = {
        "my_action": len(groups["my_action"]),
        "returned": len(groups["returned"]),
        "ready_release": len(groups["ready_release"]),
        "in_routing": len(groups["in_routing"]),
        "all": len(groups["all"]),
    }
    return render_template(
        "messaging/unit_workflow_center.html",
        groups=groups,
        stats=stats,
        labels=UNIT_WORKFLOW_LABELS,
        due_info=workflow_due_info,
    )


@bp.post("/unit-workflow/<int:broadcast_id>/remind")
@login_required
def unit_workflow_remind(broadcast_id):
    """Send a focused reminder to the current internal workflow handler."""
    b = Broadcast.query.get_or_404(broadcast_id)
    if not _can_view_unit_workflow(current_user, b):
        abort(403)
    handler_id = getattr(b, "current_handler_id", None)
    if not handler_id:
        flash("No current workflow handler is assigned to this signal.", "warning")
        return redirect(request.referrer or url_for("msg.unit_workflow_center"))
    if handler_id == current_user.id:
        flash("This signal is already waiting for your own action.", "info")
        return redirect(request.referrer or url_for("msg.unit_workflow_center"))

    due = workflow_due_info(b)
    actor = f"{getattr(current_user, 'rank', '') or ''} {current_user.full_name}".strip()
    ref = b.originator_number or b.file_reference or f"Signal #{b.id}"
    create_notification(
        handler_id,
        "BROADCAST",
        "Unit workflow reminder",
        f"{actor} requested your action on {ref} · {UNIT_WORKFLOW_LABELS.get(b.status, b.status)} · {due['label']}",
        link=url_for("msg.broadcast_detail", broadcast_id=b.id),
        thread_type="BROADCAST",
        thread_id=b.id,
        respect_dnd=False,
    )
    try:
        socketio.emit(
            "live_feed_event",
            {
                "type": "UNIT_WORKFLOW_REMINDER",
                "title": "Unit workflow reminder",
                "body": f"Action requested on {ref}",
                "link": url_for("msg.broadcast_detail", broadcast_id=b.id),
                "created_at": datetime.utcnow().isoformat() + "Z",
            },
            room=f"user_{handler_id}",
        )
    except Exception:
        current_app.logger.exception("Could not push unit workflow reminder for signal %s", b.id)
    log_event(current_user.id, "UNIT_WORKFLOW_REMINDER_SENT", {
        "target_module": "Signals/Broadcasts",
        "target_id": b.id,
        "signal_ref": ref,
        "handler_id": handler_id,
        "status": b.status,
        "sla_state": due["severity"],
    })
    flash("Workflow reminder sent to the current handler.", "success")
    return redirect(request.referrer or url_for("msg.unit_workflow_center"))


@bp.route("/broadcasts", methods=["GET","POST"])
@login_required
def broadcasts():
    may_create_signal = can_create_signal(current_user)
    if request.method == "POST":
        if not may_create_signal:
            abort(403)
        if _is_unit_internal_workflow_required(current_user) and not is_unit_chief_clerk(current_user):
            flash("Only the Chief Clerk can draft unit-originated signals. AO, signatory officers and commanders act through the workflow queue.", "danger")
            return redirect(url_for("msg.unit_workflow_center"))

        title = request.form.get("title", "").strip()
        priority = request.form.get("priority", Priority.GREEN.value)
        target_scope = request.form.get("target_scope", "ALL")
        target_unit_id = request.form.get("target_unit_id") or None
        channel_id = request.form.get("channel_id") or None
        target_level = (request.form.get("target_level") or "").strip() or None
        requires_ack = True if request.form.get("requires_ack") == "on" else False
        requested_status = (request.form.get("workflow_action") or "SUBMITTED").upper()

        # Simplified NAF signal capture: users fill only operational fields; official form fields are auto/static.
        precedence_action = _normalize_precedence(request.form.get("precedence_action", "ROUTINE"))
        precedence_info = _normalize_precedence(request.form.get("precedence_info", "ROUTINE")) if request.form.get("precedence_info") else "ROUTINE"
        routing_chain_text = request.form.get("routing_chain_text", "").strip() or None
        from_unit_id_raw = request.form.get("from_unit_id") or (str(current_user.unit_id) if current_user.unit_id else "")
        from_unit_id = int(from_unit_id_raw) if str(from_unit_id_raw).isdigit() else None
        from_unit_obj = Unit.query.get(from_unit_id) if from_unit_id else current_user.unit
        msg_from = (from_unit_obj.code or from_unit_obj.name) if from_unit_obj else (current_user.unit.code if current_user.unit else None)
        branch_office = request.form.get("branch_office", "").strip() or "CIS"
        telephone = request.form.get("telephone", "").strip() or (getattr(current_user, "phone", None) or "")
        dtg = _default_dtg(request.form.get("dtg", "").strip() or None)
        drafter_name = request.form.get("drafter_name", "").strip() or current_user.full_name.upper()
        drafter_rank = request.form.get("drafter_rank", "").strip() or (current_user.rank or "")
        if drafter_rank not in RANK_OPTIONS:
            drafter_rank = ""
        releasing_signature_rank = request.form.get("releasing_signature_rank", "").strip() or (current_user.rank or "")
        releasing_officer_name = request.form.get("releasing_officer_name", "").strip() or current_user.full_name.upper()
        message_instruction = ""
        internal_distribution = "INTERNAL DISTRIBUTION: CIS, OPS, INT"
        file_reference = request.form.get("file_reference", "").strip() or None
        refers_classified_message = True if request.form.get("refers_classified_message") == "on" else False
        comms_gen_serial_no = "AUTO"
        sender_receiver_op = "AUTO"
        transmission_system = "NAF SECURE MESSAGING PLATFORM"
        time_in_out = "AUTO"
        security_classification = request.form.get("security_classification", ClassificationLevel.RESTRICTED.value).strip() or ClassificationLevel.RESTRICTED.value
        body = _sanitize_rich_text(request.form.get("body", "").strip())

        action_user_ids = []
        info_user_ids = []
        action_unit_ids = _selected_ints("action_unit_ids")
        info_unit_ids = _selected_ints("info_unit_ids")
        # Keep the manually selected To units separate from automatically expanded
        # distribution recipients. The official signal TO line must show the
        # military route text (for example ALL NAF UNITS or LIST C LESS AHQ),
        # while the backend still expands actual recipients for delivery,
        # acknowledgement, read receipts, and audit.
        manual_action_unit_ids = list(action_unit_ids)

        # Official NAF distribution routing: ALL NAF UNITS, List A/B/C/D/E,
        # individual units, and LESS/excluded units. The frontend displays only
        # route labels; it must not auto-check/list all expanded units. Backend
        # resolves the real delivery recipients here.
        distribution_list_names = [x.strip().upper() for x in request.form.getlist("distribution_list_names") if x.strip()]
        include_all_naf_units = request.form.get("naf_all_units") == "on"
        info_distribution_list_names = [x.strip().upper() for x in request.form.getlist("info_distribution_list_names") if x.strip()]
        include_info_all_naf_units = request.form.get("info_naf_all_units") == "on"
        excluded_unit_ids = set(_selected_ints("exclude_unit_ids"))
        info_excluded_unit_ids = set(_selected_ints("info_exclude_unit_ids"))
        all_units_for_distribution = Unit.query.order_by(Unit.name.asc()).all()
        distribution_unit_ids = resolve_distribution_unit_ids(
            all_units_for_distribution,
            distribution_list_names,
            include_all=include_all_naf_units,
        )
        info_distribution_unit_ids = resolve_distribution_unit_ids(
            all_units_for_distribution,
            info_distribution_list_names,
            include_all=include_info_all_naf_units,
        )
        manual_info_unit_ids = list(info_unit_ids)
        action_unit_ids = sorted((set(action_unit_ids) | distribution_unit_ids) - excluded_unit_ids)
        info_unit_ids = sorted((set(info_unit_ids) | info_distribution_unit_ids) - info_excluded_unit_ids)
        selected_channel = None
        if target_scope == "CHANNEL":
            if not str(channel_id or "").isdigit():
                flash("Select a channel.", "danger")
                return redirect(url_for("msg.broadcasts"))
            selected_channel = Channel.query.get(int(channel_id))
            if not selected_channel or not _can_access_channel(current_user, selected_channel):
                flash("You are not permitted to send to that channel.", "danger")
                return redirect(url_for("msg.broadcasts"))
            if not can_access_classification(current_user, getattr(selected_channel, "classification_level", None)):
                flash("Your clearance does not allow this channel.", "danger")
                return redirect(url_for("msg.broadcasts"))
            action_unit_ids += list(_channel_unit_ids(selected_channel))
            action_user_ids += list(_channel_member_ids(selected_channel))
        selected_to_units = Unit.query.filter(Unit.id.in_(action_unit_ids)).order_by(Unit.name.asc()).all() if action_unit_ids else []
        manual_to_units = Unit.query.filter(Unit.id.in_(manual_action_unit_ids)).order_by(Unit.name.asc()).all() if manual_action_unit_ids else []
        manual_info_units = Unit.query.filter(Unit.id.in_(manual_info_unit_ids)).order_by(Unit.name.asc()).all() if manual_info_unit_ids else []
        excluded_units = Unit.query.filter(Unit.id.in_(list(excluded_unit_ids))).order_by(Unit.name.asc()).all() if excluded_unit_ids else []
        info_excluded_units = Unit.query.filter(Unit.id.in_(list(info_excluded_unit_ids))).order_by(Unit.name.asc()).all() if info_excluded_unit_ids else []
        msg_info_display = build_route_display(info_distribution_list_names, include_info_all_naf_units, manual_info_units, info_excluded_units) or ("; ".join([(u.code or u.name) for u in manual_info_units]) if manual_info_units else None)
        if selected_channel:
            msg_to = f"CHANNEL: {selected_channel.name}"
        else:
            # IMPORTANT: do not print every expanded unit on the signal.
            # The visible TO line remains operationally clean; expanded units
            # are stored in action_units_csv below for backend routing only.
            msg_to = build_route_display(distribution_list_names, include_all_naf_units, manual_to_units, excluded_units) or ("; ".join([(u.code or u.name) for u in manual_to_units]) if manual_to_units else None)

        # Phase 4 distribution list templates: reusable military routing shortcuts.
        for tpl in request.form.getlist("distribution_templates"):
            if tpl == "COMMANDERS":
                action_user_ids += [u.id for u in User.query.filter(User.is_active_flag.is_(True), User.role == Role.COMMANDER.value).all()]
            elif tpl == "OFFICERS":
                info_user_ids += [u.id for u in User.query.filter(User.is_active_flag.is_(True), User.role.in_([Role.COMMANDER.value, Role.OFFICER.value])).all()]
            elif tpl == "UNIT":
                if current_user.unit_id:
                    action_unit_ids.append(int(current_user.unit_id))
            elif tpl == "HQ":
                hq_units = Unit.query.filter(Unit.level == "HQ").all()
                info_unit_ids += [u.id for u in hq_units]

        action_user_ids = sorted(set(action_user_ids))
        info_user_ids = sorted(set(info_user_ids))
        action_unit_ids = sorted(set(action_unit_ids))
        info_unit_ids = sorted(set(info_unit_ids))
        if target_scope == "UNIT" and not target_unit_id and action_unit_ids:
            target_unit_id = str(action_unit_ids[0])

        files = [f for f in request.files.getlist("attachments") if f and getattr(f, "filename", "")]
        routing_warning = _routing_warning_text(title, body, action_unit_ids + info_unit_ids + ([int(target_unit_id)] if str(target_unit_id).isdigit() else []))
        if not title or not body:
            flash("Title and message text are required", "danger")
            return redirect(url_for("msg.broadcasts"))

        if not can_access_classification(current_user, security_classification):
            flash("Your clearance level does not allow you to issue this classification.", "danger")
            return redirect(url_for("msg.broadcasts"))

        allowed_priorities = {Priority.GREEN.value}
        if may_create_signal:
            allowed_priorities = {Priority.GREEN.value, Priority.AMBER.value, Priority.RED.value}
        if priority not in allowed_priorities:
            flash("You are not permitted to send this priority.", "danger")
            return redirect(url_for("msg.broadcasts"))

        if not can_target_scope(current_user, target_scope, target_unit_id):
            flash("You are not permitted to use that target scope.", "danger")
            return redirect(url_for("msg.broadcasts"))

        if target_scope == "CHANNEL":
            if not selected_channel:
                flash("Select a channel.", "danger")
                return redirect(url_for("msg.broadcasts"))
        elif target_scope in ("UNIT", "UNIT_TREE"):
            if not target_unit_id:
                flash("Select at least one target unit, list, or All NAF Units.", "danger")
                return redirect(url_for("msg.broadcasts"))
            # Corrected unit workflow rule: Chief Clerk/unit-originated signals
            # may target any authorised NAF unit/list/channel at draft time.
            # Delivery is still impossible until AO/signatory endorsement and
            # Commander final approval/sign-and-release are completed.
        elif target_scope == "LEVEL":
            if current_user.role not in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
                flash("Only ADMIN/SUPER_ADMIN can broadcast to a whole level.", "danger")
                return redirect(url_for("msg.broadcasts"))
            if not target_level:
                flash("Select a unit level for this scope.", "danger")
                return redirect(url_for("msg.broadcasts"))
        else:
            if current_user.role not in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
                flash("Only ADMIN/SUPER_ADMIN can broadcast to ALL.", "danger")
                return redirect(url_for("msg.broadcasts"))

        status = requested_status
        if status not in {"DRAFT", "SUBMITTED", "APPROVED", "RELEASED"}:
            status = "SUBMITTED"
        # New signals are never directly released from the compose form. Release
        # requires password-backed digital signing on the detail page so an
        # unsigned official signal cannot enter the live workflow.
        if status == "RELEASED":
            status = "SUBMITTED"
        if status == "APPROVED" and not can_approve_broadcast(current_user):
            status = "SUBMITTED"

        now = datetime.utcnow()
        if _is_unit_internal_workflow_required(current_user) and status != "DRAFT":
            if not is_unit_chief_clerk(current_user):
                flash("Only the Chief Clerk can submit a unit signal for AO review.", "danger")
                return redirect(url_for("msg.unit_workflow_center"))
            if not _first_unit_officer(getattr(current_user, "unit_id", None), "ADMIN_OFFICER"):
                flash("Create an Admin Officer / Unit AO before forwarding signals for review.", "danger")
                return redirect(url_for("admin.unit_officers"))
        status, initial_handler, unit_ao, unit_signatory, unit_commander, routed_to_ao_at = _initial_unit_workflow_status(current_user, status, now)
        if msg_info_display:
            internal_distribution = (internal_distribution or "INTERNAL DISTRIBUTION: CIS, OPS, INT") + "\n" + INFO_ROUTE_MARKER + msg_info_display

        b = Broadcast(
            title=title,
            priority=priority,
            issuer_id=current_user.id,
            target_scope=target_scope,
            target_unit_id=target_unit_id,
            channel_id=int(channel_id) if str(channel_id or "").isdigit() else None,
            target_level=target_level,
            requires_ack=requires_ack,
            drafter_name=drafter_name,
            drafter_rank=drafter_rank,
            precedence_action=precedence_action,
            precedence_info=precedence_info,
            msg_from=msg_from,
            from_unit_id=from_unit_id,
            msg_to=msg_to,
            branch_office=branch_office,
            telephone=telephone,
            dtg=dtg,
            releasing_signature_rank=releasing_signature_rank,
            releasing_officer_name=releasing_officer_name,
            message_instruction=message_instruction,
            internal_distribution=internal_distribution,
            file_reference=file_reference,
            refers_classified_message=refers_classified_message,
            comms_gen_serial_no=comms_gen_serial_no,
            sender_receiver_op=sender_receiver_op,
            transmission_system=transmission_system,
            time_in_out=time_in_out,
            security_classification=security_classification,
            status=status,
            body_format="html",
            submitted_at=now if status != "DRAFT" else None,
            approved_at=now if status in {"APPROVED", "APPROVED_BY_AO", "APPROVED_BY_COMMANDER", "RELEASED"} else None,
            released_at=now if status == "RELEASED" else None,
            reviewed_by_id=current_user.id if status in {"APPROVED", "APPROVED_BY_AO", "APPROVED_BY_COMMANDER", "RELEASED"} else None,
            approved_by_id=current_user.id if status in {"APPROVED", "APPROVED_BY_AO", "APPROVED_BY_COMMANDER", "RELEASED"} else None,
            released_by_id=current_user.id if status == "RELEASED" else None,
            current_handler_id=getattr(initial_handler, "id", None),
            unit_ao_id=getattr(unit_ao, "id", None),
            unit_signatory_id=getattr(unit_signatory, "id", None),
            unit_commander_id=getattr(unit_commander, "id", None),
            routed_to_ao_at=routed_to_ao_at,
            signal_precedence=precedence_action,
            ack_deadline_at=_ack_deadline_for(precedence_action, now) if (status == "RELEASED" and requires_ack) else None,
            release_authority_id=current_user.id if status == "RELEASED" else None,
            release_authority_validated_at=now if status == "RELEASED" else None,
            routing_chain_text=routing_chain_text,
            body_enc=b""
        )
        b.set_csv_ids("action_users_csv", action_user_ids)
        b.set_csv_ids("info_users_csv", info_user_ids)
        b.set_csv_ids("action_units_csv", action_unit_ids)
        b.set_csv_ids("info_units_csv", info_unit_ids)
        b.set_body(body)
        db.session.add(b)
        db.session.commit()

        b.originator_number = _originator_for(b)
        if not b.file_reference:
            b.file_reference = b.originator_number
        if not b.comms_gen_serial_no:
            b.comms_gen_serial_no = b.originator_number
        # Do not auto-fill MESSAGE INSTRUCTION with the signal title; official form keeps this blank unless explicitly set.
        if b.message_instruction is None:
            b.message_instruction = ""
        if not b.internal_distribution:
            b.internal_distribution = _from_unit_text(b) or b.msg_from
        if not b.dtg:
            b.dtg = _default_dtg(None)
        db.session.commit()

        sig_file = request.files.get("releasing_signature_image")
        if sig_file and getattr(sig_file, "filename", ""):
            ext = sig_file.filename.rsplit(".", 1)[-1].lower() if "." in sig_file.filename else "png"
            if ext in {"png", "jpg", "jpeg", "webp"}:
                sig_name = secure_filename(f"signature_{b.id}_{uuid.uuid4().hex}.{ext}")
                sig_file.save(os.path.join(current_app.config.get("UPLOAD_FOLDER"), sig_name))
                b.releasing_signature_image = sig_name
                db.session.commit()
                log_event(current_user.id, "SIGNATURE_IMAGE_UPLOADED", f"{b.id}:{sig_name}")

        if files:
            _save_broadcast_attachments(files, b.id)
            db.session.commit()
            log_event(current_user.id, "BROADCAST_ATTACHMENTS_UPLOADED", f"{b.id}:{len(files)}")

        _clear_autosave(current_user.id)
        log_event(current_user.id, f"BROADCAST_{b.status}", f"{b.id}:{priority}:{target_scope}:{security_classification}")
        if b.current_handler_id:
            _notify_current_handler(b, "Signal awaiting unit action", f"{b.originator_number or b.id} · {UNIT_WORKFLOW_LABELS.get(b.status, b.status)}")
        if routing_warning:
            flash(routing_warning, "warning")
            log_event(current_user.id, "SMART_ROUTING_WARNING", f"{b.id}:{routing_warning}")
        if b.status == "FORWARDED_TO_AO":
            flash("Signal forwarded to the unit Admin Officer for review.", "success")
        elif b.status == "APPROVED_BY_AO":
            flash("Signal captured in the unit workflow after AO review stage.", "success")
        elif b.status == "APPROVED_BY_COMMANDER":
            flash("Signal captured with commander authority pending digital release.", "success")
        else:
            flash("Signal submitted for release authority validation." if b.status == "SUBMITTED" else f"Signal {b.status.lower()} saved successfully.", "success")
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))

    # Received Signals / Broadcasts list is TO/INFO-specific.
    # It is intentionally narrower than Signal Bank, which is global by clearance.
    broadcasts_all = Broadcast.query.order_by(Broadcast.created_at.desc()).limit(300).all()
    broadcasts = []
    for b in broadcasts_all:
        if _is_inbox_signal_for_user(current_user, b):
            broadcasts.append(b)

    pending_ack_ids = set()
    for b in broadcasts:
        if b.status == "RELEASED" and b.requires_ack and not _is_recalled_signal(b):
            if not BroadcastAck.query.filter_by(broadcast_id=b.id, user_id=current_user.id).first():
                pending_ack_ids.add(b.id)
    pending_workflow_signals = []
    if may_create_signal:
        pending_candidates = Broadcast.query.order_by(Broadcast.created_at.desc()).limit(300).all()
        pending_workflow_signals = [x for x in pending_candidates if (getattr(x, "status", "") or "").upper() in UNIT_WORKFLOW_STATUSES and _can_open_signal(current_user, x)]
    units = Unit.query.order_by(Unit.name.asc()).all()
    users = User.query.filter_by(is_active_flag=True).order_by(User.full_name.asc()).all()
    channels = [c for c in Channel.query.order_by(Channel.name.asc()).all() if _can_access_channel(current_user, c)]

    now = datetime.utcnow()
    for b in broadcasts:
        if b.status != "RELEASED" or _is_recalled_signal(b) or not is_signal_delivery_recipient(current_user, b):
            continue
        r = BroadcastReceipt.query.filter_by(broadcast_id=b.id, user_id=current_user.id).first()
        if not r:
            r = BroadcastReceipt(broadcast_id=b.id, user_id=current_user.id)
            db.session.add(r)
        if r.received_at is None:
            r.received_at = now
    db.session.commit()
    try:
        for b in broadcasts:
            if b.status == "RELEASED":
                socketio.emit("broadcast_receipt_update", {"broadcast_id": b.id, "user_id": current_user.id, "user_name": current_user.full_name, "state": "received", "originator_number": b.originator_number, "link": url_for("msg.broadcast_detail", broadcast_id=b.id), "updated_at": datetime.utcnow().isoformat()+"Z"}, room="broadcast_admins")
                if b.issuer_id:
                    socketio.emit("broadcast_receipt_update", {"broadcast_id": b.id, "user_id": current_user.id, "user_name": current_user.full_name, "state": "received", "originator_number": b.originator_number, "link": url_for("msg.broadcast_detail", broadcast_id=b.id), "updated_at": datetime.utcnow().isoformat()+"Z"}, room=f"user_{b.issuer_id}")
    except Exception:
        pass

    autosave_draft = _load_autosave(current_user.id)
    return render_template(
        "messaging/broadcasts.html",
        broadcasts=broadcasts,
        Priority=Priority,
        units=units,
        users=users,
        channels=channels,
        pending_ack_ids=pending_ack_ids,
        classification_choices=CLASSIFICATION_CHOICES,
        rank_options=RANK_OPTIONS,
        autosave_draft=autosave_draft if may_create_signal else {},
        may_create_signal=may_create_signal,
        signal_templates=_template_payloads() if may_create_signal else [],
        unit_payloads=_units_payload(units),
        distribution_payload=distribution_payload(units),
        pending_workflow_signals=pending_workflow_signals,
        unit_workflow_labels=UNIT_WORKFLOW_LABELS,
    )

@bp.get("/broadcasts/<int:broadcast_id>")
@login_required
def broadcast_detail(broadcast_id):
    b = Broadcast.query.get_or_404(broadcast_id)
    if not _can_open_signal(current_user, b):
        abort(403)

    body_text = _sanitize_rich_text(b.get_body())
    routing = _action_info_targets(b)
    rs = _routing_summary(b)

    # Mark as received/read only for true TO/INFO recipients.
    # Opening a signal through the global Signal Bank should not fake delivery receipt.
    now = datetime.utcnow()
    changed_to_read = False
    if is_signal_delivery_recipient(current_user, b):
        r = BroadcastReceipt.query.filter_by(broadcast_id=b.id, user_id=current_user.id).first()
        if not r:
            r = BroadcastReceipt(broadcast_id=b.id, user_id=current_user.id)
            db.session.add(r)
        if r.received_at is None:
            r.received_at = now
        if r.read_at is None:
            r.read_at = now
            changed_to_read = True
        db.session.commit()
    if changed_to_read:
        try:
            payload = {"broadcast_id": b.id, "user_id": current_user.id, "user_name": current_user.full_name, "state": "read", "originator_number": b.originator_number, "link": url_for("msg.broadcast_detail", broadcast_id=b.id), "updated_at": datetime.utcnow().isoformat()+"Z"}
            socketio.emit("broadcast_receipt_update", payload, room="broadcast_admins")
            if b.issuer_id:
                socketio.emit("broadcast_receipt_update", payload, room=f"user_{b.issuer_id}")
        except Exception:
            pass
    ack = None
    if b.requires_ack:
        ack = BroadcastAck.query.filter_by(broadcast_id=b.id, user_id=current_user.id).first()

    receipts = []
    stats = {"not_seen": 0, "received": 0, "read": 0}
    if current_user.role in (Role.ADMIN.value, Role.SUPER_ADMIN.value) or current_user.id == b.issuer_id:
        # backfill receipts for targets (old broadcasts)
        targets = _broadcast_targets(b)
        for u in targets:
            if not BroadcastReceipt.query.filter_by(broadcast_id=b.id, user_id=u.id).first():
                db.session.add(BroadcastReceipt(broadcast_id=b.id, user_id=u.id))
        db.session.commit()

        receipts = BroadcastReceipt.query.filter_by(broadcast_id=b.id).all()
        for rr in receipts:
            if rr.read_at:
                stats["read"] += 1
            elif rr.received_at:
                stats["received"] += 1
            else:
                stats["not_seen"] += 1

    acks = []
    if current_user.role in (Role.ADMIN.value, Role.SUPER_ADMIN.value) or current_user.id == b.issuer_id:
        acks = BroadcastAck.query.filter_by(broadcast_id=b.id).all()

    ack_by_user = {a.user_id: a for a in acks}

    attachments = b.attachments.order_by(BroadcastAttachment.created_at.asc()).all() if hasattr(b, "attachments") else []

    form_ctx = _message_form_context(b)
    unit_workflow = _unit_workflow_context(b)
    signatory_options = _unit_officers(b.from_unit_id or getattr(current_user, "unit_id", None), "SIGNATORY_OFFICER")
    return render_template(
        "messaging/broadcast_detail.html",
        b=b,
        body_text=body_text,
        ack=ack,
        acks=acks,
        receipts=receipts,
        stats=stats,
        ack_by_user=ack_by_user,
        attachments=attachments,
        routing=routing,
        action_lines=rs["action_lines"],
        info_lines=rs["info_lines"],
        from_unit_text=rs["from_unit_text"],
        signature_valid=form_ctx["signature_valid"],
        signature_meta=form_ctx["signature_meta"],
        form_ctx=form_ctx,
        can_sign=_can_sign_broadcast(current_user, b),
        timeline=_workflow_timeline(b),
        ack_dash=_ack_dashboard(b),
        can_manage_workflow=_can_manage_signal_workflow(current_user, b),
        unit_workflow=unit_workflow,
        workflow_due=workflow_due_info(b),
        signatory_options=signatory_options,
        can_act_as_unit_ao=_can_act_as_unit_ao(current_user, b),
        can_act_as_unit_signatory=_can_act_as_unit_signatory(current_user, b),
        can_act_as_unit_commander=_can_act_as_unit_commander(current_user, b),
    )


@bp.route("/broadcasts/<int:broadcast_id>/edit", methods=["GET", "POST"])
@login_required
def broadcast_edit(broadcast_id):
    b = Broadcast.query.get_or_404(broadcast_id)
    if not _can_open_signal(current_user, b):
        abort(403)
    if not _can_edit_broadcast_signal(current_user, b):
        flash("Only recalled signals and editable drafts can be changed. Recall a released signal first, or use Create Editable Correction Signal.", "warning")
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))

    units = Unit.query.order_by(Unit.name.asc()).all()
    channels = [c for c in Channel.query.order_by(Channel.name.asc()).all() if _can_access_channel(current_user, c)]
    internal_clean, info_route_display = _split_internal_distribution(getattr(b, "internal_distribution", None))

    if request.method == "POST":
        action = (request.form.get("edit_action") or "submit").strip().lower()
        title = (request.form.get("title") or "").strip()
        body = _sanitize_rich_text(request.form.get("body", "").strip())
        if not title or not body:
            flash("Subject and signal text are required before saving.", "danger")
            return redirect(url_for("msg.broadcast_edit", broadcast_id=b.id))

        security_classification = (request.form.get("security_classification") or ClassificationLevel.RESTRICTED.value).strip()
        if not can_access_classification(current_user, security_classification):
            flash("Your clearance level does not allow that classification.", "danger")
            return redirect(url_for("msg.broadcast_edit", broadcast_id=b.id))

        target_scope = (request.form.get("target_scope") or b.target_scope or "UNIT").strip().upper()
        channel_id = request.form.get("channel_id") or None
        action_unit_ids = _selected_ints("action_unit_ids")
        info_unit_ids = _selected_ints("info_unit_ids")
        selected_channel = None

        if target_scope == "CHANNEL":
            if not str(channel_id or "").isdigit():
                flash("Select a valid channel before saving this channel correction.", "danger")
                return redirect(url_for("msg.broadcast_edit", broadcast_id=b.id))
            selected_channel = Channel.query.get(int(channel_id))
            if not selected_channel or not _can_access_channel(current_user, selected_channel):
                flash("You are not permitted to use that channel.", "danger")
                return redirect(url_for("msg.broadcast_edit", broadcast_id=b.id))
            action_unit_ids = sorted(set(action_unit_ids) | set(_channel_unit_ids(selected_channel)))
            b.channel_id = selected_channel.id
            b.msg_to = f"CHANNEL: {selected_channel.name}"
        else:
            b.channel_id = None
            if not action_unit_ids:
                flash("Select at least one To / Action unit, unless this is a channel signal.", "danger")
                return redirect(url_for("msg.broadcast_edit", broadcast_id=b.id))
            selected_to_units = Unit.query.filter(Unit.id.in_(action_unit_ids)).order_by(Unit.name.asc()).all()
            b.msg_to = (request.form.get("msg_to") or "").strip() or "; ".join([(u.code or u.name) for u in selected_to_units])

        info_units = Unit.query.filter(Unit.id.in_(info_unit_ids)).order_by(Unit.name.asc()).all() if info_unit_ids else []
        msg_info_display = (request.form.get("msg_info_display") or "").strip() or ("; ".join([(u.code or u.name) for u in info_units]) if info_units else "")
        internal_distribution = (request.form.get("internal_distribution") or "").strip() or "INTERNAL DISTRIBUTION: CIS, OPS, INT"
        if msg_info_display:
            internal_distribution = internal_distribution + "\n" + INFO_ROUTE_MARKER + msg_info_display

        old_status = (b.status or "").upper()
        was_recalled = _is_recalled_signal(b)

        b.title = title[:160]
        b.priority = request.form.get("priority") or Priority.GREEN.value
        b.target_scope = target_scope
        b.target_unit_id = int(action_unit_ids[0]) if (target_scope == "UNIT" and action_unit_ids) else None
        b.target_level = None
        b.requires_ack = True if request.form.get("requires_ack") == "on" else False
        b.precedence_action = _normalize_precedence(request.form.get("precedence_action") or b.precedence_action or "ROUTINE")
        b.precedence_info = _normalize_precedence(request.form.get("precedence_info") or b.precedence_info or "ROUTINE")
        b.signal_precedence = b.precedence_action
        b.security_classification = security_classification
        b.routing_chain_text = (request.form.get("routing_chain_text") or "").strip() or None
        b.branch_office = (request.form.get("branch_office") or "CIS").strip()
        b.telephone = (request.form.get("telephone") or "").strip()
        b.file_reference = (request.form.get("file_reference") or b.file_reference or b.originator_number or "").strip() or None
        b.message_instruction = (request.form.get("message_instruction") or "").strip()
        b.internal_distribution = internal_distribution
        b.refers_classified_message = True if request.form.get("refers_classified_message") == "on" else False
        b.drafter_name = (request.form.get("drafter_name") or current_user.full_name or b.drafter_name or "").strip().upper()
        b.drafter_rank = (request.form.get("drafter_rank") or current_user.rank or b.drafter_rank or "").strip()
        b.releasing_officer_name = (request.form.get("releasing_officer_name") or current_user.full_name or b.releasing_officer_name or "").strip().upper()
        b.releasing_signature_rank = (request.form.get("releasing_signature_rank") or current_user.rank or b.releasing_signature_rank or "").strip()
        from_unit_raw = request.form.get("from_unit_id") or ""
        if str(from_unit_raw).isdigit():
            b.from_unit_id = int(from_unit_raw)
            fu = Unit.query.get(b.from_unit_id)
            b.msg_from = (fu.code or fu.name) if fu else b.msg_from
        b.set_csv_ids("action_units_csv", action_unit_ids)
        b.set_csv_ids("info_units_csv", info_unit_ids)
        b.set_csv_ids("action_users_csv", _channel_member_ids(selected_channel) if selected_channel else [])
        b.set_csv_ids("info_users_csv", [])
        b.set_body(body)

        _reset_release_state_for_edit(b)
        now = datetime.utcnow()
        if action == "draft":
            b.status = "DRAFT"
            b.submitted_at = None
            msg = "Signal saved as editable draft. It is not released and cannot be printed/downloaded until signed."
        else:
            if _is_unit_internal_workflow_required(current_user):
                if not is_unit_chief_clerk(current_user):
                    flash("Only the Chief Clerk can edit and resubmit a returned unit signal.", "danger")
                    return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))
                ao = b.unit_ao or _first_unit_officer(b.from_unit_id or current_user.unit_id, "ADMIN_OFFICER")
                commander = b.unit_commander or _first_unit_officer(b.from_unit_id or current_user.unit_id, "COMMANDER")
                if not ao:
                    flash("Create an Admin Officer / Unit AO before forwarding this signal for review.", "danger")
                    return redirect(url_for("admin.unit_officers"))
                b.unit_ao_id = getattr(ao, "id", None) or b.unit_ao_id
                b.unit_commander_id = getattr(commander, "id", None) or b.unit_commander_id
                b.status = "FORWARDED_TO_AO"
                b.current_handler_id = b.unit_ao_id
                b.routed_to_ao_at = now
                msg = "Signal updated and forwarded to AO for review."
            else:
                b.status = "SUBMITTED"
                msg = "Signal updated and submitted for fresh sign-and-release."
            b.submitted_at = now
            b.recalled_at = None
            b.recalled_by_id = None
            b.recall_reason = None

        files = [f for f in request.files.getlist("attachments") if f and getattr(f, "filename", "")]
        if files:
            _save_broadcast_attachments(files, b.id)
            log_event(current_user.id, "BROADCAST_EDIT_ATTACHMENTS_ADDED", f"{b.id}:{len(files)}")

        db.session.commit()
        log_event(current_user.id, "SIGNAL_EDITED_AFTER_RECALL_OR_DRAFT", {
            "target_module": "Signals/Broadcasts",
            "target_id": b.id,
            "signal_ref": b.originator_number or b.file_reference,
            "old_status": old_status,
            "new_status": b.status,
            "was_recalled": bool(was_recalled),
            "status": "SUCCESS",
        })
        flash(msg, "success")
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))

    return render_template(
        "messaging/broadcast_edit.html",
        b=b,
        body_text=_sanitize_rich_text(b.get_body()),
        units=units,
        channels=channels,
        classification_choices=CLASSIFICATION_CHOICES,
        rank_options=RANK_OPTIONS,
        action_unit_ids=set(b.csv_ids("action_units_csv")),
        info_unit_ids=set(b.csv_ids("info_units_csv")),
        internal_distribution_clean=internal_clean,
        info_route_display=info_route_display,
    )



def _can_act_as_unit_ao(user, b: Broadcast) -> bool:
    if getattr(user, "role", "") in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        return True
    if getattr(user, "id", None) == getattr(b, "unit_ao_id", None):
        return True
    return getattr(user, "unit_id", None) == getattr(b, "from_unit_id", None) and normalize_unit_appointment(getattr(user, "appointment", None)) == "ADMIN_OFFICER"


def _can_act_as_unit_signatory(user, b: Broadcast) -> bool:
    if getattr(user, "role", "") in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        return True
    # Once AO selects a signatory, only that selected handler can endorse.
    # AO must use the AO Sign/Endorse path instead of bypassing a forwarded
    # signal after routing it to someone else.
    return (
        getattr(user, "id", None) == getattr(b, "unit_signatory_id", None)
        and getattr(user, "id", None) == getattr(b, "current_handler_id", None)
        and normalize_unit_appointment(getattr(user, "appointment", None)) in {"SIGNATORY_OFFICER", "ADMIN_OFFICER"}
    )


def _can_act_as_unit_commander(user, b: Broadcast) -> bool:
    if getattr(user, "role", "") in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        return True
    if getattr(user, "id", None) == getattr(b, "unit_commander_id", None):
        return True
    return getattr(user, "unit_id", None) == getattr(b, "from_unit_id", None) and (normalize_unit_appointment(getattr(user, "appointment", None)) == "COMMANDER" or getattr(user, "role", "") == Role.COMMANDER.value)


@bp.post("/broadcasts/<int:broadcast_id>/unit-workflow")
@login_required
def broadcast_unit_workflow(broadcast_id):
    b = Broadcast.query.get_or_404(broadcast_id)
    if not _can_open_signal(current_user, b):
        abort(403)
    if _is_recalled_signal(b):
        flash("Recalled signals must be edited and resubmitted before unit routing continues.", "warning")
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))

    action = (request.form.get("unit_workflow_action") or "").strip().lower()
    reason = (request.form.get("reason") or "").strip()
    review_note = (request.form.get("review_note") or "").strip()
    now = datetime.utcnow()
    old_status = (b.status or "").upper()

    if action == "ao_return":
        if not _can_act_as_unit_ao(current_user, b) or old_status not in {"FORWARDED_TO_AO", "RETURNED_BY_AO"}:
            abort(403)
        b.status = "RETURNED_BY_AO"
        b.returned_at = now
        b.returned_by_id = current_user.id
        b.return_reason = reason or "Returned by AO for correction."
        b.current_handler_id = b.issuer_id
        _reset_release_state_for_edit(b)
        msg = "Signal returned to drafter for correction."

    elif action in {"ao_sign_commander", "ao_approve_commander"}:
        # Corrected Phase 4: AO is not merely approving here. This path means
        # the AO is also the signatory for the signal. The AO endorses/signs
        # the internal unit draft, then the Commander becomes the mandatory
        # final approver before external release.
        if not _can_act_as_unit_ao(current_user, b) or old_status not in {"FORWARDED_TO_AO", "RETURNED_BY_AO", "APPROVED_BY_AO"}:
            abort(403)
        commander = b.unit_commander or _first_unit_officer(b.from_unit_id or current_user.unit_id, "COMMANDER")
        if not commander:
            flash("No Commander account exists in this unit. Add a Commander before final approval.", "danger")
            return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))
        b.unit_ao_id = b.unit_ao_id or current_user.id
        b.unit_signatory_id = current_user.id
        b.unit_commander_id = commander.id
        b.status = "PENDING_COMMANDER_APPROVAL"
        b.ao_reviewed_at = now
        b.approved_at = now
        b.approved_by_id = current_user.id
        b.signatory_signed_at = now
        b.routed_to_commander_at = now
        b.current_handler_id = commander.id
        b.return_reason = None
        msg = "AO reviewed and signed. Signal forwarded to Commander for final approval."

    elif action == "ao_forward_signatory":
        if not _can_act_as_unit_ao(current_user, b) or old_status not in {"FORWARDED_TO_AO", "RETURNED_BY_AO", "APPROVED_BY_AO"}:
            abort(403)
        signatory_id = request.form.get("signatory_id") or b.unit_signatory_id
        signatory = User.query.get(int(signatory_id)) if str(signatory_id or "").isdigit() else None
        if not signatory or signatory.unit_id != (b.from_unit_id or current_user.unit_id):
            flash("Select a valid signatory officer in this unit.", "danger")
            return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))
        b.unit_ao_id = b.unit_ao_id or current_user.id
        b.unit_signatory_id = signatory.id
        b.status = "FORWARDED_TO_SIGNATORY"
        b.ao_reviewed_at = now
        b.approved_at = now
        b.approved_by_id = current_user.id
        b.routed_to_signatory_at = now
        b.current_handler_id = signatory.id
        b.return_reason = None
        msg = "AO approved. Signal forwarded to selected signatory officer."

    elif action == "signatory_return":
        if not _can_act_as_unit_signatory(current_user, b) or old_status != "FORWARDED_TO_SIGNATORY":
            abort(403)
        b.status = "RETURNED_BY_AO"
        b.returned_at = now
        b.returned_by_id = current_user.id
        b.return_reason = reason or "Returned by signatory for correction."
        b.current_handler_id = b.unit_ao_id or b.issuer_id
        _reset_release_state_for_edit(b)
        msg = "Signal returned for AO/drafter correction."

    elif action == "signatory_signed":
        if not _can_act_as_unit_signatory(current_user, b) or old_status != "FORWARDED_TO_SIGNATORY":
            abort(403)
        commander = b.unit_commander or _first_unit_officer(b.from_unit_id or current_user.unit_id, "COMMANDER")
        if not commander:
            flash("No Commander account exists in this unit. Add a Commander before final approval.", "danger")
            return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))
        b.unit_signatory_id = current_user.id
        b.unit_commander_id = commander.id
        b.status = "PENDING_COMMANDER_APPROVAL"
        b.signatory_signed_at = now
        b.routed_to_commander_at = now
        b.current_handler_id = commander.id
        msg = "Signatory signed/endorsed. Signal forwarded to Commander for final approval."

    elif action == "commander_return":
        if not _can_act_as_unit_commander(current_user, b) or old_status not in {"PENDING_COMMANDER_APPROVAL", "APPROVED_BY_COMMANDER"}:
            abort(403)
        b.status = "RETURNED_BY_COMMANDER"
        b.returned_at = now
        b.returned_by_id = current_user.id
        b.return_reason = reason or "Returned by Commander for correction."
        # Returned commander signals go back to the Chief Clerk/drafter for
        # actual correction, while AO still sees the history in Unit Workflow.
        b.current_handler_id = b.issuer_id
        _reset_release_state_for_edit(b)
        msg = "Signal returned by Commander to Chief Clerk for correction."

    elif action == "commander_approve":
        if not _can_act_as_unit_commander(current_user, b) or old_status not in {"PENDING_COMMANDER_APPROVAL", "APPROVED_BY_COMMANDER"}:
            abort(403)
        b.unit_commander_id = current_user.id
        b.status = "APPROVED_BY_COMMANDER"
        b.commander_approved_at = now
        b.approved_at = now
        b.approved_by_id = current_user.id
        b.current_handler_id = current_user.id
        b.return_reason = None
        msg = "Commander approved. Signal is ready for final digital Sign & Release."

    else:
        flash("Unknown unit workflow action.", "danger")
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))

    db.session.commit()
    specific_audit_action = {
        "ao_return": "UNIT_SIGNAL_RETURNED_BY_AO",
        "ao_sign_commander": "UNIT_SIGNAL_SIGNED_BY_AO",
        "ao_approve_commander": "UNIT_SIGNAL_SIGNED_BY_AO",
        "ao_forward_signatory": "UNIT_SIGNAL_FORWARDED_TO_SIGNATORY",
        "signatory_return": "UNIT_SIGNAL_RETURNED_BY_SIGNATORY",
        "signatory_signed": "UNIT_SIGNAL_SIGNED_BY_SIGNATORY",
        "commander_return": "UNIT_SIGNAL_RETURNED_BY_COMMANDER",
        "commander_approve": "UNIT_SIGNAL_APPROVED_BY_COMMANDER",
    }.get(action, "UNIT_SIGNAL_WORKFLOW_ACTION")
    audit_payload = {
        "target_module": "Signals/Broadcasts",
        "target_id": b.id,
        "unit_id": b.from_unit_id,
        "signal_ref": b.originator_number or b.file_reference,
        "old_status": old_status,
        "new_status": b.status,
        "action": action,
        "review_note": review_note[:500] if review_note else None,
        "return_reason": reason[:500] if reason else None,
        "status": "SUCCESS",
    }
    log_event(current_user.id, specific_audit_action, audit_payload)
    if specific_audit_action != "UNIT_SIGNAL_WORKFLOW_ACTION":
        log_event(current_user.id, "UNIT_SIGNAL_WORKFLOW_ACTION", audit_payload)
    _notify_current_handler(b, "Signal workflow updated", f"{b.originator_number or b.id} · {UNIT_WORKFLOW_LABELS.get(b.status, b.status)}")
    flash(msg, "success")
    return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))


@bp.post("/broadcasts/<int:broadcast_id>/sign")
@login_required
def broadcast_sign(broadcast_id):
    b = Broadcast.query.get_or_404(broadcast_id)
    if not _can_open_signal(current_user, b):
        abort(403)
    if _broadcast_requires_unit_workflow(b):
        ready, reason = _unit_workflow_release_ready(b)
        if not ready:
            flash(reason, "danger")
            return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))
    if not _can_sign_broadcast(current_user, b):
        abort(403)
    if _block_recalled_signal_action(b, "Sign and release"):
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))
    if (b.status or "").upper() == "RELEASED" and b.digital_signature and _verify_broadcast_signature(b):
        flash("This signal is already signed and released. Use correction/recall workflow instead of re-signing it.", "warning")
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))

    signer_name = (request.form.get("signer_name") or "").strip()
    password = request.form.get("password") or ""
    signature_pad_data = (request.form.get("signature_pad_data") or "").strip()

    if not signer_name or signer_name.casefold() != (current_user.full_name or "").strip().casefold():
        flash("Enter your full account name exactly to sign and release the signal.", "danger")
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))
    if not current_user.check_password(password):
        flash("Password confirmation failed. Signal was not signed or released.", "danger")
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))
    if not signature_pad_data:
        flash("Draw your release signature with mouse, touch, or stylus before signing the signal.", "danger")
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))

    now = datetime.utcnow()
    _prepare_release_authority(b, current_user, now)
    b.releasing_officer_name = current_user.full_name.upper()
    b.releasing_signature_rank = current_user.rank or b.releasing_signature_rank
    try:
        saved_signature = _save_drawn_signature_image(b, signature_pad_data)
        if saved_signature:
            log_event(current_user.id, "DRAWN_RELEASE_SIGNATURE_CAPTURED", f"{b.id}:{saved_signature}")
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))
    _sign_broadcast(b, signer_id=current_user.id, signed_at=now)
    db.session.commit()

    _deliver_released_broadcast(b, current_user, now)
    if _broadcast_requires_unit_workflow(b):
        log_event(current_user.id, "UNIT_SIGNAL_RELEASED_BY_COMMANDER", {
            "target_id": b.id,
            "unit_id": b.from_unit_id,
            "signal_ref": b.originator_number or b.file_reference,
            "fingerprint": b.signature_fingerprint,
            "status": "SUCCESS",
        })
    log_event(current_user.id, "BROADCAST_SIGNED_RELEASED", f"{b.id}:{b.originator_number or ''}:{b.signature_fingerprint or ''}")
    flash("Signal digitally signed, released, delivered, and archived successfully.", "success")
    return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))


def _archive_folder() -> str:
    folder = current_app.config.get("SIGNAL_ARCHIVE_FOLDER")
    if not folder:
        folder = os.path.join(current_app.instance_path, "signal_bank")
        os.makedirs(folder, exist_ok=True)
        current_app.config["SIGNAL_ARCHIVE_FOLDER"] = folder
    return folder


def _pdf_password_required(classification: str | None) -> bool:
    """Require open-password protection for sensitive classified signal exports."""
    c = (classification or "").upper().replace(" ", "_")
    return c in {ClassificationLevel.SECRET.value, ClassificationLevel.TOP_SECRET.value, "SECRET", "TOP_SECRET", "TOP SECRET"}


def _suggest_pdf_password(b: Broadcast, export_id: str | None = None) -> str:
    """Suggest a strong password that the exporting user can copy before download.

    The password is not stored and is not written to audit logs.
    """
    alphabet = string.ascii_uppercase + string.digits
    random_tail = ''.join(secrets.choice(alphabet) for _ in range(8))
    unit_part = (getattr(b, "msg_from", None) or getattr(b, "from_unit_text", None) or "NAF").upper()
    unit_part = ''.join(ch for ch in unit_part if ch.isalnum())[:8] or "NAF"
    class_part = (getattr(b, "security_classification", None) or "SIG").upper().replace(" ", "")[:6]
    sig_part = str(getattr(b, "id", "0"))
    return f"{unit_part}-{class_part}-{sig_part}-{random_tail}"


def _resolve_pdf_export_password(b: Broadcast, require_password: bool):
    """Return (password, error_message). Password may be None only when optional and explicitly skipped."""
    mode = (request.form.get("password_mode") or request.args.get("password_mode") or "manual").strip().lower()
    skip = (request.form.get("skip_password") == "on" or request.args.get("skip_password") == "1")
    if skip and not require_password:
        return None, None
    if mode == "auto":
        password = (request.form.get("suggested_password") or request.args.get("suggested_password") or "").strip()
        if not password:
            password = _suggest_pdf_password(b)
    else:
        password = (request.form.get("pdf_password") or request.args.get("pdf_password") or "").strip()
    if require_password and not password:
        return None, "PDF password is required for this signal classification."
    if password and len(password) < 8:
        return None, "PDF password must be at least 8 characters."
    return password or None, None

def _archive_filename(b: Broadcast) -> str:
    sig = (b.originator_number or f"signal_{b.id}").replace("/", "-").replace(" ", "_")
    return f"{sig}.pdf"

def _signal_archive_record(b: Broadcast):
    return SignalArchive.query.filter_by(broadcast_id=b.id).first()

def _build_broadcast_pdf_bytes(b: Broadcast, watermark_context: dict | None = None, pdf_password: str | None = None) -> bytes:
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.pdfgen import canvas as rlcanvas
    from reportlab.lib.pdfencrypt import StandardEncryption

    body_html = _signal_print_body_html(b.get_body())
    attachment_block = _broadcast_attachment_print_block(b)
    if attachment_block:
        body_html = (body_html or "") + attachment_block
    export_time = None
    try:
        export_time = watermark_context.get("event_time") if watermark_context else None
    except Exception:
        export_time = None
    form_ctx = _message_form_context(b, time_out=export_time or datetime.utcnow())
    row = form_ctx["rows"][0]

    # Download/export watermark context is user-specific.
    # The archive copy can remain clean internally, but any PDF that leaves
    # the system through preview/download/export should carry forensic details.
    wm = watermark_context or {}

    class PageNumCanvas(rlcanvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_page_states = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            # Include the final page state before calculating totals. Without
            # this, the PDF engine can reuse the last page number for every page.
            self._saved_page_states.append(dict(self.__dict__))
            total = len(self._saved_page_states) or 1
            states = self._saved_page_states
            for index, state in enumerate(states, start=1):
                self.__dict__.update(state)

                # IMPORTANT: ReportLab canvas callbacks normally draw after the
                # story content, which made the exported/downloaded watermark
                # sit on top of the official signal text. To match the browser
                # print preview, the watermark commands are inserted BEFORE the
                # existing page content commands, so it becomes a faint
                # background layer. The footer trace remains on top in the
                # bottom margin only.
                page_content_code = list(getattr(self, "_code", []) or [])
                self._code = []
                self._draw_watermark(index, total)
                watermark_code = list(getattr(self, "_code", []) or [])
                self._code = watermark_code + page_content_code

                self._draw_footer(index, total)
                super().showPage()
            super().save()

        def _draw_watermark(self, page_num, page_total):
            if not wm:
                return
            page_w, page_h = A4
            printed_by = str(wm.get("printed_by") or wm.get("exported_by") or "")
            trace_id = str(wm.get("trace_id") or wm.get("export_id") or "")
            classification = str(wm.get("classification") or row.get("security_classification") or "RESTRICTED")
            timestamp = str(wm.get("timestamp") or "")
            line = f"{printed_by}  •  {classification}  •  {trace_id}".strip()
            small = f"Downloaded by: {printed_by} | {timestamp} | {trace_id} | Page {page_num} of {page_total}"

            # Match browser print-preview watermark: very faint, light grey,
            # not bold, and rendered as a background layer. Do not rely only
            # on PDF alpha because some PDF viewers/rasterizers darken alpha
            # text; use an already-light colour plus low alpha where supported.
            self.saveState()
            try:
                self.setFillAlpha(0.18)
            except Exception:
                pass
            self.setFillColor(colors.HexColor("#ECEFF3"))
            self.setFont("Helvetica", 7.2)
            self.translate(page_w / 2, page_h * 0.44)
            self.rotate(28)
            self.drawCentredString(0, 0, line[:105])
            self.restoreState()

            self.saveState()
            try:
                self.setFillAlpha(0.64)
            except Exception:
                pass
            self.setFillColor(colors.HexColor("#64748B"))
            self.setFont("Helvetica", 5.2)
            # Strategic trace line in the bottom margin only; never over signal text.
            self.drawString(8 * mm, 4.2 * mm, small[:165])
            self.restoreState()

        def _draw_footer(self, page_num, page_total):
            page_w, page_h = A4
            left = 7 * mm
            width = page_w - (14 * mm)
            bottom = 7 * mm
            row_h = [7 * mm, 10 * mm, 7 * mm]
            col_w = [width / 4.0] * 4
            y = bottom + sum(row_h)
            self.setStrokeColor(colors.black)
            self.setLineWidth(0.8)
            # Row 1
            self.rect(left, y - row_h[0], col_w[0], row_h[0])
            self.rect(left + col_w[0], y - row_h[0], col_w[1], row_h[0])
            self.rect(left + col_w[0] + col_w[1], y - row_h[0], col_w[2], row_h[0])
            self.rect(left + col_w[0] + col_w[1] + col_w[2], y - row_h[0], col_w[3], row_h[0])
            self.setFont("Helvetica-Bold", 7.8)
            self.drawString(left + 3, y - 9, "INTERNAL DISTRIBUTION")
            self.drawString(left + col_w[0] + col_w[1] + 3, y - 9, "FILE NUMBER OR REFERENCE")
            self.setFont("Helvetica", 7.8)
            self.drawString(left + col_w[0] + 3, y - 9, str(row['internal_distribution']))
            self.drawString(left + col_w[0] + col_w[1] + col_w[2] + 3, y - 9, str(row['file_reference']))
            # Row 2
            y2 = y - row_h[0]
            self.rect(left, y2 - row_h[1], col_w[0] + col_w[1], row_h[1])
            self.rect(left + col_w[0] + col_w[1], y2 - row_h[1], col_w[2] + col_w[3], row_h[1])
            self.setFont("Helvetica", 7.2)
            self.drawString(left + 3, y2 - 8, f"{'☒' if row['refers_classified_message'] else '☐'} Refers to a classified Message (tick appropriate box)")
            self.drawString(left + 3, y2 - 18, f"{'☒' if row['does_not_refer_classified_message'] else '☐'} Does not refer to a classified Message")
            self.drawString(left + col_w[0] + col_w[1] + 3, y2 - 8, f"Page {page_num}")
            self.drawString(left + col_w[0] + col_w[1] + 3, y2 - 18, f"Of {page_total} Page")
            # Row 3
            y3 = y2 - row_h[1]
            labels = [
                ("Comms/Gen Serial No", row['comms_gen_serial_no']),
                ("Sender-Receiver OP", row['sender_receiver_op']),
                ("System", row['transmission_system']),
                ("Time-In/Out", row['time_in_out']),
            ]
            x = left
            for idx, (lab, val_) in enumerate(labels):
                self.rect(x, y3 - row_h[2], col_w[idx], row_h[2])
                self.setFont("Helvetica-Bold", 7.4)
                self.drawString(x + 3, y3 - 8, lab)
                self.setFont("Helvetica", 7.2)
                text_value = str(val_ or "")
                if lab == "Time-In/Out":
                    parts = [p for p in text_value.replace("\r", "").split("\n") if p.strip()]
                    self.drawString(x + 3, y3 - 16, parts[0] if parts else "AUTO")
                    if len(parts) > 1:
                        self.drawString(x + 3, y3 - 24, parts[1])
                else:
                    self.drawString(x + 3, y3 - 16, text_value[:45])
                x += col_w[idx]

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="PrintBody", fontName="Helvetica", fontSize=8.8, leading=10.4, splitLongWords=True, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="PrintLabel", fontName="Helvetica-Bold", fontSize=8.8, leading=10.2, splitLongWords=True, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="Hdr", fontName="Helvetica-Bold", fontSize=12.3, alignment=1, leading=13.0, splitLongWords=True, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="CenterLabel", fontName="Helvetica-Bold", fontSize=8.8, alignment=2, leading=10.2, splitLongWords=True, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="Small", parent=styles["Normal"], fontName="Helvetica", fontSize=8.0, leading=9.6, splitLongWords=True, wordWrap="CJK"))

    def val(v):
        text = _normalize_nbsp_text(v or "")
        return bleach.clean(text, tags=[], strip=True).upper().replace("\n", "<br/>") or " "

    def P(v, style="PrintBody"):
        return Paragraph(_normalize_nbsp_text(v or " "), styles[style])

    def labeled(label, value=""):
        html = f"<b>{label}</b>"
        if value:
            html += f"<br/><br/>{val(value)}"
        return P(html)

    box_style = [
        ("BOX", (0,0), (-1,-1), 1, colors.black),
        ("INNERGRID", (0,0), (-1,-1), 0.75, colors.black),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]

    buf = BytesIO()
    pdf_encrypt = None
    if pdf_password:
        pdf_encrypt = StandardEncryption(
            pdf_password,
            ownerPassword=secrets.token_urlsafe(18),
            canPrint=1,
            canModify=0,
            canCopy=0,
            canAnnotate=0,
            strength=128,
        )
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=7*mm, rightMargin=7*mm, topMargin=7*mm, bottomMargin=38*mm, title=f"SIGNAL - {str(b.title or '').upper()}", encrypt=pdf_encrypt)
    story = [Paragraph("NAF MESSAGE FORM", styles["Hdr"]), Spacer(1, 4)]

    drafter = Table([[P("DRAFTER’S NAME IN<br/>BLOCK LETTERS", "CenterLabel")], [P(val(row['drafter_name']), "CenterLabel")]], colWidths=[190*mm], rowHeights=[8*mm, 10*mm])
    drafter.setStyle(TableStyle(box_style + [("ALIGN", (0,0), (-1,-1), "RIGHT"), ("RIGHTPADDING", (0,0), (-1,-1), 12), ("VALIGN", (0,0), (-1,-1), "TOP")]))
    story.extend([drafter, Spacer(1, 2)])

    merged_mid = (
        f"<b>From:</b> {val(row['from_unit_text'] or row['from'])}<br/><br/>"
        f"<b>To:</b> {val(row['to'])}" +
        (("<br/>" + "<br/>".join(val(x) for x in row['action_lines'])) if row['action_lines'] else "") +
        ((f"<br/><br/><b>Info:</b><br/>" + "<br/>".join(val(x) for x in row['info_lines'])) if row['info_lines'] else "")
    )
    sec_text = "<b>SECURITY CLASSIFICATION</b><br/><font size='7'>(MESSAGE REFERRING TO A CLASSIFIED MESSAGE MUST BE CLASSIFIED RESTRICTED OR ABOVE)</font><br/>" + val(row['security_classification'])
    main_rows = [
        [labeled("PRECEDENCE ACTION", row['precedence_action']), P(merged_mid), labeled("BRANCH OFFICE", row['branch_office'])],
        [labeled("PRECEDENCE INFO", row['precedence_info']), "", labeled("TELEPHONE NUMBER.", row['telephone'])],
        [labeled("DATE TIME GROUP MONTH", row['dtg']), P("&nbsp;"), labeled("RELEASING OFFICER’S<br/>SIGNATURE AND RANK", row['releasing_signature_rank'])],
        [labeled("MESSAGE INSTRUCTION"), P("&nbsp;"), labeled("NAME OF RELEASING OFFICER", row['releasing_officer_name'])],
        [P(sec_text), P("&nbsp;"), labeled("DIG SERIAL NO<br/>(IF USED)<br/>(ORIGINATOR’S NUMBER)", row['originator_number'])],
    ]
    main = Table(main_rows, colWidths=[57*mm, 76*mm, 57*mm], rowHeights=[26*mm, 18*mm, 20*mm, 20*mm, 23*mm])
    main.setStyle(TableStyle(box_style + [("SPAN", (1,0), (1,1)), ("LINEBELOW", (1,0), (1,0), 0, colors.white), ("LINEABOVE", (1,1), (1,1), 0, colors.white), ("LINEABOVE", (1,2), (1,4), 0, colors.white), ("LINEBELOW", (1,2), (1,4), 0, colors.white)]))
    story.extend([main, Spacer(1, 2)])

    text_header = Table([[P("<b>TEXT:</b>")]], colWidths=[190*mm])
    text_header.setStyle(TableStyle(box_style + [("BOTTOMPADDING", (0,0), (0,0), 3)]))
    story.append(text_header)
    body_flow = _rich_html_to_pdf_flowables(body_html, styles, Paragraph, Spacer, Table, TableStyle, colors)
    if not body_flow:
        body_flow = [P("&nbsp;")]
    # Let long body content split naturally across pages; wrapping it in a
    # KeepTogether/Table causes LayoutError for multi-page signals.
    story.extend(body_flow)

    doc.build(story, canvasmaker=PageNumCanvas)
    return buf.getvalue()


def _ensure_signal_archive(b: Broadcast):
    if b.status != "RELEASED" or _is_recalled_signal(b):
        return None
    if not (b.digital_signature and b.signed_at and b.signed_by_id and _verify_broadcast_signature(b)):
        current_app.logger.warning("Refusing to archive unsigned/unverified released signal %s", b.id)
        return None
    if not b.originator_number:
        b.originator_number = _originator_for(b)
    folder = _archive_folder()
    rec = _signal_archive_record(b)
    file_name = _archive_filename(b)
    path = os.path.join(folder, file_name)
    try:
        export_time = datetime.utcnow()
        export_id = f"NMS-ARCHIVE-{b.id}-{export_time.strftime('%Y%m%d%H%M%S')}"
        try:
            # Archive must use the same HTML print engine as browser preview and
            # downloaded PDFs so the Signal Bank file never drifts from print view.
            pdf_bytes = _build_broadcast_pdf_from_print_html(b, export_time, export_id, pdf_password=None)
        except Exception:
            current_app.logger.exception("HTML archive PDF generation failed for broadcast %s; falling back to legacy ReportLab renderer", b.id)
            pdf_bytes = _build_broadcast_pdf_bytes(b)
        with open(path, "wb") as f:
            f.write(pdf_bytes)
    except Exception:
        current_app.logger.exception("Signal archive PDF generation failed for broadcast %s", b.id)
        db.session.rollback()
        return rec
    if not rec:
        rec = SignalArchive(broadcast_id=b.id, file_name=file_name, title=b.title, signal_number=b.originator_number, classification=b.security_classification, priority=b.priority, from_unit_text=_from_unit_text(b), created_at=b.released_at or b.created_at)
        db.session.add(rec)
    else:
        rec.file_name = file_name
        rec.title = b.title
        rec.signal_number = b.originator_number
        rec.classification = b.security_classification
        rec.priority = b.priority
        rec.from_unit_text = _from_unit_text(b)
    if os.path.exists(path):
        checksum = _checksum_file(path)
        rec.integrity_status = "VERIFIED" if _verify_broadcast_signature(b) else "SIGNATURE_ERROR"
        rec.sha256 = checksum
        rec.signature_hash = hmac.new(_signature_secret(), checksum.encode("utf-8"), hashlib.sha256).hexdigest()
        rec.verified_at = datetime.utcnow()
    db.session.commit()
    return rec



def _signature_image_data_uri(b: Broadcast) -> str:
    """Embed release signature image into exported print HTML so headless PDF uses the same view offline."""
    filename = getattr(b, "releasing_signature_image", None)
    if not filename:
        return ""
    try:
        import base64
        import mimetypes
        path = os.path.join(current_app.config.get("UPLOAD_FOLDER"), filename)
        if not os.path.exists(path):
            return ""
        mime = mimetypes.guess_type(path)[0] or "image/png"
        with open(path, "rb") as f:
            encoded = base64.b64encode(f.read()).decode("ascii")
        return f"data:{mime};base64,{encoded}"
    except Exception:
        current_app.logger.exception("Unable to embed broadcast signature image for PDF export")
        return ""


def _broadcast_print_context(b: Broadcast, event_time: datetime | None = None, print_id: str | None = None) -> dict:
    """Build the single official print context used by both browser preview and PDF download.

    This is the source of truth for page chunks, footer page count, TO/INFO display,
    attachment summary, tables, and drafter/releasing details. PDF download must not
    rebuild the signal through ReportLab/manual layout because that creates a different
    document from the perfected browser print preview.
    """
    event_time = event_time or datetime.utcnow()
    body_text = _signal_print_body_html(b.get_body())
    attachment_block = _broadcast_attachment_print_block(b)
    if attachment_block:
        body_text = (body_text or "") + attachment_block

    form_ctx = _message_form_context(b, time_out=event_time)
    body_pages = _paginate_signal_html(body_text, first_page_chars=3000, continuation_chars=5200)
    # Remove truly empty pages so download cannot produce a footer-only final page.
    body_pages = [p for p in body_pages if bleach.clean(str(p or ""), tags=[], strip=True).replace("\xa0", " ").strip()]
    if not body_pages:
        body_pages = [""]

    total_pages = max(1, len(body_pages))
    row = form_ctx["rows"][0]
    row["time_in"] = _format_signal_created_time(b)
    row["time_out"] = _format_signal_out_time(event_time)
    row["time_in_out"] = f"IN: {row['time_in']}\nOUT: {row['time_out']}"
    row["releasing_signature_image_data"] = _signature_image_data_uri(b)

    print_pages = []
    for idx, body_html in enumerate(body_pages, start=1):
        page_row = dict(row)
        page_row["page_label"] = str(idx)
        page_row["page_total"] = str(total_pages)
        page_row["body_html"] = body_html
        page_row["is_first_page"] = (idx == 1)
        print_pages.append(page_row)
    form_ctx["print_pages"] = print_pages
    return {
        "b": b,
        "body_text": body_text,
        "form_ctx": form_ctx,
        "audit_print_id": print_id or f"NMS-PRINT-{b.id}-{event_time.strftime('%Y%m%d%H%M%S')}",
        "page_total": total_pages,
    }


def _render_broadcast_print_html(b: Broadcast, event_time: datetime | None = None, print_id: str | None = None, *, preview_mode: bool = False, export_mode: bool = False) -> str:
    ctx = _broadcast_print_context(b, event_time=event_time, print_id=print_id)
    return render_template(
        "messaging/broadcast_print.html",
        b=ctx["b"],
        body_text=ctx["body_text"],
        form_ctx=ctx["form_ctx"],
        preview_mode=preview_mode,
        export_mode=export_mode,
        audit_print_id=ctx["audit_print_id"],
    )


def _find_headless_chromium() -> str | None:
    """Find Chrome/Edge for exact HTML-to-PDF rendering on Windows/Linux/macOS."""
    import shutil
    candidates = [
        os.environ.get("NMS_CHROME_PATH"),
        os.environ.get("CHROME_PATH"),
        os.environ.get("EDGE_PATH"),
        shutil.which("chrome"),
        shutil.which("google-chrome"),
        shutil.which("google-chrome-stable"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
        shutil.which("msedge"),
        shutil.which("microsoft-edge"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def _encrypt_pdf_bytes(pdf_bytes: bytes, password: str | None) -> bytes:
    if not password:
        return pdf_bytes
    from io import BytesIO
    try:
        from pypdf import PdfReader, PdfWriter
    except Exception as exc:
        raise ImportError("PDF password protection requires 'pypdf'. Install it with: pip install pypdf") from exc
    reader = PdfReader(BytesIO(pdf_bytes))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.encrypt(user_password=password, owner_password=secrets.token_urlsafe(18))
    out = BytesIO()
    writer.write(out)
    return out.getvalue()


def _build_broadcast_pdf_from_print_html(b: Broadcast, event_time: datetime, export_id: str, pdf_password: str | None = None) -> bytes:
    """Generate downloaded PDF from the exact same HTML/CSS as browser print preview."""
    import tempfile
    import subprocess
    from pathlib import Path

    chrome = _find_headless_chromium()
    if not chrome:
        raise RuntimeError("Chrome or Microsoft Edge was not found. Install Chrome/Edge or set NMS_CHROME_PATH so PDF download can match print preview exactly.")

    html = _render_broadcast_print_html(b, event_time=event_time, print_id=export_id, preview_mode=False, export_mode=True)
    with tempfile.TemporaryDirectory(prefix="nms_print_pdf_") as tmp:
        html_path = Path(tmp) / "signal_print.html"
        pdf_path = Path(tmp) / "signal_print.pdf"
        html_path.write_text(html, encoding="utf-8")
        cmd = [
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--print-to-pdf-no-header",
            f"--print-to-pdf={str(pdf_path)}",
            html_path.as_uri(),
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        if result.returncode != 0 or not pdf_path.exists() or pdf_path.stat().st_size < 500:
            err = (result.stderr or result.stdout or b"").decode("utf-8", "ignore")[:800]
            raise RuntimeError(f"Headless Chrome/Edge PDF generation failed: {err}")
        pdf_bytes = pdf_path.read_bytes()
    return _encrypt_pdf_bytes(pdf_bytes, pdf_password)


@bp.get("/broadcasts/<int:broadcast_id>/signature-image")
@login_required
def broadcast_signature_image(broadcast_id):
    b = Broadcast.query.get_or_404(broadcast_id)
    if not _can_open_signal(current_user, b):
        abort(403)
    if not getattr(b, "releasing_signature_image", None):
        abort(404)
    return send_from_directory(current_app.config.get("UPLOAD_FOLDER"), b.releasing_signature_image)

@bp.get("/broadcasts/<int:broadcast_id>/print")
@login_required
def broadcast_print(broadcast_id):
    """Print-friendly Signal/NAF form view for recipients.

    IMPORTANT: this route is the master visual layout. PDF download now renders
    this same HTML/CSS through headless Chrome/Edge so preview and download match.
    """
    b = Broadcast.query.get_or_404(broadcast_id)
    if not _can_open_signal(current_user, b):
        abort(403)
    if _block_recalled_signal_action(b, "Print/preview"):
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))
    if (b.status or "").upper() not in {"RELEASED", "ARCHIVED"}:
        flash("Official print preview is available only after the signal has been digitally signed and released.", "warning")
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))
    if not getattr(Settings.get(), "allow_signal_print", True):
        log_event(current_user.id, "SIGNAL_PRINT_BLOCKED_BY_POLICY", {"target_id": b.id, "classification": b.security_classification, "status": "BLOCKED"})
        flash("Signal printing is currently disabled by HQ security policy.", "warning")
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))

    print_time = datetime.utcnow()
    now_stamp = print_time.strftime("%Y%m%d%H%M%S")
    print_id = f"NMS-PRINT-{b.id}-{now_stamp}"
    page_total = _broadcast_print_context(b, event_time=print_time, print_id=print_id)["page_total"]
    preview_mode = (request.args.get("preview") == "1")

    log_event(current_user.id, "SIGNAL_PRINT_PREVIEW" if preview_mode else "SIGNAL_PRINTED", {
        "target_module": "Signals/Broadcasts",
        "target_id": b.id,
        "signal_ref": b.originator_number or b.file_reference or f"BCAST-{b.id}",
        "classification": b.security_classification,
        "priority": b.priority,
        "print_id": print_id,
        "pages": page_total,
        "status": "SUCCESS",
        "remarks": "Official NAF signal print preview opened" if preview_mode else "Official NAF signal printed/exported from browser",
    })
    return _render_broadcast_print_html(b, event_time=print_time, print_id=print_id, preview_mode=preview_mode, export_mode=False)



def _pdf_safe_text(value: str) -> str:
    text = str(value or "")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace(" ", " ")
    # Help ReportLab wrap extremely long tokens instead of creating giant cells.
    out = []
    run = 0
    for ch in text:
        out.append(ch)
        if ch in {" ", "\n", "\t", "-", "/", "_", ".", ",", ":", ";"}:
            run = 0
        else:
            run += 1
            if run >= 35:
                out.append("<wbr/>")
                run = 0
    return "".join(out).replace("\n", "<br/>")

def _rich_html_to_pdf_flowables(html: str, styles, Paragraph, Spacer, Table, TableStyle, colors):
    from bs4 import BeautifulSoup

    safe_html = _sanitize_rich_text(html or "")
    soup = BeautifulSoup(safe_html, "html.parser")
    flowables = []

    def inline_html(node):
        if isinstance(node, str):
            return _pdf_safe_text(node)
        if getattr(node, "name", None) in {"strong", "b"}:
            return f"<b>{''.join(inline_html(c) for c in node.children)}</b>"
        if getattr(node, "name", None) in {"em", "i"}:
            return f"<i>{''.join(inline_html(c) for c in node.children)}</i>"
        if getattr(node, "name", None) == "u":
            return f"<u>{''.join(inline_html(c) for c in node.children)}</u>"
        if getattr(node, "name", None) == "br":
            return "<br/>"
        return ''.join(inline_html(c) for c in getattr(node, 'children', []))

    for node in soup.contents:
        name = getattr(node, "name", None)
        if name in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            flowables.append(Paragraph(f"<b>{inline_html(node)}</b>", styles["Small"]))
            flowables.append(Spacer(1, 6))
        elif name == "p":
            flowables.append(Paragraph(inline_html(node) or "&nbsp;", styles["Small"]))
            flowables.append(Spacer(1, 4))
        elif name in {"ul", "ol"}:
            for idx, li in enumerate(node.find_all("li", recursive=False), start=1):
                bullet = "•" if name == "ul" else f"{idx}."
                flowables.append(Paragraph(f"{bullet} {inline_html(li)}", styles["Small"]))
            flowables.append(Spacer(1, 4))
        elif name == "table":
            rows = []
            for tr in node.find_all("tr"):
                cells = tr.find_all(["th", "td"], recursive=False)
                if not cells:
                    continue
                rows.append([Paragraph(inline_html(cell) or "&nbsp;", styles["Small"]) for cell in cells])
            if rows:
                col_count = max(len(r) for r in rows)
                for r in rows:
                    while len(r) < col_count:
                        r.append(Paragraph("&nbsp;", styles["Small"]))
                usable_width = 190 * 2.834645669291339
                col_widths = [usable_width / col_count] * col_count
                tbl = Table(rows, colWidths=col_widths, repeatRows=1, splitByRow=1)
                tbl.setStyle(TableStyle([
                    ("BOX", (0,0), (-1,-1), 0.8, colors.black),
                    ("INNERGRID", (0,0), (-1,-1), 0.5, colors.black),
                    ("VALIGN", (0,0), (-1,-1), "TOP"),
                    ("LEFTPADDING", (0,0), (-1,-1), 5),
                    ("RIGHTPADDING", (0,0), (-1,-1), 5),
                    ("TOPPADDING", (0,0), (-1,-1), 4),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ]))
                flowables.append(tbl)
                flowables.append(Spacer(1, 6))
        elif name == "blockquote":
            flowables.append(Paragraph(inline_html(node), styles["Small"]))
            flowables.append(Spacer(1, 4))
        elif name is None and str(node).strip():
            flowables.append(Paragraph(inline_html(node), styles["Small"]))
            flowables.append(Spacer(1, 4))
    return flowables or [Paragraph("&nbsp;", styles["Small"])]


@bp.route("/broadcasts/<int:broadcast_id>/print.pdf", methods=["GET", "POST"])
@login_required
def broadcast_print_pdf(broadcast_id):
    b = Broadcast.query.get_or_404(broadcast_id)
    if not _can_open_signal(current_user, b):
        abort(403)
    if _block_recalled_signal_action(b, "Download/export"):
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))
    if (b.status or "").upper() not in {"RELEASED", "ARCHIVED"}:
        flash("Protected PDF export is available only after the signal has been digitally signed and released.", "warning")
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))
    if not getattr(Settings.get(), "allow_signal_download", True):
        log_event(current_user.id, "SIGNAL_DOWNLOAD_BLOCKED_BY_POLICY", {"target_id": b.id, "classification": b.security_classification, "status": "BLOCKED"})
        flash("Signal download/export is currently disabled by HQ security policy.", "warning")
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))
    from io import BytesIO
    require_password = _pdf_password_required(b.security_classification)
    export_time = datetime.utcnow()
    now_stamp = export_time.strftime("%Y%m%d%H%M%S")
    export_id = f"NMS-EXPORT-{b.id}-{now_stamp}"
    if request.method == "GET":
        return render_template(
            "messaging/pdf_password.html",
            b=b,
            action_url=url_for("msg.broadcast_print_pdf", broadcast_id=b.id),
            require_password=require_password,
            suggested_password=_suggest_pdf_password(b, export_id),
            export_id=export_id,
        )
    pdf_password, err = _resolve_pdf_export_password(b, require_password)
    if err:
        flash(err, "warning")
        return render_template(
            "messaging/pdf_password.html",
            b=b,
            action_url=url_for("msg.broadcast_print_pdf", broadcast_id=b.id),
            require_password=require_password,
            suggested_password=_suggest_pdf_password(b, export_id),
            export_id=export_id,
        )
    try:
        pdf_bytes = _build_broadcast_pdf_from_print_html(b, export_time, export_id, pdf_password=pdf_password)
    except Exception as exc:
        current_app.logger.exception("HTML print-preview PDF generation failed for broadcast %s", b.id)
        flash(str(exc), "warning")
        return redirect(url_for("msg.broadcast_print", broadcast_id=broadcast_id, preview=1))
    log_event(current_user.id, "SIGNAL_PDF_DOWNLOADED", {
        "target_module": "Signals/Broadcasts",
        "target_id": b.id,
        "signal_ref": b.originator_number or b.file_reference or f"BCAST-{b.id}",
        "classification": b.security_classification,
        "priority": b.priority,
        "export_id": export_id,
        "password_protected": bool(pdf_password),
        "status": "SUCCESS",
        "remarks": "Watermarked official signal PDF downloaded with PDF open-password protection" if pdf_password else "Watermarked official signal PDF downloaded without PDF password",
    })
    suffix = "protected" if pdf_password else "watermarked"
    return send_file(BytesIO(pdf_bytes), mimetype="application/pdf", as_attachment=True, download_name=f"signal_{b.id}_{suffix}.pdf")



def _signal_event_counts(broadcast_ids):
    """Return print/download counts keyed by broadcast id without failing on old audit rows."""
    counts = {int(bid): {"prints": 0, "downloads": 0, "last_activity": None} for bid in broadcast_ids if bid is not None}
    if not counts:
        return counts
    # Small archive pages only: scan recent relevant audit events and match target_id safely.
    events = AuditEvent.query.filter(
        AuditEvent.action.in_(["SIGNAL_PRINT_PREVIEW", "SIGNAL_PRINTED", "SIGNAL_PDF_DOWNLOADED", "SIGNAL_ARCHIVE_DOWNLOADED", "SIGNAL_ARCHIVE_EXPORT"])
    ).order_by(AuditEvent.created_at.desc()).limit(3000).all()
    for ev in events:
        details = {}
        try:
            details = json.loads(ev.details or "{}")
            if not isinstance(details, dict):
                details = {}
        except Exception:
            details = {}
        target_id = details.get("target_id")
        try:
            target_id = int(target_id)
        except Exception:
            continue
        if target_id not in counts:
            continue
        if "PRINT" in (ev.action or ""):
            counts[target_id]["prints"] += 1
        if "DOWNLOAD" in (ev.action or "") or "EXPORT" in (ev.action or ""):
            counts[target_id]["downloads"] += 1
        if not counts[target_id]["last_activity"]:
            counts[target_id]["last_activity"] = ev.created_at
    return counts


def _archive_ack_summary(b: Broadcast):
    total = BroadcastReceipt.query.filter_by(broadcast_id=b.id).count()
    read = BroadcastReceipt.query.filter(BroadcastReceipt.broadcast_id == b.id, BroadcastReceipt.read_at.isnot(None)).count()
    acked = BroadcastAck.query.filter(BroadcastAck.broadcast_id == b.id, BroadcastAck.acked_at.isnot(None)).count()
    pending = max(total - acked, 0) if getattr(b, "requires_ack", False) else 0
    return {"total": total, "read": read, "acked": acked, "pending": pending}

@bp.get("/signal-bank")
@login_required
def signal_bank():
    q = (request.args.get("q") or "").strip()
    classification = (request.args.get("classification") or "").strip()
    priority = (request.args.get("priority") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    integrity = (request.args.get("integrity") or "").strip()
    status = (request.args.get("status") or "").strip()
    section = (request.args.get("section") or "released").strip().lower()
    unit_id = (request.args.get("unit_id") or "").strip()
    ack_filter = (request.args.get("ack") or "").strip()
    activity_filter = (request.args.get("activity") or "").strip()
    page = max(int(request.args.get("page") or 1), 1)
    per_page = 40

    # Ensure every released signal has a bank record before listing.
    # Recalled signals remain searchable through their existing records, but no new downloadable archive is created.
    released = Broadcast.query.filter_by(status="RELEASED").order_by(Broadcast.released_at.desc(), Broadcast.created_at.desc()).limit(500).all()
    for b in released:
        if can_view_signal_bank(current_user, b):
            try:
                _ensure_signal_archive(b)
            except Exception:
                current_app.logger.exception("Failed to ensure signal archive for broadcast %s", b.id)

    aq = SignalArchive.query.join(Broadcast, SignalArchive.broadcast_id == Broadcast.id).order_by(SignalArchive.created_at.desc())
    if q:
        like = f"%{q}%"
        aq = aq.filter((SignalArchive.title.ilike(like)) | (SignalArchive.signal_number.ilike(like)) | (SignalArchive.from_unit_text.ilike(like)) | (SignalArchive.sha256.ilike(like)) | (Broadcast.msg_to.ilike(like)) | (Broadcast.msg_from.ilike(like)) | (Broadcast.file_reference.ilike(like)) | (Broadcast.internal_distribution.ilike(like)) | (Broadcast.message_instruction.ilike(like)))
    if classification:
        aq = aq.filter(SignalArchive.classification == classification)
    if priority:
        aq = aq.filter(SignalArchive.priority == priority)
    if integrity:
        aq = aq.filter(SignalArchive.integrity_status == integrity)
    if status:
        aq = aq.filter(Broadcast.status == status)
    if unit_id.isdigit():
        uid = int(unit_id)
        aq = aq.filter((Broadcast.from_unit_id == uid) | (Broadcast.target_unit_id == uid) | (Broadcast.action_units_csv.ilike(f"%{uid}%")) | (Broadcast.info_units_csv.ilike(f"%{uid}%")))
    if date_from:
        try: aq = aq.filter(SignalArchive.created_at >= datetime.strptime(date_from, "%Y-%m-%d"))
        except ValueError: pass
    if date_to:
        try: aq = aq.filter(SignalArchive.created_at < datetime.strptime(date_to, "%Y-%m-%d") + timedelta(days=1))
        except ValueError: pass

    all_archives = [a for a in aq.limit(700).all() if can_view_signal_bank(current_user, a.broadcast)]
    event_counts = _signal_event_counts([a.broadcast_id for a in all_archives])
    ack_summary = {a.broadcast_id: _archive_ack_summary(a.broadcast) for a in all_archives}

    today_date = datetime.utcnow().date()

    def _archive_event_date(a):
        b = a.broadcast
        stamp = getattr(b, "released_at", None) or getattr(a, "created_at", None) or getattr(b, "created_at", None)
        return stamp.date() if stamp else None

    def include_by_section(a):
        b = a.broadcast
        c = event_counts.get(a.broadcast_id, {})
        if section == "today":
            return _archive_event_date(a) == today_date
        if section == "printed":
            return c.get("prints", 0) > 0
        if section == "downloaded":
            return c.get("downloads", 0) > 0 or (a.export_count or 0) > 0
        if section == "pending_ack":
            return ack_summary.get(a.broadcast_id, {}).get("pending", 0) > 0
        if section == "top_secret":
            return (a.classification or b.security_classification) == ClassificationLevel.TOP_SECRET.value
        return True

    filtered = [a for a in all_archives if include_by_section(a)]
    if ack_filter:
        if ack_filter == "pending":
            filtered = [a for a in filtered if ack_summary.get(a.broadcast_id, {}).get("pending", 0) > 0]
        elif ack_filter == "acknowledged":
            filtered = [a for a in filtered if ack_summary.get(a.broadcast_id, {}).get("acked", 0) > 0]
    if activity_filter == "printed":
        filtered = [a for a in filtered if event_counts.get(a.broadcast_id, {}).get("prints", 0) > 0]
    elif activity_filter == "downloaded":
        filtered = [a for a in filtered if event_counts.get(a.broadcast_id, {}).get("downloads", 0) > 0 or (a.export_count or 0) > 0]

    total = len(filtered)
    pages = max((total + per_page - 1) // per_page, 1)
    if page > pages:
        page = pages
    start_i = (page - 1) * per_page
    archives = filtered[start_i:start_i + per_page]

    sections = {
        "today": len([a for a in all_archives if _archive_event_date(a) == today_date]),
        "released": len(all_archives),
        "printed": len([a for a in all_archives if event_counts.get(a.broadcast_id, {}).get("prints", 0) > 0]),
        "downloaded": len([a for a in all_archives if event_counts.get(a.broadcast_id, {}).get("downloads", 0) > 0 or (a.export_count or 0) > 0]),
        "pending_ack": len([a for a in all_archives if ack_summary.get(a.broadcast_id, {}).get("pending", 0) > 0]),
        "top_secret": len([a for a in all_archives if (a.classification or a.broadcast.security_classification) == ClassificationLevel.TOP_SECRET.value]),
    }
    units = Unit.query.order_by(Unit.name.asc()).all()
    return render_template("messaging/signal_bank.html", archives=archives, q=q, classification=classification, priority=priority, integrity=integrity, status=status, section=section, unit_id=unit_id, ack_filter=ack_filter, activity_filter=activity_filter, date_from=date_from, date_to=date_to, classification_choices=CLASSIFICATION_CHOICES, Priority=Priority, units=units, event_counts=event_counts, ack_summary=ack_summary, sections=sections, page=page, pages=pages, total=total)




def _suggest_bulk_export_password(prefix="SIGBANK") -> str:
    alphabet = string.ascii_uppercase + string.digits
    tail = ''.join(secrets.choice(alphabet) for _ in range(10))
    return f"{prefix}-{datetime.utcnow().strftime('%Y%m%d')}-{tail}"

def _resolve_bulk_export_password():
    mode = (request.form.get("password_mode") or "manual").strip().lower()
    if mode == "auto":
        password = (request.form.get("suggested_password") or "").strip()
    else:
        password = (request.form.get("export_password") or "").strip()
    if not password:
        return None, "Bulk export password is required."
    if len(password) < 8:
        return None, "Bulk export password must be at least 8 characters."
    return password, None

@bp.get("/signal-bank/export.csv")
@login_required
def signal_bank_export_csv():
    # Export the currently visible signal bank metadata as CSV.
    q = (request.args.get("q") or "").strip()
    classification = (request.args.get("classification") or "").strip()
    priority = (request.args.get("priority") or "").strip()
    integrity = (request.args.get("integrity") or "").strip()
    rows_q = SignalArchive.query.join(Broadcast, SignalArchive.broadcast_id == Broadcast.id)
    if q:
        like = f"%{q}%"
        rows_q = rows_q.filter((SignalArchive.title.ilike(like)) | (SignalArchive.signal_number.ilike(like)) | (SignalArchive.from_unit_text.ilike(like)) | (SignalArchive.sha256.ilike(like)) | (Broadcast.file_reference.ilike(like)))
    if classification:
        rows_q = rows_q.filter(SignalArchive.classification == classification)
    if priority:
        rows_q = rows_q.filter(SignalArchive.priority == priority)
    if integrity:
        rows_q = rows_q.filter(SignalArchive.integrity_status == integrity)
    rows = [a for a in rows_q.order_by(SignalArchive.created_at.desc()).limit(1000).all() if can_view_signal_bank(current_user, a.broadcast)]
    counts = _signal_event_counts([a.broadcast_id for a in rows])
    import csv
    from io import StringIO
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Signal Number", "Title", "Classification", "Priority", "From Unit", "To", "Status", "Created", "Released", "Integrity", "SHA256", "Print Count", "Download Count", "Export Count"])
    for a in rows:
        b = a.broadcast
        c = counts.get(a.broadcast_id, {})
        writer.writerow([a.signal_number or "", a.title or "", a.classification or b.security_classification or "", a.priority or b.priority or "", a.from_unit_text or b.msg_from or "", b.msg_to or "", b.status or "", a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else "", b.released_at.strftime("%Y-%m-%d %H:%M") if b.released_at else "", a.integrity_status or "", a.sha256 or "", c.get("prints", 0), c.get("downloads", 0), a.export_count or 0])
    log_event(current_user.id, "SIGNAL_BANK_CSV_EXPORTED", {"target_module": "Signal Bank", "items": len(rows), "status": "SUCCESS"})
    return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=signal_bank_export.csv"})


@bp.route("/signal-bank/<int:archive_id>/download", methods=["GET", "POST"])
@login_required
def signal_bank_download(archive_id):
    rec = SignalArchive.query.get_or_404(archive_id)
    if not can_view_signal_bank(current_user, rec.broadcast):
        abort(403)
    if _block_recalled_signal_action(rec.broadcast, "Signal Bank download/export"):
        return redirect(url_for("msg.signal_bank"))
    if not getattr(Settings.get(), "allow_signal_download", True):
        log_event(current_user.id, "SIGNAL_ARCHIVE_DOWNLOAD_BLOCKED_BY_POLICY", {"target_id": rec.id, "classification": rec.classification, "status": "BLOCKED"})
        flash("Signal archive download is currently disabled by HQ security policy.", "warning")
        return redirect(url_for("msg.signal_bank"))
    _ensure_signal_archive(rec.broadcast)
    from io import BytesIO
    export_time = datetime.utcnow()
    now_stamp = export_time.strftime("%Y%m%d%H%M%S")
    export_id = f"NMS-ARCHIVE-DL-{rec.id}-{now_stamp}"
    require_password = _pdf_password_required(rec.classification or rec.broadcast.security_classification)
    if request.method == "GET":
        return render_template(
            "messaging/pdf_password.html",
            b=rec.broadcast,
            archive=rec,
            action_url=url_for("msg.signal_bank_download", archive_id=rec.id),
            require_password=require_password,
            suggested_password=_suggest_pdf_password(rec.broadcast, export_id),
            export_id=export_id,
        )
    pdf_password, err = _resolve_pdf_export_password(rec.broadcast, require_password)
    if err:
        flash(err, "warning")
        return render_template(
            "messaging/pdf_password.html",
            b=rec.broadcast,
            archive=rec,
            action_url=url_for("msg.signal_bank_download", archive_id=rec.id),
            require_password=require_password,
            suggested_password=_suggest_pdf_password(rec.broadcast, export_id),
            export_id=export_id,
        )
    try:
        pdf_bytes = _build_broadcast_pdf_from_print_html(rec.broadcast, export_time, export_id, pdf_password=pdf_password)
    except Exception as exc:
        current_app.logger.exception("HTML print-preview Signal Bank PDF generation failed for archive %s", rec.id)
        flash(str(exc), "warning")
        return redirect(url_for("msg.signal_bank"))
    rec.export_count = (rec.export_count or 0) + 1
    db.session.commit()
    log_event(current_user.id, "SIGNAL_ARCHIVE_DOWNLOADED", {
        "target_module": "Signal Bank",
        "target_id": rec.id,
        "signal_ref": rec.signal_number or rec.file_name,
        "classification": rec.classification,
        "export_id": export_id,
        "sha256": rec.sha256,
        "password_protected": bool(pdf_password),
        "status": "SUCCESS",
        "remarks": "Watermarked archived signal PDF downloaded with PDF open-password protection" if pdf_password else "Watermarked archived signal PDF downloaded without PDF password",
    })
    suffix = "protected" if pdf_password else "watermarked"
    file_name = (rec.file_name or f"signal_{rec.id}.pdf").replace(".pdf", f"_{suffix}.pdf")
    return send_file(BytesIO(pdf_bytes), mimetype="application/pdf", as_attachment=True, download_name=file_name)


@bp.route("/signal-bank/export.zip", methods=["GET", "POST"])
@login_required
def signal_bank_export_zip():
    from io import BytesIO
    q = (request.values.get("q") or "").strip()
    classification = (request.values.get("classification") or "").strip()
    priority = (request.values.get("priority") or "").strip()
    integrity = (request.values.get("integrity") or "").strip()
    export_batch_id = request.values.get("export_batch_id") or f"NMS-SIGBANK-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    if request.method == "GET":
        return render_template(
            "protected_export_password.html",
            export_title="Signal Bank Bulk Export",
            export_id=export_batch_id,
            suggested_password=_suggest_bulk_export_password("SIGBANK"),
            action_url=url_for("msg.signal_bank_export_zip"),
            cancel_url=url_for("msg.signal_bank"),
            hidden_fields={"q": q, "classification": classification, "priority": priority, "integrity": integrity, "export_batch_id": export_batch_id},
        )
    password, err = _resolve_bulk_export_password()
    if err:
        flash(err, "warning")
        return redirect(url_for("msg.signal_bank_export_zip", q=q, classification=classification, priority=priority, integrity=integrity))
    try:
        import pyzipper
    except Exception:
        flash("Password-protected bulk ZIP export requires pyzipper. Install it with: pip install pyzipper", "warning")
        return redirect(url_for("msg.signal_bank"))

    archives_q = SignalArchive.query.join(Broadcast, SignalArchive.broadcast_id == Broadcast.id)
    if q:
        like = f"%{q}%"
        archives_q = archives_q.filter((SignalArchive.title.ilike(like)) | (SignalArchive.signal_number.ilike(like)) | (SignalArchive.from_unit_text.ilike(like)) | (SignalArchive.sha256.ilike(like)) | (Broadcast.file_reference.ilike(like)) | (Broadcast.internal_distribution.ilike(like)) | (Broadcast.message_instruction.ilike(like)))
    if classification:
        archives_q = archives_q.filter(SignalArchive.classification == classification)
    if priority:
        archives_q = archives_q.filter(SignalArchive.priority == priority)
    if integrity:
        archives_q = archives_q.filter(SignalArchive.integrity_status == integrity)
    archives = [a for a in archives_q.order_by(SignalArchive.created_at.desc()).all() if can_view_signal_bank(current_user, a.broadcast) and not _is_recalled_signal(a.broadcast)]

    mem = BytesIO()
    manifest = []
    with pyzipper.AESZipFile(mem, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode("utf-8"))
        zf.comment = f"{export_batch_id} | password protected Signal Bank export".encode("utf-8")
        for rec in archives:
            _ensure_signal_archive(rec.broadcast)
            export_time = datetime.utcnow()
            now_stamp = export_time.strftime("%Y%m%d%H%M%S")
            export_id = f"NMS-ZIP-{rec.id}-{now_stamp}"
            try:
                pdf_bytes = _build_broadcast_pdf_from_print_html(rec.broadcast, export_time, export_id, pdf_password=password)
                arc_name = (rec.file_name or f"signal_{rec.id}.pdf").replace(".pdf", "_protected.pdf")
                zf.writestr(arc_name, pdf_bytes)
                rec.export_count = (rec.export_count or 0) + 1
                manifest.append({"signal_number": rec.signal_number, "file_name": arc_name, "sha256": rec.sha256, "integrity": rec.integrity_status, "export_id": export_id, "watermarked": True, "pdf_password_protected": True, "zip_password_protected": True})
            except Exception:
                current_app.logger.exception("Passworded ZIP export failed for signal archive %s", rec.id)
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
    db.session.commit()
    log_event(current_user.id, "SIGNAL_ARCHIVE_EXPORT", {"target_module": "Signal Bank", "items": len(manifest), "watermarked": True, "pdf_password_protected": True, "zip_password_protected": True, "export_id": export_batch_id, "status": "SUCCESS", "remarks": "Password-protected Signal Bank bulk ZIP export generated; contained PDFs are also open-password protected"})
    mem.seek(0)
    return send_file(mem, mimetype="application/zip", as_attachment=True, download_name=f"{export_batch_id}_protected.zip")


@bp.post("/broadcasts/<int:broadcast_id>/recall")
@login_required
def broadcast_recall(broadcast_id):
    b = Broadcast.query.get_or_404(broadcast_id)
    if not _can_manage_signal_workflow(current_user, b):
        abort(403)
    if b.status not in {"RELEASED", "APPROVED", "SUBMITTED"}:
        flash("Only submitted, approved, or released signals can be recalled.", "warning")
        return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))
    reason = (request.form.get("reason") or "Recalled by releasing/issuing authority").strip()[:500]
    b.status = "RECALLED"
    b.recalled_at = datetime.utcnow()
    b.recalled_by_id = current_user.id
    b.recall_reason = reason
    b.requires_ack = False
    b.ack_deadline_at = None
    db.session.commit()
    log_event(current_user.id, "SIGNAL_RECALLED", f"{b.id}:{b.originator_number or ''}:{reason}")
    try:
        payload = {"id": b.id, "title": b.title, "originator_number": b.originator_number, "reason": reason, "link": url_for("msg.broadcast_detail", broadcast_id=b.id)}
        socketio.emit("signal_recalled", payload, room="broadcast_admins")
        for u in _broadcast_targets(b):
            socketio.emit("signal_recalled", payload, room=f"user_{u.id}")
            create_notification(u.id, "BROADCAST", f"Signal recalled: {b.title}", reason, link=url_for("msg.broadcast_detail", broadcast_id=b.id), thread_type="BROADCAST", thread_id=b.id)
    except Exception:
        pass
    flash("Signal recalled. It is now editable; make corrections and submit it for fresh sign-and-release.", "success")
    return redirect(url_for("msg.broadcast_edit", broadcast_id=b.id))


@bp.post("/broadcasts/<int:broadcast_id>/correct")
@login_required
def broadcast_correct(broadcast_id):
    old = Broadcast.query.get_or_404(broadcast_id)
    if not _can_manage_signal_workflow(current_user, old):
        abort(403)
    if old.superseded_by_id:
        existing = Broadcast.query.get(old.superseded_by_id)
        if existing and (existing.status or "").upper() == "DRAFT":
            flash("An editable correction draft already exists for this signal. Continue editing that draft.", "info")
            return redirect(url_for("msg.broadcast_edit", broadcast_id=existing.id))

    now = datetime.utcnow()
    corrected = Broadcast(
        title=f"CORRECTION - {old.title}"[:160],
        priority=old.priority,
        issuer_id=current_user.id,
        target_scope=old.target_scope,
        target_unit_id=old.target_unit_id,
        target_level=old.target_level,
        requires_ack=old.requires_ack,
        drafter_name=(current_user.full_name or old.drafter_name),
        drafter_rank=(current_user.rank or getattr(old, "drafter_rank", None)),
        precedence_action=_normalize_precedence(old.precedence_action),
        precedence_info=old.precedence_info,
        msg_from=old.msg_from,
        from_unit_id=old.from_unit_id,
        msg_to=old.msg_to,
        branch_office=old.branch_office,
        telephone=old.telephone,
        dtg=_default_dtg(None),
        releasing_signature_rank=current_user.rank or old.releasing_signature_rank,
        releasing_officer_name=current_user.full_name,
        message_instruction=f"CORRECTION TO {old.originator_number or ('SIGNAL ' + str(old.id))}",
        internal_distribution=old.internal_distribution,
        file_reference=old.originator_number or old.file_reference,
        refers_classified_message=True,
        comms_gen_serial_no=None,
        sender_receiver_op=old.sender_receiver_op,
        transmission_system=old.transmission_system,
        time_in_out=old.time_in_out,
        security_classification=old.security_classification,
        status="DRAFT",
        body_format="html",
        signal_precedence=_normalize_precedence(old.precedence_action),
        routing_chain_text=old.routing_chain_text,
        corrected_from_id=old.id,
        body_enc=b"",
    )
    corrected.set_csv_ids("action_users_csv", old.csv_ids("action_users_csv"))
    corrected.set_csv_ids("info_users_csv", old.csv_ids("info_users_csv"))
    corrected.set_csv_ids("action_units_csv", old.csv_ids("action_units_csv"))
    corrected.set_csv_ids("info_units_csv", old.csv_ids("info_units_csv"))
    corrected.set_body(f"<p><b>CORRECTION TO:</b> {old.originator_number or old.title}</p><hr>{old.get_body()}")
    db.session.add(corrected)
    db.session.commit()
    corrected.originator_number = _originator_for(corrected)
    corrected.file_reference = corrected.file_reference or corrected.originator_number
    corrected.comms_gen_serial_no = corrected.originator_number
    old.superseded_by_id = corrected.id
    db.session.commit()
    log_event(current_user.id, "SIGNAL_CORRECTION_DRAFT_CREATED", f"old={old.id};new={corrected.id}")
    flash("Editable correction signal created. Review and edit it before submitting for sign-and-release.", "success")
    return redirect(url_for("msg.broadcast_edit", broadcast_id=corrected.id))


@bp.post("/broadcasts/<int:broadcast_id>/ack")
@login_required
def broadcast_ack(broadcast_id):
    from datetime import datetime, timedelta
    b = Broadcast.query.get_or_404(broadcast_id)
    if _is_recalled_signal(b):
        abort(403)
    if not b.requires_ack:
        abort(400)
    # View-only officers are observers only: they may view, print and download, but never acknowledge.
    if current_user.role == Role.OFFICER.value:
        abort(403)
    if current_user.role not in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        # Only direct TO/INFO recipients acknowledge delivery.
        # Signal Bank visibility alone does not create acknowledgement authority.
        if not (is_signal_delivery_recipient(current_user, b) and can_access_classification(current_user, getattr(b, "security_classification", None))):
            abort(403)

    ack = BroadcastAck.query.filter_by(broadcast_id=b.id, user_id=current_user.id).first()
    if not ack:
        ack = BroadcastAck(broadcast_id=b.id, user_id=current_user.id)
        db.session.add(ack)
    ack.acked_at = datetime.utcnow()
    db.session.commit()
    try:
        payload = {"broadcast_id": b.id, "user_id": current_user.id, "user_name": current_user.full_name, "originator_number": b.originator_number, "link": url_for("msg.broadcast_detail", broadcast_id=b.id), "acked_at": ack.acked_at.isoformat()+"Z"}
        socketio.emit("broadcast_ack_update", payload, room="broadcast_admins")
        if b.issuer_id:
            socketio.emit("broadcast_ack_update", payload, room=f"user_{b.issuer_id}")
    except Exception:
        pass
    log_event(current_user.id, "BROADCAST_ACK", str(b.id))
    return redirect(url_for("msg.broadcast_detail", broadcast_id=b.id))


@bp.post("/react/<int:message_id>")
@login_required
def react(message_id):
    emoji = (request.form.get("emoji") or "").strip()
    if not emoji:
        abort(400)
    m = Message.query.get_or_404(message_id)
    # Permission check: user must be sender/recipient or in channel
    allowed = False
    if m.msg_type == MessageType.DIRECT.value:
        allowed = (m.sender_id == current_user.id) or (m.recipient_id == current_user.id)
    elif m.msg_type == MessageType.CHANNEL.value:
        ch = Channel.query.get(m.channel_id)
        allowed = ch and current_user in ch.members
    if not allowed:
        abort(403)
    existing = MessageReaction.query.filter_by(message_id=m.id, user_id=current_user.id, emoji=emoji).first()
    if existing:
        db.session.delete(existing)
    else:
        db.session.add(MessageReaction(message_id=m.id, user_id=current_user.id, emoji=emoji))
    db.session.commit()
    return redirect(request.referrer or url_for("main.dashboard"))
