from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
import json
from ..hierarchy import is_in_subtree, visible_unit_ids_for_user
from ..models import Role
from .. import db
from ..models import User, Unit, Role, Settings, Notification, UserPreference, MutedThread, NotificationType, MessageType, Message, Attachment, Broadcast
from ..audit import log_event
from ..security import can_view_broadcast, can_view_signal_bank, validate_password_strength

bp = Blueprint("main", __name__)


def _build_dashboard_analytics(user, days: int):
    """Build interactive analytics payload for the dashboard."""
    from datetime import datetime, timedelta
    from collections import defaultdict
    from sqlalchemy import func

    from ..models import (
        Unit, User, Channel,
        Broadcast, BroadcastAck, BroadcastAttachment,
        Message, Attachment,
        Notification, NotificationType, MessageType,
        Settings, Role,
    )

    days = int(days or 7)
    if days not in (7, 14, 30):
        days = 7

    now = datetime.utcnow()
    since = now - timedelta(days=days)

    settings = Settings.get()
    escalation_mins = max(int(settings.broadcast_escalation_minutes or 30), 1)

    # Visible units for the user
    visible_units = []
    visible_unit_ids = []
    if getattr(user, "unit", None):
        visible_unit_ids = list(visible_unit_ids_for_user(user.unit))
        visible_units = Unit.query.filter(Unit.id.in_(visible_unit_ids)).order_by(Unit.name.asc()).all()
    else:
        # Fallback: show all units for admins, otherwise none
        if user.role in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
            visible_units = Unit.query.order_by(Unit.name.asc()).all()
            visible_unit_ids = [u.id for u in visible_units]

    # --- KPI: direct inbound to user ---
    direct_cnt = Message.query.filter(
        Message.msg_type == MessageType.DIRECT.value,
        Message.recipient_id == user.id,
        Message.created_at >= since,
    ).count()

    # --- KPI: attachments (message + broadcast attachments) ---
    msg_att_cnt = Attachment.query.filter(Attachment.created_at >= since).count()
    b_att_cnt = BroadcastAttachment.query.filter(BroadcastAttachment.created_at >= since).count()
    attachments_cnt = msg_att_cnt + b_att_cnt

    # --- KPI: visible broadcasts (signals) ---
    visible_bcasts = []
    bq = Broadcast.query.filter(Broadcast.created_at >= since).order_by(Broadcast.created_at.desc()).limit(2500).all()
    for b in bq:
        if user.role in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
            visible_bcasts.append(b); continue
        if b.target_scope == "ALL":
            visible_bcasts.append(b); continue
        if b.target_scope == "UNIT" and user.unit_id and b.target_unit_id == user.unit_id:
            visible_bcasts.append(b); continue
        if b.target_scope == "UNIT_TREE" and getattr(user, "unit", None) and is_in_subtree(user.unit, b.target_unit_id):
            visible_bcasts.append(b); continue
    signals_cnt = len(visible_bcasts)

    # --- KPI: escalations (user notifications) ---
    escalations_cnt = Notification.query.filter(
        Notification.user_id == user.id,
        Notification.ntype == NotificationType.ESCALATION.value,
        Notification.created_at >= since,
    ).count()

    # --- ACK metrics + trend ---
    labels = []
    required_series = []
    acked_series = []
    rate_series = []

    # Build date buckets
    for i in range(days-1, -1, -1):
        d = (now - timedelta(days=i)).date()
        labels.append(d.strftime("%m/%d"))

    # Only broadcasts that require ack
    req_bcasts = [b for b in visible_bcasts if getattr(b, "requires_ack", False)]
    req_ids = [b.id for b in req_bcasts]

    # Map broadcast->created_date bucket idx
    idx_by_date = { (now - timedelta(days=i)).date(): (days-1-i) for i in range(days-1, -1, -1) }

    req_count_by_idx = [0]*days
    for b in req_bcasts:
        d = b.created_at.date()
        if d in idx_by_date:
            req_count_by_idx[idx_by_date[d]] += 1

    acked_ids = set()
    if req_ids:
        ack_rows = BroadcastAck.query.with_entities(BroadcastAck.broadcast_id).filter(
            BroadcastAck.user_id == user.id,
            BroadcastAck.broadcast_id.in_(req_ids),
            BroadcastAck.acked_at.isnot(None),
        ).all()
        acked_ids = {r[0] for r in ack_rows}

    acked_count_by_idx = [0]*days
    for b in req_bcasts:
        if b.id in acked_ids:
            d = b.created_at.date()
            if d in idx_by_date:
                acked_count_by_idx[idx_by_date[d]] += 1

    for i in range(days):
        r = req_count_by_idx[i]
        a = acked_count_by_idx[i]
        required_series.append(r)
        acked_series.append(a)
        rate_series.append(int(round((a / r) * 100)) if r else 0)

    total_ack_required = len(req_ids)
    total_acked = len(acked_ids)
    ack_rate_pct = int(round((total_acked / total_ack_required) * 100)) if total_ack_required else 0

    # Overdue ACK (requires ack, not acked, older than escalation threshold)
    overdue_ack = 0
    if req_ids:
        threshold = now - timedelta(minutes=escalation_mins)
        overdue_q = Broadcast.query.filter(
            Broadcast.id.in_(req_ids),
            Broadcast.created_at < threshold,
        )
        if acked_ids:
            overdue_q = overdue_q.filter(Broadcast.id.notin_(acked_ids))
        overdue_ack = overdue_q.count()

    # --- Unit activity (messages within channels by unit) ---
    # Signals per unit based on broadcast targeting (best-effort)
    sig_by_unit = defaultdict(int)
    for b in visible_bcasts:
        if b.target_scope == "UNIT" and b.target_unit_id:
            sig_by_unit[b.target_unit_id] += 1
        elif b.target_scope == "UNIT_TREE" and b.target_unit_id:
            sig_by_unit[b.target_unit_id] += 1
        elif b.target_scope == "ALL":
            # allocate to user's own unit if exists, else skip
            if user.unit_id:
                sig_by_unit[user.unit_id] += 1

    # Channel messages by unit (join Channel)
    chan_rows = (
        Message.query.join(Channel, Message.channel_id == Channel.id)
        .with_entities(Channel.unit_id, func.count(Message.id))
        .filter(
            Message.msg_type == MessageType.CHANNEL.value,
            Message.created_at >= since,
        )
        .group_by(Channel.unit_id)
        .all()
    )
    chan_msg_by_unit = {uid: int(cnt) for uid, cnt in chan_rows if uid}

    # Direct messages by sender's unit (inbound only)
    dm_rows = (
        Message.query.join(User, Message.sender_id == User.id)
        .with_entities(User.unit_id, func.count(Message.id))
        .filter(
            Message.msg_type == MessageType.DIRECT.value,
            Message.recipient_id == user.id,
            Message.created_at >= since,
        )
        .group_by(User.unit_id)
        .all()
    )
    dm_by_unit = {uid: int(cnt) for uid, cnt in dm_rows if uid}

    # Attachments by uploader unit (message + broadcast)
    att_rows = (
        Attachment.query.join(User, Attachment.uploader_id == User.id)
        .with_entities(User.unit_id, func.count(Attachment.id))
        .filter(Attachment.created_at >= since)
        .group_by(User.unit_id)
        .all()
    )
    msg_att_by_unit = {uid: int(cnt) for uid, cnt in att_rows if uid}

    b_att_rows = (
        BroadcastAttachment.query.join(User, BroadcastAttachment.uploader_id == User.id)
        .with_entities(User.unit_id, func.count(BroadcastAttachment.id))
        .filter(BroadcastAttachment.created_at >= since)
        .group_by(User.unit_id)
        .all()
    )
    b_att_by_unit = {uid: int(cnt) for uid, cnt in b_att_rows if uid}

    attachments_by_unit = defaultdict(int)
    for uid, cnt in msg_att_by_unit.items():
        attachments_by_unit[uid] += cnt
    for uid, cnt in b_att_by_unit.items():
        attachments_by_unit[uid] += cnt

    unit_labels = []
    unit_signals = []
    unit_direct = []
    unit_attachments = []
    unit_overdue = []

    # overdue ack per unit based on broadcast target_unit_id
    overdue_by_unit = defaultdict(int)
    if req_bcasts:
        threshold = now - timedelta(minutes=escalation_mins)
        for b in req_bcasts:
            if b.id in acked_ids:
                continue
            if b.created_at >= threshold:
                continue
            tu = b.target_unit_id or user.unit_id
            if tu:
                overdue_by_unit[tu] += 1

    for u in visible_units[:15]:  # keep chart readable
        unit_labels.append(u.name[:18])
        unit_signals.append(int(sig_by_unit.get(u.id, 0)))
        unit_direct.append(int(dm_by_unit.get(u.id, 0)))
        unit_attachments.append(int(attachments_by_unit.get(u.id, 0)))
        unit_overdue.append(int(overdue_by_unit.get(u.id, 0)))

    # --- Issuer leaderboard ---
    issuer_rows = defaultdict(lambda: {"count": 0, "requires_ack": 0, "your_acked": 0})
    for b in visible_bcasts:
        iss = b.issuer_id
        issuer_rows[iss]["count"] += 1
        if b.requires_ack:
            issuer_rows[iss]["requires_ack"] += 1
            if b.id in acked_ids:
                issuer_rows[iss]["your_acked"] += 1

    issuer_ids = list(issuer_rows.keys())
    issuer_map = {u.id: u for u in User.query.filter(User.id.in_(issuer_ids)).all()} if issuer_ids else {}

    leaderboard = []
    for uid, d in issuer_rows.items():
        uobj = issuer_map.get(uid)
        name = (uobj.full_name if uobj else f"User {uid}")
        ra = d["requires_ack"]
        ya = d["your_acked"]
        your_rate = int(round((ya/ra)*100)) if ra else 0
        leaderboard.append({
            "issuer": name,
            "count": int(d["count"]),
            "requires_ack": int(ra),
            "your_ack_rate": int(your_rate),
        })
    leaderboard.sort(key=lambda x: (x["count"], x["requires_ack"]), reverse=True)
    leaderboard = leaderboard[:10]

    return {
        "days": days,
        "kpis": {
            "signals": int(signals_cnt),
            "direct": int(direct_cnt),
            "attachments": int(attachments_cnt),
            "escalations": int(escalations_cnt),
            "ack_rate_pct": int(ack_rate_pct),
            "overdue_ack": int(overdue_ack),
            "total_ack_required": int(total_ack_required),
        },
        "ack_trend": {
            "labels": labels,
            "required": required_series,
            "acked": acked_series,
            "rate": rate_series,
        },
        "unit_activity": {
            "labels": unit_labels,
            "signals": unit_signals,
            "direct": unit_direct,
            "attachments": unit_attachments,
            "overdue": unit_overdue,
        },
        "issuer_leaderboard": leaderboard,
    }



@bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """Self-service login/profile details page for every user, including admins.

    Users may update only their own login/contact details. Rank, role, unit,
    clearance and service number remain HQ-controlled for audit integrity.
    """
    user = current_user
    if request.method == "POST":
        new_username = (request.form.get("service_number") or "").strip()
        email = (request.form.get("email") or "").strip() or None
        phone = (request.form.get("phone") or "").strip()
        current_password = request.form.get("current_password") or ""
        new_password = request.form.get("new_password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        changed = []

        if new_username and new_username != user.service_number:
            if not current_password or not user.check_password(current_password):
                flash("Current password is required before changing your login username/service number.", "danger")
                return redirect(url_for("main.account"))
            if User.query.filter(User.service_number == new_username, User.id != user.id).first():
                flash("That login username/service number is already in use.", "danger")
                return redirect(url_for("main.account"))
            old_username = user.service_number
            user.service_number = new_username
            changed.append(f"username changed from {old_username} to {new_username}")

        if email != user.email:
            user.email = email
            changed.append("email updated")

        if phone != (user.phone or ""):
            user.phone = phone or None
            changed.append("phone updated")

        if new_password or confirm_password:
            if new_password != confirm_password:
                flash("New password and confirmation do not match.", "danger")
                return redirect(url_for("main.account"))
            if not current_password and not getattr(user, "must_change_password", False):
                flash("Current password is required before changing password.", "danger")
                return redirect(url_for("main.account"))
            if current_password and not user.check_password(current_password) and not getattr(user, "must_change_password", False):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for("main.account"))
            ok, issues = validate_password_strength(new_password)
            if not ok:
                flash("Password policy failed: " + "; ".join(issues), "danger")
                return redirect(url_for("main.account"))
            user.set_password(new_password)
            user.must_change_password = False
            changed.append("password updated")

        if getattr(user, "must_change_password", False) and not new_password:
            flash("You must set a new password before continuing.", "warning")
            return redirect(url_for("main.account"))

        db.session.commit()
        log_event(user.id, "SELF_ACCOUNT_UPDATED", ", ".join(changed) if changed else "No sensitive fields changed")
        flash("Your account details have been updated.", "success")
        return redirect(url_for("main.account"))

    return render_template("account.html")

@bp.get("/")
def home():
    if User.query.count() == 0:
        return redirect(url_for("main.setup"))
    return redirect(url_for("auth.login"))

@bp.route("/setup", methods=["GET","POST"])
def setup():
    if User.query.count() > 0:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        full_name = request.form.get("full_name","").strip()
        service_number = request.form.get("service_number","").strip()
        password = request.form.get("password","")
        confirm = request.form.get("confirm","")
        if not full_name or not service_number or not password:
            flash("All fields are required", "danger")
            return redirect(url_for("main.setup"))
        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for("main.setup"))
        ok, issues = validate_password_strength(password)
        if not ok:
            flash("Password policy failed: " + "; ".join(issues), "danger")
            return redirect(url_for("main.setup"))

        defaults = [
            ("NAF HQ", "HQ"),
            ("Tactical Air Command", "TAC"),
            ("Logistics Command", "LOG"),
            ("Training Command", "TRG"),
            ("Special Operations", "SOP"),
        ]
        units=[]
        for name, code in defaults:
            u = Unit(name=name, code=code)
            db.session.add(u); units.append(u)
        db.session.commit()

        admin = User(full_name=full_name, service_number=service_number, role=Role.SUPER_ADMIN.value, unit_id=units[0].id, clearance_level="TOP SECRET", password_hash="tmp")
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()

        Settings.get()
        log_event(admin.id, "SETUP_COMPLETE", f"SUPER_ADMIN {service_number}")
        flash("Setup complete. Please sign in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("setup.html")


@bp.get("/search")
@login_required
def search():
    from ..models import User, Channel, Broadcast, SignalArchive, AuditEvent
    q = (request.args.get("q") or "").strip()
    classification = (request.args.get("classification") or "").strip()
    status = (request.args.get("status") or "").strip()
    priority = (request.args.get("priority") or "").strip()
    sender = (request.args.get("sender") or "").strip()
    unit_id = (request.args.get("unit_id") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    has_attachments = (request.args.get("has_attachments") or "").strip()
    signature_status = (request.args.get("signature_status") or "").strip()
    archive_integrity = (request.args.get("archive_integrity") or "").strip()
    users = []
    channels = []
    broadcasts = []
    archives = []
    audits = []
    units = Unit.query.order_by(Unit.name.asc()).all()

    if any([q, classification, status, priority, sender, unit_id, date_from, date_to, has_attachments, signature_status, archive_integrity]):
        like = f"%{q}%"
        if q:
            users = User.query.filter((User.full_name.ilike(like)) | (User.service_number.ilike(like)) | (User.rank.ilike(like)) | (User.specialty.ilike(like))).order_by(User.full_name.asc()).limit(50).all()
            channels = Channel.query.filter(Channel.name.ilike(like)).order_by(Channel.name.asc()).limit(50).all()

        bq = Broadcast.query
        if q:
            bq = bq.filter((Broadcast.title.ilike(like)) | (Broadcast.msg_from.ilike(like)) | (Broadcast.msg_to.ilike(like)) | (Broadcast.originator_number.ilike(like)) | (Broadcast.security_classification.ilike(like)) | (Broadcast.drafter_name.ilike(like)) | (Broadcast.releasing_officer_name.ilike(like)))
        if classification:
            bq = bq.filter(Broadcast.security_classification == classification)
        if status:
            bq = bq.filter(Broadcast.status == status)
        if priority:
            bq = bq.filter(Broadcast.priority == priority)
        if signature_status == "valid":
            bq = bq.filter(Broadcast.digital_signature.isnot(None))
        elif signature_status == "missing":
            bq = bq.filter(Broadcast.digital_signature.is_(None))
        if sender:
            s_like = f"%{sender}%"
            bq = bq.join(User, Broadcast.issuer_id == User.id).filter((User.full_name.ilike(s_like)) | (User.service_number.ilike(s_like)))
        if unit_id.isdigit():
            uid = int(unit_id)
            bq = bq.filter((Broadcast.target_unit_id == uid) | (Broadcast.from_unit_id == uid) | (Broadcast.action_units_csv.ilike(f"%{uid}%")) | (Broadcast.info_units_csv.ilike(f"%{uid}%")))
        if date_from:
            try: bq = bq.filter(Broadcast.created_at >= datetime.strptime(date_from, "%Y-%m-%d"))
            except ValueError: pass
        if date_to:
            try:
                end = datetime.strptime(date_to, "%Y-%m-%d")
                bq = bq.filter(Broadcast.created_at < end.replace(hour=23, minute=59, second=59, microsecond=999999))
            except ValueError: pass
        if has_attachments == "yes":
            bq = bq.filter(Broadcast.attachments.any())
        elif has_attachments == "no":
            bq = bq.filter(~Broadcast.attachments.any())

        q_lower = q.lower() if q else ""
        for b in bq.order_by(Broadcast.created_at.desc()).limit(300).all():
            if (b.status or '').upper() in ('RELEASED', 'ARCHIVED'):
                if not can_view_signal_bank(current_user, b):
                    continue
            elif not can_view_broadcast(current_user, b, is_in_subtree):
                continue
            if q_lower:
                searchable = " ".join([str(b.title or ""), str(b.msg_from or ""), str(b.msg_to or ""), str(b.originator_number or ""), str(b.security_classification or ""), str(b.drafter_name or ""), str(b.releasing_officer_name or ""), str(b.get_body() or ""), str(b.action_users_csv or ""), str(b.info_users_csv or ""), str(b.action_units_csv or ""), str(b.info_units_csv or "")]).lower()
                if q_lower not in searchable:
                    continue
            broadcasts.append(b)

        aq = SignalArchive.query.join(Broadcast, SignalArchive.broadcast_id == Broadcast.id)
        if q:
            aq = aq.filter((SignalArchive.title.ilike(like)) | (SignalArchive.signal_number.ilike(like)) | (SignalArchive.from_unit_text.ilike(like)) | (SignalArchive.sha256.ilike(like)) | (Broadcast.msg_to.ilike(like)) | (Broadcast.msg_from.ilike(like)))
        if classification:
            aq = aq.filter(SignalArchive.classification == classification)
        if priority:
            aq = aq.filter(SignalArchive.priority == priority)
        if archive_integrity:
            aq = aq.filter(SignalArchive.integrity_status == archive_integrity)
        archives = [a for a in aq.order_by(SignalArchive.created_at.desc()).limit(120).all() if can_view_signal_bank(current_user, a.broadcast)]

        if current_user.role in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
            audit_q = AuditEvent.query
            if q:
                audit_q = audit_q.filter((AuditEvent.action.ilike(like)) | (AuditEvent.details.ilike(like)) | (AuditEvent.event_hash.ilike(like)) | (AuditEvent.payload_sha256.ilike(like)))
            audits = audit_q.order_by(AuditEvent.created_at.desc()).limit(80).all()

        log_event(current_user.id, "SEARCH_EXECUTED", json.dumps({"q": q, "classification": classification, "status": status, "priority": priority, "sender": sender, "unit_id": unit_id, "date_from": date_from, "date_to": date_to, "has_attachments": has_attachments, "signature_status": signature_status, "archive_integrity": archive_integrity}))

    return render_template("search.html", q=q, users=users, channels=channels, broadcasts=broadcasts, archives=archives, audits=audits, units=units, classification=classification, status=status, priority=priority, sender=sender, unit_id=unit_id, date_from=date_from, date_to=date_to, has_attachments=has_attachments, signature_status=signature_status, archive_integrity=archive_integrity)

@bp.get("/api/analytics/dashboard")
@login_required
def api_dashboard_analytics():
    """JSON analytics for interactive Chart.js dashboard."""
    days = request.args.get("days", 7)
    try:
        days = int(days)
    except Exception:
        days = 7
    payload = _build_dashboard_analytics(current_user, days)
    return jsonify(payload)


@bp.get("/dashboard")
@login_required
def dashboard():
    from datetime import datetime, timedelta

    from collections import Counter
    from sqlalchemy import func

    from ..models import (
        Channel,
        Broadcast,
        BroadcastAck,
        Message,
        Attachment,
        Notification,
        AuditEvent,
        Settings,
        User,
    )

    q = Channel.query
    if current_user.unit_id:
        allowed_unit_ids = list(visible_unit_ids_for_user(current_user.unit))
        q = q.filter((Channel.unit_id.in_(allowed_unit_ids)) | (Channel.scope == "MISSION"))

    # Total visible channels for the current user (for dashboard stats)
    channel_total = q.count()
    channels = q.order_by(Channel.created_at.desc()).limit(6).all()
    broadcasts_all = Broadcast.query.order_by(Broadcast.created_at.desc()).limit(20).all()
    broadcasts = []
    for b in broadcasts_all:
        if current_user.role in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
            broadcasts.append(b); continue
        if b.target_scope == "ALL":
            broadcasts.append(b); continue
        if b.target_scope == "UNIT" and current_user.unit_id and b.target_unit_id == current_user.unit_id:
            broadcasts.append(b); continue
        if b.target_scope == "UNIT_TREE" and is_in_subtree(current_user.unit, b.target_unit_id):
            broadcasts.append(b); continue
    broadcasts = broadcasts[:6]

    # --- Operational KPIs (last 7 days) ---
    now = datetime.utcnow()
    since = now - timedelta(days=7)

    settings = Settings.get()
    escalation_mins = max(int(settings.broadcast_escalation_minutes or 30), 1)

    # Direct messages inbound to the current user
    direct_7d = Message.query.filter(
        Message.msg_type == MessageType.DIRECT.value,
        Message.recipient_id == current_user.id,
        Message.created_at >= since,
    ).count()

    # Attachments created in the last 7 days (global; simple + fast)
    attachments_7d = Attachment.query.filter(Attachment.created_at >= since).count()

    # Visible broadcasts in the last 7 days
    visible_broadcast_ids_7d = []
    b7 = Broadcast.query.filter(Broadcast.created_at >= since).order_by(Broadcast.created_at.desc()).limit(800).all()
    for b in b7:
        if current_user.role in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
            visible_broadcast_ids_7d.append(b.id)
            continue
        if b.target_scope == "ALL":
            visible_broadcast_ids_7d.append(b.id)
            continue
        if b.target_scope == "UNIT" and current_user.unit_id and b.target_unit_id == current_user.unit_id:
            visible_broadcast_ids_7d.append(b.id)
            continue
        if b.target_scope == "UNIT_TREE" and is_in_subtree(current_user.unit, b.target_unit_id):
            visible_broadcast_ids_7d.append(b.id)
            continue
    signals_7d = len(visible_broadcast_ids_7d)

    escalations_7d = Notification.query.filter(
        Notification.user_id == current_user.id,
        Notification.ntype == NotificationType.ESCALATION.value,
        Notification.created_at >= since,
    ).count()

    # --- Mission KPIs (ACK discipline) ---
    requires_ack_ids_7d = []
    if visible_broadcast_ids_7d:
        req_rows = Broadcast.query.with_entities(Broadcast.id).filter(
            Broadcast.id.in_(visible_broadcast_ids_7d),
            Broadcast.requires_ack.is_(True),
        ).all()
        requires_ack_ids_7d = [r[0] for r in req_rows]

    total_ack_required_7d = len(requires_ack_ids_7d)
    acked_7d = 0
    overdue_ack_7d = 0
    ack_rate_pct_7d = 0

    if total_ack_required_7d:
        acked_7d = BroadcastAck.query.filter(
            BroadcastAck.user_id == current_user.id,
            BroadcastAck.broadcast_id.in_(requires_ack_ids_7d),
            BroadcastAck.acked_at.isnot(None),
        ).count()

        # Overdue = requires ACK, not acked, and older than escalation threshold
        acked_ids = set(
            r[0]
            for r in BroadcastAck.query.with_entities(BroadcastAck.broadcast_id)
            .filter(
                BroadcastAck.user_id == current_user.id,
                BroadcastAck.broadcast_id.in_(requires_ack_ids_7d),
                BroadcastAck.acked_at.isnot(None),
            )
            .all()
        )
        threshold = now - timedelta(minutes=escalation_mins)
        overdue_q = Broadcast.query.filter(
            Broadcast.id.in_(requires_ack_ids_7d),
            Broadcast.created_at < threshold,
        )
        if acked_ids:
            overdue_q = overdue_q.filter(Broadcast.id.notin_(acked_ids))
        overdue_ack_7d = overdue_q.count()

        ack_rate_pct_7d = int(round((acked_7d / total_ack_required_7d) * 100))

    # --- Top activity (last 7 days) ---
    # Top channels by message volume (restricted to visible channel IDs)
    visible_channel_ids = [r[0] for r in q.with_entities(Channel.id).all()]
    top_channels = []
    if visible_channel_ids:
        rows = (
            Message.query.with_entities(Message.channel_id, func.count(Message.id))
            .filter(
                Message.msg_type == MessageType.CHANNEL.value,
                Message.channel_id.in_(visible_channel_ids),
                Message.created_at >= since,
            )
            .group_by(Message.channel_id)
            .order_by(func.count(Message.id).desc())
            .limit(5)
            .all()
        )
        ch_ids = [r[0] for r in rows if r[0]]
        ch_map = {c.id: c for c in Channel.query.filter(Channel.id.in_(ch_ids)).all()} if ch_ids else {}
        for cid, cnt in rows:
            c = ch_map.get(cid)
            if not c:
                continue
            top_channels.append({"id": c.id, "name": c.name, "scope": c.scope, "count": int(cnt)})

    # Top issuers by visible broadcasts
    since30 = now - timedelta(days=30)
    b30 = Broadcast.query.filter(Broadcast.created_at >= since30).order_by(Broadcast.created_at.desc()).limit(800).all()
    visible_issuer_ids = []
    for b in b30:
        if current_user.role in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
            visible_issuer_ids.append(b.issuer_id)
            continue
        if b.target_scope == "ALL":
            visible_issuer_ids.append(b.issuer_id)
            continue
        if b.target_scope == "UNIT" and current_user.unit_id and b.target_unit_id == current_user.unit_id:
            visible_issuer_ids.append(b.issuer_id)
            continue
        if b.target_scope == "UNIT_TREE" and is_in_subtree(current_user.unit, b.target_unit_id):
            visible_issuer_ids.append(b.issuer_id)
            continue

    top_issuers = []
    if visible_issuer_ids:
        counts = Counter(visible_issuer_ids)
        top_ids = [uid for uid, _ in counts.most_common(5)]
        u_map = {u.id: u for u in User.query.filter(User.id.in_(top_ids)).all()} if top_ids else {}
        for uid, cnt in counts.most_common(5):
            u = u_map.get(uid)
            if not u:
                continue
            top_issuers.append({"id": u.id, "name": u.full_name, "service": u.service_number, "count": int(cnt)})

    # --- Mini-bars (last 7 days, per-day buckets) ---
    day_labels = []
    series_signals = []
    series_direct = []
    for i in range(6, -1, -1):
        d0 = (now - timedelta(days=i)).date()
        d1 = d0 + timedelta(days=1)
        day_labels.append(d0.strftime("%a"))

        # Visible broadcasts count for this day
        day_bcasts = 0
        for b in b7:
            if b.created_at.date() != d0:
                continue
            if b.id in visible_broadcast_ids_7d:
                day_bcasts += 1
        series_signals.append(day_bcasts)

        day_direct = Message.query.filter(
            Message.msg_type == MessageType.DIRECT.value,
            Message.recipient_id == current_user.id,
            Message.created_at >= datetime.combine(d0, datetime.min.time()),
            Message.created_at < datetime.combine(d1, datetime.min.time()),
        ).count()
        series_direct.append(day_direct)

    # --- Activity feed ---
    activity = []
    recent_notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(8).all()
    for n in recent_notifications:
        activity.append({
            "kind": "NOTIFY",
            "title": n.title,
            "sub": (n.body or ""),
            "ts": n.created_at,
            "link": n.link or url_for("main.notifications"),
        })

    # For non-admins, show only their own audit trail; for admins show global
    aq = AuditEvent.query
    if current_user.role not in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        aq = aq.filter(AuditEvent.actor_id == current_user.id)
    recent_audit = aq.order_by(AuditEvent.created_at.desc()).limit(8).all()
    for a in recent_audit:
        who = a.actor.full_name if a.actor else "System"
        unit_name = (a.actor.unit.name if (a.actor and getattr(a.actor, "unit", None)) else None)
        who2 = f"{who} ({unit_name})" if unit_name else who
        details = f"{who2} • {a.details}" if a.details else who2
        activity.append({
            "kind": "AUDIT",
            "title": a.action,
            "sub": details,
            "ts": a.created_at,
            "link": url_for("main.notifications"),
        })

    activity = sorted(activity, key=lambda x: x.get("ts") or now, reverse=True)[:10]

    unit_workflow_counts = {"all": 0, "my_action": 0, "returned": 0, "ready_release": 0, "in_routing": 0, "action_total": 0}
    unit_workflow_preview = []
    try:
        from ..unit_workflow import workflow_counts_for_user, workflow_groups_for_user, UNIT_WORKFLOW_LABELS
        unit_workflow_counts = workflow_counts_for_user(current_user)
        unit_groups = workflow_groups_for_user(current_user, limit=30)
        preview_pool = unit_groups["my_action"] + unit_groups["returned"] + unit_groups["ready_release"] + unit_groups["in_routing"]
        seen = set()
        for item in preview_pool:
            if item.id in seen:
                continue
            seen.add(item.id)
            unit_workflow_preview.append({
                "id": item.id,
                "title": item.title,
                "status": item.status,
                "label": UNIT_WORKFLOW_LABELS.get((item.status or "").upper(), item.status),
                "handler": (f"{item.current_handler.rank or ''} {item.current_handler.full_name}".strip() if item.current_handler else "—"),
                "ref": item.originator_number or item.file_reference or f"SIG-{item.id}",
                "created_at": item.created_at,
            })
            if len(unit_workflow_preview) >= 5:
                break
    except Exception:
        pass

    return render_template(
        "dashboard.html",
        channels=channels,
        broadcasts=broadcasts,
        channel_total=channel_total,
        signals_7d=signals_7d,
        direct_7d=direct_7d,
        attachments_7d=attachments_7d,
        escalations_7d=escalations_7d,
        ack_rate_pct_7d=ack_rate_pct_7d,
        overdue_ack_7d=overdue_ack_7d,
        total_ack_required_7d=total_ack_required_7d,
        top_channels=top_channels,
        top_issuers=top_issuers,
        day_labels=day_labels,
        series_signals=series_signals,
        series_direct=series_direct,
        activity=activity,
        unit_workflow_counts=unit_workflow_counts,
        unit_workflow_preview=unit_workflow_preview,
    )


@bp.get("/health")
def health():
    return {"status":"ok"}

@bp.route("/notifications")
@login_required
def notifications():
    """Show notifications and clear the unread badge once the user opens the page.

    Opening the notification center means the notifications have been seen.
    We mark every unread notification for the current user as read before
    rendering so the sidebar badge, page count, and database state agree.
    """
    unread_items = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    if unread_items:
        for n in unread_items:
            n.is_read = True
        db.session.commit()
    items = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(200).all()
    return render_template("notifications.html", items=items, unread=0)

@bp.post("/notifications/<int:nid>/read")
@login_required
def notifications_read(nid):
    n = Notification.query.filter_by(id=nid, user_id=current_user.id).first_or_404()
    n.is_read = True
    db.session.commit()
    return redirect(url_for("main.notifications"))

@bp.post("/prefs/toggle-dark")
@login_required
def prefs_toggle_dark():
    p = UserPreference.get_for(current_user.id)
    p.dark_mode = not p.dark_mode
    db.session.commit()
    return redirect(request.referrer or url_for("main.dashboard"))

@bp.route("/prefs/dnd", methods=["GET","POST"])
@login_required
def prefs_dnd():
    p = UserPreference.get_for(current_user.id)
    if request.method == "POST":
        p.dnd_enabled = True if request.form.get("dnd_enabled") == "1" else False
        p.dnd_start_hour = int(request.form.get("dnd_start_hour") or 22)
        p.dnd_end_hour = int(request.form.get("dnd_end_hour") or 6)
        db.session.commit()
        flash("Preferences updated.", "success")
        return redirect(url_for("main.prefs_dnd"))
    return render_template("prefs_dnd.html", p=p)

@bp.post("/mute")
@login_required
def mute_toggle():
    ttype = (request.form.get("thread_type") or "").upper()
    tid = int(request.form.get("thread_id") or 0)
    if ttype not in ("DIRECT","CHANNEL") or tid <= 0:
        abort(400)
    m = MutedThread.query.filter_by(user_id=current_user.id, thread_type=ttype, thread_id=tid).first()
    if m:
        db.session.delete(m)
        db.session.commit()
    else:
        db.session.add(MutedThread(user_id=current_user.id, thread_type=ttype, thread_id=tid))
        db.session.commit()
    return redirect(request.referrer or url_for("main.dashboard"))
