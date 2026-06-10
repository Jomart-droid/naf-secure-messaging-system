from __future__ import annotations

from datetime import datetime, timedelta

from . import db
from .audit import log_event
from .models import Broadcast, BroadcastAck, Settings, Role, User


def run_escalation_sweep(socketio, app):
    """Background loop: periodically checks for broadcasts that require ACK and are overdue.

    Design goal: keep it simple and reliable for an MVP.
    - Marks broadcast.escalated_at once (idempotent)
    - Alerts the issuer + Admin/SUPER_ADMIN room
    """

    def _loop():
        while True:
            # eventlet-friendly sleep
            socketio.sleep(60)
            with app.app_context():
                s = Settings.get()
                threshold = timedelta(minutes=int(s.broadcast_escalation_minutes or 30))
                cutoff = datetime.utcnow() - threshold

                # Find candidates not yet escalated
                candidates = Broadcast.query.filter(
                    Broadcast.requires_ack.is_(True),
                    Broadcast.created_at <= cutoff,
                    Broadcast.escalated_at.is_(None),
                ).order_by(Broadcast.created_at.asc()).limit(200).all()

                for b in candidates:
                    # If *everyone* has acknowledged, skip.
                    # MVP logic: if any ACK is missing, escalate.
                    # We don't have explicit recipient list; treat as overdue attention signal.
                    b.escalated_at = datetime.utcnow()
                    b.escalation_note = f"ACK overdue (> {int(s.broadcast_escalation_minutes or 30)} min)"
                    db.session.add(b)
                    db.session.commit()

                    # Audit + notify
                    try:
                        log_event(b.issuer_id, "BROADCAST_ESCALATED", f"{b.id}")
                    except Exception:
                        pass

                    socketio.emit(
                        "broadcast_escalated",
                        {"id": b.id, "title": b.title, "priority": b.priority},
                        room="broadcast_admins",
                    )
                    socketio.emit(
                        "broadcast_escalated",
                        {"id": b.id, "title": b.title, "priority": b.priority},
                        room=f"user_{b.issuer_id}",
                    )

    socketio.start_background_task(_loop)
