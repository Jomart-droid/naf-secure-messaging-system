from __future__ import annotations

from datetime import datetime
from flask import request
from flask_login import current_user
from flask_socketio import join_room, emit

from .models import Message, MessageType, DirectRead, DirectDelivery, Broadcast, BroadcastAck, Role, User
from .hierarchy import ancestry_ids

# In-memory presence map for the running process. This is perfect for competition/LAN demo
# and can later be moved to Redis when the SocketIO deployment is scaled horizontally.
ACTIVE_CONNECTIONS: dict[str, dict] = {}
USER_SIDS: dict[int, set[str]] = {}


def _utc_now_iso():
    return datetime.utcnow().isoformat() + "Z"


def _online_users_payload(limit=50):
    seen = {}
    for sid, item in ACTIVE_CONNECTIONS.items():
        uid = item.get("user_id")
        if not uid or uid in seen:
            continue
        seen[uid] = item
    users = sorted(seen.values(), key=lambda x: (x.get("name") or "").lower())[:limit]
    return {
        "count": len(seen),
        "users": users,
        "updated_at": _utc_now_iso(),
    }


def _emit_presence(socketio):
    payload = _online_users_payload()
    socketio.emit("presence_update", payload, room="broadcast_all")
    socketio.emit("ops_presence_update", payload, room="broadcast_admins")


def _user_summary(user):
    return {
        "user_id": user.id,
        "name": user.full_name,
        "service_number": user.service_number,
        "role": user.role,
        "rank": user.rank or "",
        "unit_id": user.unit_id,
        "unit": user.unit.code if getattr(user, "unit", None) else "",
        "last_seen": _utc_now_iso(),
    }


def _personal_counts(user_id: int):
    unread_direct = 0
    inbound = Message.query.filter(
        Message.msg_type == MessageType.DIRECT.value,
        Message.recipient_id == user_id
    ).order_by(Message.created_at.desc()).limit(500).all()
    for m in inbound:
        if not DirectRead.query.filter_by(user_id=user_id, message_id=m.id).first():
            unread_direct += 1

    unread_broadcast = 0
    bcasts = Broadcast.query.filter_by(status="RELEASED").order_by(Broadcast.created_at.desc()).limit(500).all()
    for b in bcasts:
        if b.requires_ack:
            if not BroadcastAck.query.filter_by(broadcast_id=b.id, user_id=user_id).first():
                unread_broadcast += 1
    return {"unread_direct": unread_direct, "unread_broadcast": unread_broadcast}


def _ops_metrics():
    released = Broadcast.query.filter_by(status="RELEASED").count()
    pending = Broadcast.query.filter(Broadcast.status.in_(["DRAFT", "SUBMITTED", "APPROVED"])).count()
    ack_pending = 0
    for b in Broadcast.query.filter_by(status="RELEASED", requires_ack=True).order_by(Broadcast.created_at.desc()).limit(300).all():
        # Competition-safe approximate metric: count one pending ack per missing recipient record/ack.
        ack_count = BroadcastAck.query.filter_by(broadcast_id=b.id).count()
        receipt_count = max(1, getattr(b, "receipts", []) and 0 or 0)
        if ack_count == 0:
            ack_pending += 1
    return {
        "released_signals": released,
        "pending_workflow": pending,
        "pending_ack_signals": ack_pending,
        "online_users": _online_users_payload().get("count", 0),
        "updated_at": _utc_now_iso(),
    }



def _mark_direct_delivered_for_user(socketio, user_id: int, limit: int = 200):
    """Mark pending direct messages addressed to a connected user as delivered."""
    pending = Message.query.filter(
        Message.msg_type == MessageType.DIRECT.value,
        Message.recipient_id == user_id
    ).order_by(Message.created_at.desc()).limit(limit).all()
    delivered_by_sender = {}
    changed = False
    for m in pending:
        if not DirectDelivery.query.filter_by(user_id=user_id, message_id=m.id).first():
            db_added = DirectDelivery(user_id=user_id, message_id=m.id)
            from . import db
            db.session.add(db_added)
            delivered_by_sender.setdefault(m.sender_id, []).append(m.id)
            changed = True
    if changed:
        from . import db
        db.session.commit()
        for sender_id, ids in delivered_by_sender.items():
            socketio.emit("direct_delivery", {
                "recipient_id": user_id,
                "message_ids": ids,
                "delivered_at": _utc_now_iso(),
            }, room=f"user_{sender_id}")

def register_socketio_handlers(socketio):
    @socketio.on("connect")
    def _connect():
        if getattr(current_user, "is_authenticated", False):
            sid = request.sid
            summary = _user_summary(current_user)
            ACTIVE_CONNECTIONS[sid] = summary
            USER_SIDS.setdefault(current_user.id, set()).add(sid)

            join_room(f"user_{current_user.id}")
            if getattr(current_user, "role", None) in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
                join_room("broadcast_admins")
            join_room("broadcast_all")
            if getattr(current_user, "unit_id", None):
                join_room(f"broadcast_unit_{current_user.unit_id}")
                for uid in [current_user.unit_id] + ancestry_ids(getattr(current_user, "unit", None)):
                    join_room(f"broadcast_tree_{uid}")

            emit("connected", {"ok": True, "user": summary, "server_time": _utc_now_iso()})
            emit("badge_counts", _personal_counts(current_user.id))
            emit("realtime_metrics", _ops_metrics())
            _mark_direct_delivered_for_user(socketio, current_user.id)
            _emit_presence(socketio)

    @socketio.on("disconnect")
    def _disconnect():
        sid = request.sid
        item = ACTIVE_CONNECTIONS.pop(sid, None)
        if item and item.get("user_id") in USER_SIDS:
            sids = USER_SIDS[item["user_id"]]
            sids.discard(sid)
            if not sids:
                USER_SIDS.pop(item["user_id"], None)
        _emit_presence(socketio)

    @socketio.on("join_channel")
    def _join_channel(data):
        if not getattr(current_user, "is_authenticated", False):
            return
        channel_id = data.get("channel_id")
        if channel_id:
            join_room(f"channel_{int(channel_id)}")
            emit("channel_presence", {"channel_id": int(channel_id), "user": _user_summary(current_user), "event": "joined"}, room=f"channel_{int(channel_id)}", include_self=False)

    @socketio.on("direct_typing")
    def _direct_typing(data):
        if not getattr(current_user, "is_authenticated", False):
            return
        recipient_id = int(data.get("recipient_id") or 0)
        if not recipient_id:
            return
        emit("typing", {"scope": "DIRECT", "from_user_id": current_user.id, "from_name": current_user.full_name, "recipient_id": recipient_id, "is_typing": bool(data.get("is_typing"))}, room=f"user_{recipient_id}")

    @socketio.on("channel_typing")
    def _channel_typing(data):
        if not getattr(current_user, "is_authenticated", False):
            return
        channel_id = int(data.get("channel_id") or 0)
        if not channel_id:
            return
        emit("typing", {"scope": "CHANNEL", "from_user_id": current_user.id, "from_name": current_user.full_name, "channel_id": channel_id, "is_typing": bool(data.get("is_typing"))}, room=f"channel_{channel_id}", include_self=False)

    @socketio.on("request_realtime_metrics")
    def _request_realtime_metrics():
        if getattr(current_user, "is_authenticated", False):
            emit("realtime_metrics", _ops_metrics())
            emit("presence_update", _online_users_payload())


    @socketio.on("direct_mark_delivered")
    def _direct_mark_delivered(data):
        if not getattr(current_user, "is_authenticated", False):
            return
        try:
            message_ids = [int(x) for x in (data.get("message_ids") or [])]
        except Exception:
            return
        if not message_ids:
            return
        from . import db
        delivered_by_sender = {}
        messages = Message.query.filter(Message.id.in_(message_ids)).all()
        for m in messages:
            if m.msg_type != MessageType.DIRECT.value or m.recipient_id != current_user.id:
                continue
            if not DirectDelivery.query.filter_by(user_id=current_user.id, message_id=m.id).first():
                db.session.add(DirectDelivery(user_id=current_user.id, message_id=m.id))
                delivered_by_sender.setdefault(m.sender_id, []).append(m.id)
        if delivered_by_sender:
            db.session.commit()
            for sender_id, ids in delivered_by_sender.items():
                emit("direct_delivery", {"recipient_id": current_user.id, "message_ids": ids, "delivered_at": _utc_now_iso()}, room=f"user_{sender_id}")

    @socketio.on("direct_mark_read")
    def _direct_mark_read(data):
        if not getattr(current_user, "is_authenticated", False):
            return
        try:
            message_ids = [int(x) for x in (data.get("message_ids") or [])]
        except Exception:
            return
        if not message_ids:
            return
        from . import db
        read_by_sender = {}
        messages = Message.query.filter(Message.id.in_(message_ids)).all()
        for m in messages:
            if m.msg_type != MessageType.DIRECT.value or m.recipient_id != current_user.id:
                continue
            if not DirectDelivery.query.filter_by(user_id=current_user.id, message_id=m.id).first():
                db.session.add(DirectDelivery(user_id=current_user.id, message_id=m.id))
            if not DirectRead.query.filter_by(user_id=current_user.id, message_id=m.id).first():
                db.session.add(DirectRead(user_id=current_user.id, message_id=m.id))
                read_by_sender.setdefault(m.sender_id, []).append(m.id)
        if read_by_sender:
            db.session.commit()
            for sender_id, ids in read_by_sender.items():
                emit("direct_read", {
                    "reader_id": current_user.id,
                    "reader_name": current_user.full_name,
                    "message_ids": ids,
                    "read_at": _utc_now_iso()
                }, room=f"user_{sender_id}")

    @socketio.on("ping")
    def _ping():
        emit("pong", {"ok": True, "server_time": _utc_now_iso()})
