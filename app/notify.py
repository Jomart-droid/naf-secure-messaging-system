from __future__ import annotations

from datetime import datetime
from flask_login import current_user
from . import db, socketio
from .models import Notification, NotificationType, MutedThread, UserPreference

def _is_dnd(uid:int) -> bool:
    p = UserPreference.get_for(uid)
    if not p.dnd_enabled:
        return False
    # Simple hour-window check (UTC); good enough for MVP
    h = datetime.utcnow().hour
    if p.dnd_start_hour <= p.dnd_end_hour:
        return p.dnd_start_hour <= h < p.dnd_end_hour
    return (h >= p.dnd_start_hour) or (h < p.dnd_end_hour)

def is_muted(uid:int, thread_type:str, thread_id:int) -> bool:
    return MutedThread.query.filter_by(user_id=uid, thread_type=thread_type, thread_id=thread_id).first() is not None

def create_notification(user_id:int, ntype:str, title:str, body:str|None=None, link:str|None=None, *,
                        thread_type:str|None=None, thread_id:int|None=None, respect_dnd:bool=True):
    if thread_type and thread_id is not None:
        if is_muted(user_id, thread_type, thread_id):
            return
    if respect_dnd and _is_dnd(user_id):
        # still store, just don't push loudly
        pass
    n = Notification(user_id=user_id, ntype=ntype, title=title, body=body, link=link)
    db.session.add(n)
    db.session.commit()
    try:
        socketio.emit("notification", {"type": ntype, "title": title, "body": body, "link": link}, room=f"user_{user_id}")
    except Exception:
        pass

def unread_count(user_id:int) -> int:
    return Notification.query.filter_by(user_id=user_id, is_read=False).count()
