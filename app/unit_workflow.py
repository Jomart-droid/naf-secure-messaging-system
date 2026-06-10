"""Reusable helpers for unit internal signal workflow dashboards and badges.

This module intentionally avoids importing route functions so it can be used
inside template context processors without circular imports.
"""
from __future__ import annotations

from sqlalchemy import or_

from .models import Broadcast, Role
from .security import normalize_unit_appointment

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
    "FORWARDED_TO_AO": "With AO",
    "RETURNED_BY_AO": "Returned by AO",
    "APPROVED_BY_AO": "AO Approved",
    "FORWARDED_TO_SIGNATORY": "With Signatory",
    "SIGNED_BY_SIGNATORY": "Signatory Endorsed",
    "PENDING_COMMANDER_APPROVAL": "With Commander",
    "RETURNED_BY_COMMANDER": "Returned by Commander",
    "APPROVED_BY_COMMANDER": "Ready for Release",
}



# Phase 7: unit workflow service-level monitoring.
# These targets are deliberately conservative defaults for a command workflow.
UNIT_WORKFLOW_SLA_HOURS = {
    "DRAFT": 24,
    "FORWARDED_TO_AO": 4,
    "RETURNED_BY_AO": 8,
    "APPROVED_BY_AO": 4,
    "FORWARDED_TO_SIGNATORY": 3,
    "SIGNED_BY_SIGNATORY": 2,
    "PENDING_COMMANDER_APPROVAL": 3,
    "RETURNED_BY_COMMANDER": 8,
    "APPROVED_BY_COMMANDER": 2,
}


def _workflow_anchor_time(b):
    status = (getattr(b, "status", "") or "").upper()
    if status == "FORWARDED_TO_AO":
        return getattr(b, "routed_to_ao_at", None) or getattr(b, "submitted_at", None) or getattr(b, "created_at", None)
    if status in {"APPROVED_BY_AO", "FORWARDED_TO_SIGNATORY"}:
        return getattr(b, "routed_to_signatory_at", None) or getattr(b, "ao_reviewed_at", None) or getattr(b, "created_at", None)
    if status == "SIGNED_BY_SIGNATORY":
        return getattr(b, "signatory_signed_at", None) or getattr(b, "created_at", None)
    if status == "PENDING_COMMANDER_APPROVAL":
        return getattr(b, "routed_to_commander_at", None) or getattr(b, "signatory_signed_at", None) or getattr(b, "ao_reviewed_at", None) or getattr(b, "created_at", None)
    if status in {"RETURNED_BY_AO", "RETURNED_BY_COMMANDER"}:
        return getattr(b, "returned_at", None) or getattr(b, "created_at", None)
    if status == "APPROVED_BY_COMMANDER":
        return getattr(b, "commander_approved_at", None) or getattr(b, "created_at", None)
    return getattr(b, "created_at", None)


def workflow_due_info(b, now=None):
    """Return display-safe age/SLA information for a unit workflow signal."""
    from datetime import datetime, timedelta
    now = now or datetime.utcnow()
    status = (getattr(b, "status", "") or "").upper()
    anchor = _workflow_anchor_time(b) or now
    try:
        age_seconds = max((now - anchor).total_seconds(), 0)
    except Exception:
        anchor = now
        age_seconds = 0
    age_hours = age_seconds / 3600.0
    sla_hours = UNIT_WORKFLOW_SLA_HOURS.get(status, 12)
    due_at = anchor + timedelta(hours=sla_hours)
    remaining_seconds = (due_at - now).total_seconds()
    is_overdue = remaining_seconds < 0
    is_warning = (not is_overdue) and remaining_seconds <= 3600
    if is_overdue:
        severity = "overdue"
        label = "Overdue"
    elif is_warning:
        severity = "warning"
        label = "Due soon"
    else:
        severity = "normal"
        label = "Within time"

    if age_hours < 1:
        age_text = f"{int(age_seconds // 60)}m"
    elif age_hours < 24:
        age_text = f"{age_hours:.1f}h"
    else:
        age_text = f"{age_hours / 24:.1f}d"

    return {
        "status": status,
        "anchor": anchor,
        "due_at": due_at,
        "sla_hours": sla_hours,
        "age_hours": round(age_hours, 2),
        "age_text": age_text,
        "severity": severity,
        "label": label,
        "is_overdue": is_overdue,
        "is_warning": is_warning,
    }


RETURNED_STATUSES = {"RETURNED_BY_AO", "RETURNED_BY_COMMANDER"}
READY_RELEASE_STATUSES = {"APPROVED_BY_COMMANDER"}


def _visible_workflow_filter(user):
    """Build a safe visibility filter for workflow counters/lists."""
    role = getattr(user, "role", "")
    if role in (Role.ADMIN.value, Role.SUPER_ADMIN.value):
        return True

    uid = getattr(user, "id", None)
    unit_id = getattr(user, "unit_id", None)
    appointment = normalize_unit_appointment(getattr(user, "appointment", None))

    clauses = []
    if uid:
        clauses.extend([
            Broadcast.issuer_id == uid,
            Broadcast.current_handler_id == uid,
            Broadcast.unit_ao_id == uid,
            Broadcast.unit_signatory_id == uid,
            Broadcast.unit_commander_id == uid,
            Broadcast.returned_by_id == uid,
        ])

    # AO and Commander need a unit-wide oversight view; other officers only see
    # items they drafted or are handling.
    if unit_id and appointment in {"ADMIN_OFFICER", "COMMANDER"}:
        clauses.append(Broadcast.from_unit_id == unit_id)

    return or_(*clauses) if clauses else False


def visible_unit_workflow_items(user, limit: int = 500):
    """Return workflow broadcasts visible to a user, newest first."""
    if not getattr(user, "is_authenticated", False):
        return []

    filt = _visible_workflow_filter(user)
    if filt is False:
        return []

    query = Broadcast.query.filter(Broadcast.status.in_(list(UNIT_WORKFLOW_STATUSES)))
    if filt is not True:
        query = query.filter(filt)
    return query.order_by(Broadcast.created_at.desc()).limit(limit).all()


def workflow_groups_for_user(user, limit: int = 500):
    """Group visible unit workflow signals for dashboards and queues."""
    items = visible_unit_workflow_items(user, limit=limit)
    uid = getattr(user, "id", None)

    my_action = [b for b in items if getattr(b, "current_handler_id", None) == uid]
    returned = [b for b in items if (getattr(b, "status", "") or "").upper() in RETURNED_STATUSES]
    ready_release = [b for b in items if (getattr(b, "status", "") or "").upper() in READY_RELEASE_STATUSES]
    in_routing = [b for b in items if b not in my_action and b not in returned and b not in ready_release]

    return {
        "all": items,
        "my_action": my_action,
        "returned": returned,
        "ready_release": ready_release,
        "in_routing": in_routing,
    }


def workflow_counts_for_user(user):
    groups = workflow_groups_for_user(user, limit=500)
    action_total = len(groups["my_action"]) + len(groups["returned"]) + len(groups["ready_release"])
    return {
        "all": len(groups["all"]),
        "my_action": len(groups["my_action"]),
        "returned": len(groups["returned"]),
        "ready_release": len(groups["ready_release"]),
        "in_routing": len(groups["in_routing"]),
        "action_total": action_total,
    }
