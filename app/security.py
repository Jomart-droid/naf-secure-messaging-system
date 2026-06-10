from functools import wraps
from flask import abort
from flask_login import current_user

CLEARANCE_RANK = {
    "UNCLASSIFIED": 0,
    "RESTRICTED": 1,
    "CONFIDENTIAL": 2,
    "SECRET": 3,
    "TOP SECRET": 4,
}



UNIT_APPOINTMENTS = {
    "CHIEF_CLERK": "Chief Clerk",
    "ADMIN_OFFICER": "Admin Officer",
    "SIGNATORY_OFFICER": "Signatory Officer",
    "OTHER_OFFICER": "Other Officer",
    "COMMANDER": "Commander",
}

def normalize_unit_appointment(value: str | None) -> str:
    raw = (value or "").strip().upper().replace("-", "_").replace(" ", "_")
    aliases = {
        "AO": "ADMIN_OFFICER",
        "ADMIN": "ADMIN_OFFICER",
        "ADMIN_OFFICER": "ADMIN_OFFICER",
        "ADMINISTRATIVE_OFFICER": "ADMIN_OFFICER",
        "CHIEFCLERK": "CHIEF_CLERK",
        "CHIEF_CLERK": "CHIEF_CLERK",
        "CLERK": "CHIEF_CLERK",
        "SIGNATORY": "SIGNATORY_OFFICER",
        "SIGNATORY_OFFICER": "SIGNATORY_OFFICER",
        "OFFICER": "OTHER_OFFICER",
        "OTHER_OFFICER": "OTHER_OFFICER",
        "COMMANDER": "COMMANDER",
        "OC": "COMMANDER",
    }
    return aliases.get(raw, raw)

def unit_appointment_label(value: str | None) -> str:
    key = normalize_unit_appointment(value)
    return UNIT_APPOINTMENTS.get(key, (value or "").strip() or "Officer")



def is_unit_ao_account(user) -> bool:
    """True only for the Admin Officer / Unit AO of a unit workspace.

    The AO is the unit-level administrator: unit users, unit audit, and
    internal workflow oversight are controlled by this appointment, not by
    giving the AO global HQ ADMIN rights.
    """
    return bool(getattr(user, "unit_id", None)) and normalize_unit_appointment(getattr(user, "appointment", None)) == "ADMIN_OFFICER"

def is_unit_workspace_account(user) -> bool:
    """The single login created with the unit record, used to bootstrap unit users."""
    return bool(getattr(user, "unit_id", None)) and getattr(user, "account_type", "") == "UNIT"

def can_manage_unit_users(user) -> bool:
    """Unit user administration guard.

    - HQ Admin/Super Admin can manage all units.
    - The Unit AO manages users inside that unit.
    - The unit workspace account can bootstrap/manage its own unit users.
    - The Commander may view/control the unit space, but AO remains the
      day-to-day unit super admin.
    """
    role = getattr(user, "role", "")
    if role in ("ADMIN", "SUPER_ADMIN"):
        return True
    if not getattr(user, "unit_id", None):
        return False
    if is_unit_ao_account(user):
        return True
    if is_unit_workspace_account(user):
        return True
    # Commander approves signals, but user administration belongs to the Unit AO
    # and the initial Unit Workspace account.
    return False

def is_unit_management_account(user) -> bool:
    """Backward-compatible alias for templates/routes.

    In the corrected unit-account design, the Unit AO is the unit-level super
    admin, while the unit workspace account is used to bootstrap that unit.
    """
    return can_manage_unit_users(user)

def is_unit_chief_clerk(user) -> bool:
    """Only the Chief Clerk drafts unit-originated signals.

    The corrected unit workflow is intentionally strict:
    Chief Clerk drafts -> AO reviews/signs or forwards -> Commander approves -> final release.
    AO, signatory officers and commanders are workflow authorities, not normal drafters.
    """
    return bool(getattr(user, "unit_id", None)) and normalize_unit_appointment(getattr(user, "appointment", None)) == "CHIEF_CLERK"

def is_unit_drafter(user) -> bool:
    # Backward-compatible helper name used in the project. In the corrected
    # design, the unit drafter is the Chief Clerk only.
    return is_unit_chief_clerk(user)

def is_unit_release_authority(user) -> bool:
    appointment = normalize_unit_appointment(getattr(user, "appointment", None))
    return appointment in {"ADMIN_OFFICER", "SIGNATORY_OFFICER", "COMMANDER"}

def require_roles(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role == 'SUPER_ADMIN':
                return fn(*args, **kwargs)
            if current_user.role not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def clearance_rank(level: str | None) -> int:
    return CLEARANCE_RANK.get((level or "RESTRICTED").strip().upper(), 1)

def can_access_classification(user, classification: str | None) -> bool:
    if getattr(user, "role", "") == "SUPER_ADMIN":
        return True
    return clearance_rank(getattr(user, "clearance_level", "RESTRICTED")) >= clearance_rank(classification)


def can_create_signal(user) -> bool:
    """Signal drafting access.

    HQ Admin/Super Admin keep platform-level drafting authority. Inside a unit,
    only the Chief Clerk can create/draft unit-originated signals. AO, Signatory
    Officer and Commander participate later in the approval/release chain.
    """
    if getattr(user, "role", "") in ("ADMIN", "SUPER_ADMIN"):
        return True
    return bool(getattr(user, "unit_id", None)) and is_unit_chief_clerk(user)


def can_target_scope(user, scope: str, unit_id=None) -> bool:
    if getattr(user, "role", "") in ("ADMIN", "SUPER_ADMIN"):
        return True
    # Unit-originated external routing is selected by the Chief Clerk at draft
    # time. The selected recipients may be any valid NAF unit/list/channel;
    # actual external delivery remains blocked until AO/signatory review and
    # Commander final approval are complete.
    if is_unit_chief_clerk(user):
        return scope in ("UNIT", "UNIT_TREE", "CHANNEL", "ALL")
    return False

def can_release_broadcast(user) -> bool:
    if getattr(user, "role", "") in ("ADMIN", "SUPER_ADMIN", "COMMANDER"):
        return True
    return bool(getattr(user, "unit_id", None)) and is_unit_release_authority(user)

def can_approve_broadcast(user) -> bool:
    if getattr(user, "role", "") in ("ADMIN", "SUPER_ADMIN", "COMMANDER"):
        return True
    return bool(getattr(user, "unit_id", None)) and is_unit_release_authority(user)

def is_explicit_broadcast_recipient(user, broadcast) -> bool:
    user_id = getattr(user, "id", None)
    unit_id = getattr(user, "unit_id", None)
    try:
        action_users = set(broadcast.csv_ids("action_users_csv"))
        info_users = set(broadcast.csv_ids("info_users_csv"))
        action_units = set(broadcast.csv_ids("action_units_csv"))
        info_units = set(broadcast.csv_ids("info_units_csv"))
    except Exception:
        return False
    return (user_id in action_users) or (user_id in info_users) or (unit_id in action_units) or (unit_id in info_units)


def can_view_broadcast(user, broadcast, is_target_func) -> bool:
    if getattr(user, "role", "") in ("ADMIN", "SUPER_ADMIN"):
        return True
    if not can_access_classification(user, getattr(broadcast, "security_classification", None)):
        return False
    if is_explicit_broadcast_recipient(user, broadcast):
        return True
    scope = getattr(broadcast, "target_scope", "ALL")
    if scope == "ALL":
        return True
    if scope == "UNIT":
        return bool(getattr(user, "unit_id", None)) and getattr(broadcast, "target_unit_id", None) == getattr(user, "unit_id", None)
    if scope == "UNIT_TREE":
        return bool(getattr(user, "unit", None)) and is_target_func(user.unit, getattr(broadcast, "target_unit_id", None))
    if scope == "LEVEL":
        unit = getattr(user, "unit", None)
        target_level = getattr(broadcast, "target_level", None)
        while unit is not None:
            if getattr(unit, "level", None) == target_level:
                return True
            unit = getattr(unit, "parent", None)
        return False
    return False



def can_view_signal_bank(user, broadcast) -> bool:
    """Global Signal Bank rule.

    Signal Bank is a platform-wide archive of released/archived signals.
    Access is controlled by classification clearance only, not by TO/INFO delivery.
    Draft/submitted/private workflow items remain outside the global bank.
    """
    if getattr(user, "role", "") in ("ADMIN", "SUPER_ADMIN"):
        return True
    status = (getattr(broadcast, "status", "") or "").upper()
    if status not in ("RELEASED", "ARCHIVED"):
        return False
    return can_access_classification(user, getattr(broadcast, "security_classification", None))


def is_signal_delivery_recipient(user, broadcast) -> bool:
    """Unit Inbox/notification rule.

    A user/unit receives notification and inbox receipt only when the user's ID
    or unit is explicitly selected in ACTION/TO or INFO routing.
    """
    return is_explicit_broadcast_recipient(user, broadcast)


def can_external_direct_messages(user) -> bool:
    """Users allowed to open direct message threads outside their own unit.

    Unit Commanders must be able to coordinate with other units and HQ.
    HQ Admin/Super Admin retain full messaging reach. Internal unit messages
    remain available through Unit Messages for same-unit coordination.
    """
    role = getattr(user, "role", "")
    if role in ("ADMIN", "SUPER_ADMIN"):
        return True
    appointment = normalize_unit_appointment(getattr(user, "appointment", None))
    if role == "COMMANDER" or appointment == "COMMANDER":
        return True
    return False

def can_direct_message_user(sender, recipient) -> bool:
    """Direct message permission guard.

    Everyone may message active personnel in their own unit. Unit Commanders
    and HQ operators may message outside their unit.
    """
    if not sender or not recipient:
        return False
    if getattr(recipient, "is_active_flag", True) is False:
        return False
    if getattr(sender, "id", None) == getattr(recipient, "id", None):
        return False
    if can_external_direct_messages(sender):
        return True
    return bool(getattr(sender, "unit_id", None)) and getattr(sender, "unit_id", None) == getattr(recipient, "unit_id", None)


def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """Return password policy status using HQ-configured security settings when available."""
    password = password or ""
    issues = []
    min_len = 12
    require_complexity = True
    try:
        from .models import Settings
        s = Settings.get()
        min_len = int(getattr(s, "password_min_length", 12) or 12)
        require_complexity = bool(getattr(s, "require_password_complexity", True))
    except Exception:
        pass
    if len(password) < min_len:
        issues.append(f"Password must be at least {min_len} characters long")
    if require_complexity:
        if not any(c.isupper() for c in password):
            issues.append("Password must include an uppercase letter")
        if not any(c.islower() for c in password):
            issues.append("Password must include a lowercase letter")
        if not any(c.isdigit() for c in password):
            issues.append("Password must include a number")
        if not any(not c.isalnum() for c in password):
            issues.append("Password must include a special character")
    return (len(issues) == 0, issues)
