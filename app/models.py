from __future__ import annotations
from datetime import datetime
from enum import Enum
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, login_manager
from .crypto import encrypt_text, decrypt_text

class Role(str, Enum):
    # Keep SUPER_ADMIN internally for setup/technical override. Operational UI exposes only OFFICER, COMMANDER and ADMIN.
    SUPER_ADMIN = "SUPER_ADMIN"
    ADMIN = "ADMIN"  # General Admin / HQ
    COMMANDER = "COMMANDER"
    OFFICER = "OFFICER"  # View-only officer
    MEMBER = "MEMBER"

class Priority(str, Enum):
    RED = "RED"
    AMBER = "AMBER"
    GREEN = "GREEN"

class ClassificationLevel(str, Enum):
    UNCLASSIFIED = "UNCLASSIFIED"
    RESTRICTED = "RESTRICTED"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP SECRET"


class UnitLevel(str, Enum):
    HQ = "HQ"
    COMMAND = "COMMAND"
    BASE = "BASE"
    WING = "WING"
    SQUADRON = "SQUADRON"
    UNIT = "UNIT"


class Unit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    code = db.Column(db.String(40), unique=True, nullable=False)
    level = db.Column(db.String(20), default=UnitLevel.UNIT.value, nullable=False)

    parent_id = db.Column(db.Integer, db.ForeignKey("unit.id"), nullable=True, index=True)
    parent = db.relationship("Unit", remote_side=[id], backref=db.backref("children", lazy="dynamic"))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def ancestry_ids(self) -> list[int]:
        """Return parent chain IDs from immediate parent up to root."""
        ids = []
        p = self.parent
        while p is not None:
            ids.append(p.id)
            p = p.parent
        return ids

    def descendant_ids(self) -> list[int]:
        """Return all descendant unit IDs (depth-first)."""
        ids = []
        stack = list(self.children.all())
        while stack:
            n = stack.pop()
            ids.append(n.id)
            stack.extend(n.children.all())
        return ids


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_number = db.Column(db.String(40), unique=True, nullable=False)
    full_name = db.Column(db.String(140), nullable=False)
    rank = db.Column(db.String(60), nullable=True)
    specialty = db.Column(db.String(120), nullable=True)
    email = db.Column(db.String(140), nullable=True, index=True)
    phone = db.Column(db.String(40), nullable=True)
    appointment = db.Column(db.String(120), nullable=True)
    account_type = db.Column(db.String(20), default="OFFICER", nullable=False)  # OFFICER or UNIT
    role = db.Column(db.String(20), default=Role.MEMBER.value, nullable=False)
    unit_id = db.Column(db.Integer, db.ForeignKey("unit.id"), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active_flag = db.Column(db.Boolean, default=True)
    clearance_level = db.Column(db.String(20), default=ClassificationLevel.RESTRICTED.value, nullable=False)
    failed_login_count = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(64), nullable=True)
    password_changed_at = db.Column(db.DateTime, nullable=True)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    unit = db.relationship("Unit")

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = datetime.utcnow()
        self.failed_login_count = 0
        self.locked_until = None

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        return self.is_active_flag

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

channel_members = db.Table(
    "channel_members",
    db.Column("channel_id", db.Integer, db.ForeignKey("channel.id"), primary_key=True),
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
)

channel_units = db.Table(
    "channel_units",
    db.Column("channel_id", db.Integer, db.ForeignKey("channel.id"), primary_key=True),
    db.Column("unit_id", db.Integer, db.ForeignKey("unit.id"), primary_key=True),
)

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    scope = db.Column(db.String(20), default="UNIT")  # UNIT or MISSION
    classification_level = db.Column(db.String(20), default=ClassificationLevel.RESTRICTED.value, nullable=False)
    description = db.Column(db.String(300), nullable=True)
    unit_id = db.Column(db.Integer, db.ForeignKey("unit.id"), nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    unit = db.relationship("Unit")
    units = db.relationship("Unit", secondary=channel_units, backref="channels")
    created_by = db.relationship("User", foreign_keys=[created_by_id])
    members = db.relationship("User", secondary=channel_members, backref="channels")

class MessageType(str, Enum):
    CHANNEL = "CHANNEL"
    DIRECT = "DIRECT"
    BROADCAST = "BROADCAST"

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    msg_type = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    channel_id = db.Column(db.Integer, db.ForeignKey("channel.id"), nullable=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    broadcast_id = db.Column(db.Integer, db.ForeignKey("broadcast.id"), nullable=True)
    reply_to_id = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=True)
    edited_at = db.Column(db.DateTime, nullable=True)
    deleted_at = db.Column(db.DateTime, nullable=True)
    deleted_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)


    body_enc = db.Column(db.LargeBinary, nullable=False)

    sender = db.relationship("User", foreign_keys=[sender_id])
    channel = db.relationship("Channel")
    recipient = db.relationship("User", foreign_keys=[recipient_id])
    reply_to = db.relationship("Message", remote_side=[id])
    deleted_by = db.relationship("User", foreign_keys=[deleted_by_id])

    def set_body(self, body: str):
        self.body_enc = encrypt_text(body)

    def get_body(self) -> str:
        return decrypt_text(self.body_enc)


class DirectRead(db.Model):
    __tablename__ = "direct_read"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    message_id = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'message_id', name='uq_direct_read_user_msg'),)


class DirectDelivery(db.Model):
    __tablename__ = "direct_delivery"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    message_id = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'message_id', name='uq_direct_delivery_user_msg'),)

class Attachment(db.Model):
    """File attachments for channel/direct messages."""
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=False, index=True)
    uploader_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    original_filename = db.Column(db.String(260), nullable=False)
    stored_filename = db.Column(db.String(260), nullable=False, unique=True)
    mime_type = db.Column(db.String(120), nullable=True)
    size_bytes = db.Column(db.Integer, nullable=False, default=0)
    sha256 = db.Column(db.String(64), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    message = db.relationship("Message", backref=db.backref("attachments", lazy="dynamic"))
    uploader = db.relationship("User", foreign_keys=[uploader_id])


class BroadcastAttachment(db.Model):
    """File attachments for broadcasts/signals."""
    __tablename__ = "broadcast_attachment"
    id = db.Column(db.Integer, primary_key=True)
    broadcast_id = db.Column(db.Integer, db.ForeignKey("broadcast.id"), nullable=False, index=True)
    uploader_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    original_filename = db.Column(db.String(260), nullable=False)
    stored_filename = db.Column(db.String(260), nullable=False, unique=True)
    mime_type = db.Column(db.String(120), nullable=True)
    size_bytes = db.Column(db.Integer, nullable=False, default=0)
    sha256 = db.Column(db.String(64), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    broadcast = db.relationship("Broadcast", backref=db.backref("attachments", lazy="dynamic"))
    uploader = db.relationship("User", foreign_keys=[uploader_id])
class Broadcast(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Display helpers
    title = db.Column(db.String(160), nullable=False)
    priority = db.Column(db.String(10), default=Priority.GREEN.value, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    issuer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    # Targeting
    # - ALL: everyone
    # - UNIT: a single unit
    # - UNIT_TREE: a unit and all its descendants
    # - LEVEL: all units of a given level (+ their descendants)
    target_scope = db.Column(db.String(20), default="ALL")
    target_unit_id = db.Column(db.Integer, db.ForeignKey("unit.id"), nullable=True)
    target_level = db.Column(db.String(20), nullable=True)
    requires_ack = db.Column(db.Boolean, default=True)

    # Escalation (auto-triggered when ACK overdue)
    escalated_at = db.Column(db.DateTime, nullable=True)
    escalation_note = db.Column(db.String(240), nullable=True)

    # --- NAF Message Form skeleton fields ---
    drafter_name = db.Column(db.String(140), nullable=True)
    drafter_rank = db.Column(db.String(40), nullable=True)
    precedence_action = db.Column(db.String(40), nullable=True)
    precedence_info = db.Column(db.String(40), nullable=True)
    msg_from = db.Column(db.String(160), nullable=True)
    from_unit_id = db.Column(db.Integer, db.ForeignKey("unit.id"), nullable=True)
    msg_to = db.Column(db.String(160), nullable=True)
    branch_office = db.Column(db.String(120), nullable=True)
    telephone = db.Column(db.String(40), nullable=True)
    dtg = db.Column(db.String(40), nullable=True)  # Date Time Group
    releasing_signature_rank = db.Column(db.String(80), nullable=True)
    releasing_officer_name = db.Column(db.String(120), nullable=True)
    releasing_signature_image = db.Column(db.String(255), nullable=True)
    message_instruction = db.Column(db.String(200), nullable=True)
    internal_distribution = db.Column(db.String(200), nullable=True)
    file_reference = db.Column(db.String(120), nullable=True)
    refers_classified_message = db.Column(db.Boolean, default=False, nullable=False)
    comms_gen_serial_no = db.Column(db.String(80), nullable=True)
    sender_receiver_op = db.Column(db.String(120), nullable=True)
    transmission_system = db.Column(db.String(120), nullable=True)
    time_in_out = db.Column(db.String(80), nullable=True)
    security_classification = db.Column(db.String(40), nullable=True)
    originator_number = db.Column(db.String(80), nullable=True, index=True)
    digital_signature = db.Column(db.String(128), nullable=True, index=True)
    signature_fingerprint = db.Column(db.String(24), nullable=True)
    signed_at = db.Column(db.DateTime, nullable=True)
    signed_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    # Workflow + routing
    status = db.Column(db.String(20), default="RELEASED", nullable=False, index=True)  # DRAFT, SUBMITTED, APPROVED, RELEASED, ARCHIVED
    body_format = db.Column(db.String(20), default="html", nullable=False)
    submitted_at = db.Column(db.DateTime, nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    released_at = db.Column(db.DateTime, nullable=True)
    reviewed_by_id = db.Column(db.Integer, nullable=True)
    approved_by_id = db.Column(db.Integer, nullable=True)
    released_by_id = db.Column(db.Integer, nullable=True)

    # Unit internal routing workflow (Chief Clerk -> AO -> Signatory -> Commander)
    current_handler_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    unit_ao_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    unit_signatory_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    unit_commander_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    routed_to_ao_at = db.Column(db.DateTime, nullable=True)
    ao_reviewed_at = db.Column(db.DateTime, nullable=True)
    routed_to_signatory_at = db.Column(db.DateTime, nullable=True)
    signatory_signed_at = db.Column(db.DateTime, nullable=True)
    routed_to_commander_at = db.Column(db.DateTime, nullable=True)
    commander_approved_at = db.Column(db.DateTime, nullable=True)
    returned_at = db.Column(db.DateTime, nullable=True)
    returned_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    return_reason = db.Column(db.String(500), nullable=True)

    # Phase 4 - military workflow realism
    signal_precedence = db.Column(db.String(20), default="ROUTINE", nullable=False, index=True)
    ack_deadline_at = db.Column(db.DateTime, nullable=True, index=True)
    release_authority_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    release_authority_validated_at = db.Column(db.DateTime, nullable=True)
    routing_chain_text = db.Column(db.String(500), nullable=True)
    recalled_at = db.Column(db.DateTime, nullable=True, index=True)
    recalled_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    recall_reason = db.Column(db.String(500), nullable=True)
    corrected_from_id = db.Column(db.Integer, db.ForeignKey("broadcast.id"), nullable=True)
    superseded_by_id = db.Column(db.Integer, db.ForeignKey("broadcast.id"), nullable=True)

    action_users_csv = db.Column(db.Text, nullable=True)
    info_users_csv = db.Column(db.Text, nullable=True)
    action_units_csv = db.Column(db.Text, nullable=True)
    info_units_csv = db.Column(db.Text, nullable=True)
    channel_id = db.Column(db.Integer, db.ForeignKey("channel.id"), nullable=True, index=True)

    # Main body (encrypted at rest)
    body_enc = db.Column(db.LargeBinary, nullable=False)

    issuer = db.relationship("User", foreign_keys=[issuer_id])
    target_unit = db.relationship("Unit", foreign_keys=[target_unit_id])
    from_unit = db.relationship("Unit", foreign_keys=[from_unit_id])
    channel = db.relationship("Channel", foreign_keys=[channel_id])
    signed_by = db.relationship("User", foreign_keys=[signed_by_id])
    current_handler = db.relationship("User", foreign_keys=[current_handler_id])
    unit_ao = db.relationship("User", foreign_keys=[unit_ao_id])
    unit_signatory = db.relationship("User", foreign_keys=[unit_signatory_id])
    unit_commander = db.relationship("User", foreign_keys=[unit_commander_id])
    returned_by = db.relationship("User", foreign_keys=[returned_by_id])
    release_authority = db.relationship("User", foreign_keys=[release_authority_id])
    recalled_by = db.relationship("User", foreign_keys=[recalled_by_id])
    corrected_from = db.relationship("Broadcast", remote_side=[id], foreign_keys=[corrected_from_id])
    superseded_by = db.relationship("Broadcast", remote_side=[id], foreign_keys=[superseded_by_id])

    def csv_ids(self, attr_name: str) -> list[int]:
        raw = getattr(self, attr_name, "") or ""
        vals = []
        for part in raw.split(","):
            part = part.strip()
            if part.isdigit():
                vals.append(int(part))
        return vals

    def set_csv_ids(self, attr_name: str, values):
        cleaned = []
        for v in values or []:
            v = str(v).strip()
            if v.isdigit():
                cleaned.append(v)
        setattr(self, attr_name, ",".join(cleaned))

    def set_body(self, body: str):
        self.body_enc = encrypt_text(body)

    def get_body(self) -> str:
        return decrypt_text(self.body_enc)




class SignalArchive(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    broadcast_id = db.Column(db.Integer, db.ForeignKey("broadcast.id"), unique=True, nullable=False, index=True)
    file_name = db.Column(db.String(260), nullable=False, unique=True)
    title = db.Column(db.String(160), nullable=False)
    signal_number = db.Column(db.String(80), nullable=True, index=True)
    classification = db.Column(db.String(40), nullable=True, index=True)
    priority = db.Column(db.String(10), nullable=True, index=True)
    from_unit_text = db.Column(db.String(180), nullable=True)
    sha256 = db.Column(db.String(64), nullable=True, index=True)
    signature_hash = db.Column(db.String(128), nullable=True)
    integrity_status = db.Column(db.String(20), default="PENDING", nullable=False, index=True)
    verified_at = db.Column(db.DateTime, nullable=True)
    export_count = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    broadcast = db.relationship("Broadcast")


class BroadcastReceipt(db.Model):
    """Delivery/Read states for broadcasts (3-tick model).

    - not seen: received_at is NULL
    - received: received_at set, read_at is NULL
    - read: read_at set
    """
    id = db.Column(db.Integer, primary_key=True)
    broadcast_id = db.Column(db.Integer, db.ForeignKey("broadcast.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    received_at = db.Column(db.DateTime, nullable=True)
    read_at = db.Column(db.DateTime, nullable=True)

    __table_args__ = (db.UniqueConstraint('broadcast_id', 'user_id', name='uq_bcast_receipt'),)

    broadcast = db.relationship("Broadcast")
    user = db.relationship("User")


class BroadcastAck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    broadcast_id = db.Column(db.Integer, db.ForeignKey("broadcast.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    acked_at = db.Column(db.DateTime, nullable=True)

    broadcast = db.relationship("Broadcast")
    user = db.relationship("User")

class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(120), nullable=False)
    details = db.Column(db.String(500), nullable=True)
    payload_sha256 = db.Column(db.String(64), nullable=True, index=True)
    prev_hash = db.Column(db.String(64), nullable=True, index=True)
    event_hash = db.Column(db.String(64), nullable=True, unique=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    actor = db.relationship("User", foreign_keys=[actor_id])

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Messaging platform settings
    platform_name = db.Column(db.String(120), default="NAF Secure Messaging", nullable=False)
    maintenance_mode = db.Column(db.Boolean, default=False, nullable=False)
    maintenance_banner = db.Column(db.String(240), default="", nullable=False)
    maintenance_reason = db.Column(db.String(60), default="Scheduled maintenance", nullable=False)
    maintenance_expected_return = db.Column(db.String(80), default="", nullable=False)
    dark_mode_default = db.Column(db.Boolean, default=False, nullable=False)
    allowed_extensions = db.Column(db.String(400), default="png,jpg,jpeg,gif,webp,pdf,doc,docx,xls,xlsx,ppt,pptx,txt,csv,zip,webm,ogg,mp3,wav,m4a,aac", nullable=False)
    storage_backend = db.Column(db.String(40), default="local", nullable=False)  # local or s3/minio later
    retention_days = db.Column(db.Integer, default=90, nullable=False)
    allow_direct_messages = db.Column(db.Boolean, default=True, nullable=False)
    # Allow file uploads for direct/channel/broadcast messages.
    # Default True so attachments work out-of-the-box.
    allow_attachments = db.Column(db.Boolean, default=True, nullable=False)
    max_attachment_mb = db.Column(db.Integer, default=10, nullable=False)
    session_timeout_minutes = db.Column(db.Integer, default=60, nullable=False)

    # Security policy controls
    password_min_length = db.Column(db.Integer, default=12, nullable=False)
    require_password_complexity = db.Column(db.Boolean, default=True, nullable=False)
    failed_login_limit = db.Column(db.Integer, default=5, nullable=False)
    lockout_minutes = db.Column(db.Integer, default=15, nullable=False)
    audit_retention_days = db.Column(db.Integer, default=365, nullable=False)
    allow_signal_print = db.Column(db.Boolean, default=True, nullable=False)
    allow_signal_download = db.Column(db.Boolean, default=True, nullable=False)

    # Broadcast escalation policy
    broadcast_escalation_minutes = db.Column(db.Integer, default=30, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @staticmethod
    def get():
        s = Settings.query.first()
        if not s:
            s = Settings()
            db.session.add(s)
            db.session.commit()
        return s


class NotificationType(str, Enum):
    DIRECT_MESSAGE = "DIRECT_MESSAGE"
    CHANNEL_MESSAGE = "CHANNEL_MESSAGE"
    BROADCAST = "BROADCAST"
    ESCALATION = "ESCALATION"
    SYSTEM = "SYSTEM"

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    ntype = db.Column(db.String(40), nullable=False)
    title = db.Column(db.String(160), nullable=False)
    body = db.Column(db.String(500), nullable=True)
    link = db.Column(db.String(240), nullable=True)
    is_read = db.Column(db.Boolean, default=False, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    user = db.relationship("User", foreign_keys=[user_id])

class UserPreference(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    dark_mode = db.Column(db.Boolean, default=False, nullable=False)
    dnd_enabled = db.Column(db.Boolean, default=False, nullable=False)
    dnd_start_hour = db.Column(db.Integer, default=22, nullable=False)
    dnd_end_hour = db.Column(db.Integer, default=6, nullable=False)

    user = db.relationship("User", foreign_keys=[user_id])

    @staticmethod
    def get_for(uid: int):
        p = UserPreference.query.filter_by(user_id=uid).first()
        if not p:
            s = Settings.get()
            p = UserPreference(user_id=uid, dark_mode=bool(getattr(s, "dark_mode_default", False)))
            db.session.add(p)
            db.session.commit()
        return p

class MutedThread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    thread_type = db.Column(db.String(20), nullable=False)  # DIRECT or CHANNEL
    thread_id = db.Column(db.Integer, nullable=False)       # user_id or channel_id
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", foreign_keys=[user_id])

class MessageReaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    emoji = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    message = db.relationship("Message", backref=db.backref("reactions", lazy="dynamic"))
    user = db.relationship("User", foreign_keys=[user_id])

class UserSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    session_id = db.Column(db.String(80), unique=True, nullable=False, index=True)
    ip = db.Column(db.String(80), nullable=True)
    user_agent = db.Column(db.String(240), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    revoked_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User", foreign_keys=[user_id])

