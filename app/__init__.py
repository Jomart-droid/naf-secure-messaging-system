import os
import logging
from pathlib import Path
from logging.handlers import RotatingFileHandler
from flask import Flask, request, session, redirect, url_for, flash, jsonify
from flask_login import current_user
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from dotenv import load_dotenv
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import Markup

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)

# SocketIO for real-time messaging
socketio = SocketIO(async_mode="threading", cors_allowed_origins=[])


def _auto_seed_naf_units(app):
    """Seed bundled NAF units once for a fresh database."""
    try:
        from pathlib import Path
        import csv
        from .models import Unit

        if Unit.query.count() > 0:
            return

        csv_path = Path(app.root_path).parent / "data" / "naf_units_seed.csv"
        if not csv_path.exists():
            app.logger.warning("NAF unit seed file not found: %s", csv_path)
            return

        with csv_path.open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))

        by_code = {}
        for row in rows:
            code = (row.get("code") or "").strip()
            if not code:
                continue
            unit = Unit(
                code=code,
                name=(row.get("name") or code).strip(),
                level=(row.get("level") or "UNIT").strip().upper(),
            )
            db.session.add(unit)
            by_code[code] = unit

        db.session.flush()

        for row in rows:
            code = (row.get("code") or "").strip()
            parent_code = (row.get("parent_code") or "").strip()
            unit = by_code.get(code)
            if unit is None:
                continue
            unit.parent = by_code.get(parent_code) if parent_code else None

        db.session.commit()
        app.logger.info("Auto-seeded %s NAF units from %s", len(by_code), csv_path.name)
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to auto-seed NAF units")


def _sqlite_ensure_schema(app):
    """Best-effort additive schema upgrade for existing SQLite databases."""
    import sqlite3
    from sqlalchemy import text
    uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if not uri.startswith("sqlite:///"):
        return
    db_path = uri.replace("sqlite:///", "", 1)
    if not os.path.isabs(db_path):
        db_path = os.path.join(app.instance_path, os.path.basename(db_path))
    if not os.path.exists(db_path):
        return

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        def cols(table):
            cur.execute(f"PRAGMA table_info({table})")
            return {row[1] for row in cur.fetchall()}
        def add_col(table, ddl):
            name = ddl.split()[0]
            if name not in cols(table):
                cur.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
        add_col("user", "clearance_level VARCHAR(20) DEFAULT 'RESTRICTED' NOT NULL")
        add_col("user", "rank VARCHAR(60)")
        add_col("user", "specialty VARCHAR(120)")
        add_col("user", "email VARCHAR(140)")
        add_col("user", "phone VARCHAR(40)")
        add_col("user", "appointment VARCHAR(120)")
        add_col("user", "account_type VARCHAR(20) DEFAULT 'OFFICER' NOT NULL")
        for ddl in [
            "failed_login_count INTEGER DEFAULT 0 NOT NULL",
            "locked_until DATETIME",
            "last_login_at DATETIME",
            "last_login_ip VARCHAR(64)",
            "password_changed_at DATETIME",
            "must_change_password BOOLEAN DEFAULT 0 NOT NULL",
        ]:
            add_col("user", ddl)
        for ddl in [
            "maintenance_reason VARCHAR(60) DEFAULT 'Scheduled maintenance' NOT NULL",
            "maintenance_expected_return VARCHAR(80) DEFAULT '' NOT NULL",
            "password_min_length INTEGER DEFAULT 12 NOT NULL",
            "require_password_complexity BOOLEAN DEFAULT 1 NOT NULL",
            "failed_login_limit INTEGER DEFAULT 5 NOT NULL",
            "lockout_minutes INTEGER DEFAULT 15 NOT NULL",
            "audit_retention_days INTEGER DEFAULT 365 NOT NULL",
            "allow_signal_print BOOLEAN DEFAULT 1 NOT NULL",
            "allow_signal_download BOOLEAN DEFAULT 1 NOT NULL",
        ]:
            try:
                add_col("settings", ddl)
            except Exception:
                pass
        for ddl in [
            "status VARCHAR(20) DEFAULT 'RELEASED' NOT NULL",
            "body_format VARCHAR(20) DEFAULT 'html' NOT NULL",
            "submitted_at DATETIME",
            "approved_at DATETIME",
            "released_at DATETIME",
            "reviewed_by_id INTEGER",
            "approved_by_id INTEGER",
            "released_by_id INTEGER",
            "current_handler_id INTEGER",
            "unit_ao_id INTEGER",
            "unit_signatory_id INTEGER",
            "unit_commander_id INTEGER",
            "routed_to_ao_at DATETIME",
            "ao_reviewed_at DATETIME",
            "routed_to_signatory_at DATETIME",
            "signatory_signed_at DATETIME",
            "routed_to_commander_at DATETIME",
            "commander_approved_at DATETIME",
            "returned_at DATETIME",
            "returned_by_id INTEGER",
            "return_reason VARCHAR(500)",
            "action_users_csv TEXT",
            "info_users_csv TEXT",
            "action_units_csv TEXT",
            "info_units_csv TEXT",
            "from_unit_id INTEGER",
            "drafter_rank VARCHAR(40)",
            "message_instruction VARCHAR(200)",
            "internal_distribution VARCHAR(200)",
            "file_reference VARCHAR(120)",
            "refers_classified_message BOOLEAN DEFAULT 0 NOT NULL",
            "comms_gen_serial_no VARCHAR(80)",
            "sender_receiver_op VARCHAR(120)",
            "transmission_system VARCHAR(120)",
            "time_in_out VARCHAR(80)",
            "digital_signature VARCHAR(128)",
            "signature_fingerprint VARCHAR(24)",
            "signed_at DATETIME",
            "signed_by_id INTEGER",
            "releasing_signature_image VARCHAR(255)",
            "signal_precedence VARCHAR(20) DEFAULT 'ROUTINE' NOT NULL",
            "ack_deadline_at DATETIME",
            "release_authority_id INTEGER",
            "release_authority_validated_at DATETIME",
            "routing_chain_text VARCHAR(500)",
            "recalled_at DATETIME",
            "recalled_by_id INTEGER",
            "recall_reason VARCHAR(500)",
            "corrected_from_id INTEGER",
            "superseded_by_id INTEGER",
            "channel_id INTEGER",
        ]:
            add_col("broadcast", ddl)
        add_col("attachment", "sha256 VARCHAR(64)")
        add_col("broadcast_attachment", "sha256 VARCHAR(64)")
        for ddl in [
            "sha256 VARCHAR(64)",
            "signature_hash VARCHAR(128)",
            "integrity_status VARCHAR(20) DEFAULT 'PENDING' NOT NULL",
            "verified_at DATETIME",
            "export_count INTEGER DEFAULT 0 NOT NULL",
        ]:
            try:
                add_col("signal_archive", ddl)
            except Exception:
                pass
        for ddl in [
            "payload_sha256 VARCHAR(64)",
            "prev_hash VARCHAR(64)",
            "event_hash VARCHAR(64)",
        ]:
            try:
                add_col("audit_event", ddl)
            except Exception:
                pass
        cur.execute("""CREATE TABLE IF NOT EXISTS channel_units (
            channel_id INTEGER NOT NULL,
            unit_id INTEGER NOT NULL,
            PRIMARY KEY (channel_id, unit_id),
            FOREIGN KEY(channel_id) REFERENCES channel(id),
            FOREIGN KEY(unit_id) REFERENCES unit(id)
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS direct_delivery (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            message_id INTEGER NOT NULL,
            created_at DATETIME,
            UNIQUE(user_id, message_id),
            FOREIGN KEY(user_id) REFERENCES user(id),
            FOREIGN KEY(message_id) REFERENCES message(id)
        )""")
        for ddl in [
            "classification_level VARCHAR(20) DEFAULT 'RESTRICTED' NOT NULL",
            "description VARCHAR(300)",
        ]:
            try:
                add_col("channel", ddl)
            except Exception:
                pass
        conn.commit()
    finally:
        conn.close()


def _auto_seed_signal_distribution_units(app):
    """Ensure official NAF signal distribution units exist without slowing startup.

    Older builds loaded every Unit as a full SQLAlchemy object on every app boot:
        Unit.query.all()
    That becomes very slow once thousands of officers/units are imported and can
    make the development server appear frozen. This version reads only the two
    columns needed for duplicate checks and commits in one batch.
    """
    try:
        from .models import Unit
        from .distribution import all_official_unit_names, unit_code_from_name, normalize_unit_name

        official_names = list(all_official_unit_names())
        if not official_names:
            return

        # Lightweight column-only reads. Do NOT instantiate thousands of Unit objects.
        existing_names = {
            normalize_unit_name(name)
            for (name,) in db.session.query(Unit.name).all()
            if name
        }
        existing_codes = {
            code
            for (code,) in db.session.query(Unit.code).all()
            if code
        }

        new_units = []
        for name in official_names:
            normalized_name = normalize_unit_name(name)
            if normalized_name in existing_names:
                continue

            base_code = unit_code_from_name(name)
            code = base_code
            n = 2
            while code in existing_codes:
                suffix = f"-{n}"
                code = (base_code[:40-len(suffix)] + suffix)
                n += 1

            new_units.append(Unit(name=name, code=code, level="UNIT"))
            existing_names.add(normalized_name)
            existing_codes.add(code)

        if new_units:
            db.session.bulk_save_objects(new_units)
            db.session.commit()
            app.logger.info("Auto-seeded %s official signal distribution units", len(new_units))
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to auto-seed signal distribution units")

def create_app():
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    from config import Config, validate_required_config

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    validate_required_config(app)

    # Uploads (attachments)
    upload_dir = os.path.join(app.instance_path, "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    app.config["UPLOAD_FOLDER"] = upload_dir

    archive_dir = os.path.join(app.instance_path, "signal_bank")
    os.makedirs(archive_dir, exist_ok=True)
    app.config["SIGNAL_ARCHIVE_FOLDER"] = archive_dir

    # App logs to instance/logs/app.log (for SUPER_ADMIN viewing)
    logs_dir = os.path.join(app.instance_path, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    log_path = os.path.join(logs_dir, "app.log")
    handler = RotatingFileHandler(log_path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    ))
    # Avoid duplicate handlers in debug reloads
    if not any(isinstance(h, RotatingFileHandler) for h in app.logger.handlers):
        app.logger.addHandler(handler)
        app.logger.setLevel(logging.INFO)
        app.logger.propagate = False

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    socketio.init_app(app, cors_allowed_origins=os.getenv("SOCKETIO_CORS_ORIGINS", "").split(",") if os.getenv("SOCKETIO_CORS_ORIGINS") else [])

    with app.app_context():
        from . import models  # noqa: F401
        db.create_all()
        _sqlite_ensure_schema(app)

        # Ensure Settings row exists
        from .models import Settings
        from .backup import ensure_daily_system_backup
        Settings.get()
        _auto_seed_naf_units(app)
        _auto_seed_signal_distribution_units(app)
        try:
            ensure_daily_system_backup(app)
        except Exception:
            app.logger.exception("Daily backup generation failed during startup")

    @app.context_processor
    def inject_globals():
        """Global template helpers: platform name + badge counts."""
        from .models import Settings, Message, MessageType, DirectRead, Broadcast, BroadcastAck, User, Notification, UserPreference
        s = Settings.get()
        unread_direct = 0
        unread_broadcast = 0
        unread_notifications = 0
        unit_workflow_counts = {"all": 0, "my_action": 0, "returned": 0, "ready_release": 0, "in_routing": 0, "action_total": 0}
        dark_mode = False

        try:
            if getattr(current_user, "is_authenticated", False):
                inbound = Message.query.filter(
                    Message.msg_type == MessageType.DIRECT.value,
                    Message.recipient_id == current_user.id,
                ).order_by(Message.created_at.desc()).limit(500).all()
                for m in inbound:
                    if not DirectRead.query.filter_by(user_id=current_user.id, message_id=m.id).first():
                        unread_direct += 1

                # View-only officers must not see acknowledgement workload/badges.
                if getattr(current_user, "role", "") != "OFFICER":
                    bcasts = Broadcast.query.order_by(Broadcast.created_at.desc()).limit(500).all()
                    for b in bcasts:
                        if b.requires_ack and not BroadcastAck.query.filter_by(broadcast_id=b.id, user_id=current_user.id).first():
                            unread_broadcast += 1

                unread_notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
                try:
                    from .unit_workflow import workflow_counts_for_user
                    unit_workflow_counts = workflow_counts_for_user(current_user)
                except Exception:
                    unit_workflow_counts = {"all": 0, "my_action": 0, "returned": 0, "ready_release": 0, "in_routing": 0, "action_total": 0}
                dark_mode = UserPreference.get_for(current_user.id).dark_mode
        except Exception:
            pass

        setup_available = False
        try:
            setup_available = (User.query.count() == 0)
        except Exception:
            pass

        def can_create_signal_template(user=None):
            try:
                from .security import can_create_signal
                return can_create_signal(user or current_user)
            except Exception:
                return False

        def is_view_only_officer_template(user=None):
            try:
                u = user or current_user
                return getattr(u, "role", "") == "OFFICER"
            except Exception:
                return False

        def can_manage_unit_officers_template(user=None):
            try:
                from .security import is_unit_management_account
                return is_unit_management_account(user or current_user)
            except Exception:
                return False

        def unit_appointment_label_template(value=None):
            try:
                from .security import unit_appointment_label
                return unit_appointment_label(value if value is not None else getattr(current_user, "appointment", None))
            except Exception:
                return value or "Officer"

        def unit_workflow_responsibility_template(user=None):
            try:
                from .security import normalize_unit_appointment
                u = user or current_user
                appt = normalize_unit_appointment(getattr(u, "appointment", None))
                if getattr(u, "account_type", "") == "UNIT":
                    return "Unit workspace administration"
                return {
                    "CHIEF_CLERK": "Drafts signals and forwards to AO",
                    "ADMIN_OFFICER": "Unit admin, reviews drafts and signs/routes",
                    "SIGNATORY_OFFICER": "Signs signals routed by AO",
                    "COMMANDER": "Final approval and release authority",
                    "OTHER_OFFICER": "Unit officer / internal coordination",
                }.get(appt, "Platform user")
            except Exception:
                return "Platform user"

        return {
            "can_create_signal": can_create_signal_template,
            "is_view_only_officer": is_view_only_officer_template,
            "can_manage_unit_officers": can_manage_unit_officers_template,
            "unit_appointment_label": unit_appointment_label_template,
            "unit_workflow_responsibility": unit_workflow_responsibility_template,
            "settings_platform_name": getattr(s, "platform_name", "NAF Secure Messaging"),
            "unread_direct_count": unread_direct,
            "unread_broadcast_count": unread_broadcast,
            "unread_notification_count": unread_notifications,
            "unit_workflow_count": unit_workflow_counts.get("action_total", 0),
            "unit_workflow_my_action_count": unit_workflow_counts.get("my_action", 0),
            "unit_workflow_returned_count": unit_workflow_counts.get("returned", 0),
            "unit_workflow_ready_release_count": unit_workflow_counts.get("ready_release", 0),
            "unit_workflow_all_count": unit_workflow_counts.get("all", 0),
            "dark_mode": dark_mode,
            "setup_available": setup_available,
            "allow_attachments": bool(getattr(s, "allow_attachments", False)),
            "max_attachment_mb": int(getattr(s, "max_attachment_mb", 10)),
            "session_timeout_seconds": max(60, int(getattr(s, "session_timeout_minutes", 60) or 60) * 60),
            "session_warning_seconds": min(60, max(20, int((int(getattr(s, "session_timeout_minutes", 60) or 60) * 60) * 0.20))),
            "csrf_field": lambda: Markup(f'<input type="hidden" name="csrf_token" value="{Markup.escape(__import__("flask_wtf.csrf", fromlist=["generate_csrf"]).generate_csrf())}">'),
        }



    @app.errorhandler(403)
    def forbidden(error):
        return __import__("flask", fromlist=["render_template"]).render_template("errors/403.html"), 403


    @app.before_request
    def _session_timeout_guard():
        from datetime import datetime, timezone
        from flask_login import logout_user
        if request.endpoint and (request.endpoint.startswith("static") or request.endpoint in {"auth.logout", "auth.session_keepalive", "auth.session_expired_logout"}):
            return
        if getattr(current_user, "is_authenticated", False):
            try:
                from .models import Settings, UserSession
                from .audit import log_event
                timeout_seconds = max(60, int(Settings.get().session_timeout_minutes or 60) * 60)
            except Exception:
                timeout_seconds = int(app.config["PERMANENT_SESSION_LIFETIME"].total_seconds())
                log_event = None
                UserSession = None
            now_ts = int(datetime.now(timezone.utc).timestamp())
            last_seen = int(session.get("last_seen", now_ts))
            if now_ts - last_seen > timeout_seconds:
                user_id = getattr(current_user, "id", None)
                sid = session.get("sid")
                try:
                    if UserSession and sid:
                        rec = UserSession.query.filter_by(session_id=sid, user_id=user_id).order_by(UserSession.created_at.desc()).first()
                        if rec and rec.revoked_at is None:
                            rec.revoked_at = datetime.utcnow()
                            db.session.commit()
                    if log_event:
                        log_event(user_id, "SESSION_EXPIRED_INACTIVITY", {"idle_seconds": now_ts - last_seen, "timeout_seconds": timeout_seconds, "status": "AUTO_LOGOUT"})
                except Exception:
                    db.session.rollback()
                logout_user()
                session.clear()
                flash("Your session expired due to inactivity. Please login again.", "warning")
                return redirect(url_for("auth.login"))
            session["last_seen"] = now_ts
            session.permanent = True

    @app.after_request
    def _security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        return response

    @app.get("/api/health")
    def api_health():
        status = {"app": "ok", "database": "unknown", "encryption": "configured", "socketio": "configured"}
        try:
            from sqlalchemy import text
            db.session.execute(text("SELECT 1"))
            status["database"] = "ok"
        except Exception as exc:
            status["database"] = f"error: {exc.__class__.__name__}"
        return jsonify(status), (200 if status["database"] == "ok" else 503)

    @app.before_request
    def _run_daily_backup_guard():
        from .backup import ensure_daily_system_backup
        try:
            ensure_daily_system_backup(app)
        except Exception:
            app.logger.exception("Daily backup generation failed during request guard")

    # Blueprints
    from .routes.auth import bp as auth_bp
    from .routes.main import bp as main_bp
    from .routes.messaging import bp as msg_bp
    from .routes.admin import bp as admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(msg_bp)
    app.register_blueprint(admin_bp)


    @app.cli.command("import-naf-units")
    def import_naf_units_command():
        """Import the bundled NAF units seed file into the Unit table."""
        import csv
        from pathlib import Path
        from .models import Unit
        csv_path = Path(app.root_path).parent / "data" / "naf_units_seed.csv"
        created = 0
        updated = 0
        with csv_path.open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        by_code = {u.code: u for u in Unit.query.all()}
        for row in rows:
            code = (row.get("code") or "").strip()
            if not code:
                continue
            unit = by_code.get(code)
            if unit is None:
                unit = Unit(code=code)
                db.session.add(unit)
                by_code[code] = unit
                created += 1
            else:
                updated += 1
            unit.name = (row.get("name") or code).strip()
            unit.level = (row.get("level") or "UNIT").strip().upper()
        db.session.flush()
        for row in rows:
            code = (row.get("code") or "").strip()
            parent_code = (row.get("parent_code") or "").strip()
            unit = by_code.get(code)
            if not unit:
                continue
            unit.parent = by_code.get(parent_code) if parent_code else None
        db.session.commit()
        print(f"Imported NAF units. Created: {created}, updated: {updated}")

    # Socket handlers
    from .sockets import register_socketio_handlers
    register_socketio_handlers(socketio)

    # Background policy jobs (ACK escalation)
    from .escalation import run_escalation_sweep
    run_escalation_sweep(socketio, app)

    @app.before_request
    def _enforce_policies():
        from flask import session, redirect, url_for, request, flash
        from flask_login import current_user, logout_user
        from .models import Settings, UserSession
        s = Settings.get()
        # System lock / maintenance mode:
        # - Static assets, health, logout and login page remain available.
        # - HQ admins may sign in to unlock/change the notice.
        # - Normal users see a polished lock screen instead of entering the app.
        if getattr(s, "maintenance_mode", False):
            allow_prefix = ("/static",)
            allow_exact = {"/login", "/logout", "/health"}
            admin_unlock_paths = {"/admin/settings"}
            is_admin = getattr(current_user, "is_authenticated", False) and getattr(current_user, "role", "") in {"ADMIN", "SUPER_ADMIN"}
            if request.path not in allow_exact and not request.path.startswith(allow_prefix):
                if is_admin and (request.path in admin_unlock_paths or request.path.startswith("/admin/settings")):
                    pass
                elif not is_admin:
                    return redirect(url_for("auth.login"))
        # Force temporary password change before normal platform use.
        if getattr(current_user, "is_authenticated", False) and getattr(current_user, "must_change_password", False):
            if request.path not in {"/account", "/logout"} and not request.path.startswith("/static"):
                flash("Please update your temporary login details before continuing.", "security")
                return redirect(url_for("main.account"))
        # Session revocation
        if getattr(current_user, "is_authenticated", False):
            sid = session.get("sid")
            if sid:
                rec = UserSession.query.filter_by(session_id=sid, user_id=current_user.id).order_by(UserSession.created_at.desc()).first()
                if rec and rec.revoked_at is not None:
                    logout_user()
                    session.pop("sid", None)
                    flash("Your session was revoked. Please login again.", "warning")
                    return redirect(url_for("auth.login"))

    @app.teardown_request
    def _log_exceptions(exc):
        # Ensure exceptions make it into instance/logs/app.log for SUPER_ADMIN review.
        if exc is not None:
            try:
                app.logger.exception("Unhandled exception")
            except Exception:
                pass

    return app
