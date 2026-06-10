import uuid
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from ..models import User, UserSession, Settings, Role
from ..audit import log_event
from .. import db, limiter

bp = Blueprint("auth", __name__)

@bp.get("/login")
def login():
    settings = Settings.get()
    expired_notice = "Your session expired due to inactivity. Please login again." if request.args.get("expired") else None
    if getattr(settings, "maintenance_mode", False):
        return render_template("auth/login.html", maintenance_lock=settings, login_notice=expired_notice)
    return render_template("auth/login.html", login_notice=expired_notice)

@bp.post("/login")
@limiter.limit("5 per minute")
def login_post():
    service_number = request.form.get("service_number","").strip()
    password = request.form.get("password","")
    remember = bool(request.form.get("remember"))
    user = User.query.filter_by(service_number=service_number).first()
    now = datetime.utcnow()
    if user and user.locked_until and user.locked_until > now:
        # Keep login-specific errors on the login page. Do not flash/redirect,
        # otherwise Flask stores the message and it can appear later in the dashboard.
        return render_template(
            "auth/login.html",
            login_error="Account temporarily locked after repeated failed attempts. Try again later or contact an administrator.",
            service_number=service_number,
        ), 401
    settings = Settings.get()
    if getattr(settings, "maintenance_mode", False) and user and user.check_password(password) and user.is_active and user.role not in {Role.ADMIN.value, Role.SUPER_ADMIN.value}:
        log_event(user.id, "LOGIN_BLOCKED_SYSTEM_LOCK", user.service_number)
        return render_template("auth/login.html", maintenance_lock=settings, service_number=service_number), 423

    if not user or not user.check_password(password) or not user.is_active:
        if user:
            user.failed_login_count = int(user.failed_login_count or 0) + 1
            policy = Settings.get()
            max_attempts = int(getattr(policy, "failed_login_limit", 5) or 5)
            lock_minutes = int(getattr(policy, "lockout_minutes", 15) or 15)
            if user.failed_login_count >= max_attempts:
                user.locked_until = now + timedelta(minutes=lock_minutes)
                log_event(user.id, "ACCOUNT_LOCKED_FAILED_LOGIN", f"locked for {lock_minutes} minutes after {user.failed_login_count} failed attempts")
            else:
                log_event(user.id, "FAILED_LOGIN", f"attempt {user.failed_login_count}/{max_attempts}")
            db.session.commit()
        # Render the login template directly so the error cannot leak into the
        # authenticated dashboard flash area on the next request.
        return render_template(
            "auth/login.html",
            login_error="Invalid service number or password.",
            service_number=service_number,
        ), 401
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    user.last_login_ip = request.remote_addr
    db.session.commit()
    login_user(user, remember=remember)
    session["last_seen"] = int(datetime.utcnow().timestamp())
    session.permanent = True
    sid = session.get("sid") or str(uuid.uuid4())
    session["sid"] = sid
    try:
        db.session.add(UserSession(user_id=user.id, session_id=sid, ip=request.remote_addr, user_agent=request.headers.get("User-Agent")))
        db.session.commit()
    except Exception:
        db.session.rollback()
    log_event(user.id, "LOGIN", user.service_number)
    if getattr(user, "must_change_password", False):
        flash("Please update your temporary login details before continuing.", "security")
        return redirect(url_for("main.account"))
    if getattr(Settings.get(), "maintenance_mode", False) and user.role in {Role.ADMIN.value, Role.SUPER_ADMIN.value}:
        flash("System lock is active. Normal users cannot login until it is turned off.", "warning")
        return redirect(url_for("admin.settings"))
    return redirect(url_for("main.dashboard"))

@bp.post("/session/keepalive")
@login_required
def session_keepalive():
    session["last_seen"] = int(datetime.utcnow().timestamp())
    session.permanent = True
    settings = Settings.get()
    return jsonify({
        "ok": True,
        "timeout_seconds": max(60, int(settings.session_timeout_minutes or 60) * 60),
    })


@bp.post("/session/expired")
@login_required
def session_expired_logout():
    user_id = current_user.id
    sid = session.get("sid")
    try:
        if sid:
            rec = UserSession.query.filter_by(session_id=sid, user_id=user_id).order_by(UserSession.created_at.desc()).first()
            if rec and rec.revoked_at is None:
                rec.revoked_at = datetime.utcnow()
        log_event(user_id, "SESSION_EXPIRED_INACTIVITY", {"source": "client_timer", "status": "AUTO_LOGOUT"})
        db.session.commit()
    except Exception:
        db.session.rollback()
    logout_user()
    session.clear()
    return jsonify({"ok": True, "redirect": url_for("auth.login", expired="1")})


@bp.get("/logout")
@login_required
def logout():
    user_id = current_user.id
    sid = session.get("sid")
    try:
        if sid:
            rec = UserSession.query.filter_by(session_id=sid, user_id=user_id).order_by(UserSession.created_at.desc()).first()
            if rec and rec.revoked_at is None:
                rec.revoked_at = datetime.utcnow()
        log_event(user_id, "LOGOUT", {"status": "USER_LOGOUT"})
        db.session.commit()
    except Exception:
        db.session.rollback()
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))
