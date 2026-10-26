import os
from functools import wraps
from flask import session, redirect, url_for, flash, request, abort, current_app
from werkzeug.security import generate_password_hash, check_password_hash

ALLOWED_ROLES = {"superadmin", "platform_admin", "admin", "billing_user", "customer"}

def hash_password(password):
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Password must be at least 12 characters.")
    return generate_password_hash(password, method="scrypt")

def verify_password(stored_hash, password):
    try:
        return check_password_hash(stored_hash, password)
    except (ValueError, TypeError):
        return False

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped

def roles_required(*roles):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator

def business_id():
    bid = session.get("business_id")
    if not bid:
        abort(403)
    return int(bid)

def audit(conn, action, business_id=None, details=None):
    # Never put passwords, tokens, full payment-card data, or session cookies in details.
    conn.execute(
        """INSERT INTO audit_log(business_id, actor_user_id, action, details, ip_address)
           VALUES (%s, %s, %s, %s::jsonb, %s)""",
        (business_id, session.get("user_id"), action,
         __import__("json").dumps(details or {}), request.remote_addr)
    )
