# backend/app/auth.py
import functools
from flask import session, request, redirect, url_for, render_template

# Role hierarchy — higher index = more privilege
ROLE_HIERARCHY = ["viewer", "analyst", "admin"]

def role_required(*allowed_roles):
    """
    Decorator that restricts a route to the given roles.
    Usage:
        @role_required('admin')
        @role_required('analyst', 'admin')
    Redirects to role select if no role in session.
    Shows access_denied page if role is not allowed.
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            current_role = session.get("role", "")
            if not current_role:
                return redirect(url_for("dashboard_bp.role_select"))
            if current_role not in allowed_roles:
                return render_template(
                    "access_denied.html",
                    path=request.path,
                ), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def has_access(role: str, *allowed_roles) -> bool:
    """
    Pure helper — use in templates or context processors
    to conditionally render elements.
    """
    return role in allowed_roles