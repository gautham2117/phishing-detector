# backend/app/auth.py
import functools
from flask import session, request, redirect, url_for, render_template

ROLE_HIERARCHY = ["visitor", "analyst", "admin"]

def role_required(*allowed_roles):
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


def get_current_role() -> str:
    return session.get("role", "")



def has_access(role: str, *allowed_roles) -> bool:
    """
    Pure helper — use in templates or context processors
    to conditionally render elements.
    """
    return role in allowed_roles