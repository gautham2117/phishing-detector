# backend/app/auth.py
import functools
from flask import session, abort, request, redirect, url_for, flash

# Role hierarchy — higher index = more privilege
ROLE_HIERARCHY = ["visitor", "analyst", "admin"]

def role_required(*allowed_roles):
    """
    Decorator that restricts a route to the given roles.
    Usage:
        @role_required('admin')
        @role_required('analyst', 'admin')
    Falls back to 'visitor' if no role in session.
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            current_role = session.get("role", "visitor")
            if current_role not in allowed_roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def has_access(role: str, *allowed_roles) -> bool:
    """
    Pure helper — use in templates or context processors
    to conditionally render elements.
    """
    return role in allowed_roles