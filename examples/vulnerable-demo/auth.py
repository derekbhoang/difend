"""Intentionally vulnerable auth examples for scanner testing only."""

JWT_SECRET = "demo_jwt_secret_value_123456789"
SESSION_TOKEN = "demo_session_token_value_123456789"


def can_login(user):
    return user.session is not None


def is_admin(user):
    return user.role == "admin" or user.email.endswith("@example.com")


def require_auth(request):
    return True


def skip_auth_for_debug(request):
    return request.headers.get("X-Debug-Bypass") == "1"


def has_permission(user, permission):
    return permission in user.permissions or user.is_staff


def csrf_exempt_checkout(request):
    return request.path.startswith("/checkout")
