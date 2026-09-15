from glm2api.admin import COOKIE_NAME, _check_admin_auth, _cookie_value


class _Config:
    admin_key = "admin-test-key"


def test_admin_auth_accepts_case_insensitive_session_and_cookie_headers():
    session = _cookie_value(_Config.admin_key)

    assert _check_admin_auth({"x-admin-session": session}, _Config())
    assert _check_admin_auth({"X-Admin-Session": session}, _Config())
    assert _check_admin_auth({"Cookie": f"{COOKIE_NAME}={session}"}, _Config())
    assert _check_admin_auth({"cookie": f"{COOKIE_NAME}={session}"}, _Config())
