"""Offline authentication checks for the traced HW2 endpoint."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from server import app as server_app


@pytest.fixture(autouse=True)
def isolated_sessions(tmp_path, monkeypatch):
    """Keep server-side session state and SQLite history local to each test."""
    server_app._SESSIONS.clear()
    monkeypatch.setattr(server_app, "SESSIONS_DB", tmp_path / "sessions.db")
    yield
    server_app._SESSIONS.clear()


def test_create_session_rejects_claimed_role_mismatch(world) -> None:
    """A caller cannot bind shopper 1 to the merchant role."""
    with pytest.raises(HTTPException) as error:
        server_app.create_session(
            server_app.SessionCreate(user_id=1, role="merchant")
        )

    assert error.value.status_code == 403


def test_token_cannot_authorize_another_session(world) -> None:
    """A token is bound to exactly the session that issued it."""
    first = server_app.create_session(
        server_app.SessionCreate(user_id=1, role="shopper")
    )
    second = server_app.create_session(
        server_app.SessionCreate(user_id=1, role="shopper")
    )

    with pytest.raises(HTTPException) as error:
        server_app._authorize(
            second["session_id"], f"Bearer {first['token']}"
        )

    assert error.value.status_code == 403
