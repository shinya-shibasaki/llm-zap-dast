"""Fixtures for the live suite. See README.md for how to run it."""
import os
import time

import pytest

from harness import start_target, zap


@pytest.fixture(scope="module")
def token_target():
    """The Juice-Shop-shaped token target: Bearer header, JSON API, 401s with a body."""
    yield from start_target("target.py")


@pytest.fixture(scope="module")
def cookie_target():
    """The Rails/Django-shaped session target: cookie session, redirects to /login."""
    yield from start_target("target_cookie.py")


@pytest.fixture
def zap_context():
    """A uniquely named ZAP context, torn down afterwards whatever the test did.

    Tests append every user they create to `user_ids`; forced-user mode is switched off
    first because ZAP refuses to remove a user that is still forced (HTTP 200, Result=FAIL).
    """
    name = f"dast-live-{os.getpid()}-{int(time.time() * 1000) % 100000}"
    cid = zap("context", "action", "newContext", contextName=name)["contextId"]
    state = {"name": name, "id": cid, "user_ids": []}
    try:
        yield state
    finally:
        zap("forcedUser", "action", "setForcedUserModeEnabled", boolean="false")
        for uid in state["user_ids"]:
            zap("users", "action", "removeUser", contextId=cid, userId=uid)
        zap("context", "action", "removeContext", contextName=name)
