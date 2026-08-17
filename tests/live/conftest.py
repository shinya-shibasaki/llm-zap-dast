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
def own_target():
    """A target on its OWN port, one per test.

    The scope tests populate and delete ZAP's site tree, and several of the behaviours they
    pin depend on what is already in it. A fresh port means a fresh site node, which isolates
    them from each other without any test calling newSession — the plugin never calls it
    either, and a test that did would wipe the session of whoever is running the daemon.
    """
    yield from start_target("target.py")


@pytest.fixture
def zap_mode():
    """Restore ZAP's mode afterwards. It is global to the session, not per context."""
    before = zap("core", "view", "mode").get("mode", "standard")
    try:
        yield lambda mode: zap("core", "action", "setMode", mode=mode)
    finally:
        zap("core", "action", "setMode", mode=before)


@pytest.fixture
def contexts():
    """Hand out uniquely named contexts and remove every one of them afterwards."""
    made = []

    def new(suffix=""):
        name = f"dast-live-{os.getpid()}-{int(time.time() * 1000) % 100000}{suffix}"
        cid = zap("context", "action", "newContext", contextName=name)["contextId"]
        made.append(name)
        return name, cid

    try:
        yield new
    finally:
        zap("forcedUser", "action", "setForcedUserModeEnabled", boolean="false")
        for name in made:
            zap("context", "action", "removeContext", contextName=name)


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
