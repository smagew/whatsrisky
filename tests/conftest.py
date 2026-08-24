"""Shared fixtures.

The vulnerable sample project is generated at test time, never committed: a repo
carrying real-looking credentials trips GitHub push protection and every secret
scanner pointed at this repository.

The fake credentials are *derived* from a fixed seed rather than written down.
Splitting a literal across two string parts is not enough - the halves are still
high-entropy strings, and CPython folds the concatenation into the .pyc, so the
whole token reappears in the bytecode. A seeded PRNG leaves nothing to find in
either place while keeping the values reproducible.
"""

from __future__ import annotations

import random
import shutil
import string
import subprocess
from pathlib import Path

import pytest

APP_PY = '''\
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
app.secret_key = "hardcoded-flask-secret-key-do-not-do-this"

AWS_ACCESS_KEY_ID = "{aws_id}"
AWS_SECRET_ACCESS_KEY = "{aws_secret}"


@app.route("/user")
def get_user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))


@app.route("/read")
def read():
    return open(os.path.join("/data", request.args["p"])).read()


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
'''

REQUIREMENTS = "Flask==0.12.2\nrequests==2.19.1\nPyYAML==3.13\nJinja2==2.10\n"

DOCKERFILE = '''\
FROM python:3.9
USER root
COPY . /app
RUN pip install -r /app/requirements.txt
ENV API_TOKEN={gh_token}
CMD ["python", "/app/app.py"]
'''

UPLOAD_PY = '''\
import os

from flask import request

UPLOAD_DIR = "/var/www/uploads"


def save_upload():
    f = request.files["file"]
    dest = os.path.join(UPLOAD_DIR, f.filename)
    f.save(dest)
    os.chmod(dest, 0o777)
    return dest


def render_profile(bio):
    return "<div class='bio'>" + bio + "</div>"
'''


SEED = 20260824


def _fake_secrets() -> dict[str, str]:
    """Shaped like the real thing so scanner rules fire; a literal nowhere."""
    rng = random.Random(SEED)

    def body(length: int, alphabet: str = string.ascii_letters + string.digits) -> str:
        return "".join(rng.choice(alphabet) for _ in range(length))

    return {
        "aws_id": "AKIA" + body(16, string.ascii_uppercase + string.digits),
        "aws_secret": body(40),
        "gh_token": "ghp_" + body(36),
    }


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        env={
            "GIT_AUTHOR_NAME": "test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
            "PATH": "/usr/bin:/bin:/usr/local/bin",
            "HOME": str(repo),
        },
    )


@pytest.fixture(scope="session")
def vulnapp(tmp_path_factory) -> Path:
    """A deliberately vulnerable Flask app in a git repo with two commits.

    Commit 1 carries the secrets and the injection sinks; commit 2 adds
    upload.py, so `HEAD~1..HEAD` is a meaningful diff to scope a scan to.
    """
    if not shutil.which("git"):
        pytest.skip("git is required to build the fixture")
    root = tmp_path_factory.mktemp("vulnapp")
    secrets = _fake_secrets()
    (root / "app.py").write_text(APP_PY.format(**secrets), encoding="utf-8")
    (root / "requirements.txt").write_text(REQUIREMENTS, encoding="utf-8")
    (root / "Dockerfile").write_text(DOCKERFILE.format(**secrets), encoding="utf-8")
    _git(root, "init", "-q", ".")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "initial vulnerable app")
    (root / "upload.py").write_text(UPLOAD_PY, encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "add upload handler")
    return root
