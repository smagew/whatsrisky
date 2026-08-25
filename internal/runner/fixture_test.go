package runner

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The vulnerable sample project is generated at test time, never committed: a repo
// carrying real-looking credentials trips GitHub push protection and every secret
// scanner pointed at it. The fake credentials are derived from a fixed seed rather
// than written down - splitting a literal is not enough, because the halves are
// still high-entropy strings.

const seed = 20260824

const appTemplate = `import os
import pickle
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
app.secret_key = "hardcoded-flask-secret-key-do-not-do-this"

AWS_ACCESS_KEY_ID = "%s"
AWS_SECRET_ACCESS_KEY = "%s"


@app.route("/user")
def get_user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%%s'" %% name)
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
`

const requirements = "Flask==0.12.2\nrequests==2.19.1\nPyYAML==3.13\nJinja2==2.10\n"

const dockerfile = `FROM python:3.9
USER root
COPY . /app
RUN pip install -r /app/requirements.txt
ENV API_TOKEN=%s
CMD ["python", "/app/app.py"]
`

const uploadPy = `import os

from flask import request

UPLOAD_DIR = "/var/www/uploads"


def save_upload():
    f = request.files["file"]
    dest = os.path.join(UPLOAD_DIR, f.filename)
    f.save(dest)
    os.chmod(dest, 0o777)
    return dest
`

func fakeSecrets() (awsID, awsSecret, ghToken string) {
	source := rand.New(rand.NewSource(seed))
	body := func(length int, alphabet string) string {
		out := make([]byte, length)
		for i := range out {
			out[i] = alphabet[source.Intn(len(alphabet))]
		}
		return string(out)
	}
	const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	return "AKIA" + body(16, upper), body(40, alnum), "ghp_" + body(36, alnum)
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = dir
	command.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}

// vulnApp builds a deliberately vulnerable Flask app in a git repo with two
// commits, so HEAD~1..HEAD is a meaningful diff to scope a scan to.
func vulnApp(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required to build the fixture")
	}
	root := t.TempDir()
	awsID, awsSecret, ghToken := fakeSecrets()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	write("app.py", fmt.Sprintf(appTemplate, awsID, awsSecret))
	write("requirements.txt", requirements)
	write("Dockerfile", fmt.Sprintf(dockerfile, ghToken))
	git(t, root, "init", "-q", ".")
	git(t, root, "add", "-A")
	git(t, root, "commit", "-qm", "initial vulnerable app")
	write("upload.py", uploadPy)
	git(t, root, "add", "-A")
	git(t, root, "commit", "-qm", "add upload handler")
	return root
}

func requireBinary(t *testing.T, binary string) {
	t.Helper()
	if _, err := exec.LookPath(binary); err != nil {
		t.Skipf("%s is not installed", binary)
	}
}

func testConfig(t *testing.T, root string) Config {
	t.Helper()
	return Config{
		Target:          root,
		WorkDir:         t.TempDir(),
		SemgrepConfigs:  []string{"p/security-audit"},
		SemgrepTimeout:  timeout,
		TrivyScanners:   "vuln,misconfig",
		TrivyTimeout:    timeout,
		GitleaksMode:    "auto",
		GitleaksTimeout: timeout,
	}
}
