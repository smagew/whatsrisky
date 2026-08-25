// Package fixture builds the deliberately vulnerable sample project the tests
// scan.
//
// It is generated rather than committed: a repository carrying real-looking
// credentials trips GitHub push protection and every secret scanner pointed at
// it. The fake credentials are derived from a fixed seed rather than written
// down - splitting a literal is not enough, because the halves are still
// high-entropy strings, and a repeating pattern has too little entropy for a
// secret scanner to accept as real.
package fixture

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// seed makes the fixture reproducible. The bytes are derived from a hash stream
// rather than math/rand: determinism is the requirement, and a hash says
// "derived deterministically" more plainly than a seeded PRNG - which a scanner
// also, reasonably, flags on sight.
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


@app.route("/read")
def read():
    return open(os.path.join("/data", request.args["p"])).read()


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


def render_profile(bio):
    return "<div class='bio'>" + bio + "</div>"
`

// stream yields deterministic bytes from the seed: sha256(seed || counter),
// consumed in order.
type stream struct {
	counter uint64
	buffer  []byte
}

func (s *stream) next() byte {
	if len(s.buffer) == 0 {
		var block [8]byte
		binary.BigEndian.PutUint64(block[:], seed+s.counter)
		sum := sha256.Sum256(block[:])
		s.buffer = sum[:]
		s.counter++
	}
	value := s.buffer[0]
	s.buffer = s.buffer[1:]
	return value
}

// Secrets returns the fake credentials, shaped so scanner rules fire. They are
// derived rather than written down: a literal in the source would trip GitHub
// push protection and every secret scanner pointed at this repository, and a
// low-entropy pattern would be rejected by the very rules the fixture exists to
// exercise.
func Secrets() (awsID, awsSecret, ghToken string) {
	source := &stream{}
	body := func(length int, alphabet string) string {
		out := make([]byte, length)
		for i := range out {
			out[i] = alphabet[int(source.next())%len(alphabet)]
		}
		return string(out)
	}
	const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	return "AKIA" + body(16, upper), body(40, alnum), "ghp_" + body(36, alnum)
}

// Write builds the project in root: a Flask app with a planted flaw for every
// scanner, in a git repo with two commits, so HEAD~1..HEAD is a meaningful diff
// to scope a scan to.
func Write(root string) error {
	awsID, awsSecret, ghToken := Secrets()
	files := map[string]string{
		"app.py":           fmt.Sprintf(appTemplate, awsID, awsSecret),
		"requirements.txt": requirements,
		"Dockerfile":       fmt.Sprintf(dockerfile, ghToken),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			return err
		}
	}
	steps := [][]string{{"init", "-q", "."}, {"add", "-A"}, {"commit", "-qm", "initial vulnerable app"}}
	if err := git(root, steps); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "upload.py"), []byte(uploadPy), 0o600); err != nil {
		return err
	}
	return git(root, [][]string{{"add", "-A"}, {"commit", "-qm", "add upload handler"}})
}

func git(root string, steps [][]string) error {
	for _, args := range steps {
		command := exec.Command("git", args...)
		command.Dir = root
		command.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("git %v: %w\n%s", args, err, output)
		}
	}
	return nil
}
