"""VulnRez — intentionally vulnerable Flask app for testing GraphSAST.

DO NOT deploy this. Every route here has intentional security flaws.
"""

import os
import sqlite3
import subprocess

from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
DB_PATH = "vulnrez.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ─── VULN 1: SQL Injection via string concatenation ───────────────────────────

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = get_db()
    cursor = conn.cursor()
    # BAD: direct concatenation into SQL query
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    rows = cursor.fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/search")
def search_users():
    name = request.args.get("name", "")
    conn = get_db()
    cursor = conn.cursor()
    # BAD: f-string interpolation into SQL
    cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{name}%'")
    rows = cursor.fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    conn = get_db()
    cursor = conn.cursor()
    # BAD: % formatting into SQL
    cursor.execute(
        "SELECT * FROM users WHERE username='%s' AND password='%s'" % (username, password)
    )
    user = cursor.fetchone()
    if user:
        return jsonify({"status": "ok", "user_id": user["id"]})
    return jsonify({"status": "fail"}), 401


# ─── VULN 2: Command Injection ────────────────────────────────────────────────

@app.route("/ping")
def ping():
    host = request.args.get("host")
    # BAD: user input passed directly to shell command
    output = os.popen("ping -c 1 " + host).read()
    return output


@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    # BAD: eval of user input
    result = eval(cmd)
    return str(result)


# ─── VULN 3: Path Traversal ───────────────────────────────────────────────────

@app.route("/file")
def read_file():
    filename = request.args.get("name")
    # BAD: no path validation
    with open("/var/data/" + filename) as f:
        return f.read()


# ─── VULN 4: XSS via template injection ──────────────────────────────────────

@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    # BAD: user input directly in template string
    template = "<h1>Hello, " + name + "!</h1>"
    return render_template_string(template)


# ─── VULN 5: Missing authentication (IDOR) ───────────────────────────────────

@app.route("/profile/<int:user_id>")
def get_profile(user_id):
    # BAD: no check that requesting user owns this profile
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if user:
        return jsonify(dict(user))
    return jsonify({"error": "not found"}), 404


@app.route("/admin/users")
def list_all_users():
    # BAD: no authentication check whatsoever
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    return jsonify([dict(r) for r in rows])


# ─── SAFE: Parameterised query (should NOT be flagged) ────────────────────────

@app.route("/safe/user")
def get_user_safe():
    user_id = request.args.get("id")
    conn = get_db()
    cursor = conn.cursor()
    # GOOD: parameterised query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    return jsonify(dict(row) if row else {})


if __name__ == "__main__":
    app.run(debug=True)
