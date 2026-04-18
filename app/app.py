"""
Intentionally vulnerable Flask application for security scanner testing.
DO NOT deploy this application in any production environment.
"""

import os
import sqlite3

from flask import Flask, request, render_template_string

app = Flask(__name__)

# VULN: Hardcoded secret / API key (triggers secret scanner)
API_KEY = "sk-ant-api03-FAKE-KEY-FOR-TESTING-ONLY-do-not-use-xxxxxxxxxxxxxxxx"
DATABASE_PASSWORD = "SuperSecret123!"


def get_db():
    """Get a SQLite database connection."""
    db = sqlite3.connect("app.db")
    db.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)"
    )
    db.execute(
        "INSERT OR IGNORE INTO users (id, username, email) VALUES (1, 'admin', 'admin@example.com')"
    )
    db.commit()
    return db


@app.route("/")
def index():
    return render_template_string(
        "<h1>Vulnerable Test App</h1>"
        "<p>Endpoints: /search, /greet, /health</p>"
    )


@app.route("/search")
def search():
    """VULN: SQL injection via unsanitized user input."""
    query = request.args.get("q", "")
    db = get_db()
    # BAD: string formatting in SQL query
    results = db.execute(
        f"SELECT username, email FROM users WHERE username LIKE '%{query}%'"
    ).fetchall()
    db.close()
    return {"results": [{"username": r[0], "email": r[1]} for r in results]}


@app.route("/greet")
def greet():
    """VULN: Reflected XSS via unsanitized user input in rendered template."""
    name = request.args.get("name", "World")
    # BAD: user input directly interpolated into HTML template
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
