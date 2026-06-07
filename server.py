"""
BizCommand — AI Business Analyzer + Auth Backend
------------------------------------------------
1. Get a free API key at https://console.anthropic.com
2. Paste it below where it says YOUR_API_KEY_HERE
   (or set the ANTHROPIC_API_KEY environment variable instead)
3. Install deps:  pip install flask flask-cors anthropic
4. Run:           python server.py
5. Open dashboard.html in your browser

Accounts are stored in a local SQLite database (bizcommand.db).
A default owner account is seeded on first run:  admin / admin
"""

import os
import json
import sqlite3
import secrets
from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import anthropic

# ── CONFIG ──────────────────────────────────────────────
API_KEY = os.environ.get("ANTHROPIC_API_KEY")
PORT    = int(os.environ.get("PORT", 5000))
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bizcommand.db")
# ────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
CORS(app)  # allow the HTML file to call this from any origin


# ── FRONTEND ────────────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    """Serve the dashboard so the whole app runs from one service."""
    return send_from_directory(BASE_DIR, "dashboard.html")

client = anthropic.Anthropic(api_key=API_KEY) if API_KEY else None

# Roles that can be assigned to a member. Only "owner" can manage the team.
ALLOWED_ROLES = (
    "owner", "admin", "manager", "developer", "designer",
    "sales", "marketing", "support", "finance", "member", "viewer",
)

# In-memory session tokens: token -> user_id. Cleared on server restart.
SESSIONS = {}


def hash_pw(password):
    # pbkdf2:sha256 is portable everywhere; scrypt (werkzeug's default) needs
    # an OpenSSL build that some Python installs lack.
    return generate_password_hash(password, method="pbkdf2:sha256")


# ── DATABASE ────────────────────────────────────────────
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            email         TEXT,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'member',
            created_at    TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            assignee_id INTEGER,
            priority    TEXT NOT NULL DEFAULT 'medium',
            status      TEXT NOT NULL DEFAULT 'pending',
            created_by  INTEGER,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    # Seed the default owner account if no owner exists.
    cur = db.execute("SELECT COUNT(*) FROM users WHERE role = 'owner'")
    if cur.fetchone()[0] == 0:
        db.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
            ("admin", "owner@bizcommand.io", hash_pw("admin"), "owner"),
        )
    db.commit()
    db.close()


def user_public(row):
    """Serialize a user row without the password hash."""
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "role": row["role"],
        "created_at": row["created_at"],
    }


# ── AUTH HELPERS ────────────────────────────────────────
def current_user():
    """Return the user row for the request's bearer token, or None."""
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.startswith("Bearer ") else None
    if not token:
        return None
    user_id = SESSIONS.get(token)
    if user_id is None:
        return None
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return row


def require_owner():
    """Return (user_row, None) if the caller is an owner, else (None, error_response)."""
    user = current_user()
    if user is None:
        return None, (jsonify({"error": "Not authenticated"}), 401)
    if user["role"] != "owner":
        return None, (jsonify({"error": "Owner access required"}), 403)
    return user, None


def require_auth():
    """Return (user_row, None) if the caller is signed in, else (None, error_response)."""
    user = current_user()
    if user is None:
        return None, (jsonify({"error": "Not authenticated"}), 401)
    return user, None


def task_public(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "assignee_id": row["assignee_id"],
        "assignee": row["assignee_username"],   # joined; None if unassigned
        "priority": row["priority"],
        "status": row["status"],
        "created_at": row["created_at"],
    }


# ── AUTH ENDPOINTS ──────────────────────────────────────
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    email    = (data.get("email") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400

    db = get_db()
    exists = db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
    if exists:
        return jsonify({"error": "That username is already taken"}), 409

    cur = db.execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
        (username, email, hash_pw(password), "member"),
    )
    db.commit()
    row = db.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()

    token = secrets.token_hex(24)
    SESSIONS[token] = row["id"]
    return jsonify({"token": token, "user": user_public(row)})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    row = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Invalid username or password"}), 401

    token = secrets.token_hex(24)
    SESSIONS[token] = row["id"]
    return jsonify({"token": token, "user": user_public(row)})


@app.route("/logout", methods=["POST"])
def logout():
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.startswith("Bearer ") else None
    if token:
        SESSIONS.pop(token, None)
    return jsonify({"ok": True})


@app.route("/me", methods=["GET"])
def me():
    user = current_user()
    if user is None:
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify({"user": user_public(user)})


# ── MEMBER MANAGEMENT (OWNER ONLY) ──────────────────────
@app.route("/roles", methods=["GET"])
def list_roles():
    return jsonify({"roles": list(ALLOWED_ROLES)})


@app.route("/members", methods=["GET"])
def list_members():
    owner, err = require_owner()
    if err:
        return err
    rows = get_db().execute("SELECT * FROM users ORDER BY id").fetchall()
    return jsonify({"members": [user_public(r) for r in rows]})


@app.route("/members", methods=["POST"])
def add_member():
    owner, err = require_owner()
    if err:
        return err

    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    email    = (data.get("email") or "").strip()
    password = data.get("password") or ""
    role     = (data.get("role") or "member").strip().lower()
    if role not in ALLOWED_ROLES:
        role = "member"

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        return jsonify({"error": "That username is already taken"}), 409

    cur = db.execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
        (username, email, hash_pw(password), role),
    )
    db.commit()
    row = db.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
    return jsonify({"member": user_public(row)})


@app.route("/members/<int:member_id>", methods=["DELETE"])
def kick_member(member_id):
    owner, err = require_owner()
    if err:
        return err

    if member_id == owner["id"]:
        return jsonify({"error": "You can't remove yourself"}), 400

    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (member_id,)).fetchone()
    if row is None:
        return jsonify({"error": "Member not found"}), 404

    # Unassign any tasks that pointed at the removed member.
    db.execute("UPDATE tasks SET assignee_id = NULL WHERE assignee_id = ?", (member_id,))
    db.execute("DELETE FROM users WHERE id = ?", (member_id,))
    db.commit()

    # Drop any active sessions for the kicked user.
    for tok, uid in list(SESSIONS.items()):
        if uid == member_id:
            SESSIONS.pop(tok, None)

    return jsonify({"ok": True, "removed": member_id})


# ── TASKS (any signed-in user) ──────────────────────────
PRIORITIES = ("low", "medium", "high")
STATUSES   = ("pending", "done")

# Join expression reused by every task query so task_public() always has assignee_username.
_TASK_SELECT = """
    SELECT t.*, u.username AS assignee_username
    FROM tasks t LEFT JOIN users u ON u.id = t.assignee_id
"""


@app.route("/assignees", methods=["GET"])
def list_assignees():
    """Lightweight people list for assignment dropdowns — any signed-in user."""
    user, err = require_auth()
    if err:
        return err
    rows = get_db().execute("SELECT id, username, role FROM users ORDER BY username").fetchall()
    return jsonify({"assignees": [{"id": r["id"], "username": r["username"], "role": r["role"]} for r in rows]})


@app.route("/tasks", methods=["GET"])
def list_tasks():
    user, err = require_auth()
    if err:
        return err
    db = get_db()
    # Optional filter: /tasks?assignee=me or /tasks?assignee=<id>
    who = request.args.get("assignee")
    if who == "me":
        rows = db.execute(_TASK_SELECT + " WHERE t.assignee_id = ? ORDER BY t.id DESC", (user["id"],)).fetchall()
    elif who and who.isdigit():
        rows = db.execute(_TASK_SELECT + " WHERE t.assignee_id = ? ORDER BY t.id DESC", (int(who),)).fetchall()
    else:
        rows = db.execute(_TASK_SELECT + " ORDER BY t.id DESC").fetchall()
    return jsonify({"tasks": [task_public(r) for r in rows]})


@app.route("/tasks", methods=["POST"])
def create_task():
    user, err = require_auth()
    if err:
        return err

    data = request.get_json() or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"error": "Task title is required"}), 400

    priority = (data.get("priority") or "medium").strip().lower()
    if priority not in PRIORITIES:
        priority = "medium"

    assignee_id = data.get("assignee_id")
    db = get_db()
    if assignee_id in ("", None):
        assignee_id = None
    else:
        try:
            assignee_id = int(assignee_id)
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid assignee"}), 400
        if db.execute("SELECT 1 FROM users WHERE id = ?", (assignee_id,)).fetchone() is None:
            return jsonify({"error": "Assignee not found"}), 404

    cur = db.execute(
        "INSERT INTO tasks (title, assignee_id, priority, status, created_by) VALUES (?,?,?,?,?)",
        (title, assignee_id, priority, "pending", user["id"]),
    )
    db.commit()
    row = db.execute(_TASK_SELECT + " WHERE t.id = ?", (cur.lastrowid,)).fetchone()
    return jsonify({"task": task_public(row)})


@app.route("/tasks/<int:task_id>", methods=["PATCH"])
def update_task(task_id):
    user, err = require_auth()
    if err:
        return err

    db = get_db()
    row = db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if row is None:
        return jsonify({"error": "Task not found"}), 404

    data = request.get_json() or {}
    fields, values = [], []

    if "title" in data:
        title = (data.get("title") or "").strip()
        if not title:
            return jsonify({"error": "Task title cannot be empty"}), 400
        fields.append("title = ?"); values.append(title)

    if "priority" in data:
        p = (data.get("priority") or "").strip().lower()
        if p not in PRIORITIES:
            return jsonify({"error": "Invalid priority"}), 400
        fields.append("priority = ?"); values.append(p)

    if "status" in data:
        s = (data.get("status") or "").strip().lower()
        if s not in STATUSES:
            return jsonify({"error": "Invalid status"}), 400
        fields.append("status = ?"); values.append(s)

    if "assignee_id" in data:
        aid = data.get("assignee_id")
        if aid in ("", None):
            aid = None
        else:
            try:
                aid = int(aid)
            except (TypeError, ValueError):
                return jsonify({"error": "Invalid assignee"}), 400
            if db.execute("SELECT 1 FROM users WHERE id = ?", (aid,)).fetchone() is None:
                return jsonify({"error": "Assignee not found"}), 404
        fields.append("assignee_id = ?"); values.append(aid)

    if not fields:
        return jsonify({"error": "Nothing to update"}), 400

    values.append(task_id)
    db.execute(f"UPDATE tasks SET {', '.join(fields)} WHERE id = ?", values)
    db.commit()
    updated = db.execute(_TASK_SELECT + " WHERE t.id = ?", (task_id,)).fetchone()
    return jsonify({"task": task_public(updated)})


@app.route("/tasks/<int:task_id>", methods=["DELETE"])
def delete_task(task_id):
    user, err = require_auth()
    if err:
        return err
    db = get_db()
    if db.execute("SELECT 1 FROM tasks WHERE id = ?", (task_id,)).fetchone() is None:
        return jsonify({"error": "Task not found"}), 404
    db.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    db.commit()
    return jsonify({"ok": True, "removed": task_id})


# ── AI ANALYZER ─────────────────────────────────────────
SYSTEM_PROMPT = """You are a sharp business analyst and software consultant.
When given a business type, you identify its most painful real-world operational problems
and explain exactly what software or code could be built to fix each one.
Be specific, practical, and direct. Focus on problems that are genuinely solved by code —
not management advice or hiring decisions.
Always respond with valid JSON only — no markdown, no explanation outside the JSON."""

USER_PROMPT_TEMPLATE = """Analyze the business type: "{business}"

Return a JSON array of exactly 6 to 8 problems this business commonly faces that can be fixed with code or software.

Each problem must follow this exact structure:
{{
  "icon": "<a single relevant emoji>",
  "title": "<short problem title, max 8 words>",
  "desc": "<2-3 sentence description of the problem and its impact on the business>",
  "solution": "<strong>Build:</strong> <1-2 sentence description of the specific software/code solution>",
  "tags": ["<tech tag 1>", "<tech tag 2>", "<tech tag 3>"]
}}

Rules:
- icon: pick the most fitting single emoji
- title: punchy, describes the pain point
- desc: explain WHY this is a real business problem and what it costs them
- solution: start with "<strong>Build:</strong>" then describe a concrete tool/app/script to solve it
- tags: 2-4 short technical labels (e.g. "Stripe", "SMS API", "Dashboard", "Mobile App", "Automation")
- Return ONLY the JSON array, nothing else"""


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    business = (data or {}).get("business", "").strip()

    if not business:
        return jsonify({"error": "No business provided"}), 400

    if not API_KEY:
        return jsonify({"error": "API key not set. Set the ANTHROPIC_API_KEY environment variable."}), 500

    try:
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",   # fast + cheap for this use case
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": USER_PROMPT_TEMPLATE.format(business=business)}
            ]
        )

        raw = message.content[0].text.strip()

        # Strip markdown code fences if the model adds them anyway
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        problems = json.loads(raw)
        return jsonify({"business": business, "problems": problems})

    except json.JSONDecodeError as e:
        return jsonify({"error": f"AI returned invalid JSON: {str(e)}", "raw": raw}), 500
    except anthropic.AuthenticationError:
        return jsonify({"error": "Invalid API key. Check your key at console.anthropic.com"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── AI CHAT ASSISTANT ───────────────────────────────────
CHAT_SYSTEM_PROMPT = """You are the BizCommand AI assistant, embedded inside an analytics
dashboard for the business "BizCommand LLC". You help the owner understand their data and
decide what to focus on.

Current dashboard snapshot — ground every answer in these numbers:
- Monthly Recurring Revenue (MRR): $24,830 (up 12.4% vs last month)
- Active customers: 1,284 (38 new this month)
- Churn rate: 2.1% (improved 0.3%)
- Open support tickets: 17 (up 3 since yesterday)
- Annual Run Rate (ARR): $297,960 (up 18% year over year)
- Average Revenue Per User (ARPU): $19.34
- Renewal rate: 97.9%
- Plan mix: Starter 742 (57.8%), Pro 398 (31.0%), Enterprise 144 (11.2%)
- Attention items: RedOak LLC (Enterprise, $499/mo) had a FAILED payment — needs a retry.
  SkyBridge is on a Starter trial that hasn't converted yet.

Style: concise, practical, specific. Use the numbers above and reason from them. When asked
what to focus on, give a short prioritized list. Reply in plain text with short paragraphs or
bullet points — no markdown headers. Don't fabricate precise figures beyond what's given."""


@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json() or {}
    message = (data.get("message") or "").strip()
    history = data.get("history") or []

    if not message:
        return jsonify({"error": "No message provided"}), 400
    if not API_KEY:
        return jsonify({"error": "API key not set. Set the ANTHROPIC_API_KEY environment variable."}), 500

    # Carry up to the last 10 turns for context.
    msgs = []
    for h in history[-10:]:
        role = h.get("role")
        content = (h.get("content") or "").strip()
        if role in ("user", "assistant") and content:
            msgs.append({"role": role, "content": content})
    msgs.append({"role": "user", "content": message})

    try:
        resp = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            system=CHAT_SYSTEM_PROMPT,
            messages=msgs,
        )
        return jsonify({"reply": resp.content[0].text.strip()})
    except anthropic.AuthenticationError:
        return jsonify({"error": "Invalid API key. Check your key at console.anthropic.com"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "api_key_set": bool(API_KEY)})


# Initialize the database at import time so it also runs under gunicorn,
# which never executes the __main__ block below.
init_db()


if __name__ == "__main__":
    print("\n✅  BizCommand server starting...")
    print(f"   Listening on http://localhost:{PORT}")
    print(f"   Database: {DB_PATH}")
    print("   Default owner login:  admin / admin")
    if not API_KEY:
        print("\n⚠️  No API key set! (set ANTHROPIC_API_KEY to enable the AI features)")
    else:
        print("   API key: ✓ set")
    print("   Ready — open http://localhost:%d in your browser\n" % PORT)
    app.run(host="0.0.0.0", port=PORT, debug=False)
