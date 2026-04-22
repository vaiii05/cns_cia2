"""
CNS Lab — Unified Client-Server Application
============================================
One integrated system that uses:
  - SHA-256 (Practical 9)  → for password hashing during Register/Login
  - AES-128 CBC (Practical 5) → for message encryption/decryption after login
  - Session-based Authentication → gates access to encrypt/decrypt

Flow:
  REGISTER  →  hash password with SHA-256  →  store hash
  LOGIN     →  hash entered password  →  compare hashes  →  create session
  ENCRYPT   →  (must be logged in)  →  AES-CBC encrypt message
  DECRYPT   →  (must be logged in)  →  AES-CBC decrypt message
"""

from flask import Flask, request, jsonify, render_template, session
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib, base64, os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Simple in-memory user store: { username: password_hash }
users_db = {}


# ─── HELPERS ────────────────────────────────────────────────────────────────

def sha256(text: str) -> str:
    """SHA-256 hash — Practical 9: Message Digest."""
    return hashlib.sha256(text.encode()).hexdigest()


def aes_encrypt(plaintext: str, key_str: str) -> dict:
    """AES-128 CBC encryption — Practical 5."""
    key    = hashlib.sha256(key_str.encode()).digest()[:16]   # 16-byte key
    iv     = os.urandom(16)                                   # random IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct     = cipher.encrypt(pad(plaintext.encode(), 16))
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "iv":         base64.b64encode(iv).decode(),
    }


def aes_decrypt(ct_b64: str, iv_b64: str, key_str: str) -> str:
    """AES-128 CBC decryption — Practical 5."""
    key    = hashlib.sha256(key_str.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, base64.b64decode(iv_b64))
    return unpad(cipher.decrypt(base64.b64decode(ct_b64)), 16).decode()


# ─── ROUTES ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/register", methods=["POST"])
def register():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"ok": False, "msg": "Username and password required."}), 400
    if username in users_db:
        return jsonify({"ok": False, "msg": "Username already taken."}), 409

    h = sha256(password)                     # ← SHA-256 hashing
    users_db[username] = h

    return jsonify({
        "ok":   True,
        "msg":  "Account created! You can now log in.",
        "hash": h                            # shown in UI for learning
    })


@app.route("/api/login", methods=["POST"])
def login():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if username not in users_db:
        return jsonify({"ok": False, "msg": "User not found."}), 404

    entered_hash = sha256(password)          # ← hash what user typed
    stored_hash  = users_db[username]

    if entered_hash != stored_hash:          # ← compare hashes
        return jsonify({"ok": False, "msg": "Wrong password.", "entered": entered_hash, "stored": stored_hash}), 401

    session["user"] = username               # ← grant session
    return jsonify({
        "ok":           True,
        "msg":          f"Welcome, {username}!",
        "entered_hash": entered_hash,
        "stored_hash":  stored_hash
    })


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    if "user" not in session:
        return jsonify({"ok": False, "msg": "Not authenticated."}), 401

    data  = request.get_json()
    msg   = data.get("message", "").strip()
    key   = data.get("key", "").strip()

    if not msg or not key:
        return jsonify({"ok": False, "msg": "Message and key required."}), 400

    result = aes_encrypt(msg, key)           # ← AES encrypt
    return jsonify({"ok": True, **result})


@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    if "user" not in session:
        return jsonify({"ok": False, "msg": "Not authenticated."}), 401

    data = request.get_json()
    try:
        pt = aes_decrypt(data["ciphertext"], data["iv"], data["key"])
        return jsonify({"ok": True, "plaintext": pt})
    except Exception:
        return jsonify({"ok": False, "msg": "Decryption failed — wrong key or corrupted data."}), 400


if __name__ == "__main__":
    print("\n  CNS Lab Server  →  http://127.0.0.1:5000\n")
    app.run(debug=True, port=5000)