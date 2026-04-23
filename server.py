"""
CNS Lab — Hardened Client-Server Application
=============================================
Security features implemented:

1. SHA-256 + SALT (Practical 9)
   - Random 32-byte salt generated per user at registration
   - Stored as  salt:hash  — rainbow tables are defeated

2. Diffie-Hellman Key Exchange (Practical 7)
   - Client & server agree on a shared AES key WITHOUT transmitting it
   - Attacker who intercepts traffic cannot compute the shared key

3. AES-128 CBC Encryption (Practical 5)
   - Messages encrypted with the DH-derived shared key
   - Fresh random IV per message

4. HTTPS / TLS (Practical 13)
   - Self-signed certificate generated at startup
   - All traffic encrypted in transit — defeats MITM & eavesdropping

5. Rate Limiting
   - Max 5 failed login attempts per IP, then 60-second lockout

6. HMAC Integrity Check
   - Every ciphertext is tagged with HMAC-SHA256
   - Server rejects any tampered ciphertext before decryption

7. Secure Session Flags
   - Sessions expire after 30 minutes
   - Cookies are HttpOnly + Secure + SameSite=Strict
"""

from flask import Flask, request, jsonify, render_template, session
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib, hmac, base64, os, ssl, time
from datetime import timedelta

app = Flask(__name__)
app.secret_key         = os.urandom(32)
app.permanent_session_lifetime = timedelta(minutes=30)

# ── Security config ──────────────────────────────────────────────────────────
app.config.update(
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SECURE   = True,       # only sent over HTTPS
    SESSION_COOKIE_SAMESITE = 'Strict',
)

# ── In-memory stores ─────────────────────────────────────────────────────────
users_db   = {}   # { username: { "salt": hex, "hash": hex } }
dh_store   = {}   # { session_id: { "private": int, "shared_key": bytes } }
login_attempts = {}  # { ip: { "count": int, "lockout_until": float } }

# ── Diffie-Hellman Parameters (RFC 3526 — 1024-bit MODP Group 2) ─────────────
# These are public values agreed upon by both sides
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF", 16
)
DH_G = 2   # generator


# ═══════════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def salted_hash(password: str) -> dict:
    """
    SHA-256 + Salt  (Practical 9 — hardened)
    Random 32-byte salt defeats rainbow table attacks.
    Stored format:  { salt: hex, hash: hex }
    """
    salt = os.urandom(32)
    h    = hashlib.sha256(salt + password.encode()).hexdigest()
    return {"salt": salt.hex(), "hash": h}

def verify_password(password: str, stored: dict) -> bool:
    """Re-hash with the stored salt and compare."""
    salt = bytes.fromhex(stored["salt"])
    h    = hashlib.sha256(salt + password.encode()).hexdigest()
    # Constant-time comparison prevents timing attacks
    return hmac.compare_digest(h, stored["hash"])

def dh_generate_keypair() -> dict:
    """
    Diffie-Hellman key generation  (Practical 7)
    Returns { private: int, public: int }
    """
    private = int.from_bytes(os.urandom(32), 'big') % (DH_P - 2) + 2
    public  = pow(DH_G, private, DH_P)
    return {"private": private, "public": public}

def dh_compute_shared(their_public: int, my_private: int) -> bytes:
    """
    Compute shared secret:  shared = their_public ^ my_private mod p
    Both sides get the same value without ever transmitting it.
    """
    shared_int = pow(their_public, my_private, DH_P)
    # Derive a 16-byte AES key from the shared integer via SHA-256
    return hashlib.sha256(shared_int.to_bytes(128, 'big')).digest()[:16]

def aes_encrypt(plaintext: str, key: bytes) -> dict:
    """AES-128 CBC encryption  (Practical 5)"""
    iv     = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct     = cipher.encrypt(pad(plaintext.encode(), 16))
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "iv":         base64.b64encode(iv).decode(),
    }

def aes_decrypt(ct_b64: str, iv_b64: str, key: bytes) -> str:
    """AES-128 CBC decryption  (Practical 5)"""
    cipher = AES.new(key, AES.MODE_CBC, base64.b64decode(iv_b64))
    return unpad(cipher.decrypt(base64.b64decode(ct_b64)), 16).decode()

def make_hmac(key: bytes, data: str) -> str:
    """HMAC-SHA256 for message integrity."""
    return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()

def verify_hmac(key: bytes, data: str, tag: str) -> bool:
    """Constant-time HMAC verification."""
    expected = hmac.new(key, data.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, tag)

def check_rate_limit(ip: str) -> tuple[bool, str]:
    """
    Rate limiting: max 5 failed attempts, then 60-second lockout.
    Returns (allowed, message).
    """
    now = time.time()
    rec = login_attempts.get(ip, {"count": 0, "lockout_until": 0})
    if rec["lockout_until"] > now:
        remaining = int(rec["lockout_until"] - now)
        return False, f"Too many attempts. Try again in {remaining}s."
    return True, ""

def record_failed(ip: str):
    now = time.time()
    rec = login_attempts.get(ip, {"count": 0, "lockout_until": 0})
    rec["count"] += 1
    if rec["count"] >= 5:
        rec["lockout_until"] = now + 60
        rec["count"] = 0
    login_attempts[ip] = rec

def clear_attempts(ip: str):
    login_attempts.pop(ip, None)

def get_session_key() -> bytes | None:
    """Retrieve the DH-derived AES key for this session."""
    sid = session.get("sid")
    if sid and sid in dh_store:
        return dh_store[sid].get("shared_key")
    return None


# ═══════════════════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


# ── Step 1: Client initiates DH handshake ──────────────────────────
@app.route("/api/dh/init", methods=["POST"])
def dh_init():
    """
    DH Handshake — Step 1 of 2  (Practical 7)
    Client sends its DH public key.
    Server generates its own keypair, computes shared secret,
    and returns its public key to the client.
    """
    data           = request.get_json()
    client_pub_hex = data.get("client_public")
    if not client_pub_hex:
        return jsonify({"ok": False, "msg": "Missing client public key."}), 400

    client_public = int(client_pub_hex, 16)

    # Server generates its own DH keypair
    server_kp = dh_generate_keypair()

    # Server computes shared secret
    shared_key = dh_compute_shared(client_public, server_kp["private"])

    # Store shared key mapped to a unique session ID
    sid = base64.b64encode(os.urandom(16)).decode()
    dh_store[sid] = {"shared_key": shared_key}
    session["sid"] = sid
    session.permanent = True

    return jsonify({
        "ok":            True,
        "server_public": hex(server_kp["public"]),
        "p":             hex(DH_P),
        "g":             DH_G,
        "sid":           sid,
    })


# ── Register ───────────────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"ok": False, "msg": "Username and password required."}), 400
    if len(password) < 6:
        return jsonify({"ok": False, "msg": "Password must be at least 6 characters."}), 400
    if username in users_db:
        return jsonify({"ok": False, "msg": "Username already taken."}), 409

    stored = salted_hash(password)   # ← SHA-256 + salt
    users_db[username] = stored

    return jsonify({
        "ok":   True,
        "msg":  "Account created! You can now log in.",
        "salt": stored["salt"][:16] + "...",   # show partial for demo
        "hash": stored["hash"],
    })


# ── Login ──────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    ip       = request.remote_addr
    allowed, msg = check_rate_limit(ip)
    if not allowed:
        return jsonify({"ok": False, "msg": msg}), 429   # 429 Too Many Requests

    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if username not in users_db:
        record_failed(ip)
        return jsonify({"ok": False, "msg": "User not found."}), 404

    if not verify_password(password, users_db[username]):
        record_failed(ip)
        remaining = 5 - login_attempts.get(ip, {}).get("count", 0)
        return jsonify({
            "ok":  False,
            "msg": f"Wrong password. {max(0,remaining)} attempt(s) left before lockout."
        }), 401

    clear_attempts(ip)
    session["user"] = username
    session.permanent = True

    return jsonify({
        "ok":          True,
        "msg":         f"Welcome, {username}!",
        "salt_used":   users_db[username]["salt"][:16] + "...",
        "stored_hash": users_db[username]["hash"],
    })


# ── Logout ─────────────────────────────────────────────────────────
@app.route("/api/logout", methods=["POST"])
def logout():
    sid = session.get("sid")
    if sid:
        dh_store.pop(sid, None)
    session.clear()
    return jsonify({"ok": True})


# ── Encrypt ────────────────────────────────────────────────────────
@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    if "user" not in session:
        return jsonify({"ok": False, "msg": "Not authenticated."}), 401

    key = get_session_key()
    if not key:
        return jsonify({"ok": False, "msg": "DH handshake not completed."}), 400

    data = request.get_json()
    msg  = data.get("message", "").strip()
    if not msg:
        return jsonify({"ok": False, "msg": "Message required."}), 400

    # AES encrypt using DH-derived key
    result = aes_encrypt(msg, key)

    # Attach HMAC for integrity
    tag = make_hmac(key, result["ciphertext"] + result["iv"])

    return jsonify({"ok": True, **result, "hmac": tag})


# ── Decrypt ────────────────────────────────────────────────────────
@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    if "user" not in session:
        return jsonify({"ok": False, "msg": "Not authenticated."}), 401

    key = get_session_key()
    if not key:
        return jsonify({"ok": False, "msg": "DH handshake not completed."}), 400

    data       = request.get_json()
    ciphertext = data.get("ciphertext", "")
    iv         = data.get("iv", "")
    tag        = data.get("hmac", "")

    # Verify HMAC before decrypting — reject tampered data
    if not verify_hmac(key, ciphertext + iv, tag):
        return jsonify({"ok": False, "msg": "⚠ HMAC verification failed — message may be tampered!"}), 400

    try:
        plaintext = aes_decrypt(ciphertext, iv, key)
        return jsonify({"ok": True, "plaintext": plaintext})
    except Exception:
        return jsonify({"ok": False, "msg": "Decryption failed — wrong key or corrupted data."}), 400


# ── Generate self-signed TLS certificate ──────────────────────────
def generate_self_signed_cert():
    """
    Creates a self-signed certificate for HTTPS/TLS  (Practical 13)
    Uses OpenSSL via subprocess — no extra Python deps needed.
    """
    cert_path = "/tmp/cns_cert.pem"
    key_path  = "/tmp/cns_key.pem"
    if not os.path.exists(cert_path):
        os.system(
            f'openssl req -x509 -newkey rsa:2048 -keyout {key_path} '
            f'-out {cert_path} -days 365 -nodes '
            f'-subj "/CN=CNSLab/O=FCRIT/C=IN" 2>/dev/null'
        )
    return cert_path, key_path


if __name__ == "__main__":
    cert, key_file = generate_self_signed_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key_file)

    print("\n" + "="*58)
    print("  CNS Lab — Hardened Secure Server")
    print("  HTTPS → https://127.0.0.1:5443")
    print("  (Accept the self-signed cert warning in browser)")
    print("="*58 + "\n")

    app.run(host="0.0.0.0", port=5443, ssl_context=ctx, debug=False)
