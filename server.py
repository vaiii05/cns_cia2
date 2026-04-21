"""
CNS Lab - Client-Server Application
Features:
  - Authentication (Register / Login)
  - Password Hashing using SHA-256 (Practical 9)
  - Message Encryption/Decryption using AES (Practical 5)
"""

from flask import Flask, request, jsonify, render_template, session
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64
import os
import json

app = Flask(__name__)
app.secret_key = os.urandom(24)   # Session secret key

# ---------- In-memory "database" ----------
# { username: { "password_hash": "...", "messages": [] } }
users_db = {}

# ==================== HELPER FUNCTIONS ====================

def sha256_hash(text: str) -> str:
    """
    Hash a string using SHA-256.
    Practical 9: Message Digest using SHA algorithm.
    """
    return hashlib.sha256(text.encode()).hexdigest()


def aes_encrypt(plaintext: str, key_str: str) -> dict:
    """
    Encrypt a message using AES (CBC mode).
    Practical 5: AES algorithm for practical applications.

    AES requires key length of 16, 24, or 32 bytes.
    We derive a 16-byte key from the user-provided key via SHA-256.
    IV (Initialization Vector) is randomly generated per encryption.
    """
    # Derive a 16-byte key from the user-provided key string
    key = hashlib.sha256(key_str.encode()).digest()[:16]

    # Generate a random 16-byte IV
    iv = os.urandom(16)

    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad the plaintext to be a multiple of 16 bytes, then encrypt
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iv": base64.b64encode(iv).decode()
    }


def aes_decrypt(ciphertext_b64: str, iv_b64: str, key_str: str) -> str:
    """
    Decrypt a message using AES (CBC mode).
    Reverses the aes_encrypt function.
    """
    # Same key derivation as encryption
    key = hashlib.sha256(key_str.encode()).digest()[:16]

    # Decode base64 ciphertext and IV
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)

    # Create AES cipher with the same key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt and remove padding
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return plaintext.decode()


# ==================== ROUTES ====================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/register", methods=["POST"])
def register():
    """
    Registration endpoint.
    Step 1: Receive username + password from client.
    Step 2: Hash the password using SHA-256.
    Step 3: Store username + hash in the database (never store plain password).
    """
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required."}), 400

    if username in users_db:
        return jsonify({"success": False, "message": "Username already exists."}), 409

    # ---- HASHING (Practical 9: SHA-256) ----
    password_hash = sha256_hash(password)

    users_db[username] = {
        "password_hash": password_hash,
        "messages": []
    }

    return jsonify({
        "success": True,
        "message": "Registration successful!",
        "hash_preview": password_hash[:20] + "..."  # Show first 20 chars for demo
    })


@app.route("/api/login", methods=["POST"])
def login():
    """
    Login endpoint.
    Step 1: Receive username + password from client.
    Step 2: Hash the received password using SHA-256.
    Step 3: Compare hash with stored hash.
    Step 4: If match → create session token.
    """
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if username not in users_db:
        return jsonify({"success": False, "message": "User not found."}), 404

    # ---- HASH COMPARISON ----
    entered_hash = sha256_hash(password)
    stored_hash = users_db[username]["password_hash"]

    if entered_hash != stored_hash:
        return jsonify({"success": False, "message": "Incorrect password."}), 401

    # ---- SESSION (Authentication Token) ----
    session["username"] = username

    return jsonify({
        "success": True,
        "message": f"Welcome, {username}!",
        "entered_hash": entered_hash[:20] + "...",
        "stored_hash": stored_hash[:20] + "..."
    })


@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("username", None)
    return jsonify({"success": True, "message": "Logged out."})


@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    """
    Encryption endpoint.
    Practical 5: AES Algorithm.
    Step 1: Verify user is logged in (authentication check).
    Step 2: Receive plaintext + AES key from client.
    Step 3: Encrypt using AES-128 CBC mode.
    Step 4: Return ciphertext (base64) + IV (base64).
    """
    if "username" not in session:
        return jsonify({"success": False, "message": "Please login first."}), 401

    data = request.get_json()
    plaintext = data.get("message", "").strip()
    aes_key = data.get("key", "").strip()

    if not plaintext or not aes_key:
        return jsonify({"success": False, "message": "Message and key are required."}), 400

    # ---- AES ENCRYPTION (Practical 5) ----
    result = aes_encrypt(plaintext, aes_key)

    # Store encrypted message for the user
    users_db[session["username"]]["messages"].append({
        "ciphertext": result["ciphertext"],
        "iv": result["iv"]
    })

    return jsonify({
        "success": True,
        "ciphertext": result["ciphertext"],
        "iv": result["iv"],
        "key_used": aes_key
    })


@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    """
    Decryption endpoint.
    Practical 5: AES Algorithm (reverse).
    Step 1: Verify user is logged in.
    Step 2: Receive ciphertext + IV + AES key.
    Step 3: Decrypt using AES-128 CBC mode.
    Step 4: Return original plaintext.
    """
    if "username" not in session:
        return jsonify({"success": False, "message": "Please login first."}), 401

    data = request.get_json()
    ciphertext = data.get("ciphertext", "").strip()
    iv = data.get("iv", "").strip()
    aes_key = data.get("key", "").strip()

    if not ciphertext or not iv or not aes_key:
        return jsonify({"success": False, "message": "Ciphertext, IV, and key are required."}), 400

    try:
        # ---- AES DECRYPTION (Practical 5) ----
        plaintext = aes_decrypt(ciphertext, iv, aes_key)
        return jsonify({"success": True, "plaintext": plaintext})
    except Exception as e:
        return jsonify({"success": False, "message": "Decryption failed. Check key/ciphertext."}), 400


@app.route("/api/hash_demo", methods=["POST"])
def hash_demo():
    """
    Demo endpoint: show SHA-256 hash of any text.
    Practical 9: Message Digest using SHA.
    """
    data = request.get_json()
    text = data.get("text", "")
    return jsonify({
        "success": True,
        "input": text,
        "sha256": sha256_hash(text)
    })


if __name__ == "__main__":
    print("=" * 60)
    print("CNS Lab - Client-Server App (Auth + SHA-256 + AES)")
    print("Server running at http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, port=5000)