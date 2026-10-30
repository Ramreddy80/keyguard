from flask import Flask, render_template, jsonify, request
import base64
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)


def derive_key(shared_secret: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


def raw_public_bytes(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def fingerprint(key: bytes) -> str:
    return hashes.Hash(hashes.SHA256()).finalize().hex() if False else __import__("hashlib").sha256(key).hexdigest()[:24].upper()


def seal(key: bytes, plaintext: bytes):
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, None)


def open_sealed(key: bytes, nonce: bytes, ciphertext: bytes):
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def common_response(mode, message, status, status_class, summary, steps, details, lesson, metrics):
    return {
        "mode": mode,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "title": "Unauthenticated Exchange" if mode == "insecure" else "Authenticated Exchange",
        "status": status,
        "status_class": status_class,
        "summary": summary,
        "message": message,
        "steps": steps,
        "details": details,
        "lesson": lesson,
        "metrics": metrics,
    }


def run_insecure_demo(message):
    # Simulated local attack: Eve substitutes ephemeral public keys.
    alice_private = x25519.X25519PrivateKey.generate()
    bob_private = x25519.X25519PrivateKey.generate()
    eve_for_alice_private = x25519.X25519PrivateKey.generate()
    eve_for_bob_private = x25519.X25519PrivateKey.generate()

    alice_eve_secret = alice_private.exchange(eve_for_alice_private.public_key())
    eve_alice_secret = eve_for_alice_private.exchange(alice_private.public_key())
    bob_eve_secret = bob_private.exchange(eve_for_bob_private.public_key())
    eve_bob_secret = eve_for_bob_private.exchange(bob_private.public_key())

    alice_eve_key = derive_key(alice_eve_secret, b"KeyGuard demo Alice-Eve")
    eve_alice_key = derive_key(eve_alice_secret, b"KeyGuard demo Alice-Eve")
    bob_eve_key = derive_key(bob_eve_secret, b"KeyGuard demo Bob-Eve")
    eve_bob_key = derive_key(eve_bob_secret, b"KeyGuard demo Bob-Eve")

    plaintext = message.encode("utf-8")
    nonce_a, ciphertext_a = seal(alice_eve_key, plaintext)
    eve_plaintext = open_sealed(eve_alice_key, nonce_a, ciphertext_a)
    nonce_b, ciphertext_b = seal(eve_bob_key, eve_plaintext)
    bob_plaintext = open_sealed(bob_eve_key, nonce_b, ciphertext_b)

    a_fp = fingerprint(alice_eve_key)
    b_fp = fingerprint(bob_eve_key)

    steps = [
        {"phase": "01", "name": "Handshake initiated", "actor": "ALICE", "kind": "info",
         "detail": "Alice begins an ephemeral X25519 key exchange with Bob."},
        {"phase": "02", "name": "Public key substituted", "actor": "EVE", "kind": "danger",
         "detail": "Without authentication, Eve replaces the public-key messages with her own."},
        {"phase": "03", "name": "Two sessions created", "actor": "SYSTEM", "kind": "warning",
         "detail": "Alice derives a key with Eve; Bob independently derives another key with Eve."},
        {"phase": "04", "name": "Message decrypted", "actor": "EVE", "kind": "danger",
         "detail": "Eve decrypts the message on the first link, then encrypts it for Bob."},
        {"phase": "05", "name": "Message delivered", "actor": "BOB", "kind": "warning",
         "detail": "Bob receives the original text, but the exchange was not end-to-end authenticated."},
    ]

    details = [
        {"label": "Key agreement", "value": "X25519", "state": "neutral"},
        {"label": "Key derivation", "value": "HKDF-SHA-256", "state": "neutral"},
        {"label": "Message encryption", "value": "AES-256-GCM", "state": "neutral"},
        {"label": "Alice ↔ Eve key fingerprints", "value": a_fp, "state": "warning"},
        {"label": "Bob ↔ Eve key fingerprints", "value": b_fp, "state": "warning"},
        {"label": "Alice and Bob share one end-to-end key", "value": "NO", "state": "danger"},
        {"label": "Eve recovered message", "value": eve_plaintext.decode("utf-8"), "state": "danger"},
        {"label": "Bob received message", "value": bob_plaintext.decode("utf-8"), "state": "neutral"},
    ]
    return common_response(
        "insecure", message, "VULNERABLE", "danger",
        "The message was encrypted, but the identities behind the exchanged public keys were not authenticated.",
        steps, details,
        "Encryption protects data in transit only when keys are established correctly. Without authentication, an attacker can create two encrypted links and relay messages between them.",
        {"identity_verified": 0, "attack_detected": 0, "confidentiality_to_attacker": 0, "key_match": 0},
    )


def run_secure_demo(message, attack=True):
    # The trusted signing keys are provisioned by this local demo.
    alice_signing_private = ed25519.Ed25519PrivateKey.generate()
    bob_signing_private = ed25519.Ed25519PrivateKey.generate()
    alice_signing_public = alice_signing_private.public_key()
    bob_signing_public = bob_signing_private.public_key()

    alice_ephemeral_private = x25519.X25519PrivateKey.generate()
    bob_ephemeral_private = x25519.X25519PrivateKey.generate()
    alice_ephemeral_bytes = raw_public_bytes(alice_ephemeral_private.public_key())
    bob_ephemeral_bytes = raw_public_bytes(bob_ephemeral_private.public_key())

    alice_signature = alice_signing_private.sign(alice_ephemeral_bytes)
    bob_signature = bob_signing_private.sign(bob_ephemeral_bytes)

    if attack:
        eve_private = x25519.X25519PrivateKey.generate()
        presented_bob_key = raw_public_bytes(eve_private.public_key())
    else:
        presented_bob_key = bob_ephemeral_bytes

    try:
        bob_signing_public.verify(bob_signature, presented_bob_key)
        verification_passed = True
    except InvalidSignature:
        verification_passed = False

    genuine_alice_secret = alice_ephemeral_private.exchange(bob_ephemeral_private.public_key())
    genuine_bob_secret = bob_ephemeral_private.exchange(alice_ephemeral_private.public_key())
    alice_key = derive_key(genuine_alice_secret, b"KeyGuard authenticated transcript")
    bob_key = derive_key(genuine_bob_secret, b"KeyGuard authenticated transcript")

    if attack:
        status = "ATTACK DETECTED" if not verification_passed else "CHECK FAILED"
        status_class = "success" if not verification_passed else "danger"
        summary = "Alice rejects the substituted key because it does not validate against Bob's trusted Ed25519 signature."
        final_detail = "Eve's replacement key is rejected before it can be accepted as Bob's key."
    else:
        status = "AUTHENTICATED"
        status_class = "success"
        summary = "No substitution was attempted. Bob's signature verifies, and the genuine peers derive matching session keys."
        final_detail = "The original signed public key is accepted after verification."

    steps = [
        {"phase": "01", "name": "Handshake initiated", "actor": "ALICE + BOB", "kind": "info",
         "detail": "Both parties generate ephemeral X25519 key pairs for this session."},
        {"phase": "02", "name": "Keys signed", "actor": "IDENTITY", "kind": "info",
         "detail": "Ed25519 signatures bind each ephemeral public key to a previously trusted identity key."},
        {"phase": "03", "name": "Verification", "actor": "ALICE", "kind": "success" if verification_passed else "danger",
         "detail": "Bob's signature is checked against the public key presented in the handshake."},
        {"phase": "04", "name": "Substitution attempt", "actor": "EVE" if attack else "SYSTEM", "kind": "danger" if attack else "success",
         "detail": "Eve substitutes a public key." if attack else "No attacker substitution was configured."},
        {"phase": "05", "name": "Session decision", "actor": "SYSTEM", "kind": "success" if (not attack or not verification_passed) else "danger",
         "detail": final_detail},
    ]

    details = [
        {"label": "Key agreement", "value": "X25519", "state": "neutral"},
        {"label": "Identity signatures", "value": "Ed25519", "state": "neutral"},
        {"label": "Key derivation", "value": "HKDF-SHA-256", "state": "neutral"},
        {"label": "Message encryption", "value": "AES-256-GCM", "state": "neutral"},
        {"label": "Alice signature generated", "value": "YES" if bool(alice_signature) else "NO", "state": "neutral"},
        {"label": "Bob's presented key signature valid", "value": "YES" if verification_passed else "NO", "state": "success" if verification_passed else "danger"},
        {"label": "Substituted key accepted", "value": "YES" if (attack and verification_passed) else "NO", "state": "danger" if (attack and verification_passed) else "success"},
        {"label": "Genuine session key fingerprints match", "value": "YES" if alice_key == bob_key else "NO", "state": "success" if alice_key == bob_key else "danger"},
        {"label": "Message for secure-session illustration", "value": message, "state": "neutral"},
    ]
    return common_response(
        "secure", message, status, status_class, summary, steps, details,
        "Authentication helps prevent public-key substitution. This educational demo assumes the signing public keys are already trusted; real systems should use established protocols such as TLS 1.3 with proper certificate validation.",
        {"identity_verified": 1 if verification_passed else 0, "attack_detected": 1 if attack and not verification_passed else 0,
         "confidentiality_to_attacker": 1 if attack and verification_passed else 0,
         "key_match": 1 if alice_key == bob_key else 0},
    )


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/run")
def run():
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "insecure")
    message = str(data.get("message", "Transfer 100 credits to Bob")).strip()
    if not message:
        return jsonify({"error": "Please enter a message to simulate."}), 400
    if len(message) > 240:
        return jsonify({"error": "Please keep the demo message under 240 characters."}), 400

    if mode == "insecure":
        result = run_insecure_demo(message)
    elif mode == "secure":
        result = run_secure_demo(message, attack=bool(data.get("attack", True)))
    else:
        return jsonify({"error": "Choose the insecure or secure scenario."}), 400
    return jsonify(result)


if __name__ == "__main__":
    # Local classroom demo only. Do not expose the development server publicly.
    app.run(host="127.0.0.1", port=5000, debug=True)
