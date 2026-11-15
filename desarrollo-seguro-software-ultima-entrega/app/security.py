"""Funciones comprobables sin base de datos: cifrado, cálculo y auditoría."""
import base64
import hashlib
import json
import os
from decimal import Decimal, ROUND_HALF_UP
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def load_key():
    encoded = os.environ.get("DATA_KEY_B64", "")
    if not encoded:
        raise RuntimeError("Falta DATA_KEY_B64. Ejecuta scripts/preparar.py")
    try:
        key = base64.urlsafe_b64decode(encoded.encode("ascii"))
    except Exception as exc:
        raise RuntimeError("DATA_KEY_B64 inválida") from exc
    if len(key) != 32:
        raise RuntimeError("DATA_KEY_B64 debe contener 32 bytes")
    return key


def key_fingerprint(key):
    return hashlib.sha256(b"academic-lab:key-check:v1:" + key).hexdigest()


def aad_for_grade(record_id, student_id, course_id, term, version, kind):
    return json.dumps(
        {"r": str(record_id), "s": str(student_id), "c": str(course_id),
         "t": int(term), "v": int(version), "f": kind},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def encrypt_bytes(plaintext, *, key, aad):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt_bytes(blob, *, key, aad):
    if blob is None or len(blob) < 29:
        raise ValueError("Texto cifrado ausente o inválido")
    payload = bytes(blob)
    return AESGCM(key).decrypt(payload[:12], payload[12:], aad)


def encrypt_grade(value, *, key, record_id, student_id, course_id, term, version, kind):
    return encrypt_bytes(str(value).encode("utf-8"), key=key,
                         aad=aad_for_grade(record_id, student_id, course_id,
                                           term, version, kind))


def decrypt_grade(blob, *, key, record_id, student_id, course_id, term, version, kind):
    return decrypt_bytes(blob, key=key,
                         aad=aad_for_grade(record_id, student_id, course_id,
                                           term, version, kind)).decode("utf-8")


def encrypt_totp(secret, *, key, user_id):
    blob = encrypt_bytes(secret.encode(), key=key, aad=f"totp:v1:{user_id}".encode())
    return "enc:v1:" + base64.urlsafe_b64encode(blob).decode("ascii")


def decrypt_totp(value, *, key, user_id):
    if not value or not value.startswith("enc:v1:"):
        raise ValueError("Secreto TOTP no migrado")
    blob = base64.urlsafe_b64decode(value[7:].encode("ascii"))
    return decrypt_bytes(blob, key=key, aad=f"totp:v1:{user_id}".encode()).decode()


def definitive_grade(terms):
    """terms: {1: Decimal, 2: Decimal, 3: Decimal}; None if incomplete."""
    if set(terms) != {1, 2, 3}:
        return None
    weights = {1: Decimal("0.30"), 2: Decimal("0.30"), 3: Decimal("0.40")}
    value = sum(Decimal(str(terms[n])) * weights[n] for n in weights)
    return value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def hash_audit(previous_hash, payload):
    return hashlib.sha256((previous_hash + payload).encode("utf-8")).hexdigest()


def verify_chain(records):
    previous = "GENESIS"
    for record in records:
        if record["hash_previo"] != previous or record["hash"] != hash_audit(previous, record["payload"]):
            return False, record.get("id")
        previous = record["hash"]
    return True, None
