import os
import uuid
from decimal import Decimal

import pytest
from cryptography.exceptions import InvalidTag

from app.security import (
    aad_for_grade, decrypt_grade, decrypt_totp, definitive_grade,
    encrypt_grade, encrypt_totp, hash_audit, key_fingerprint,
    load_key, verify_chain,
)


@pytest.fixture
def case():
    return dict(key=os.urandom(32),record_id=uuid.uuid4(),student_id=uuid.uuid4(),
                course_id=uuid.uuid4(),term=1,version=1,kind="nota")


def test_aesgcm_roundtrip(case):
    blob=encrypt_grade("4.20",**case)
    assert decrypt_grade(blob,**case)=="4.20"


def test_ciphertext_not_plaintext(case):
    blob=encrypt_grade("4.20",**case)
    assert b"4.20" not in blob


def test_tampering_rejected(case):
    blob=bytearray(encrypt_grade("4.20",**case))
    blob[-1]^=1
    with pytest.raises(InvalidTag):
        decrypt_grade(blob,**case)


def test_wrong_student_rejected(case):
    blob=encrypt_grade("4.20",**case)
    other={**case,"student_id":uuid.uuid4()}
    with pytest.raises(InvalidTag):
        decrypt_grade(blob,**other)


def test_rollback_to_other_version_rejected(case):
    blob=encrypt_grade("4.20",**case)
    with pytest.raises(InvalidTag):
        decrypt_grade(blob,**{**case,"version":2})


def test_swapping_note_observation_rejected(case):
    blob=encrypt_grade("4.20",**case)
    with pytest.raises(InvalidTag):
        decrypt_grade(blob,**{**case,"kind":"observacion"})


def test_different_key_rejected(case):
    blob=encrypt_grade("4.20",**case)
    with pytest.raises(InvalidTag):
        decrypt_grade(blob,**{**case,"key":os.urandom(32)})


def test_totp_secret_roundtrip():
    uid=uuid.uuid4(); key=os.urandom(32)
    enc=encrypt_totp("JBSWY3DPEHPK3PXP",key=key,user_id=uid)
    assert enc.startswith("enc:v1:")
    assert "JBSWY3DPEHPK3PXP" not in enc
    assert decrypt_totp(enc,key=key,user_id=uid)=="JBSWY3DPEHPK3PXP"


def test_totp_wrong_account_rejected():
    key=os.urandom(32)
    encrypted=encrypt_totp("JBSWY3DPEHPK3PXP",key=key,user_id="a")
    with pytest.raises(InvalidTag):
        decrypt_totp(encrypted,key=key,user_id="b")


def test_weighted_grade():
    assert definitive_grade({1:Decimal("3.8"),2:Decimal("4.2"),3:Decimal("4.5")})==Decimal("4.20")


def test_incomplete_grade():
    assert definitive_grade({1:Decimal("3.8")}) is None


def test_chain_valid():
    first="a"; second="b"
    r1={"id":1,"payload":first,"hash_previo":"GENESIS","hash":hash_audit("GENESIS",first)}
    r2={"id":2,"payload":second,"hash_previo":r1["hash"],"hash":hash_audit(r1["hash"],second)}
    assert verify_chain([r1,r2])==(True,None)


def test_chain_modified_detected():
    r1={"id":1,"payload":"alterado","hash_previo":"GENESIS","hash":hash_audit("GENESIS","original")}
    assert verify_chain([r1])==(False,1)


def test_key_fingerprint_changes():
    assert key_fingerprint(os.urandom(32))!=key_fingerprint(os.urandom(32))


def test_missing_key_fails_closed(monkeypatch):
    monkeypatch.delenv("DATA_KEY_B64",raising=False)
    with pytest.raises(RuntimeError,match="DATA_KEY_B64"):
        load_key()


def test_aad_is_context_specific(case):
    first=aad_for_grade(case["record_id"],case["student_id"],case["course_id"],1,1,"nota")
    second=aad_for_grade(case["record_id"],case["student_id"],case["course_id"],2,1,"nota")
    assert first!=second
