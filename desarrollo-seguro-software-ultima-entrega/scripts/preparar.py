"""Prepara .env y CA privada para red LOCAL. Ejecutar: python scripts/preparar.py"""
import base64
import ipaddress
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

BASE = Path(__file__).resolve().parents[1]
CERTS = BASE / "certs"

def save(path, data, private=False):
    path.write_bytes(data)
    if private and os.name != "nt":
        path.chmod(0o600)


def create_certs():
    names = ["ca.crt", "ca.key", "localhost.crt", "localhost.key", "db.crt", "db.key"]
    existing = [name for name in names if (CERTS / name).exists()]
    if len(existing) == len(names):
        print("Certificados existentes: conservados")
        return
    if existing:
        raise RuntimeError(f"Certificados incompletos: {existing}. No se sobrescribirá la CA existente.")
    CERTS.mkdir(exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"CA privada laboratorio (NO producción)")])
    ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True,key_cert_sign=True,crl_sign=True,
            key_encipherment=False,content_commitment=False,data_encipherment=False,
            key_agreement=False,encipher_only=False,decipher_only=False),critical=True)
        .sign(ca_key,hashes.SHA256()))
    save(CERTS/"ca.key", ca_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),True)
    save(CERTS/"ca.crt",ca_cert.public_bytes(serialization.Encoding.PEM))
    for common, hosts in [("localhost", [x509.DNSName("localhost"),
                                    x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                          ("db", [x509.DNSName("db")])]:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,common)])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
            .add_extension(x509.SubjectAlternativeName(hosts),critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
            .sign(ca_key,hashes.SHA256()))
        save(CERTS/f"{common}.key",key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),True)
        save(CERTS/f"{common}.crt",cert.public_bytes(serialization.Encoding.PEM))
    print("Generados certificados de uso exclusivo local en certs/")


def create_env():
    env = BASE/".env"
    if env.exists():
        original=env.read_text(encoding="utf-8")
        keys = {x.split("=",1)[0].strip() for x in original.splitlines() if "=" in x and not x.startswith("#")}
        additions=[]
        if "DATA_KEY_B64" not in keys:
            additions.append("DATA_KEY_B64="+base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
        if "DB_CA_FILE" not in keys:
            additions.append("DB_CA_FILE=/run/certs/ca.crt")
        if "COOKIE_SECURE" not in keys:
            additions.append("COOKIE_SECURE=true")
        else:
            print("AVISO: revisa que COOKIE_SECURE=true en .env antes de exponer HTTPS")
        if additions:
            with env.open("a",encoding="utf-8") as out:
                out.write("\n# Agregado por preparar.py\n"+"\n".join(additions)+"\n")
        print(".env existente conservado; revisa credenciales y DATABASE_URL")
        return
    password = secrets.token_urlsafe(24)
    demo = secrets.token_urlsafe(18)
    totp = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    data_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    env.write_text("\n".join([
        "# Exclusivo para laboratorio. No subir a Git.",
        "POSTGRES_DB=calificaciones", "POSTGRES_USER=labuser", f"POSTGRES_PASSWORD={password}",
        f"DATABASE_URL=postgresql://labuser:{password}@db:5432/calificaciones",
        f"DEMO_PASSWORD={demo}", f"DEMO_TOTP_SECRET={totp}",f"DATA_KEY_B64={data_key}",
        "COOKIE_SECURE=true","DB_CA_FILE=/run/certs/ca.crt",""]),encoding="utf-8")
    if os.name!="nt": env.chmod(0o600)
    print("Creado .env con credenciales aleatorias. Conserva la clave DATA_KEY_B64 y no la publiques.")

if __name__=="__main__":
    try:
        create_env()
        create_certs()
        print("Preparación local completada. Continua con docker compose up -d --build")
    except Exception as exc:
        sys.exit(f"ERROR: {exc}")
