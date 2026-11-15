"""API académica reforzada. No desplegar en Internet sin revisión adicional."""
import hashlib
import json
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Literal

import psycopg
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from psycopg.rows import dict_row
from pydantic import BaseModel, Field

from .security import (decrypt_grade, decrypt_totp, definitive_grade,
                       encrypt_grade, encrypt_totp, hash_audit,
                       key_fingerprint, load_key, verify_chain)

DB_URL = os.environ["DATABASE_URL"]
DEMO_PASSWORD = os.environ["DEMO_PASSWORD"]
DEMO_TOTP_SECRET = os.environ["DEMO_TOTP_SECRET"]
KEY = load_key()
PASSWORD_HASHER = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
SENSITIVE_ROLES = {"docente", "auditor", "administrador"}
ALLOWED_ROLES = {"estudiante", *SENSITIVE_ROLES}
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() == "true"


def utcnow():
    return datetime.now(timezone.utc)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def connect():
    return psycopg.connect(DB_URL, row_factory=dict_row, sslmode="verify-full",
                           sslrootcert=os.environ.get("DB_CA_FILE", "/run/certs/ca.crt"),
                           connect_timeout=8)


def deny(status, message):
    raise HTTPException(status_code=status, detail=message)


def audit(cur, actor, action, resource, outcome):
    cur.execute("SELECT pg_advisory_xact_lock(424242)")
    cur.execute("SELECT hash FROM auditoria ORDER BY id DESC LIMIT 1")
    previous_record = cur.fetchone()
    previous = previous_record["hash"] if previous_record else "GENESIS"
    payload = json.dumps({"fecha": utcnow().isoformat(), "usuario": str(actor) if actor else None,
                          "accion": action, "recurso": resource, "resultado": outcome},
                         sort_keys=True, separators=(",", ":"))
    cur.execute("""INSERT INTO auditoria (fecha,usuario_id,accion,recurso,resultado,payload,hash_previo,hash)
                   VALUES (NOW(),%s,%s,%s,%s,%s,%s,%s)""",
                (actor, action, resource, outcome, payload, previous, hash_audit(previous, payload)))


def enc_columns(record_id, student_id, course_id, term, version, grade, observation):
    fields = {"key": KEY, "record_id": record_id, "student_id": student_id,
              "course_id": course_id, "term": term, "version": version}
    return (encrypt_grade(str(grade), kind="nota", **fields),
            encrypt_grade(observation or "", kind="observacion", **fields))


def decode_row(record):
    fields = {"key": KEY, "record_id": record["id"], "student_id": record["estudiante_id"],
              "course_id": record["curso_id"], "term": record["corte"],
              "version": record["version"]}
    return (Decimal(decrypt_grade(record["nota_cifrada"], kind="nota", **fields)),
            decrypt_grade(record["observacion_cifrada"], kind="observacion", **fields))


def initialize_database():
    schema = [
        """CREATE TABLE IF NOT EXISTS seguridad_meta (id TEXT PRIMARY KEY, valor TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS usuarios (id UUID PRIMARY KEY,correo TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,rol TEXT NOT NULL,secreto_totp TEXT,activo BOOLEAN NOT NULL DEFAULT TRUE,
            intentos INTEGER NOT NULL DEFAULT 0,bloqueado_hasta TIMESTAMPTZ)""",
        """CREATE TABLE IF NOT EXISTS cursos (id UUID PRIMARY KEY,nombre TEXT UNIQUE NOT NULL,
            docente_id UUID NOT NULL REFERENCES usuarios(id))""",
        """CREATE TABLE IF NOT EXISTS matriculas (estudiante_id UUID REFERENCES usuarios(id),
            curso_id UUID REFERENCES cursos(id),PRIMARY KEY(estudiante_id,curso_id))""",
        """CREATE TABLE IF NOT EXISTS calificaciones (id UUID PRIMARY KEY,
            estudiante_id UUID REFERENCES usuarios(id),curso_id UUID REFERENCES cursos(id),
            corte INTEGER NOT NULL CHECK(corte BETWEEN 1 AND 3),
            nota_cifrada BYTEA NOT NULL,observacion_cifrada BYTEA NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,actualizado_por UUID REFERENCES usuarios(id),
            actualizado_en TIMESTAMPTZ NOT NULL, UNIQUE(estudiante_id,curso_id,corte))""",
        """CREATE TABLE IF NOT EXISTS sesiones (id_hash TEXT PRIMARY KEY,
            usuario_id UUID NOT NULL REFERENCES usuarios(id), csrf_token TEXT NOT NULL, expira_en TIMESTAMPTZ NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS desafios_mfa (id_hash TEXT PRIMARY KEY,
            usuario_id UUID NOT NULL REFERENCES usuarios(id), expira_en TIMESTAMPTZ NOT NULL,
            intentos INTEGER NOT NULL DEFAULT 0)""",
        """CREATE TABLE IF NOT EXISTS auditoria (id BIGSERIAL PRIMARY KEY,
            fecha TIMESTAMPTZ NOT NULL,usuario_id UUID,accion TEXT NOT NULL,
            recurso TEXT NOT NULL,resultado TEXT NOT NULL,payload TEXT NOT NULL,
            hash_previo TEXT NOT NULL,hash TEXT NOT NULL)""",
    ]
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(737312)")
            for sql in schema:
                cur.execute(sql)
            fingerprint = key_fingerprint(KEY)
            cur.execute("SELECT valor FROM seguridad_meta WHERE id='data_key_fingerprint'")
            existing_key = cur.fetchone()
            if existing_key and existing_key["valor"] != fingerprint:
                raise RuntimeError("DATA_KEY_B64 distinta de la usada en esta base de datos")
            if not existing_key:
                cur.execute("INSERT INTO seguridad_meta(id,valor) VALUES ('data_key_fingerprint',%s)",
                            (fingerprint,))
            # Migración no destructiva de los datos de la Entrega 2: en una sola transacción.
            cur.execute("ALTER TABLE calificaciones ADD COLUMN IF NOT EXISTS nota_cifrada BYTEA")
            cur.execute("ALTER TABLE calificaciones ADD COLUMN IF NOT EXISTS observacion_cifrada BYTEA")
            cur.execute("ALTER TABLE desafios_mfa ADD COLUMN IF NOT EXISTS intentos INTEGER NOT NULL DEFAULT 0")
            cur.execute("""SELECT column_name FROM information_schema.columns
                           WHERE table_schema='public' AND table_name='calificaciones'""")
            columns = {x["column_name"] for x in cur.fetchall()}
            if {"nota", "observacion"}.issubset(columns):
                cur.execute("""SELECT id,estudiante_id,curso_id,corte,version,nota,observacion
                               FROM calificaciones WHERE nota_cifrada IS NULL OR observacion_cifrada IS NULL""")
                for row in cur.fetchall():
                    note, observation = enc_columns(row["id"],row["estudiante_id"],row["curso_id"],
                                                    row["corte"],row["version"],row["nota"],row["observacion"])
                    cur.execute("UPDATE calificaciones SET nota_cifrada=%s,observacion_cifrada=%s WHERE id=%s",
                                (note, observation, row["id"]))
                cur.execute("ALTER TABLE calificaciones DROP COLUMN nota")
                cur.execute("ALTER TABLE calificaciones DROP COLUMN observacion")
            cur.execute("SELECT COUNT(*) AS n FROM calificaciones WHERE nota_cifrada IS NULL OR observacion_cifrada IS NULL")
            if cur.fetchone()["n"]:
                raise RuntimeError("Existen calificaciones sin cifrar: migración interrumpida")
            cur.execute("ALTER TABLE calificaciones ALTER COLUMN nota_cifrada SET NOT NULL")
            cur.execute("ALTER TABLE calificaciones ALTER COLUMN observacion_cifrada SET NOT NULL")
            cur.execute("SELECT id,secreto_totp FROM usuarios WHERE secreto_totp IS NOT NULL")
            for row in cur.fetchall():
                if not row["secreto_totp"].startswith("enc:v1:"):
                    cur.execute("UPDATE usuarios SET secreto_totp=%s WHERE id=%s",
                                (encrypt_totp(row["secreto_totp"],key=KEY,user_id=row["id"]),row["id"]))


def seed():
    accounts = [
        ("estudiante@lab.local","estudiante"),("estudiante2@lab.local","estudiante"),
        ("docente@lab.local","docente"),("docente2@lab.local","docente"),
        ("auditor@lab.local","auditor"),("admin@lab.local","administrador"),
    ]
    with connect() as conn:
        with conn.cursor() as cur:
            for email, role in accounts:
                uid = uuid.uuid4()
                secret = encrypt_totp(DEMO_TOTP_SECRET,key=KEY,user_id=uid) if role in SENSITIVE_ROLES else None
                cur.execute("""INSERT INTO usuarios(id,correo,password_hash,rol,secreto_totp)
                    VALUES (%s,%s,%s,%s,%s) ON CONFLICT(correo) DO NOTHING""",
                    (uid,email,PASSWORD_HASHER.hash(DEMO_PASSWORD),role,secret))
            cur.execute("SELECT correo,id FROM usuarios")
            users = {r["correo"]:r["id"] for r in cur.fetchall()}
            for name, teacher in [("Seguridad de Software","docente@lab.local"),
                                  ("Bases de Datos","docente2@lab.local")]:
                cur.execute("INSERT INTO cursos(id,nombre,docente_id) VALUES (%s,%s,%s) ON CONFLICT(nombre) DO NOTHING",
                            (uuid.uuid4(),name,users[teacher]))
            cur.execute("SELECT nombre,id FROM cursos")
            courses = {r["nombre"]:r["id"] for r in cur.fetchall()}
            sid,cid = users["estudiante@lab.local"],courses["Seguridad de Software"]
            cur.execute("INSERT INTO matriculas(estudiante_id,curso_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                        (sid,cid))
            for term,grade in [(1,Decimal("3.8")),(2,Decimal("4.2")),(3,Decimal("4.5"))]:
                uid = uuid.uuid4()
                encrypted_note,encrypted_obs = enc_columns(uid,sid,cid,term,1,grade,"")
                cur.execute("""INSERT INTO calificaciones(id,estudiante_id,curso_id,corte,
                    nota_cifrada,observacion_cifrada,version,actualizado_por,actualizado_en)
                    VALUES (%s,%s,%s,%s,%s,%s,1,%s,NOW()) ON CONFLICT(estudiante_id,curso_id,corte) DO NOTHING""",
                    (uid,sid,cid,term,encrypted_note,encrypted_obs,users["docente@lab.local"]))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    initialize_database()
    seed()
    yield


app = FastAPI(title="Laboratorio de Desarrollo Seguro",version="3.0.0",lifespan=lifespan)


class LoginInput(BaseModel):
    correo: str = Field(min_length=3,max_length=254)
    password: str


class MFAInput(BaseModel):
    challenge: str
    codigo: str = Field(pattern=r"^\d{6}$")


class GradeInput(BaseModel):
    corte: int = Field(ge=1,le=3)
    nota: Decimal = Field(ge=Decimal("0"),le=Decimal("5"),decimal_places=2)
    observacion: str = Field(default="",max_length=200)


class UserInput(BaseModel):
    correo: str = Field(min_length=3,max_length=254)
    password: str = Field(min_length=12,max_length=256)
    rol: Literal["estudiante","docente","auditor","administrador"]


class UserUpdate(BaseModel):
    activo: bool | None = None
    rol: Literal["estudiante","docente","auditor","administrador"] | None = None


def current_user(request: Request):
    token = request.cookies.get("sid")
    if not token:
        deny(401,"No autenticado")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT u.id,u.correo,u.rol,u.activo,s.csrf_token
                FROM sesiones s JOIN usuarios u ON u.id=s.usuario_id
                WHERE s.id_hash=%s AND s.expira_en>NOW() AND u.activo=TRUE""",(digest(token),))
            user = cur.fetchone()
            if not user:
                deny(401,"Sesión inválida o expirada")
            cur.execute("UPDATE sesiones SET expira_en=NOW()+INTERVAL '15 minutes' WHERE id_hash=%s",
                        (digest(token),))
    return user


def require_role(user,*roles):
    if user["rol"] not in roles:
        deny(403,"Operación no autorizada")


def verify_csrf(request,user):
    supplied = request.headers.get("X-CSRF-Token", "")
    if not supplied or not secrets.compare_digest(supplied,user["csrf_token"]):
        deny(403,"CSRF inválido")


def issue_session(user_id):
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO sesiones(id_hash,usuario_id,csrf_token,expira_en)
                VALUES (%s,%s,%s,NOW()+INTERVAL '15 minutes')""",(digest(raw),user_id,csrf))
    response = JSONResponse({"authenticated":True,"csrf_token":csrf})
    response.set_cookie("sid",raw,httponly=True,secure=COOKIE_SECURE,samesite="strict",max_age=900)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
def health():
    return {"status":"ok"}


@app.post("/api/v1/auth/login")
def login(data: LoginInput):
    user_id, role, challenge, denied = None,None,None,True
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM usuarios WHERE correo=%s FOR UPDATE",(data.correo,))
            user = cur.fetchone()
            if user and user["activo"] and not (user["bloqueado_hasta"] and user["bloqueado_hasta"] > utcnow()):
                try:
                    PASSWORD_HASHER.verify(user["password_hash"],data.password)
                    valid = True
                except VerificationError:
                    valid = False
                if valid:
                    user_id,role,denied = user["id"],user["rol"],False
                    cur.execute("UPDATE usuarios SET intentos=0,bloqueado_hasta=NULL WHERE id=%s",(user_id,))
                    audit(cur,user_id,"login","autenticacion","credenciales_validas")
                    if role in SENSITIVE_ROLES:
                        challenge = secrets.token_urlsafe(32)
                        cur.execute("""INSERT INTO desafios_mfa(id_hash,usuario_id,expira_en)
                            VALUES (%s,%s,NOW()+INTERVAL '3 minutes')""",(digest(challenge),user_id))
                else:
                    cur.execute("""UPDATE usuarios SET intentos=intentos+1,
                        bloqueado_hasta=CASE WHEN intentos+1>=5 THEN NOW()+INTERVAL '15 minutes'
                            ELSE bloqueado_hasta END WHERE id=%s""",(user["id"],))
                    audit(cur,user["id"],"login","autenticacion","rechazado")
    # La transacción se confirmó ANTES de lanzar HTTP 401: el bloqueo persiste.
    if denied:
        deny(401,"Credenciales inválidas")
    if challenge:
        return {"mfa_required":True,"challenge":challenge}
    return issue_session(user_id)


@app.post("/api/v1/auth/mfa")
def verify_mfa(data: MFAInput):
    user_id, approved = None,False
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT d.usuario_id,d.intentos,u.secreto_totp
                FROM desafios_mfa d JOIN usuarios u ON u.id=d.usuario_id
                WHERE d.id_hash=%s AND d.expira_en>NOW() AND u.activo=TRUE FOR UPDATE OF d""",
                (digest(data.challenge),))
            challenge = cur.fetchone()
            if challenge:
                secret = decrypt_totp(challenge["secreto_totp"],key=KEY,user_id=challenge["usuario_id"])
                approved = pyotp.TOTP(secret).verify(data.codigo,valid_window=1)
                if approved:
                    user_id = challenge["usuario_id"]
                    cur.execute("DELETE FROM desafios_mfa WHERE id_hash=%s",(digest(data.challenge),))
                    audit(cur,user_id,"mfa","autenticacion","aprobado")
                else:
                    cur.execute("""UPDATE desafios_mfa SET intentos=intentos+1,
                        expira_en=CASE WHEN intentos+1>=5 THEN NOW() ELSE expira_en END WHERE id_hash=%s""",
                        (digest(data.challenge),))
    if not approved:
        deny(401,"Verificación inválida")
    return issue_session(user_id)


@app.get("/api/v1/me")
def me(user=Depends(current_user)):
    return {"id":str(user["id"]),"correo":user["correo"],"rol":user["rol"],
            "csrf_token":user["csrf_token"]}


@app.post("/api/v1/auth/logout")
def logout(request:Request,user=Depends(current_user)):
    verify_csrf(request,user)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sesiones WHERE id_hash=%s",(digest(request.cookies["sid"]),))
            audit(cur,user["id"],"logout","sesion","aprobado")
    response = Response(status_code=204)
    response.delete_cookie("sid",secure=COOKIE_SECURE,httponly=True,samesite="strict")
    return response


@app.get("/api/v1/cursos")
def courses(user=Depends(current_user)):
    with connect() as conn:
        with conn.cursor() as cur:
            if user["rol"] == "docente":
                cur.execute("SELECT id,nombre FROM cursos WHERE docente_id=%s",(user["id"],))
            elif user["rol"] == "estudiante":
                cur.execute("""SELECT c.id,c.nombre FROM cursos c JOIN matriculas m ON m.curso_id=c.id
                    WHERE m.estudiante_id=%s""",(user["id"],))
            elif user["rol"] == "administrador":
                cur.execute("SELECT id,nombre FROM cursos")
            else:
                deny(403,"Operación no autorizada")
            return cur.fetchall()


@app.get("/api/v1/me/calificaciones")
def my_grades(user=Depends(current_user)):
    require_role(user,"estudiante")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT c.id AS curso_id,c.nombre,g.id,g.estudiante_id,g.corte,
                g.nota_cifrada,g.observacion_cifrada,g.version
                FROM matriculas m JOIN cursos c ON c.id=m.curso_id
                LEFT JOIN calificaciones g ON g.curso_id=c.id AND g.estudiante_id=m.estudiante_id
                WHERE m.estudiante_id=%s ORDER BY c.nombre,g.corte""",(user["id"],))
            records = cur.fetchall()
    result = {}
    for row in records:
        key = str(row["curso_id"])
        item = result.setdefault(key,{"curso_id":key,"curso":row["nombre"],"cortes":[],"definitiva":None})
        if row["corte"] is not None:
            # JOIN devuelve course_id; el descifrado exige campos ligados a esa fila.
            grade,_ = decode_row(row)
            item["cortes"].append({"corte":row["corte"],"nota":float(grade),"version":row["version"]})
    for item in result.values():
        values = {r["corte"]:Decimal(str(r["nota"])) for r in item["cortes"]}
        final = definitive_grade(values)
        item["definitiva"] = float(final) if final is not None else None
    return list(result.values())


def validate_teacher(cur,teacher_id,course_id):
    cur.execute("SELECT id FROM cursos WHERE id=%s AND docente_id=%s",(course_id,teacher_id))
    if not cur.fetchone():
        deny(403,"Curso no autorizado")


@app.get("/api/v1/cursos/{course_id}/calificaciones")
def course_grades(course_id:uuid.UUID,user=Depends(current_user)):
    require_role(user,"docente")
    with connect() as conn:
        with conn.cursor() as cur:
            validate_teacher(cur,user["id"],course_id)
            cur.execute("""SELECT g.id,g.estudiante_id,g.curso_id,u.correo AS estudiante,
                g.corte,g.nota_cifrada,g.observacion_cifrada,g.version
                FROM calificaciones g JOIN usuarios u ON u.id=g.estudiante_id
                WHERE g.curso_id=%s ORDER BY u.correo,g.corte""",(course_id,))
            records = cur.fetchall()
    result=[]
    for r in records:
        grade,observation=decode_row(r)
        result.append({"id":r["id"],"estudiante_id":r["estudiante_id"],
                       "estudiante":r["estudiante"],"corte":r["corte"],
                       "nota":float(grade),"observacion":observation,"version":r["version"]})
    return result


@app.put("/api/v1/cursos/{course_id}/calificaciones/{student_id}")
def update_grade(course_id:uuid.UUID,student_id:uuid.UUID,data:GradeInput,
                 request:Request,user=Depends(current_user)):
    require_role(user,"docente")
    verify_csrf(request,user)
    with connect() as conn:
        with conn.cursor() as cur:
            validate_teacher(cur,user["id"],course_id)
            cur.execute("SELECT 1 FROM matriculas WHERE estudiante_id=%s AND curso_id=%s",
                        (student_id,course_id))
            if not cur.fetchone():
                deny(422,"Estudiante no matriculado")
            # Serializa incluso la primera inserción concurrente para este recurso.
            lock_key = digest(f"{course_id}:{student_id}:{data.corte}")[:16]
            cur.execute("SELECT pg_advisory_xact_lock(%s)",(int(lock_key,16) - (1<<63),))
            cur.execute("""SELECT id,version FROM calificaciones
                WHERE estudiante_id=%s AND curso_id=%s AND corte=%s FOR UPDATE""",
                (student_id,course_id,data.corte))
            previous = cur.fetchone()
            record_id = previous["id"] if previous else uuid.uuid4()
            version = previous["version"]+1 if previous else 1
            note,observation = enc_columns(record_id,student_id,course_id,data.corte,version,data.nota,data.observacion)
            if previous:
                cur.execute("""UPDATE calificaciones SET nota_cifrada=%s,observacion_cifrada=%s,
                    version=%s,actualizado_por=%s,actualizado_en=NOW() WHERE id=%s""",
                    (note,observation,version,user["id"],record_id))
            else:
                cur.execute("""INSERT INTO calificaciones(id,estudiante_id,curso_id,corte,
                    nota_cifrada,observacion_cifrada,version,actualizado_por,actualizado_en)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,NOW())""",
                    (record_id,student_id,course_id,data.corte,note,observation,version,user["id"]))
            audit(cur,user["id"],"modificar_nota",f"{course_id}:{student_id}:{data.corte}","aprobado")
    return {"updated":True,"version":version,"nota":float(data.nota)}


@app.get("/api/v1/auditoria/estado-db")
def state_db(user=Depends(current_user)):
    require_role(user,"auditor")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT ssl,version,cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
            info=cur.fetchone()
    return {"ssl":info["ssl"],"version":info["version"],"cipher":info["cipher"]}


@app.get("/api/v1/auditoria")
def get_audit(user=Depends(current_user)):
    require_role(user,"auditor")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM auditoria ORDER BY id")
            rows = cur.fetchall()
    integrity,broken_at = verify_chain(rows)
    return {"integridad":integrity,"registro_alterado":broken_at,"total":len(rows),
            "eventos":[{"id":r["id"],"fecha":r["fecha"].isoformat(),"accion":r["accion"],
                       "recurso":r["recurso"],"resultado":r["resultado"]} for r in rows]}


@app.post("/api/v1/usuarios",status_code=201)
def create_user(data:UserInput,request:Request,user=Depends(current_user)):
    require_role(user,"administrador")
    verify_csrf(request,user)
    uid = uuid.uuid4()
    generated_secret = pyotp.random_base32() if data.rol in SENSITIVE_ROLES else None
    stored_secret = encrypt_totp(generated_secret,key=KEY,user_id=uid) if generated_secret else None
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM usuarios WHERE correo=%s",(data.correo,))
            if cur.fetchone():
                deny(409,"El usuario ya existe")
            cur.execute("INSERT INTO usuarios(id,correo,password_hash,rol,secreto_totp) VALUES (%s,%s,%s,%s,%s)",
                        (uid,data.correo,PASSWORD_HASHER.hash(data.password),data.rol,stored_secret))
            audit(cur,user["id"],"crear_usuario",str(uid),"aprobado")
    # En laboratorio se entrega una sola vez para enrolar TOTP; no registrar la respuesta.
    return {"id":str(uid),"rol":data.rol,"secreto_totp":generated_secret}


@app.patch("/api/v1/usuarios/{target_id}")
def update_user(target_id:uuid.UUID,data:UserUpdate,request:Request,user=Depends(current_user)):
    require_role(user,"administrador")
    verify_csrf(request,user)
    if target_id == user["id"] and data.activo is False:
        deny(422,"No puede desactivar su cuenta")
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT rol,activo,secreto_totp FROM usuarios WHERE id=%s FOR UPDATE",(target_id,))
            previous = cur.fetchone()
            if not previous:
                deny(404,"Usuario inexistente")
            role = data.rol if data.rol is not None else previous["rol"]
            active = data.activo if data.activo is not None else previous["activo"]
            secret = previous["secreto_totp"]
            if role in SENSITIVE_ROLES and not secret:
                secret = encrypt_totp(pyotp.random_base32(),key=KEY,user_id=target_id)
            cur.execute("UPDATE usuarios SET rol=%s,activo=%s,secreto_totp=%s WHERE id=%s",
                        (role,active,secret,target_id))
            if role != previous["rol"] or not active:
                cur.execute("DELETE FROM sesiones WHERE usuario_id=%s",(target_id,))
            audit(cur,user["id"],"actualizar_usuario",str(target_id),"aprobado")
    return {"id":str(target_id),"rol":role,"activo":active}
