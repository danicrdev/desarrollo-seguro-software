import os
import json
import uuid
import hashlib
import secrets

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from contextlib import asynccontextmanager

import psycopg
import pyotp

from psycopg.rows import dict_row
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


DATABASE_URL = os.environ["DATABASE_URL"]

DEMO_PASSWORD = os.getenv(
    "DEMO_PASSWORD", "Laboratorio2026!"
)

DEMO_TOTP_SECRET = os.getenv(
    "DEMO_TOTP_SECRET", "JBSWY3DPEHPK3PXP"
)

COOKIE_SECURE = (
    os.getenv("COOKIE_SECURE", "false").lower() == "true"
)

PASSWORD_HASHER = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1
)

SENSITIVE_ROLES = {"docente", "auditor", "administrador"}


def utcnow():
    return datetime.now(timezone.utc)


def connect():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row
    )


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def deny(status: int, message: str):
    raise HTTPException(status_code=status, detail=message)


def initialize_database():
    statements = [
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id UUID PRIMARY KEY,
            correo TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            rol TEXT NOT NULL,
            secreto_totp TEXT,
            activo BOOLEAN NOT NULL DEFAULT TRUE,
            intentos INTEGER NOT NULL DEFAULT 0,
            bloqueado_hasta TIMESTAMPTZ
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS cursos (
            id UUID PRIMARY KEY,
            nombre TEXT UNIQUE NOT NULL,
            docente_id UUID NOT NULL REFERENCES usuarios(id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS matriculas (
            estudiante_id UUID REFERENCES usuarios(id),
            curso_id UUID REFERENCES cursos(id),
            PRIMARY KEY(estudiante_id, curso_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS calificaciones (
            id UUID PRIMARY KEY,
            estudiante_id UUID REFERENCES usuarios(id),
            curso_id UUID REFERENCES cursos(id),
            corte INTEGER NOT NULL CHECK(corte BETWEEN 1 AND 3),
            nota NUMERIC(3,2) NOT NULL CHECK(nota BETWEEN 0 AND 5),
            observacion VARCHAR(200) NOT NULL DEFAULT '',
            version INTEGER NOT NULL DEFAULT 1,
            actualizado_por UUID REFERENCES usuarios(id),
            actualizado_en TIMESTAMPTZ NOT NULL,
            UNIQUE(estudiante_id, curso_id, corte)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS sesiones (
            id_hash TEXT PRIMARY KEY,
            usuario_id UUID NOT NULL REFERENCES usuarios(id),
            csrf_token TEXT NOT NULL,
            expira_en TIMESTAMPTZ NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS desafios_mfa (
            id_hash TEXT PRIMARY KEY,
            usuario_id UUID NOT NULL REFERENCES usuarios(id),
            expira_en TIMESTAMPTZ NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS auditoria (
            id BIGSERIAL PRIMARY KEY,
            fecha TIMESTAMPTZ NOT NULL,
            usuario_id UUID,
            accion TEXT NOT NULL,
            recurso TEXT NOT NULL,
            resultado TEXT NOT NULL,
            payload TEXT NOT NULL,
            hash_previo TEXT NOT NULL,
            hash TEXT NOT NULL
        )
        """
    ]

    with connect() as conn:
        with conn.cursor() as cursor:
            for statement in statements:
                cursor.execute(statement)


def audit(cursor, actor, action, resource, result):
    cursor.execute("SELECT pg_advisory_xact_lock(424242)")

    cursor.execute(
        "SELECT hash FROM auditoria ORDER BY id DESC LIMIT 1"
    )

    last = cursor.fetchone()
    previous = last["hash"] if last else "GENESIS"

    when = utcnow()

    payload = json.dumps({
        "fecha": when.isoformat(),
        "usuario": str(actor) if actor else None,
        "accion": action,
        "recurso": resource,
        "resultado": result
    }, sort_keys=True)

    current_hash = digest(previous + payload)

    cursor.execute(
        """
        INSERT INTO auditoria (
            fecha, usuario_id, accion, recurso,
            resultado, payload, hash_previo, hash
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            when, actor, action, resource,
            result, payload, previous, current_hash
        )
    )


def seed():
    accounts = [
        ("estudiante@lab.local", "estudiante"),
        ("estudiante2@lab.local", "estudiante"),
        ("docente@lab.local", "docente"),
        ("docente2@lab.local", "docente"),
        ("auditor@lab.local", "auditor"),
        ("admin@lab.local", "administrador"),
    ]

    password_hash = PASSWORD_HASHER.hash(DEMO_PASSWORD)

    with connect() as conn:
        with conn.cursor() as cur:
            for email, role in accounts:
                cur.execute(
                    """
                    INSERT INTO usuarios (
                        id, correo, password_hash, rol,
                        secreto_totp
                    )
                    VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT(correo) DO NOTHING
                    """,
                    (
                        uuid.uuid4(), email, password_hash, role,
                        DEMO_TOTP_SECRET
                        if role in SENSITIVE_ROLES else None
                    )
                )

            cur.execute(
                "SELECT id, correo FROM usuarios"
            )

            users = {
                row["correo"]: row["id"]
                for row in cur.fetchall()
            }

            courses = [
                ("Seguridad de Software", "docente@lab.local"),
                ("Bases de Datos", "docente2@lab.local")
            ]

            for name, teacher_email in courses:
                cur.execute(
                    """
                    INSERT INTO cursos(id,nombre,docente_id)
                    VALUES (%s,%s,%s)
                    ON CONFLICT(nombre) DO NOTHING
                    """,
                    (
                        uuid.uuid4(),
                        name,
                        users[teacher_email]
                    )
                )

            cur.execute("SELECT id, nombre FROM cursos")

            course_ids = {
                row["nombre"]: row["id"]
                for row in cur.fetchall()
            }

            student = users["estudiante@lab.local"]
            course = course_ids["Seguridad de Software"]

            cur.execute(
                """
                INSERT INTO matriculas(estudiante_id,curso_id)
                VALUES (%s,%s)
                ON CONFLICT DO NOTHING
                """,
                (student, course)
            )

            for term, grade in [(1, 3.8), (2, 4.2), (3, 4.5)]:
                cur.execute(
                    """
                    INSERT INTO calificaciones (
                        id, estudiante_id, curso_id,
                        corte, nota, actualizado_por,
                        actualizado_en
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT(estudiante_id,curso_id,corte)
                    DO NOTHING
                    """,
                    (
                        uuid.uuid4(), student, course, term,
                        grade, users["docente@lab.local"],
                        utcnow()
                    )
                )


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    seed()
    yield


app = FastAPI(
    title="Laboratorio de Desarrollo Seguro de Software",
    version="1.0.0",
    lifespan=lifespan
)


class LoginInput(BaseModel):
    correo: str
    password: str


class MFAInput(BaseModel):
    challenge: str
    codigo: str


class GradeInput(BaseModel):
    corte: int = Field(ge=1, le=3)
    nota: Decimal = Field(
        ge=Decimal("0"),
        le=Decimal("5"),
        decimal_places=2
    )
    observacion: str = Field(default="", max_length=200)


class UserInput(BaseModel):
    correo: str
    password: str = Field(min_length=10)
    rol: str


class UserUpdate(BaseModel):
    activo: bool | None = None
    rol: str | None = None


def current_user(request: Request):
    token = request.cookies.get("sid")

    if not token:
        deny(401, "No autenticado")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    u.id, u.correo, u.rol, u.activo,
                    s.csrf_token
                FROM sesiones s
                JOIN usuarios u ON u.id = s.usuario_id
                WHERE s.id_hash=%s
                  AND s.expira_en > NOW()
                  AND u.activo = TRUE
                """,
                (digest(token),)
            )

            user = cur.fetchone()

            if not user:
                deny(401, "Sesión inválida o expirada")

            cur.execute(
                """
                UPDATE sesiones
                SET expira_en=NOW()+INTERVAL '15 minutes'
                WHERE id_hash=%s
                """,
                (digest(token),)
            )

            return user


def require_role(user, *roles):
    if user["rol"] not in roles:
        deny(403, "Operación no autorizada")


def verify_csrf(request, user):
    supplied = request.headers.get("X-CSRF-Token", "")

    if not secrets.compare_digest(
        supplied, user["csrf_token"]
    ):
        deny(403, "Token CSRF inválido")


def issue_session(user_id):
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sesiones (
                    id_hash, usuario_id, csrf_token, expira_en
                )
                VALUES (%s,%s,%s,%s)
                """,
                (
                    digest(raw),
                    user_id,
                    csrf,
                    utcnow() + timedelta(minutes=15)
                )
            )

    response = JSONResponse({
        "authenticated": True,
        "csrf_token": csrf
    })

    response.set_cookie(
        "sid",
        raw,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=900
    )

    return response


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/v1/auth/login")
def login(data: LoginInput):
    user_id = None
    role = None

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM usuarios WHERE correo=%s",
                (data.correo,)
            )

            user = cur.fetchone()

            if not user or not user["activo"]:
                deny(401, "Credenciales inválidas")

            if (
                user["bloqueado_hasta"]
                and user["bloqueado_hasta"] > utcnow()
            ):
                deny(401, "Credenciales inválidas")

            try:
                PASSWORD_HASHER.verify(
                    user["password_hash"],
                    data.password
                )
            except VerifyMismatchError:
                cur.execute(
                    """
                    UPDATE usuarios
                    SET intentos=intentos+1,
                        bloqueado_hasta=CASE
                            WHEN intentos+1>=5
                            THEN NOW()+INTERVAL '15 minutes'
                            ELSE bloqueado_hasta
                        END
                    WHERE id=%s
                    """,
                    (user["id"],)
                )

                audit(
                    cur, user["id"], "login",
                    "autenticacion", "rechazado"
                )

                deny(401, "Credenciales inválidas")

            cur.execute(
                """
                UPDATE usuarios
                SET intentos=0, bloqueado_hasta=NULL
                WHERE id=%s
                """,
                (user["id"],)
            )

            user_id = user["id"]
            role = user["rol"]

            audit(
                cur, user_id, "login",
                "autenticacion", "credenciales_validas"
            )

            if role in SENSITIVE_ROLES:
                challenge = secrets.token_urlsafe(32)

                cur.execute(
                    """
                    INSERT INTO desafios_mfa(
                        id_hash,usuario_id,expira_en
                    )
                    VALUES (%s,%s,%s)
                    """,
                    (
                        digest(challenge),
                        user_id,
                        utcnow() + timedelta(minutes=3)
                    )
                )

                return {
                    "mfa_required": True,
                    "challenge": challenge
                }

    return issue_session(user_id)


@app.post("/api/v1/auth/mfa")
def verify_mfa(data: MFAInput):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT d.usuario_id, u.secreto_totp
                FROM desafios_mfa d
                JOIN usuarios u ON u.id=d.usuario_id
                WHERE d.id_hash=%s
                  AND d.expira_en>NOW()
                  AND u.activo=TRUE
                """,
                (digest(data.challenge),)
            )

            row = cur.fetchone()

            if not row:
                deny(401, "Verificación inválida")

            if not pyotp.TOTP(
                row["secreto_totp"]
            ).verify(data.codigo, valid_window=1):
                deny(401, "Verificación inválida")

            cur.execute(
                "DELETE FROM desafios_mfa WHERE id_hash=%s",
                (digest(data.challenge),)
            )

            user_id = row["usuario_id"]

            audit(
                cur, user_id, "mfa",
                "autenticacion", "aprobado"
            )

    return issue_session(user_id)


@app.get("/api/v1/me")
def me(user=Depends(current_user)):
    return {
        "id": str(user["id"]),
        "correo": user["correo"],
        "rol": user["rol"],
        "csrf_token": user["csrf_token"]
    }


@app.post("/api/v1/auth/logout")
def logout(
    request: Request,
    user=Depends(current_user)
):
    verify_csrf(request, user)

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM sesiones WHERE id_hash=%s",
                (digest(request.cookies["sid"]),)
            )

            audit(
                cur, user["id"], "logout",
                "sesion", "aprobado"
            )

    response = Response(status_code=204)
    response.delete_cookie("sid")
    return response


@app.get("/api/v1/cursos")
def courses(user=Depends(current_user)):
    with connect() as conn:
        with conn.cursor() as cur:
            if user["rol"] == "docente":
                cur.execute(
                    """
                    SELECT id,nombre
                    FROM cursos
                    WHERE docente_id=%s
                    """,
                    (user["id"],)
                )
            elif user["rol"] == "estudiante":
                cur.execute(
                    """
                    SELECT c.id,c.nombre
                    FROM cursos c
                    JOIN matriculas m ON m.curso_id=c.id
                    WHERE m.estudiante_id=%s
                    """,
                    (user["id"],)
                )
            else:
                cur.execute("SELECT id,nombre FROM cursos")

            return cur.fetchall()


@app.get("/api/v1/me/calificaciones")
def my_grades(user=Depends(current_user)):
    require_role(user, "estudiante")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT c.id AS curso_id, c.nombre,
                       g.corte,g.nota,g.version
                FROM matriculas m
                JOIN cursos c ON c.id=m.curso_id
                LEFT JOIN calificaciones g
                  ON g.curso_id=c.id
                 AND g.estudiante_id=m.estudiante_id
                WHERE m.estudiante_id=%s
                ORDER BY c.nombre,g.corte
                """,
                (user["id"],)
            )

            records = cur.fetchall()

    output = {}

    for row in records:
        course_id = str(row["curso_id"])

        if course_id not in output:
            output[course_id] = {
                "curso_id": course_id,
                "curso": row["nombre"],
                "cortes": [],
                "definitiva": None
            }

        if row["corte"] is not None:
            output[course_id]["cortes"].append({
                "corte": row["corte"],
                "nota": float(row["nota"]),
                "version": row["version"]
            })

    for item in output.values():
        notes = {
            row["corte"]: row["nota"]
            for row in item["cortes"]
        }

        if len(notes) == 3:
            final_grade = (
                Decimal(str(notes[1])) * Decimal("0.30")
                + Decimal(str(notes[2])) * Decimal("0.30")
                + Decimal(str(notes[3])) * Decimal("0.40")
            )

            item["definitiva"] = float(
                round(final_grade, 2)
            )

    return list(output.values())


def validate_teacher(cur, teacher_id, course_id):
    cur.execute(
        """
        SELECT id FROM cursos
        WHERE id=%s AND docente_id=%s
        """,
        (course_id, teacher_id)
    )

    if not cur.fetchone():
        deny(403, "Curso no autorizado")


@app.get("/api/v1/cursos/{course_id}/calificaciones")
def course_grades(
    course_id: uuid.UUID,
    user=Depends(current_user)
):
    require_role(user, "docente")

    with connect() as conn:
        with conn.cursor() as cur:
            validate_teacher(
                cur, user["id"], course_id
            )

            cur.execute(
                """
                SELECT
                    g.id,g.estudiante_id,
                    u.correo AS estudiante,
                    g.corte,g.nota,
                    g.observacion,g.version
                FROM calificaciones g
                JOIN usuarios u ON u.id=g.estudiante_id
                WHERE g.curso_id=%s
                ORDER BY u.correo,g.corte
                """,
                (course_id,)
            )

            return cur.fetchall()


@app.put(
    "/api/v1/cursos/{course_id}/calificaciones/{student_id}"
)
def update_grade(
    course_id: uuid.UUID,
    student_id: uuid.UUID,
    data: GradeInput,
    request: Request,
    user=Depends(current_user)
):
    require_role(user, "docente")
    verify_csrf(request, user)

    with connect() as conn:
        with conn.cursor() as cur:
            validate_teacher(
                cur, user["id"], course_id
            )

            cur.execute(
                """
                SELECT 1 FROM matriculas
                WHERE estudiante_id=%s
                  AND curso_id=%s
                """,
                (student_id, course_id)
            )

            if not cur.fetchone():
                deny(422, "Estudiante no matriculado")

            cur.execute(
                """
                SELECT id,version
                FROM calificaciones
                WHERE estudiante_id=%s
                  AND curso_id=%s
                  AND corte=%s
                FOR UPDATE
                """,
                (student_id, course_id, data.corte)
            )

            previous = cur.fetchone()

            if previous:
                version = previous["version"] + 1

                cur.execute(
                    """
                    UPDATE calificaciones
                    SET nota=%s,
                        observacion=%s,
                        version=%s,
                        actualizado_por=%s,
                        actualizado_en=%s
                    WHERE id=%s
                    """,
                    (
                        data.nota,
                        data.observacion,
                        version,
                        user["id"],
                        utcnow(),
                        previous["id"]
                    )
                )

            else:
                version = 1

                cur.execute(
                    """
                    INSERT INTO calificaciones(
                        id,estudiante_id,curso_id,
                        corte,nota,observacion,
                        version,actualizado_por,
                        actualizado_en
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        uuid.uuid4(),
                        student_id,
                        course_id,
                        data.corte,
                        data.nota,
                        data.observacion,
                        version,
                        user["id"],
                        utcnow()
                    )
                )

            audit(
                cur,
                user["id"],
                "modificar_nota",
                f"{course_id}:{student_id}:{data.corte}",
                "aprobado"
            )

    return {
        "updated": True,
        "version": version,
        "nota": float(data.nota)
    }


@app.get("/api/v1/auditoria")
def get_audit(user=Depends(current_user)):
    require_role(user, "auditor")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM auditoria ORDER BY id"
            )
            records = cur.fetchall()

    previous = "GENESIS"
    broken_at = None

    for record in records:
        expected = digest(previous + record["payload"])

        if (
            record["hash_previo"] != previous
            or record["hash"] != expected
        ):
            broken_at = record["id"]
            break

        previous = record["hash"]

    return {
        "integridad": broken_at is None,
        "registro_alterado": broken_at,
        "total": len(records),
        "eventos": [
            {
                "id": row["id"],
                "fecha": row["fecha"].isoformat(),
                "accion": row["accion"],
                "recurso": row["recurso"],
                "resultado": row["resultado"]
            }
            for row in records
        ]
    }


@app.post("/api/v1/usuarios", status_code=201)
def create_user(
    data: UserInput,
    request: Request,
    user=Depends(current_user)
):
    require_role(user, "administrador")
    verify_csrf(request, user)

    allowed = {
        "estudiante", "docente",
        "auditor", "administrador"
    }

    if data.rol not in allowed:
        deny(422, "Rol no permitido")

    if "@" not in data.correo:
        deny(422, "Correo inválido")

    new_id = uuid.uuid4()

    secret = (
        pyotp.random_base32()
        if data.rol in SENSITIVE_ROLES
        else None
    )

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM usuarios WHERE correo=%s",
                (data.correo,)
            )

            if cur.fetchone():
                deny(409, "El usuario ya existe")

            cur.execute(
                """
                INSERT INTO usuarios(
                    id,correo,password_hash,
                    rol,secreto_totp
                )
                VALUES (%s,%s,%s,%s,%s)
                """,
                (
                    new_id,
                    data.correo,
                    PASSWORD_HASHER.hash(data.password),
                    data.rol,
                    secret
                )
            )

            audit(
                cur,
                user["id"],
                "crear_usuario",
                str(new_id),
                "aprobado"
            )

    return {
        "id": str(new_id),
        "rol": data.rol,
        "secreto_totp": secret
    }


@app.patch("/api/v1/usuarios/{target_id}")
def update_user(
    target_id: uuid.UUID,
    data: UserUpdate,
    request: Request,
    user=Depends(current_user)
):
    require_role(user, "administrador")
    verify_csrf(request, user)

    if data.rol is not None and data.rol not in {
        "estudiante", "docente",
        "auditor", "administrador"
    }:
        deny(422, "Rol no permitido")

    if target_id == user["id"] and data.activo is False:
        deny(422, "No puede desactivar su propia cuenta")

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM usuarios WHERE id=%s",
                (target_id,)
            )

            target = cur.fetchone()

            if not target:
                deny(404, "Usuario inexistente")

            new_role = (
                data.rol if data.rol is not None
                else target["rol"]
            )

            new_active = (
                data.activo if data.activo is not None
                else target["activo"]
            )

            secret = target["secreto_totp"]

            if new_role in SENSITIVE_ROLES and not secret:
                secret = pyotp.random_base32()

            cur.execute(
                """
                UPDATE usuarios
                SET rol=%s,activo=%s,secreto_totp=%s
                WHERE id=%s
                """,
                (
                    new_role,
                    new_active,
                    secret,
                    target_id
                )
            )

            audit(
                cur,
                user["id"],
                "actualizar_usuario",
                str(target_id),
                "aprobado"
            )

    return {
        "id": str(target_id),
        "rol": new_role,
        "activo": new_active
    }