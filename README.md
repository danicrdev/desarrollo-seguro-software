# Entrega 3 — actualización para `desarrollo-seguro-software`

> **Alcance:** laboratorio académico, exclusivamente `localhost`. Código preparado y con **16 pruebas unitarias ejecutadas aquí**. No se ha realizado despliegue integral Docker/PostgreSQL en este entorno; no debe afirmarse que las pruebas MitM o SQL Injection ya se superaron.

Este paquete **sustituye** `app/main.py`, `Dockerfile`, `requirements.txt`, `compose.yaml` y `.gitignore` existentes. Agrega `app/security.py`, `postgres/`, `nginx/`, `scripts/`, `tests/` y documentos de evidencias. Mantiene los endpoints `/api/v1` y los roles Estudiante, Docente, Auditor y Administrador.

## 1. Antes de actualizar

1. Crea una rama en el repositorio original: `git switch -c aseguramiento-entrega3`.
2. Respalda el volumen de PostgreSQL antes de iniciar el nuevo código. Ejemplo con el contenedor de la entrega anterior en ejecución:
   ```bash
   docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > copia_previa.dump
   ```
   Verifica que `copia_previa.dump` **no** esté vacío; no lo subas a Git.
3. Copia el **contenido** de esta carpeta sobre la raíz de tu repositorio. Comprueba que `app/main.py` queda sustituido.
4. Si ya tienes `.env`, **no lo borres**. El asistente de preparación conserva las contraseñas existentes y agrega los parámetros que falten.
5. Si ya existe un `.env` y cambiaste la contraseña del servidor respecto a la inicialmente almacenada en el volumen, el arranque fallará. No utilices `docker compose down -v` para intentar corregirlo sin respaldar los datos.

## 2. Preparación de una sola vez

Desde la raíz del repositorio, con Python 3.12+ y `cryptography` instalado:

```bash
python -m pip install 'cryptography>=43,<48'
python scripts/preparar.py
```

El script genera `.env` si no existe y crea una CA local y certificados de laboratorio en `certs/`, con SAN `localhost` y `db`. Conserva **DATA_KEY_B64**, los certificados y el respaldo. Perder la clave hace irrecuperables las calificaciones cifradas.

> **Seguridad:** `.env`, `certs/`, los volcados de base de datos y capturas de red NO deben ir a un repositorio público. Esta versión incluye una cuenta de base de datos privilegiada para la migración académica. Para un despliegue real habría que separar el rol de migración del rol de aplicación y usar un gestor de claves. El TLS del servidor PostgreSQL utiliza una clave privada incorporada a la imagen *local* de laboratorio: no publiques ni distribuyas esa imagen.

## 3. Ejecutar en Docker

```bash
docker compose config
docker compose up -d --build
docker compose ps
docker compose logs --tail=120 app
```

Comprueba:

```bash
curl --cacert certs/ca.crt https://localhost:8443/health
curl -I --cacert certs/ca.crt https://localhost:8443/health
curl -I http://localhost:8080/health
```

Esperado, **no medido en tu máquina**: `{"status":"ok"}` y HTTP 200 para `/health` en HTTPS; HSTS (`max-age=300`); redirección HTTP 308 hacia `https://localhost:8443`. Nginx restringe TLS a 1.3 y FastAPI exige `sslmode=verify-full` hacia PostgreSQL; la configuración real debe verificarse ejecutando las pruebas.

Swagger (laboratorio): `https://localhost:8443/docs`; para que el navegador confíe en la CA local puedes importar `certs/ca.crt` en el ámbito de pruebas si corresponde. Evita confiar globalmente en esta CA experimental; también puedes usar `curl --cacert` para no alterar la configuración del equipo.

## 4. Cuentas de demostración

`estudiante@lab.local`, `estudiante2@lab.local`, `docente@lab.local`, `docente2@lab.local`, `auditor@lab.local`, `admin@lab.local`. La contraseña de todas se define en `DEMO_PASSWORD` dentro de `.env`. Para los roles sensibles se utiliza el secreto `DEMO_TOTP_SECRET` (guardado cifrado en PostgreSQL). Nunca lo incluyas en una captura pública.

## 5. Ejecutar pruebas

**Pruebas unitarias (no requieren PostgreSQL):**

```bash
python -m pip install -r requirements.txt
python -m pytest -q tests/test_seguridad.py
```

**Pruebas locales de la API (requieren Docker activo, no son pruebas de ataque exhaustivas):**

```bash
python scripts/verificar_lab.py
```

El archivo `evidence/resultados_locales.json` se genera **solo si el script fue ejecutado**. Contiene resultados de observación, sin copiar contraseñas ni cookies. Si hay errores de infraestructura, el script finaliza sin declarar éxito. Para verificar PostgreSQL con el usuario Auditor hay un endpoint nuevo `GET /api/v1/auditoria/estado-db` que muestra `ssl`, `version` y `cipher` para su conexión.

**Pruebas MitM y SQL Injection completas:** requieren un entorno autorizado de red y ejecución adicional con herramientas como Wireshark, mitmproxy y sqlmap. El hecho de que una prueba unitaria pase **no permite declarar mitigada una vulnerabilidad en un servidor real**. Véase `RESULTADOS_PARA_INFORME.md`.

## 6. Cambios implementados (por lectura de código)

| Requisito | Cambio en este código | Validación integral |
|---|---|---|
| RS-01 | Proxy TLS 1.3, HSTS, PostgreSQL con TLS y `verify-full` | Pendiente de levantar Docker, inspeccionar sesiones y capturas |
| RS-02 | Argon2id, TOTP cifrado, bloqueo confirmado antes del error HTTP | Pendiente de pruebas de API y fuerza bruta limitada |
| RS-03 | Autorización servidor por rol y objeto | Pendiente de pruebas de API |
| RS-04 | SQL parametrizado, tipos Pydantic, UUID | Pendiente de SQLi contra API real y revisión de privilegios |
| RS-05 | AES-256-GCM con AAD de registro, estudiante, curso, corte y versión | Unidad criptográfica aprobada; manipulación DB pendiente |
| RS-06 | Cifrado de nota, observación y secreto TOTP | Unidad aprobada; respaldo cifrado no incluido |
| RS-07 | Auditoría con cadena hash y transacción | Unidad aprobada; cadena NO está anclada fuera de BD |
| RS-08 | Cookie segura, HttpOnly, SameSite Strict; CSRF, cabeceras Nginx | Pendiente prueba real; CSP excluida en `/docs` del laboratorio |
| RS-09 | `client_max_body_size` y timeout Nginx | Rate limit/IP **pendiente** |
| RS-10 | Clave fuera de código y secretos gitignored | Migración sigue ejecutándose con cuenta administrativa |
| RS-11 | Rangos de versiones de dependencias | `pip-audit` y pinning exacto **pendientes** |

**Límites importantes:** esta actualización no debe describirse como cumplimiento del 100% de RS-01 a RS-11. El despliegue completo, permisos mínimos de BD, cifrado de respaldos, rate limiting, rotación de claves y auditoría inmutable fuera de la BD requieren trabajo y verificación adicionales.

## 7. Migración de notas antiguas

Al iniciar con el volumen de la Entrega 2, `initialize_database()` agrega columnas `nota_cifrada` y `observacion_cifrada`, cifra las filas antiguas con AES-GCM, comprueba su integridad básica y elimina las columnas en claro **en una única transacción de PostgreSQL**. También cifra los secretos TOTP preexistentes. Esto modifica el esquema: **respaldar antes es obligatorio**. En nuevos despliegues las notas se crean cifradas desde el principio. Se comprueba huella de la clave para evitar cambios accidentales de `DATA_KEY_B64`.

No ejecutes el código de las entregas anteriores sobre una base de datos ya migrada; ese código espera la columna `nota` en claro.

## 8. Actualizar Git

```bash
git status
git add app scripts tests nginx postgres Dockerfile compose.yaml requirements.txt README.md .gitignore .dockerignore .env.example RESULTADOS_PARA_INFORME.md
git commit -m "Implementar controles de aseguramiento y pruebas de entrega 3"
git push -u origin aseguramiento-entrega3
```
