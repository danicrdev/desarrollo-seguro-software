# Laboratorio de Desarrollo Seguro de Software

Proyecto académico del Politécnico Grancolombiano para el intercambio seguro de información confidencial mediante una aplicación web de gestión de calificaciones.

## Descripción

El proyecto implementa una arquitectura basada en FastAPI y PostgreSQL para gestionar usuarios, cursos y calificaciones académicas. Incluye mecanismos de autenticación, autorización por roles, control de sesiones y auditoría de operaciones.

El laboratorio permite estudiar los riesgos asociados al intercambio de información y evaluar controles de seguridad mediante pruebas funcionales, análisis de vulnerabilidades y captura de tráfico de red.

### Tecnologías

- Python 3.12
- FastAPI
- PostgreSQL 16
- Docker y Docker Compose
- OWASP ZAP
- Nmap
- Wireshark
- pytest

## Requisitos previos

Antes de iniciar, asegúrate de tener instalados:

- Docker Engine o Docker Desktop.
- Docker Compose v2.
- Git.
- `curl` para verificar las respuestas de la API.
- Wireshark y OWASP ZAP para las evaluaciones de seguridad.

## Estructura del proyecto

```text
desarrollo-seguro-software/
├── app/
│   └── main.py
├── evidence/
│   ├── functional/
│   ├── zap/
│   └── captures/
├── .env
├── .gitignore
├── compose.yaml
├── Dockerfile
├── requirements.txt
└── README.md
```

## 1. Configuración del entorno

Clona el repositorio y accede a su directorio:

```bash
git clone https://github.com/danicrdev/desarrollo-seguro-software
cd desarrollo-seguro-software
```

Crea el archivo `.env` en la raíz del proyecto con las siguientes variables:

```dotenv
POSTGRES_DB=calificaciones
POSTGRES_USER=labuser
POSTGRES_PASSWORD=CAMBIAR_POR_UN_SECRETO_LOCAL

DATABASE_URL=postgresql://labuser:CAMBIAR_POR_UN_SECRETO_LOCAL@db:5432/calificaciones

DEMO_PASSWORD=CAMBIAR_POR_UNA_CLAVE_DE_LABORATORIO
DEMO_TOTP_SECRET=JBSWY3DPEHPK3PXP
COOKIE_SECURE=false
```



## 2. Iniciar la aplicación

Desde la raíz del repositorio, ejecuta:

```bash
docker compose up -d --build
```

Comprueba el estado de los contenedores:

```bash
docker compose ps
```

Consulta los registros de la aplicación:

```bash
docker compose logs -f app
```

Verifica que la API esté disponible:

```bash
curl http://127.0.0.1:8000/health
```

La respuesta esperada es:

```json
{
  "status": "ok"
}
```

Para detener los servicios:

```bash
docker compose down
```

Para detenerlos y eliminar también los datos persistidos en el volumen de PostgreSQL:

```bash
docker compose down -v
```


## 3. Acceso a la API

Con la aplicación en ejecución, puedes consultar la documentación interactiva en:

- Swagger UI: http://127.0.0.1:8000/docs
- OpenAPI: http://127.0.0.1:8000/openapi.json
- Estado del servicio: http://127.0.0.1:8000/health

La documentación permite revisar los endpoints, los parámetros requeridos y los códigos de respuesta.

## 4. Cuentas de prueba

El entorno de demostración contempla las siguientes cuentas:

| Rol | Correo electrónico |
|---|---|
| Estudiante | `estudiante@lab.local` |
| Estudiante 2 | `estudiante2@lab.local` |
| Docente | `docente@lab.local` |
| Docente 2 | `docente2@lab.local` |
| Auditor | `auditor@lab.local` |
| Administrador | `admin@lab.local` |

La contraseña se configura mediante la variable `DEMO_PASSWORD`.

Los roles sensibles requieren un segundo factor TOTP. Para obtener el código actual de las cuentas de laboratorio, ejecuta:

```bash
docker compose exec app python -c \
'import os, pyotp; print(pyotp.TOTP(os.environ["DEMO_TOTP_SECRET"]).now())'
```

El código es temporal y cambia periódicamente.

Estas cuentas y credenciales deben utilizarse exclusivamente en el entorno de pruebas.

## 5. Endpoints principales

| Método | Endpoint | Función |
|---|---|---|
| GET | `/health` | Verificar disponibilidad. |
| POST | `/api/v1/auth/login` | Iniciar sesión. |
| POST | `/api/v1/auth/mfa` | Verificar el segundo factor. |
| GET | `/api/v1/me` | Consultar el usuario autenticado. |
| POST | `/api/v1/auth/logout` | Cerrar sesión. |
| GET | `/api/v1/cursos` | Consultar cursos según el rol. |
| GET | `/api/v1/me/calificaciones` | Consultar calificaciones propias. |
| GET | `/api/v1/cursos/{course_id}/calificaciones` | Consultar calificaciones de un curso autorizado. |
| PUT | `/api/v1/cursos/{course_id}/calificaciones/{student_id}` | Registrar o modificar una calificación. |
| GET | `/api/v1/auditoria` | Consultar los registros de auditoría. |
| POST | `/api/v1/usuarios` | Crear un usuario. |
| PATCH | `/api/v1/usuarios/{target_id}` | Actualizar el estado o rol de un usuario. |

Los endpoints protegidos requieren autenticación y, para las operaciones de modificación, validación del token CSRF cuando corresponda.

## 6. Pruebas funcionales

Los casos de prueba deben cubrir los siete requerimientos funcionales definidos en el proyecto:

- **RF-01:** autenticación y verificación del segundo factor.
- **RF-02:** administración de sesiones y cierre de sesión.
- **RF-03:** consulta de calificaciones propias.
- **RF-04:** consulta de calificaciones de cursos asignados.
- **RF-05:** registro y modificación de calificaciones.
- **RF-06:** consulta y verificación de auditoría.
- **RF-07:** administración de usuarios.

Si se implementan las pruebas automatizadas con pytest, se pueden ejecutar mediante:

```bash
python -m pip install -r requirements.txt
pytest -v
```

Los resultados deberán guardarse en `evidence/functional/`. Los casos que todavía no tengan pruebas automatizadas deberán ejecutarse mediante las solicitudes HTTP o Swagger UI y registrarse manualmente.

## 7. Evaluación de vulnerabilidades con OWASP ZAP

Crea el directorio de evidencias:

```bash
mkdir -p evidence/zap
```

Con la aplicación en ejecución, ejecuta el análisis base:

```bash
docker compose --profile security run --rm zap
```

El análisis está configurado para producir:

- `evidence/zap/report.html`
- `evidence/zap/report.json`

OWASP ZAP Baseline realiza una exploración pasiva y no sustituye una prueba de penetración completa. Los hallazgos deben revisarse y confirmarse antes de reportarlos como vulnerabilidades verificadas.

Para realizar pruebas activas, utiliza únicamente un entorno aislado y sistemas para los que tengas autorización explícita.

## 8. Captura de tráfico con Wireshark

Utiliza Wireshark para registrar las comunicaciones generadas durante los siguientes escenarios:

| Identificador | Escenario |
|---|---|
| CT-01 | Inicio de sesión. |
| CT-02 | Consulta de calificaciones. |
| CT-03 | Actualización de calificaciones. |
| CT-04 | Cierre de sesión. |
| CT-05 | Comunicación entre FastAPI y PostgreSQL. |

Para analizar el tráfico HTTP de la aplicación, puedes utilizar el filtro:

```text
tcp.port == 8000
```

Para observar las conexiones PostgreSQL:

```text
tcp.port == 5432
```




