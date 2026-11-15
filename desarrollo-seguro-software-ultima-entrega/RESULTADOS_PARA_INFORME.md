# Texto para el informe de la Entrega 3 — resultados diferenciados

> Este documento distingue los **resultados medidos en el entorno del asistente** de los **resultados esperados al ejecutar el laboratorio**. Las pruebas contra la aplicación con PostgreSQL, MitM y sqlmap **no se realizaron** porque el laboratorio Docker no estaba disponible. Sustituye los estados pendientes solo si obtienes registros reales de tu ejecución.

## 1. Resultados efectivamente ejecutados

**Entorno evaluado:** pruebas unitarias aisladas de las funciones de seguridad en Python, sin servidor de aplicaciones ni PostgreSQL.

**Comando:** `PYTHONPATH=. pytest -q tests/test_seguridad.py`

**Salida obtenida:**

```text
................                                                         [100%]
16 passed in 0.14s
```

**Interpretación:** las 16 pruebas realizadas respaldan el funcionamiento unitario del cifrado AES-256-GCM y el rechazo de alteraciones del texto cifrado; la autenticación contextual por registro, estudiante, curso y versión; el cifrado del secreto TOTP; la verificación de una cadena de hashes; y el cálculo ponderado de las calificaciones. **No representan pruebas de ataque al sistema desplegado.**

## 2. Matriz de escenarios de ataque: no ejecutados contra la aplicación

| Caso | Procedimiento previsto | Resultado esperado según el diseño reforzado | Estado real |
|---|---|---|---|
| M-01 | Capturar solicitud HTTP de la versión inicial | Tráfico HTTP potencialmente legible en red observada | **NO EJECUTADO** |
| M-02 | Capturar intercambio HTTPS sobre 8443 | TLS 1.3; datos HTTP no visibles en captura pasiva | **NO EJECUTADO** |
| M-03 | Interponer certificado de intermediario no confiable | Cliente que valida CA y nombre debe rechazar conexión | **NO EJECUTADO** |
| M-04 | Probar HTTP 8080 y cabecera HSTS HTTPS | HTTP 308, URL HTTPS y cabecera Strict-Transport-Security | **NO EJECUTADO** |
| M-05 | Consultar `pg_stat_ssl` y validar CA y nombre `db` | `ssl=true`, `version=TLSv1.3` y `sslmode=verify-full` en Psycopg | **NO EJECUTADO** |
| S-01 | Intentar `x' OR '1'='1' --` en correo de login | HTTP 401 o 422; no se crea sesión | **NO EJECUTADO** |
| S-02 | Enviar `'` como correo de login | Rechazo genérico; sin error SQL | **NO EJECUTADO** |
| S-03 | Usar identificador de curso no válido | HTTP 422 por validación UUID (sesión válida) | **NO EJECUTADO** |
| S-04 | Enviar `nota='0 OR 1=1'` en actualización | HTTP 422; nota y versión sin cambios | **NO EJECUTADO** |
| S-05 | Ejecutar sqlmap contra la API autorizada | No confirmar inyección; analizar resultado y falsos negativos | **NO EJECUTADO** |

La ejecución de un escáner sin detectar hallazgos no equivale automáticamente a ausencia de SQL Injection. Deben registrarse alcance, parámetros probados, respuestas y limitaciones.

## 3. Controles complementarios

| Caso | Qué demostrar | Evidencia actual |
|---|---|---|
| A-01 | HTTP 403 cuando estudiante intenta modificar notas | Código RBAC disponible, respuesta API **no ejecutada** |
| A-02 | HTTP 403 al consultar curso de otro docente | Código de pertenencia disponible, respuesta API **no ejecutada** |
| A-03 | Tras cinco fallos se persiste bloqueo de 15 min | Condición implementada, **sin ejecución DB** |
| A-04 | Falta de CSRF genera HTTP 403 | Código implementado, **sin ejecución API** |
| A-05 | Endpoint Auditor verifica cadena de hashes | **Prueba unitaria del verificador aprobada**, endpoint no ejecutado |
| A-06 | Alteración del texto cifrado genera rechazo | **Prueba unitaria AES-GCM aprobada**, alteración real DB no ejecutada |
| A-07 | Nota legítima conserva su valor tras ataques | **Sin comparación de estados DB** |

## 4. Redacción académica propuesta para pegar en el Word

### 4.1. Implementación de controles

> En esta etapa desarrollamos una actualización de la aplicación, conservando FastAPI y PostgreSQL y agregando mecanismos de protección de transporte y almacenamiento. La configuración propuesta incorpora Nginx con TLS 1.3 para el cliente, conexión verificada hacia PostgreSQL, cifrado AES-256-GCM de calificaciones con datos asociados al registro, controles por rol, validación de entradas y protección de sesiones. Además, corregimos la persistencia del contador de accesos fallidos y estructuramos pruebas automatizadas. La implementación corresponde al código entregado; su operación integrada queda pendiente de comprobar en el entorno Docker.

### 4.2. Resultados unitarios de integridad

> Ejecutamos un conjunto de dieciséis pruebas unitarias sobre las funciones criptográficas y de validación independientes del servidor. Todas terminaron satisfactoriamente. Entre los casos comprobados se encuentran la recuperación de datos cifrados con la clave correcta, el rechazo ante alteraciones del texto cifrado, la falla de descifrado al modificar la versión o el estudiante asociado, la protección de secretos TOTP, la verificación de la cadena de hashes y el cálculo de la nota definitiva. Estos resultados respaldan el funcionamiento aislado de dichos componentes, pero no permiten afirmar que los ataques MitM y SQL Injection hayan sido contenidos por la aplicación desplegada.

### 4.3. Resultados de las pruebas MitM

> Las pruebas de intermediario M-01 a M-05 quedaron pendientes de ejecución debido a que no fue posible preparar el laboratorio con los contenedores y las interfaces de captura. Sin embargo, incorporamos una configuración orientada a restringir las comunicaciones a TLS 1.3, presentar un certificado para el servidor local y verificar el certificado de PostgreSQL. La ausencia de capturas y de registros de conexión impide emitir una conclusión experimental sobre la resistencia frente a MitM. Los criterios de aceptación y las configuraciones quedan documentados para su verificación posterior.

### 4.4. Resultados de SQL Injection

> Las pruebas de ataque S-01 a S-05 contra la API operativa no pudieron completarse, por lo que se clasificaron como no ejecutadas. Realizamos una revisión estática del código que muestra la utilización de parámetros separados del texto SQL y validaciones de tipos mediante Pydantic. Estas medidas reducen el riesgo de inyección SQL, pero no sustituyen la ejecución de los intentos maliciosos ni un escaneo efectivo del servidor. Se documentaron los escenarios, las entradas de prueba y los resultados HTTP esperados para una futura validación.

### 4.5. Limitaciones y conclusión

> Como limitación principal identificamos que no fue posible reproducir el despliegue integral ni efectuar las capturas y escaneos requeridos por la guía. En consecuencia, los resultados verificables de esta etapa se restringen a las pruebas unitarias ejecutadas y a la revisión del código preparado. La evidencia permite describir los controles incorporados y su comportamiento aislado, pero aún no demostrar experimentalmente que el sistema completo satisfaga todos los requisitos de seguridad. Recomendamos completar las pruebas de MitM y SQL Injection sobre una red de laboratorio aislada antes de cerrar la evaluación de aseguramiento.

## 5. Evidencias que sí se pueden anexar ahora

- Captura del archivo `app/security.py` con AES-GCM y los datos asociados.
- Captura de `nginx/nginx.conf` mostrando TLS 1.3 y HSTS.
- Captura de `app/main.py` con `sslmode='verify-full'` y consultas SQL parametrizadas.
- Salida real de `pytest`: `16 passed in 0.14s` (si deseas reproducir, vuelve a ejecutar).
- Matrices de escenarios pendientes y resultado esperado, claramente diferenciadas.

**No usar como evidencia de ataque ejecutado** capturas solo de código, configuraciones, ni resultados esperados.
