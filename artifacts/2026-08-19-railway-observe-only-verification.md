# Evidencia de verificación — servicio observe-only de Railway

**Fecha:** 2026-08-19
**Ámbito:** ejecución local y empaquetada; no se contactó ni modificó el servicio remoto de Railway.

| Comprobación | Resultado observado |
|---|---|
| `PYTHONPATH=src pytest -q` | `345 passed in 4.53s` |
| `ruff check src tests` | Correcto. |
| `mypy src` | Correcto en 55 archivos fuente. |
| `pip check` | Sin requisitos rotos. |
| `pip-audit -r requirements-dev.txt` | Sin vulnerabilidades conocidas. |
| `pip wheel . --no-deps` | Wheel construido correctamente. |
| `git diff --check` | Correcto. |
| `railway.toml` | Sintaxis TOML validada; declara Railpack, `ati-service`, `/health`, timeout y reinicio en fallo. |
| `GET /health` con `PORT=9199` | HTTP 200; `status=ok`, `mode=observe-only`, endpoint de análisis habilitado por secreto. |
| `POST /v1/analyze` sin token | HTTP 401 y `{"error":"unauthorized"}`. |
| `POST /v1/analyze` con `Content-Type: application/json` | HTTP 400 y `{"error":"content_type_must_be_application_x_ndjson"}`. |
| `POST /v1/analyze` con token | Dos detecciones; la respuesta no contenía IP `203.0.113.*` ni valores de query string. |
| Cierre | Tras `SIGTERM`, no permaneció un listener en el puerto 9200. |

El primer intento de construir el wheel falló por un directorio `build/` generado con propiedad `root`, no por el código. Tras retirar sólo ese metadato generado y regenerar el wheel como el usuario del repositorio, la construcción y `git diff --check` finalizaron correctamente.
