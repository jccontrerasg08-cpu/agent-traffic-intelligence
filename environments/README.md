# Entornos de ATI

Los archivos `*.env.example` describen límites y nombres de variables, no secretos reutilizables. Para pruebas locales, copia el ejemplo requerido fuera del repositorio o cárgalo sólo en una shell controlada. Los patrones `.env` y `.env.*` ya están ignorados por Git; los ejemplos versionados son la excepción deliberada.

| Entorno | Objetivo | Puede usar secretos | Puede acceder a red | Puede retener datos |
|---|---|---:|---:|---:|
| Desarrollo | Analizar fixtures o JSONL propio. | Sólo clave local de hash. | No por defecto. | No. |
| Identidad offline | Verificar fixtures y cachés de prueba. | No. | No. | Sólo fixture versionado. |
| Servicio | Validar adaptador HTTP o desplegar observe-only. | Sí, mediante gestor de secretos. | No para el adaptador base. | No. |
| Observación pública | Catalogar capacidades declaradas de una sola solicitud. | No. | No. | No. |
| Corpus controlado | Evaluar campaña autorizada. | Sólo clave de corpus. | No. | Sólo artefacto permitido por manifiesto. |
| CI | Regresión determinista. | No. | No. | No. |

Ningún ejemplo habilita fingerprints de red, grafos, eBPF, telemetría de navegador ni descubrimiento de desconocidos. Esas rutas permanecen bloqueadas hasta cumplir los contratos descritos en `docs/architecture/modular-boundaries.md`.

Para una campaña local propia, el único target versionado es [`../lab/controlled_observer.py`](../lab/controlled_observer.py). Su contrato se prueba dentro de `make test-controlled`, registra sólo JSONL minimizado y no convierte las solicitudes no marcadas en etiquetas negativas.

El perfil `public-observation.env.example` deja la ingestión deshabilitada y sirve sólo `GET /health`, `GET /v1/catalog` y `GET /v1/observe`. Este último devuelve presencia de señales y límites de inferencia; no devuelve valores de cabecera ni confirma que un visitante sea una persona, IA, bot, automatización o usuario de DNS.
