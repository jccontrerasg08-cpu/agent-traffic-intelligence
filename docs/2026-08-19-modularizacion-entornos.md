# Cierre de modularización, casos y entornos

**Fecha:** 2026-08-19  
**Autor:** Manus AI  
**Estado:** Cambio local validado; pendiente de revisión protegida y fusión.

## Objetivo cumplido

Esta iteración convierte las recomendaciones de la conversación adjunta en límites de código, contratos de investigación, perfiles operativos y casos comprobables. El cambio mantiene ATI como una sola distribución Python y un sistema **observe-only**. No activa fingerprints de red, ML, eBPF, captura de navegador, grafos de infraestructura, recolección de corpus ni mitigación; esas rutas quedan documentadas detrás de contratos y criterios de entrada.

| Resultado | Implementación | Compatibilidad preservada |
|---|---|---|
| Ingestión explícita | `ingestion.jsonl` es la implementación canónica de normalización y privacidad. | `parsers.jsonl` reexporta los mismos objetos. |
| Detección explícita | `detection.pipeline` contiene el orquestador, evidencia y puntuación. | `engine` reexporta los mismos objetos. |
| Runtime segmentado | `runtime.config`, `runtime.http` y `runtime.server` separan límites, protocolo y ciclo de vida. | `service` conserva `main` y las importaciones públicas. |
| Investigación bloqueada por contrato | `research.contracts` exige owner, autorización, datos, retención y métricas. | No añade detector ni fuente de datos activa. |
| Entornos reproducibles | Makefile, ejemplos de entorno y CI ejecutan perfiles aislados. | `make check`, CLI y `ati-service` continúan disponibles. |

## Casos y variaciones

El catálogo [`cases-and-variations.md`](cases-and-variations.md) cubre las rutas actualmente activas de ingreso, identidad, servicio, evaluación y corpus, así como las variaciones propuestas que permanecen bloqueadas. Cada caso declara su entrada, salida esperada, límite de seguridad y perfil de prueba. La documentación no interpreta los fixtures como un benchmark real ni convierte el tráfico no etiquetado en ground truth.

| Perfil | Propósito | Aislamiento |
|---|---|---|
| `make test-core` | Parser, modelos, features, reglas, score y fachadas. | Sólo fixtures locales. |
| `make test-identity` | Cachés, evidencia de identidad y errores offline. | Sin refresh de fuentes. |
| `make test-service` | Autenticación, límites y protocolo del adaptador. | HTTP local. |
| `make test-research` | Contratos de rutas futuras. | Sin detectores experimentales. |
| `make test-controlled` | CLI, etiquetas y evaluación controlada. | Artefactos autorizados. |
| `make test-evaluation` | Métricas y valores indefinidos. | Detecciones y labels de fixture. |
| `make smoke-service` | Wheel instalado, proceso, salud y privacidad. | Loopback temporal. |
| `make profile-matrix` | Ejecución secuencial de todos los perfiles anteriores. | No requiere secretos de producción. |

GitHub Actions incorpora además una matriz `profiles` para que cada perfil se ejecute de forma independiente en Python 3.11. Las matrices de núcleo y verificación existentes conservan Python 3.11, 3.12 y 3.13, cobertura, build y clean-install.

## Evidencia de verificación local

| Comprobación | Resultado |
|---|---|
| `make profile-matrix` | Correcto: perfiles de core, identidad, servicio, investigación, corpus controlado, evaluación y servicio empaquetado. |
| `make check` | Correcto: Ruff, mypy y **351 pruebas**. |
| `pip check` | Sin requisitos rotos. |
| `pip-audit -r requirements-dev.txt` | Sin vulnerabilidades conocidas. |
| `git diff --check` | Correcto. |
| Wheel | Construido y usado por el smoke test. |

El smoke test empaquetado comprobó salud HTTP, rechazo de token ausente, rechazo de Content-Type no JSONL y salida libre de IP cruda/query string. El primer sondeo de disponibilidad puede ocurrir antes de que el proceso escuche y producir un fallo transitorio de conexión; el script reintenta sólo dentro del periodo local de arranque y sólo declara éxito después de comprobar las respuestas del contrato.

## Límites pendientes

No se revisó ni modificó un corpus real, un dominio de Railway, secretos de despliegue o tráfico de producción. Cualquier nueva fuente de datos debe actualizar el registro de evidencia, el catálogo de casos y la matriz de entornos antes de entrar en el pipeline activo. Para rutas de investigación, el contrato debe pasar de `blocked` a revisión explícita con autorización, retención, baseline y objetivo de falsa alarma definidos.

## Referencia interna

[1] Conversación adjunta por el usuario: `Pasted_content_01.txt`.
