# Registro de verificación — observación controlada por repetición

**Cambio verificado:** Declaraciones públicas de iteración e interacción en `GET /v1/observe`.

**Artefacto y entorno:** Árbol local de `agent-traffic-intelligence` basado en `origin/main` `cc720813`; Python 3.11; wheel local construido e instalado en el entorno de prueba.

**Afirmación bajo prueba:** ATI normaliza clases de cliente, iteración y modo de interacción declarados para solicitudes individuales sin devolver valores crudos, ni crear un contador persistente o un perfil de cliente.

**Línea base:** El contrato público anterior exponía sólo la clase de cliente y presencias de cabeceras; `schema_version` y `catalog_version` eran `1`.

**Criterio de éxito:** Las clases declaradas y las etiquetas de iteración/modo admitidas devuelven sólo categorías cerradas; las entradas inválidas no se reflejan; el paquete, smoke test, tipado y perfiles concluyen correctamente.

**Criterio de fallo:** Cualquier valor literal de cabecera sensible aparece en la respuesta, una prueba de contrato falla, el wheel no arranca o un control estático falla.

## Pasos de verificación

| Paso | Comando o inspección exacta | Observación esperada | Resultado observado | Estado |
|---|---|---|---|---|
| 1 | `PYTHONPATH=src:. pytest -q tests/test_public_observation.py tests/test_service.py` | Contratos públicos y de servicio aprobados. | `15 passed in 7.97s`. | Aprobado |
| 2 | `ruff check src tests && mypy src && git diff --check` | Sin defectos de estilo, tipos o espacios. | Ruff correcto; mypy correcto en 66 archivos; diff sin errores. | Aprobado |
| 3 | `make profile-matrix && make check` | Perfiles, empaquetado, smoke test y suite global correctos. | Wheel construido e instalado, `pip check` correcto, smoke test correcto y `360 passed in 9.22s`. | Aprobado |
| 4 | Prueba `test_public_observation_rejects_invalid_control_declarations_without_reflection` | Valores inválidos se degradan sin reflejarse. | La iteración devolvió `invalid_declaration`, el modo `unspecified` y los literales de prueba no aparecieron en JSON. | Aprobado |

## Cobertura y límites

| Verificado | No verificado | Riesgo o acción restante |
|---|---|---|
| Contrato local de respuesta, ausencia de reflexión de valores de prueba, instalación del wheel, arranque empaquetado y perfiles definidos. | Despliegue activo de Railway y ejecución por una IA externa concreta. | Requieren la URL real desplegada y un ejecutor externo que conserve su propio recuento de respuestas. |
| Etiquetas `first_declared`, `repeat_declared`, `not_declared`, `invalid_declaration` y modos cerrados. | Frecuencia histórica, identidad real, intención, contenido de interacción, IP, DNS y navegador subyacente. | Están fuera del contrato observe-only; no deben inferirse. |

## Resultado

**Estado final:** `confirmed` para el comportamiento local verificado.

**Decisión:** Conservar el cambio y enviarlo a revisión protegida.

**Ubicación de evidencia:** `tests/test_public_observation.py`, `scripts/smoke_service.sh`, `Makefile` y los comandos de verificación indicados arriba.

**Siguiente acción:** Crear la PR y, tras el despliegue automático de Railway, realizar una solicitud pública contra la URL real para confirmar el entorno activo.
