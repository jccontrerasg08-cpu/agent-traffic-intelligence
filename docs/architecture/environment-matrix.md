# Matriz de entornos y perfiles de prueba

Los perfiles están diseñados para ejecutar variaciones con datos propios o fixtures deterministas. Ningún perfil consulta Internet, refresca fuentes de identidad, captura tráfico de navegador ni requiere secretos de producción.

## Perfiles disponibles

| Perfil | Comando | Finalidad | Datos y red | Resultado esperado |
|---|---|---|---|---|
| Núcleo | `make test-core` | Modelos, parser, señales, reglas, score y motor. | Fixtures locales; red prohibida. | Detecciones explainable compatibles. |
| Identidad offline | `make test-identity` | Perfiles, caché, DNS simulado, rangos y firmas almacenadas. | Fixtures locales; no DNS real ni refresh. | Verificación neutral ante fallos operativos. |
| Servicio | `make test-service` | Salud, autenticación, Content-Type, límites y privacidad del adaptador HTTP. | Loopback local; sin UI ni persistencia. | 200 de salud, 401 sin token y rechazo de entradas inválidas. |
| Corpus controlado | `make test-controlled` | Marcadores de campaña, manifiestos, etiquetas, `ati run` y readiness. | Fixture autorizado; no tráfico externo. | Artefacto privacy-safe y `review-required` cuando falta cobertura. |
| Evaluación | `make test-evaluation` | Métricas, cobertura, clases ausentes y calibración. | Detecciones/etiquetas locales. | Métricas explícitas y nulos cuando una métrica no está definida. |
| Regresión completa | `make test-all` | Toda la suite. | Local y determinista. | Todas las pruebas correctas. |
| Calidad | `make check` | Lint, tipos y regresión. | Local. | Ruff y mypy correctos, además de suite completa. |
| Paquete | `make package` | Construcción wheel/sdist y clean-install. | Build local; no red durante análisis. | Artefacto instalable y ejecutable. |
| Servicio empaquetado | `make smoke-service` | Ejecutable `ati-service` con `PORT` y lote autorizado mínimo. | Loopback; secretos de prueba efímeros. | Health, autenticación y salida privacy-safe. |

## Archivos de entorno de ejemplo

Los archivos bajo `environments/` no contienen secretos y describen el mínimo para cada modo. Cópialos a un archivo local ignorado por Git o define las variables en el shell. Nunca subas `ATI_HASH_KEY`, `ATI_SERVICE_TOKEN`, logs de producción, etiquetas sensibles o material de verificación.

| Archivo | Uso | Variables destacadas |
|---|---|---|
| `environments/development.env.example` | Análisis local de JSONL. | `ATI_HASH_KEY`, límites de línea y sesión. |
| `environments/identity-offline.env.example` | Verificación basada en caché. | `ATI_SOURCE_CACHE`, modo offline. |
| `environments/service.env.example` | Servicio técnico local/Railway. | `PORT`, `ATI_SERVICE_TOKEN`, límites de lote. |
| `environments/controlled-corpus.env.example` | Campaña con corpus local autorizado. | `ATI_HASH_KEY`, identificador de corpus y directorio de artefactos. |
| `environments/ci.env.example` | Regresión determinista. | Sin secretos ni rutas de usuario. |

## Reglas para variantes

Cada nueva variante debe declarar en su manifiesto o documento de caso el objetivo, propietario, autorización, datos que toca, transformaciones de minimización, retención, etiquetas, baseline, métrica de éxito, umbral de parada y negativo de control. Las variantes no deben reutilizar una marca de campaña como etiqueta humana, ni presentar tráfico sintético como evidencia de rendimiento de producción.

El perfil de corpus controlado sólo demuestra la corrección de los contratos de campaña y evaluación. El resultado no es un benchmark representativo hasta que incluya tráfico no controlado con etiquetas autorizadas y un manifiesto que describa sesgos, cobertura y separación temporal/familiar.
