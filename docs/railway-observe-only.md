# Servicio técnico observe-only para Railway

**Fecha:** 2026-08-19
**Autor:** Manus AI
**Estado:** Implementado localmente; no aplicado aún a la instancia remota de Railway.

## Propósito y límite operativo

Este repositorio ahora incluye un adaptador HTTP mínimo y versionado, `ati-service`, para ejecutar **análisis explícitamente autorizado** en Railway sin crear una página, panel, navegador embebido ni interfaz de usuario. El proceso permanece en modo **observe-only**: no bloquea, desafía, limita, reescribe, reenvía ni modifica tráfico; tampoco descarga material de identidad ni persiste cuerpos de solicitudes o detecciones.

La decisión responde al requisito de Railway de iniciar un proceso explícito y, cuando se configura una comprobación de salud, escuchar el puerto de la plataforma y devolver HTTP 200 desde la ruta declarada.[1] [2] El archivo `railway.toml` vive en la raíz y define las decisiones de build, start, salud y reinicio como configuración versionada; Railway aplica esa configuración al despliegue y esta tiene precedencia sobre la configuración del dashboard para dicho despliegue.[3]

| Elemento | Contrato implementado | Decisión de seguridad |
|---|---|---|
| Proceso | `ati-service` ejecuta `agent_traffic_intelligence.service:main`. | No arranca un servidor de UI ni un proxy. |
| Enlace | Lee `PORT` y escucha por defecto en `0.0.0.0`. | Permite el contrato de Railway sin fijar un puerto en código. |
| Salud | `GET /health` devuelve 200 con estado, modo y versión. | No autentica ni expone secretos; sólo indica si el endpoint analítico está habilitado. |
| Ingestión | `POST /v1/analyze` acepta un lote UTF-8 JSONL. | Sólo se habilita al definir `ATI_SERVICE_TOKEN`; exige `Authorization: Bearer <token>`. |
| Salida | Devuelve detecciones privacy-safe en la respuesta HTTP. | No conserva bodies, detecciones, etiquetas, caché ni resultados por defecto. |
| Identidad | No activa verificación de fuentes desde el endpoint. | El servicio no refresca rangos, DNS ni material criptográfico. |
| Persistencia | Ninguna en el modelo base. | No se adjunta volumen ni se presupone que el disco efímero sea durable. |

## Rutas y respuestas

| Método y ruta | Autenticación | Respuesta esperada | Finalidad |
|---|---|---|---|
| `GET /health` | No | `200` con JSON `status: "ok"`. | Health check de Railway. |
| `POST /v1/analyze` | `Bearer` obligatorio, comparación en tiempo constante y `Content-Type: application/x-ndjson`. | `200` con `processed` y `detections`; `401` sin token válido; `400` con otro tipo de contenido. | Analizar un lote JSONL autorizado. |
| `POST /v1/analyze` sin `ATI_SERVICE_TOKEN` | No aplicable. | `503` con `analysis_endpoint_disabled`. | Mantener la superficie de datos cerrada por defecto. |
| Cualquier otra ruta | No | `404`. | No existe una interfaz web ni rutas implícitas. |

El adaptador crea un `Detector` y un estado de sesión **por lote**, lo cual preserva la naturaleza acotada del servicio. Las señales conductuales no atraviesan solicitudes HTTP independientes ni se convierten en un perfil persistente. Esta es una limitación deliberada: un sensor continuo requiere, antes de implementarse, una decisión explícita sobre origen autorizado, retención, volumen o backend externo y control de acceso.

## Configuración en Railway

La configuración versionada es:

```toml
[build]
builder = "RAILPACK"
buildCommand = "pip install ."

[deploy]
startCommand = "ati-service"
healthcheckPath = "/health"
healthcheckTimeout = 120
restartPolicyType = "ON_FAILURE"
restartPolicyMaxRetries = 10
```

Railway detecta `railway.toml` en el código y soporta estos campos de build y deploy.[3] La ruta de salud debe ser accesible para el proceso recién iniciado y responder 200 antes de activar la versión desplegada.[2]

| Variable | Obligatoria | Valor o límite por defecto | Uso |
|---|---:|---|---|
| `PORT` | La inyecta Railway. | `8080` sólo para desarrollo local. | Puerto del listener. |
| `ATI_SERVICE_TOKEN` | Sí, para `POST /v1/analyze`. | Sin valor: endpoint analítico deshabilitado. | Secreto compartido de ingestión. |
| `ATI_HASH_KEY` | Sí, si los JSONL incluyen IPs crudas. | Sin valor: entradas con IP cruda se rechazan. | Pseudonimización BLAKE2b. |
| `ATI_MAX_REQUEST_BYTES` | No. | `10_000_000`. | Límite total del body HTTP. |
| `ATI_MAX_BATCH_EVENTS` | No. | `1_000`. | Límite de eventos por lote. |
| `ATI_MAX_LINE_CHARACTERS` | No. | `1_000_000`. | Límite de una línea JSONL. |
| `ATI_MAX_CLIENTS` | No. | `10_000`. | Cota de sesiones del lote. |
| `ATI_MAX_EVENTS_PER_CLIENT` | No. | `128`. | Cota de historial por cliente. |
| `ATI_SESSION_WINDOW_SECONDS` | No. | `900`. | Ventana de las señales de sesión. |

Los valores de secreto se deben cargar en el panel de variables de Railway, nunca en Git, `railway.toml`, artefactos de prueba, logs ni mensajes. La configuración en código no actualiza permanentemente el dashboard; sólo prevalece para el despliegue que la contiene.[3]

## Procedimiento de aplicación

Primero, revisa el diff y confirma que el servicio de Railway apunta a la raíz de este repositorio. Luego configura, como mínimo, `ATI_SERVICE_TOKEN` y, si habrá una dirección IP cruda en la carga, `ATI_HASH_KEY`. Railway debe conservar su `PORT` inyectado; no se le debe asignar manualmente una dirección o puerto diferente.

En segundo lugar, despliega una revisión que incluya `railway.toml`, `ati-service` y el adaptador. Comprueba la salida de build para confirmar `pip install .`, y la de inicio para confirmar que el proceso no termina. Finalmente, comprueba `GET /health` desde el dominio interno o público de Railway. La existencia de un 200 de salud sólo confirma que el proceso está disponible; no autoriza ni demuestra el endpoint de análisis.

Para la prueba controlada del endpoint, envía exclusivamente un JSONL sintético o un artefacto autorizado y con los datos minimizados. Usa `Authorization: Bearer <ATI_SERVICE_TOKEN>` y confirma que una solicitud sin token recibe 401. No uses logs reales, cookies, encabezados Authorization originales, claves de hash ni resultados con IPs crudas para probar el despliegue.

> El repositorio queda listo para este contrato, pero **no se aplicó ningún cambio a Railway**: esta sesión no tiene acceso a su servicio, dominio, logs ni variables. El commit y push siguen siendo necesarios para que Railway pueda desplegar el cambio desde GitHub.

## Evidencia local

La validación local se realizó sobre el árbol fuente y después sobre el ejecutable empaquetado. Las seis pruebas nuevas cubren salud sin secreto expuesto, endpoint deshabilitado por defecto, rechazo sin token, rechazo de Content-Type no permitido, salida pseudonimizada de un lote autorizado, lote vacío y error de enlace controlado. La suite completa alcanzó **345 pruebas correctas**; `ruff check src tests`, `mypy src`, `pip check`, `pip-audit -r requirements-dev.txt`, `git diff --check` y la construcción de wheel resultaron correctos.

El smoke test final con el ejecutable instalado, `PORT=9200`, verificó lo siguiente: `GET /health` respondió 200 con `mode: observe-only`, una solicitud sin token devolvió 401, un JSONL con `Content-Type: application/json` devolvió 400 y un lote autorizado de dos eventos con `application/x-ndjson` produjo dos detecciones sin IP cruda ni valores de query string en la respuesta. El proceso se detuvo limpiamente después de recibir `SIGTERM` y no dejó listener en el puerto.

## Límites y siguiente decisión

Este adaptador resuelve el bloqueo de proceso, puerto, salud y endpoint cerrado por defecto. No convierte ATI en un sensor continuo ni en un sistema de mitigación. La siguiente mejora sólo es justificable si se define con evidencia un origen autorizado de logs y una necesidad real de correlación entre lotes. En ese caso, el diseño debe incluir retención, minimización, cifrado, rotación de token, almacenamiento persistente y health semantics coherentes con un volumen; Railway advierte que servicios con un volumen adjunto pueden tener una breve indisponibilidad durante redespliegues.[2]

## Referencias

[1] [Railway Docs: Set a Start Command](https://docs.railway.com/deployments/start-command)
[2] [Railway Docs: Healthchecks](https://docs.railway.com/deployments/healthchecks)
[3] [Railway Docs: Config as Code Reference](https://docs.railway.com/config-as-code/reference)
