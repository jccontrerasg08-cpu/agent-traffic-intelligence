# Evidencia externa — rutas ATI no servidas en Railway

**Fecha:** 2026-08-19  
**Dominio comprobado:** `https://ati-observation-lab-production.up.railway.app`

## Observaciones confirmadas

| Solicitud pública, sin cabeceras ATI | Resultado observado | Estado |
|---|---|---|
| `GET /v1/observe` | El usuario reportó `HTTP 404 Not Found`; la comprobación directa mostró el cuerpo `{"detail":"Not Found"}`. | Confirmado |
| `GET /health` | La comprobación directa mostró el cuerpo `{"detail":"Not Found"}`. | Confirmado |

## Interpretación acotada

| Conclusión | Estado | Motivo |
|---|---|---|
| El dominio público no está sirviendo en este momento las rutas ATI esperadas. | Confirmado | Ambas rutas públicas devolvieron el mismo cuerpo de ruta ausente. |
| El dominio apunta a un despliegue distinto, a una revisión anterior o a un servicio mal configurado. | Inferido | El mismo 404 es compatible con varias causas; no hay acceso autenticado de Railway en esta sesión. |
| La implementación de `GET /v1/observe` es incorrecta. | No verificado | Las comprobaciones locales empaquetadas habían aprobado; falta contrastar la configuración y el despliegue remotos. |

## Evidencia del plano de control de Railway

| Dato mostrado por Railway | Resultado observado | Estado |
|---|---|---|
| Proyecto y servicio vinculados al dominio | Proyecto `triumphant-miracle`; servicio `ati-observation-lab`; dominio `ati-observation-lab-production.up.railway.app`; estado `Online`. | Confirmado |
| Despliegue activo | `Merge pull request #4 from jccontrerasg08-cpu/fix/support-head-observation`; Railway lo marca `Deployment successful`; entorno `python@3.13.14`. | Confirmado |
| Historial visible | Muestra PR #1 a #4 de `ati-observation-lab`; no muestra las PR #30/#31 de `agent-traffic-intelligence`. | Confirmado |
| Diagnóstico más probable | El dominio está vinculado a un servicio o repositorio de laboratorio distinto del repositorio `agent-traffic-intelligence` que contiene `railway.toml` y las rutas ATI. | Inferido |

## Configuración y contrato efectivos

| Elemento | Código o ajuste observado | Estado |
|---|---|---|
| Fuente desplegada | Railway está conectado a `jccontrerasg08-cpu/ati-observation-lab`, rama `main`, con despliegue automático. | Confirmado |
| Proceso de arranque | `uvicorn observation_lab.app:app --host 0.0.0.0 --port $PORT --no-access-log`. | Confirmado |
| Health check | `/healthz`. | Confirmado |
| Ruta pública de observación | `GET` y `HEAD /observe` devuelven `{"status":"observed"}`. | Confirmado por código; no comprobado en vivo durante esta incidencia. |
| Rutas solicitadas al dominio | `/health` y `/v1/observe` no existen en el repositorio conectado. | Confirmado |
| Riesgo de privacidad | El middleware escribe en logs un identificador derivado de dirección de cliente y el valor truncado de `User-Agent`; por tanto no implementa el contrato sin retención de ATI. | Confirmado por código; el contenido de los logs de producción no fue inspeccionado. |

La configuración versionada de `agent-traffic-intelligence` establece `startCommand = "ati-service"` y `healthcheckPath = "/health"`. En contraste, el servicio activo utiliza un repositorio FastAPI distinto con las rutas `/observe` y `/healthz`. Por ello, el 404 no se debe atribuir al controlador HTTP de `agent-traffic-intelligence`.

## Bloqueo operativo para la corrección

| Acción autorizada | Resultado | Estado |
|---|---|---|
| Editar la fuente desde el panel Railway conectado | La extensión de `My Browser` devolvió `HTTP 504` dos veces al abrir el control `Edit`; recargar el panel sí funcionó. | Bloqueado temporalmente |
| Usar la CLI como alternativa | El binario `railway` no está instalado en el entorno. | Bloqueado |

La confirmación del usuario para reemplazar la fuente ya fue recibida. No se hizo ningún cambio de configuración remota debido a estos bloqueos de interfaz.

## Siguiente comprobación

Decidir explícitamente entre (a) reemplazar la fuente Railway por `agent-traffic-intelligence`, que satisface el contrato observe-only sin retención, o (b) modificar el repositorio FastAPI separado. La opción (b) exige eliminar primero su retención de identificador derivado y `User-Agent`; no debe añadirse una simple ruta alias que perpetúe esa retención. No interpretar solicitudes externas 404 como observaciones de cliente ni como datos de identidad.

## Despliegue aislado de ATI — evidencia adicional

El 19 de agosto de 2026 se creó un segundo servicio `agent-traffic-intelligence` dentro del proyecto Railway existente, conectado a `jccontrerasg08-cpu/agent-traffic-intelligence`, rama `main`. Railway construyó la imagen e instaló el paquete con éxito, pero el registro de ejecución informó repetidamente: `/bin/bash: line 1: ati-service: command not found`. El health check configurado en `/health` agotó sus reintentos porque no existía un proceso activo.

La causa confirmada es la disponibilidad del ejecutable de consola en el `PATH` del contenedor, no una ausencia de la ruta `/health` ni un problema del contrato HTTP. La corrección pendiente de publicar usa un módulo Python explícito que carga el mismo servidor sin depender de ese `PATH`.
