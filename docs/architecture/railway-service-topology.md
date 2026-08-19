# Topología Railway — laboratorio y analizador separados

## Decisión

Conservar `ati-observation-lab` como un servicio Railway independiente destinado a pruebas controladas. Desplegar `agent-traffic-intelligence` como un **segundo servicio del mismo proyecto Railway**, con su propio dominio público, fuente GitHub, ciclo de despliegue y configuración de entorno.

Esta decisión evita que el dominio del laboratorio prometa rutas que no implementa y evita trasladar al analizador observe-only la retención de identificadores derivados y `User-Agent` que actualmente forma parte del laboratorio.

## Contratos separados

| Componente | Repositorio fuente | Rutas públicas previstas | Persistencia y propósito |
|---|---|---|---|
| Laboratorio controlado | `jccontrerasg08-cpu/ati-observation-lab` | `/`, `/observe`, `/healthz` | Objetivo FastAPI para experimentos controlados; su política es independiente de ATI. |
| Analizador ATI | `jccontrerasg08-cpu/agent-traffic-intelligence` | `/health`, `/v1/catalog`, `/v1/observe` | Servicio observe-only por solicitud, sin retención de datos de visitante por defecto. |

## Límites operativos

El laboratorio no debe reutilizarse como si fuera el API público de ATI. El servicio ATI no debe recibir variables, dominio, registros o mecanismos de rate limit por identificador del laboratorio. Las pruebas de clientes externos deben dirigirse al dominio exclusivo de ATI y deben distinguir una declaración opt-in de una identidad verificable.

## Estado de despliegue

| Paso | Estado |
|---|---|
| Laboratorio existente conservado sin cambios | Confirmado |
| Configuración `railway.toml` de ATI versionada | Confirmado localmente |
| Segundo servicio `agent-traffic-intelligence` en el proyecto existente | Confirmado; vinculado a `jccontrerasg08-cpu/agent-traffic-intelligence`, rama `main`, con Python `3.13.15` y health check configurado. |
| Validación pública del nuevo dominio | Confirmada para `/health`, `/v1/catalog` y `/v1/observe` sin cabeceras ATI. |

## Reversibilidad

La creación de un segundo servicio no modifica la fuente, dominio ni variables del laboratorio existente. Si el despliegue de ATI falla, se puede eliminar el nuevo servicio sin afectar el destino de pruebas controladas.

## Configuración mínima de ATI

El servicio puede arrancar con la variable `PORT` que Railway inyecta. `ATI_SERVICE_TOKEN` es opcional y sólo habilita `POST /v1/analyze`; mantenerla ausente deja el análisis de cargas de logs deshabilitado. `ATI_HASH_KEY` también es opcional para las rutas públicas. Por tanto, el primer despliegue no debe copiar ninguna variable del laboratorio.

## Incidencia de arranque y corrección

El primer despliegue del segundo servicio compiló e instaló el paquete, pero los registros de ejecución mostraron repetidamente `/bin/bash: line 1: ati-service: command not found`; el health check `/health` no pudo llegar a un proceso activo. La corrección sustituye el ejecutable de consola por el módulo explícito `PYTHONPATH=src python -m agent_traffic_intelligence.runtime`. El nuevo módulo delega en `runtime.server.main`, conserva el mismo ciclo de vida del servicio y evita depender de que el directorio de scripts de `pip` esté en `PATH`.

La PR #32 que contiene esta corrección superó la CI protegida y fue fusionada en `main`. Railway detectó el commit, completó el redespliegue y el dominio generado se verificó públicamente.

El despliegue corregido ahora figura `ACTIVE` y el servicio `agent-traffic-intelligence` está `Online` dentro del proyecto `triumphant-miracle`. El panel confirma la fuente `jccontrerasg08-cpu/agent-traffic-intelligence`, rama `main`, y la configuración proveniente de `railway.toml`. Aún es un servicio no expuesto: Railway ofrece la acción `Generate Domain`; su nombre privado es `agent-traffic-intelligence.railway.internal`.

Se generó el dominio público independiente `https://agent-traffic-intelligence-production.up.railway.app`. La solicitud anónima `GET /health` respondió `200` con `status: ok`, `mode: observe-only`, `persistence: none`, `analysis_endpoint: disabled` y la versión `0.1.0.dev0`. Esta comprobación confirma el proceso y el contrato de salud del servicio ATI, no el laboratorio separado.

Las rutas públicas también fueron comprobadas sin token en el dominio nuevo. `GET /v1/catalog` respondió `200`, `catalog_version: "2"`, `authentication: "not_required"`, `persistence: "none"` y el catálogo de clases declaradas `ai`, `automation`, `bot` y `human`. `GET /v1/observe` respondió `200` con `schema_version: "2"`, `persistence: "none"`, `declared_client_class: "unspecified"`, `controlled_iteration: "not_declared"`, `interaction_mode: "unspecified"`, `client_identity: "not_verified"`, `client_intent: "not_observable"` y `dns_resolution: "not_observable_over_http"`. La presencia de `Forwarded` se devolvió como `present_but_untrusted`, conforme al contrato de frontera de proxy.

La PR #34 corrige además la comparación de nombres de las cabeceras declarativas sin distinguir mayúsculas de minúsculas. Railway detectó esa fusión y creó un nuevo despliegue del segundo servicio; durante su compilación el despliegue previo se mantuvo activo. La prueba pública de las tres rondas declaradas se realizará cuando este nuevo despliegue alcance `Deployment successful`.

El panel de Railway confirmó después que el despliegue de la PR #34 alcanzó `Deployment successful` y que `agent-traffic-intelligence` sigue `Online` con una réplica. La siguiente comprobación debe enviar las tres cabeceras declarativas al dominio público y verificar únicamente etiquetas derivadas en la respuesta.

La comprobación pública posterior devolvió `200` en las tres rondas declarativas. Con `X-ATI-Client-Class: ai`, la ronda `1` devolvió `declared_client_class: "ai"`, `controlled_iteration: "first_declared"` e `interaction_mode: "text"`; las rondas `2` y `3` devolvieron `controlled_iteration: "repeat_declared"`, con modos `text` y `tool_call`, respectivamente. Todas mantuvieron `schema_version: "2"`, `persistence: "none"`, `client_identity: "not_verified"`, `client_intent: "not_observable"` y `dns_resolution: "not_observable_over_http"`. Esto confirma el reconocimiento externo de los nombres de cabecera normalizados, no la identidad ni el historial del cliente.
