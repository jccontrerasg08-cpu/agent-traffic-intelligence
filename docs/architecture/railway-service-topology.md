# Topología Railway — laboratorio y analizador separados

## Decisión

Conservar `ati-observation-lab` como un servicio Railway independiente destinado a pruebas controladas. Desplegar `agent-traffic-intelligence` como un **proyecto Railway independiente** con su propio dominio público, fuente GitHub, ciclo de despliegue y configuración de entorno.

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
| Segundo servicio `agent-traffic-intelligence` en el proyecto existente | Creado y vinculado a `jccontrerasg08-cpu/agent-traffic-intelligence`, rama `main`; Railway ejecuta el primer despliegue con Python `3.13.15` y realiza el health check configurado. |
| Validación pública del nuevo dominio | Pendiente del despliegue |

## Reversibilidad

La creación de un segundo servicio no modifica la fuente, dominio ni variables del laboratorio existente. Si el despliegue de ATI falla, se puede eliminar el nuevo servicio sin afectar el destino de pruebas controladas.

## Configuración mínima de ATI

El servicio puede arrancar con la variable `PORT` que Railway inyecta. `ATI_SERVICE_TOKEN` es opcional y sólo habilita `POST /v1/analyze`; mantenerla ausente deja el análisis de cargas de logs deshabilitado. `ATI_HASH_KEY` también es opcional para las rutas públicas. Por tanto, el primer despliegue no debe copiar ninguna variable del laboratorio.

## Incidencia de arranque y corrección

El primer despliegue del segundo servicio compiló e instaló el paquete, pero los registros de ejecución mostraron repetidamente `/bin/bash: line 1: ati-service: command not found`; el health check `/health` no pudo llegar a un proceso activo. La corrección sustituye el ejecutable de consola por el módulo explícito `PYTHONPATH=src python -m agent_traffic_intelligence.runtime`. El nuevo módulo delega en `runtime.server.main`, conserva el mismo ciclo de vida del servicio y evita depender de que el directorio de scripts de `pip` esté en `PATH`.
