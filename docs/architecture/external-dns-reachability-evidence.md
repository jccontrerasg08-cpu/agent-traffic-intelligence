# Registro de alcance DNS — clientes externos

**Fecha de comprobación:** 2026-08-19

**Dominio bajo prueba:** `agent-traffic-intelligence-production.up.railway.app`

## Incidente reportado

Un ejecutor externo configuró correctamente las tres rondas declarativas, pero su cliente devolvió `curl: (6) Could not resolve host`. No obtuvo código HTTP ni JSON. Por tanto, el informe no se clasifica como una respuesta ATI ni como una evidencia de identidad, intención, DNS del cliente o recepción de cabeceras.

## Contraste independiente

| Fuente de comprobación | Resultado | Interpretación limitada |
|---|---|---|
| Resolutor local del entorno de verificación | `69.46.46.75` | El dominio resolvía en ese entorno. |
| Google Public DNS DoH | Estado DNS `0`, respuesta A `69.46.46.75`, TTL `60`. | El registro A era visible mediante un resolutor público independiente. |
| Cloudflare DNS DoH | Estado DNS `0`, respuesta A `69.46.46.75`, TTL `60`. | El registro A era visible mediante un segundo resolutor público independiente. |
| HTTPS anónimo a `/health` | HTTP `200`. | El servicio público ATI respondía al momento de la comprobación. |

## Conclusión acotada

La evidencia disponible confirma que el dominio estaba publicado y atendía HTTPS durante la comprobación. El `curl: (6)` de la otra IA corresponde a una limitación de resolución o salida de **ese entorno**, no demuestra una incidencia del servicio Railway. No es posible atribuir una causa más específica —por ejemplo, política de red, caché o aislamiento del resolutor— sin observabilidad de dicho entorno.

## Protocolo alternativo para ejecutores externos

Antes de probar rondas declarativas, el ejecutor debe solicitar `GET /health` al dominio exacto. Si recibe HTTP `200`, puede continuar con `GET /v1/observe` y sus cabeceras opt-in. Si obtiene `curl: (6)`, un error de conexión o un bloqueo de la plataforma, debe detenerse y registrar el fallo literal; no debe emitir valores ATI esperados, simular una respuesta ni usar una IP obtenida de otro entorno para forzar la conexión.

Para las rondas con cabeceras, el ejecutor necesita un cliente que permita solicitudes HTTP personalizadas y resolución DNS saliente. Una herramienta de navegación sin configuración de cabeceras puede comprobar sólo la variante anónima de `GET /v1/observe`.
