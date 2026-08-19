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

## Alcance de la integración Cloudflare conectada

El 2026-08-19 se consultó en modo de sólo lectura el endpoint **List Zones** de la cuenta Cloudflare conectada para los dos FQDN públicos y sus dos zonas padre pertinentes: `agent-traffic-intelligence-production.up.railway.app`, `ati-observation-lab-production.up.railway.app`, `up.railway.app` y `railway.app`. Las cuatro respuestas HTTP de la API fueron satisfactorias y devolvieron `zone_count: 0`, sin zonas ni identificadores de zona. La consulta no leyó registros, analítica de tráfico, reglas ni otros recursos de una zona ajena.

| Evidencia | Resultado confirmado | Límite de interpretación |
|---|---|---|
| API de zonas de Cloudflare con filtros por FQDN y zona padre | Las cuatro operaciones fueron correctas; ningún FQDN ATI ni las zonas `up.railway.app` o `railway.app` pertenece a la cuenta conectada. | No prueba que Railway o un tercero no empleen infraestructura Cloudflare; sólo descarta la gestión de esas zonas desde esta cuenta. |
| Registros DNS y analítica de zona de la cuenta conectada | No consultados, porque no existe una zona ATI relacionada que habilite esas rutas. | No existen datos de esta integración que permitan medir tráfico, clientes o disponibilidad del servicio Railway. |
| DNS público y HTTPS directo registrados arriba | Permanecen como evidencia independiente de resolución pública y disponibilidad puntual. | El resolutor público Cloudflare no equivale a la administración de una zona Cloudflare en la cuenta conectada. |

La inspección refuerza que la disponibilidad del FQDN de ATI debe verificarse desde Railway y mediante resolutores y clientes externos independientes. Esta integración no puede añadir observabilidad propietaria de DNS ni tráfico para ese dominio mientras Railway mantenga la zona fuera de la cuenta Cloudflare conectada. Por ello no corresponde atribuir el fallo de resolución del ejecutor externo a una configuración de esta cuenta Cloudflare.

## Referencias

[1] [Cloudflare API — List Zones](https://developers.cloudflare.com/api/resources/zones/methods/list/)
