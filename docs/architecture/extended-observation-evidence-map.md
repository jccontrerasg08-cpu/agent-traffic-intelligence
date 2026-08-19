# Mapa extendido de evidencia observe-only

**Inicio del ciclo:** 2026-08-19
**Estado:** Ciclo acotado completado; inventario de hipótesis verificables, no una promesa de cubrir todas las formas de tráfico de Internet.

## Propósito y criterio de alcance

Este mapa organiza el siguiente ciclo de observación alrededor del servicio público ATI, su laboratorio independiente y sus dependencias de publicación. El objetivo es comprobar hechos reproducibles sobre disponibilidad, contrato, privacidad y configuración versionada sin retener datos de visitantes, enviar cargas de análisis, cambiar Railway, modificar Cloudflare ni tratar declaraciones HTTP como identidad.

> Una solicitud HTTP permite observar lo que llega al servidor, no el resolver, la intención ni la identidad real del cliente. Las ramas que dependen de esos datos quedan clasificadas como no observables o bloqueadas, no como pruebas pendientes de completar. [1] [2]

## Ramas de evidencia

| Rama | Hipótesis verificable | Fuente o comprobación primaria | Resultado que la respalda | Límite explícito |
|---|---|---|---|---|
| Publicación HTTP | El dominio ATI sirve las tres rutas públicas documentadas con respuestas JSON seguras. | Solicitudes `GET` independientes a `/health`, `/v1/catalog` y `/v1/observe`. | Código HTTP, Content-Type, cabeceras de control y campos contractuales esperados. | No prueba la disponibilidad para cada red ni la resolución del cliente. |
| Resolución DNS | El FQDN público tiene respuestas DNS públicas coherentes en resolutores independientes. | Consultas DNS públicas para A, AAAA, CNAME y cadena de autoridad cuando esté disponible. | Respuestas de cada tipo, TTL y ausencia/presencia de registros. | No identifica el resolver que usó un visitante ni garantiza accesibilidad desde su red. |
| Transporte TLS | El punto público presenta un certificado y negociación TLS válidos para el FQDN en el momento de consulta. | Cliente TLS contra el FQDN sin forzar IP. | Nombre validado, emisor, periodo de validez y protocolo/cifrado negociado. | No prueba que todas las rutas o clientes negocien igual. |
| Contrato observe-only | La respuesta pública mantiene etiquetas derivadas, no refleja datos sensibles y conserva las categorías cerradas. | Implementación versionada, pruebas de contrato y peticiones de control. | Coincidencia entre catálogo, respuesta y pruebas; ausencia de valores enviados. | No demuestra la identidad, intención, DNS o historial real de quien solicita. |
| Despliegue versionado | El arranque y las rutas expuestas derivan de la configuración versionada en `main`. | `railway.toml`, entrypoint, CI y comprobación pública. | Configuración sintáctica, pruebas empaquetadas y respuesta pública compatible. | No permite leer secretos ni sustituye la observación del panel de Railway. |
| Frontera de proxy | Las cabeceras de proxy se degradan a presencia no confiable. | Prueba local y, si el cliente admite cabeceras, petición declarativa pública. | `present_but_untrusted` sin IP ni valor reflejado. | No acredita una cadena de proxies ni la ubicación del cliente. |
| Integración Cloudflare | La cuenta conectada puede o no aportar evidencia propietaria de la zona Railway. | Consultas de sólo lectura a zonas relacionadas. | Zona relacionada o ausencia confirmada por la API. | Una cuenta sin zona no describe la infraestructura de Railway ni la de terceros. |
| Ramas de investigación | Las extensiones de fingerprint, clustering, grafo, eBPF y navegador sólo se activan con datos, autorización y métricas previas. | Contratos de investigación y catálogo de casos. | Owner, autorización, retención, baseline y métrica definidos antes de código activo. | No deben habilitarse mediante tráfico público ni suposiciones. |

## Ramas excluidas por diseño

| Variable solicitada o posible | Clasificación | Motivo |
|---|---|---|
| Tipo real de cliente: persona, IA, bot o automatización | No verificada | Las cabeceras son declaraciones y pueden ser modificadas por el cliente o intermediarios. |
| Identidad, frecuencia histórica, sesión, IP, cookie o perfil de visitante | Fuera de la respuesta pública | El contrato no persiste ni devuelve esos datos. |
| Resolver, caché o camino DNS de un cliente | No observable sobre HTTP | El mensaje HTTP no transporta esa información de forma fiable. |
| Intención, prompts, texto, herramientas o contenido de interacción | No observable y no retenido | `interaction_mode` es una categoría opt-in, no un canal de contenido. |
| Fingerprint TLS/JA4, instrumentación de navegador, eBPF y atribución de infraestructura | Bloqueada | Requieren una fuente propia autorizada, minimización, retención, evaluación y una métrica de falsa alarma. |

## Orden de ejecución

El ciclo debe priorizar primero las comprobaciones que son externas, no destructivas y reproducibles: publicación HTTP, resolución DNS y TLS. A continuación se compara la evidencia externa con la implementación y el empaquetado versionados. Finalmente se revisan los límites de Railway y Cloudflare sin leer ni revelar secretos. Cualquier discrepancia se registra como contradicción o bloqueo; no se corrige automáticamente sin una causa reproducible.

## Registro de comprobaciones externas

| Momento de comprobación | Fuente | Resultado confirmado | Clasificación y límite |
|---|---|---|---|
| 2026-08-19, 22:07 UTC | HTTPS directo al FQDN ATI | `/health`, `/v1/catalog` y `/v1/observe?probe=excluded` respondieron HTTP/2 `200`, `application/json; charset=utf-8` y `Cache-Control: no-store`. `/health` declaró `status: ok`, `mode: observe-only`, `persistence: none` y análisis deshabilitado; el catálogo declaró versión `2`. | Confirmado para esta red y este instante. El parámetro de prueba no apareció en la parte observada de la respuesta; la comprobación específica de no reflexión se registra abajo. |
| 2026-08-19, 22:07 UTC | Google Public DNS y Cloudflare DNS | Ambos resolutores devolvieron estado DNS `0` y un registro A para el FQDN ATI con `69.46.46.75`; las consultas AAAA y CNAME no devolvieron respuestas de esos tipos. | Confirmado como respuesta de dos resolutores públicos en ese instante. No identifica el resolver de un visitante ni garantiza conectividad desde su red. |
| 2026-08-19, 22:07 UTC | TLS directo con SNI del FQDN ATI | Certificado `*.up.railway.app`, emitido por Let's Encrypt, válido de 2026-07-29 a 2026-10-27; verificación de nombre correcta; negociación TLS 1.3 con `TLS_AES_256_GCM_SHA384`. El cliente HTTP negoció HTTP/2. | Confirmado para este cliente y ruta. No describe todas las redes ni sustituye una auditoría de la infraestructura Railway. |
| 2026-08-19, 22:08 UTC | HTTPS anónimo al laboratorio | `/observe` devolvió HTTP/2 `200` y `{"status":"observed"}`; `/v1/observe` devolvió `404`. `/healthz` presentó primero un tiempo de espera TLS, pero respondió HTTP/1.1 `200` mediante una comprobación independiente. | Confirma separación de contratos en el momento de prueba. El primer timeout se registra como transitorio o específico de la negociación inicial; no permite inferir caída del laboratorio. |
| 2026-08-19, 22:08 UTC | Solicitud ATI con canarios sintéticos | Con clase `automation`, iteración `2`, modo `mixed`, User-Agent, Forwarded y query ficticios, la respuesta devolvió sólo etiquetas derivadas: `automation`, `repeat_declared`, `mixed`, presencia de UA y proxy `present_but_untrusted`. Una comprobación literal confirmó que los tres canarios no se reflejaron. | Confirmado para esos valores sintéticos. No prueba ausencia de toda fuga posible fuera de las entradas y rutas comprobadas. |
| 2026-08-19, 22:08 UTC | Métodos y análisis no autorizado de ATI | `POST /v1/observe` devolvió `404`; `PUT` y `DELETE /v1/observe`, `405`; `POST /v1/analyze` sin token y sin carga, `503 analysis_endpoint_disabled`. | Confirma el cierre de esas ramas públicas mientras el análisis siga deshabilitado. No prueba el flujo autorizado ni cambia su estado. |
| 2026-08-19, 22:08 UTC | Declaraciones inválidas con canarios sintéticos | Clase y modo se degradaron a `unspecified`; iteración a `invalid_declaration`; los canarios no se reflejaron. | Confirmado para la variante enviada. No constituye una prueba de protección volumétrica ni de un WAF. |
| 2026-08-19, 22:09 UTC | Panel Railway autenticado, modo lectura | El proyecto `triumphant-miracle` mostró en el entorno `production` dos servicios distintos, `agent-traffic-intelligence` y `ati-observation-lab`, ambos con sus dominios públicos y estado `Online`. | Confirma el estado declarado por el panel en ese momento y la separación de topología. No reemplaza un health check ni permite inferir capacidad, latencia o tráfico. |
| 2026-08-19, 22:09 UTC | Despliegue Railway del servicio ATI, modo lectura | El servicio ATI mostró Python `3.13.15`, región US East, una réplica y despliegue `ACTIVE`/`Deployment successful` a partir de la fusión de la PR #37. | Correlaciona el commit documental activo con la topología y las respuestas HTTPS observadas. No expone ni verifica secretos, variables ocultas o volumen de tráfico. |
| 2026-08-19, 22:10 UTC | Registros de despliegue Railway, modo lectura | La vista del despliegue activo registró el inicio del contenedor y mantuvo estado `Active`. | Es coherente con la configuración versionada y los health checks externos. La vista no mostró un comando de arranque completo, por lo que el entrypoint se conserva como evidencia de configuración, no como transcripción de log. |
| 2026-08-19, 22:10 UTC | Vista principal de Railway, comprobación repetida | El servicio continuó marcándose `ACTIVE`, `Deployment successful`, una réplica, región US East y Python `3.13.15`. | Reduce la posibilidad de que el primer estado fuese una carga parcial de interfaz. Sigue siendo una instantánea administrativa, no una métrica de disponibilidad histórica. |
| 2026-08-19, 22:11 UTC | Métricas Railway mediante navegador conectado | La apertura de la pestaña de métricas y la lectura posterior agotaron el tiempo de respuesta de la extensión del navegador con HTTP `504`. | Bloqueado en esta sesión de navegador. No se infiere ausencia de métricas, degradación de Railway ni incidencia del servicio a partir de ese fallo de automatización. |

## Correlación con configuración y publicación versionadas

La configuración `railway.toml` instala el paquete, arranca `python -m agent_traffic_intelligence.runtime`, usa `/health` como health check y limita ese chequeo a 120 segundos. El módulo ejecutable delega en el servidor de ATI, el cual lee `PORT` dentro de límites y mantiene el endpoint de análisis deshabilitado si `ATI_SERVICE_TOKEN` no está configurado. Esa cadena es coherente con la respuesta observada de `/health`, que declaró análisis deshabilitado, y con el estado activo que expuso Railway. [5] [6] [7]

La protección de la rama `main` exige comprobaciones de núcleo para Python 3.11, 3.12 y 3.13, verificación para las mismas versiones, empaquetado limpio, análisis CodeQL y revisión de dependencias; también exige resolver conversaciones. La revisión documental activa anterior concluyó con 19 comprobaciones correctas. Esta protección reduce el riesgo de publicar un cambio no probado, pero no sustituye la validación de red o la observación continuada de Railway. [8]

| Elemento relacionado | Estado confirmado | Qué no aporta |
|---|---|---|
| `railway.toml` y entrypoint | El proceso versionado utiliza el módulo explícito y `/health` como señal de salud. | No demuestra por sí solo qué variables secretas existen en Railway. |
| Configuración del adaptador | Las rutas públicas no necesitan token; el análisis requiere un token explícito. | No permite comprobar el flujo de análisis autorizado sin autorización ni cargar datos de prueba. |
| CI y protección de `main` | Los perfiles de núcleo, servicio, observación pública, investigación, corpus y evaluación forman parte del flujo de publicación. | No prueba que un dominio público sea accesible desde todas las redes. |
| Cuenta Cloudflare conectada | Las consultas anteriores de sólo lectura no encontraron las zonas ATI ni las zonas padre Railway en esa cuenta. | No explica la infraestructura de Railway ni proporciona analítica propietaria de ese FQDN. |

## Decisiones por rama y siguiente experimento mínimo

| Rama | Decisión basada en la evidencia | Próximo experimento mínimo | Condición para ampliar alcance |
|---|---|---|---|
| Disponibilidad pública | Mantener las rutas ATI y el laboratorio separados; ambos estuvieron disponibles desde la red de prueba y el panel Railway. | Repetir `GET /health` y `GET /v1/observe` desde otra red independiente, registrando sólo estado, tiempo y cabeceras no sensibles. | Una discrepancia reproducible entre redes, resolutores o rutas TLS. |
| DNS y TLS | Tratar la resolución pública y la negociación TLS como señales de borde, no como identidad ni trazabilidad del cliente. | Comparar A, AAAA, CNAME y TLS desde un segundo proveedor de red sin forzar IP. | Una respuesta contradictoria que persista en más de un resolutor y momento. |
| Declaraciones HTTP | Conservar las etiquetas como declaraciones controladas, incluida su degradación segura cuando son inválidas. | Ejecutar una ronda adicional desde un cliente que permita cabeceras, con sólo categorías permitidas y canarios sintéticos. | Un contrato documentado que requiera una nueva categoría cerrada y sus pruebas. |
| Análisis autenticado | Mantener `/v1/analyze` deshabilitado mientras no haya un token explícito ni un conjunto de prueba autorizado. | Ninguno contra producción; usar el smoke empaquetado y datos sintéticos locales. | Propietario, propósito, retención, autorización y métrica de seguridad documentados. |
| Métricas Railway | No deducir ausencia de métricas por el error de automatización del navegador. | Reabrir manualmente la vista de métricas o leer una exportación agregada que no contenga solicitudes ni secretos. | Acceso estable a una fuente agregada y autorización para registrar sus campos. |
| Cloudflare | No mover DNS ni crear una zona basándose en esta inspección; la cuenta conectada no gestiona esos nombres Railway. | Ninguno mientras Railway conserve sus dominios administrados. | Una decisión explícita de aportar un dominio propio bajo la cuenta Cloudflare. |
| Investigación avanzada | Mantener fingerprint, eBPF, clustering y grafo como contratos de investigación, no como captura de tráfico público. | Definir una métrica, un corpus autorizado y una política de minimización antes de escribir código activo. | Aprobación de un protocolo de investigación con propietarios y límites de retención. |

No se programó un bucle persistente ni se creó un agente autónomo recurrente durante este ciclo. La evidencia disponible basta para cerrar las ramas consultadas; una monitorización futura debe fijar frecuencia, fuente de datos, destino de informes y presupuesto antes de automatizarse.

## Referencias

[1] [Catálogo público de observación HTTP](public-observation-catalog.md)
[2] [Registro de evidencia de observación pública](public-observation-evidence-ledger.md)
[3] [Catálogo de casos y variaciones](../cases-and-variations.md)
[4] [Implementación de normalización pública](../../src/agent_traffic_intelligence/runtime/public_observation.py)
[5] [Configuración Railway](../../railway.toml)
[6] [Punto de entrada de runtime](../../src/agent_traffic_intelligence/runtime/__main__.py)
[7] [Configuración de servicio](../../src/agent_traffic_intelligence/runtime/config.py)
[8] [Flujo central de integración continua](../../.github/workflows/ci.yml)
