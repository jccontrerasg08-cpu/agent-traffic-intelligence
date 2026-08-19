# Catálogo público de observación HTTP

**Fecha:** 2026-08-19
**Estado:** Contrato público versionado (`2`), de respuesta única y sin interfaz gráfica.

## Propósito

El servicio expone `GET /v1/catalog` y `GET /v1/observe` para que una persona, un agente de IA, un bot o una automatización pueda consultar qué **capacidades declaradas** llegan en una sola solicitud HTTP. No se requiere token para estas dos rutas. El resultado es una respuesta JSON no almacenada; no se crean perfiles, sesiones, identificadores, registros de visitas, cookies, cuerpos, valores de cabecera, IPs ni query strings.

> HTTP es un protocolo sin estado y no obliga al servidor a conocer el propósito de su cliente. Por ello, ATI expone categorías declaradas y límites de observación, no juicios de humanidad, intención o identidad. [1]

## Rutas públicas

| Ruta | Método | Autenticación | Resultado |
|---|---|---:|---|
| `/health` | `GET` | No | Salud del proceso y estado del endpoint protegido. |
| `/v1/catalog` | `GET` | No | Diccionario versionado de rutas, clases admitidas y límites. |
| `/v1/observe` | `GET` | No | Presencia de señales y estados de confianza de una solicitud. |
| `/v1/analyze` | `POST` | Sí | Análisis JSONL autorizado; no forma parte de la observación pública. |

Los parámetros de query se ignoran para decidir la ruta y nunca se reflejan. Las respuestas usan `Cache-Control: no-store`.

## Clases de cliente

Un cliente puede declarar opcionalmente `X-ATI-Client-Class` con uno de cuatro valores: `human`, `ai`, `bot` o `automation`. ATI devuelve ese valor únicamente como `declared_client_class`; no verifica que sea veraz. El valor ausente o fuera de catálogo se devuelve como `unspecified`.

| Variable | Clasificación | Cómo se trata |
|---|---|---|
| Clase declarada | `declared` | Normaliza una enumeración de opt-in; no es prueba de identidad. |
| `User-Agent` | `declared` | Sólo devuelve si existe; nunca devuelve el valor. |
| UA Client Hints | `declared` | Sólo devuelve presencia; no solicita hints de alta entropía. |
| `Accept-Language`, `Accept-Encoding` | `measurable` | Sólo devuelve presencia. |
| `Content-Type`, `Content-Length` | `measurable` | Sólo devuelve presencia. |
| Iteración de experimento | `declared` | Normaliza primera/repetición; no cuenta visitas ni almacena historial. |
| Modo de interacción | `declared` | Normaliza `silent`, `text`, `tool_call` o `mixed`; no captura contenido. |
| `Forwarded`, `X-Forwarded-For` | `proxy_trusted_only` | Indica presencia pero siempre como no confiable. |
| Resolver, caché o ruta DNS del cliente | `not_observable` | Devuelve `not_observable_over_http`. |
| Persona, IA, bot o automatización real | `not_verified` | No intenta inferirlo desde cabeceras. |
| Intención del cliente | `not_observable` | No intenta inferirla desde una solicitud. |

RFC 7239 define `Forwarded` como un campo opcional y sensible, cuyo sentido depende de los proxies que lo insertan. [2] Un cliente público puede fabricar cualquier cabecera de proxy, por lo que ATI nunca la interpreta como IP, procedencia, DNS o categoría de cliente sin una frontera administrada. User-Agent Client Hints busca reducir la exposición pasiva y los detalles adicionales requieren un mecanismo de opt-in; por eso ATI trata estos campos como declaraciones y no los conserva. [3]

## Variaciones comprobables

| Variante | Ejemplo | Resultado esperado |
|---|---|---|
| Persona declarada | `X-ATI-Client-Class: human` | `declared_client_class: human`; identidad no verificada. |
| Agente de IA declarado | `X-ATI-Client-Class: ai` | `declared_client_class: ai`; no se devuelve UA. |
| Bot declarado | `X-ATI-Client-Class: bot` | `declared_client_class: bot`; no se decide si es legítimo. |
| Automatización declarada | `X-ATI-Client-Class: automation` | `declared_client_class: automation`; no se bloquea. |
| Primera ronda controlada | `X-ATI-Observation-Iteration: 1` | `controlled_iteration: first_declared`; no crea contador. |
| Ronda repetida controlada | `X-ATI-Observation-Iteration: 2` o superior | `controlled_iteration: repeat_declared`; no expone el número literal. |
| Interacción declarada | `X-ATI-Interaction-Mode: text` | `interaction_mode: text`; no devuelve texto ni prompts. |
| Declaración de control inválida | Texto o valor no permitido | `invalid_declaration` o `unspecified`, sin reflejar el valor. |
| Sin declaración | Cabeceras mínimas | `declared_client_class: unspecified`. |
| UA/UA-CH presentes | Encabezados estándares | Booleans de presencia, sin valores. |
| Proxy declarado por el cliente | `Forwarded` o `X-Forwarded-For` | `present_but_untrusted`, sin IP ni host. |
| Con DNS, sin DNS o IP directa | Cualquier ruta HTTP alcanzable | `dns_resolution: not_observable_over_http`. |
| Query con información sensible | `/v1/observe?x=...` | No se refleja ni conserva. |

## Límites de operación

El contrato no ofrece un mecanismo para demostrar que un visitante resolvió un nombre DNS, que llegó por una IP directa o que utiliza un resolver específico. El origen HTTP identifica el destino solicitado, no el proceso de resolución local del cliente. [1] Si un experimento necesita esa dimensión, debe ser controlado, autorizado y usar una señal explícita independiente de HTTP; seguirá siendo una declaración de experimento, no telemetría inferida.

Una secuencia de solicitudes tampoco prueba la frecuencia histórica de un cliente. `X-ATI-Observation-Iteration` sólo etiqueta una ronda que el ejecutor afirma estar realizando; el recuento de respuestas debe mantenerse fuera de ATI. El protocolo reproducible para una persona u otra IA está en [`controlled-observation-protocol.md`](controlled-observation-protocol.md).

La protección contra abuso del endpoint público debe hacerse en la frontera administrada de Railway o de un proxy/WAF: límite de tasa, tamaño de cabecera y protección volumétrica. El proceso de ATI no mantiene un contador por IP porque ello crearía estado e identificación que este contrato evita.

## Referencias

[1] [RFC 9110: HTTP Semantics](https://datatracker.ietf.org/doc/html/rfc9110)
[2] [RFC 7239: Forwarded HTTP Extension](https://datatracker.ietf.org/doc/html/rfc7239)
[3] [User-Agent Client Hints](https://wicg.github.io/ua-client-hints/)
