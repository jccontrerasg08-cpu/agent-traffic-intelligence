# Registro de evidencia — observación pública de capacidades

**Fecha:** 2026-08-19
**Estado:** Base de diseño; no prueba comportamiento de clientes individuales.

| Afirmación o decisión | Evidencia directa | Estado | Límite operativo |
|---|---|---|---|
| HTTP trata cada solicitud como un mensaje de aplicación y el servidor no conoce por sí mismo el propósito del cliente. | RFC 9110 describe HTTP como protocolo *stateless* y explica que un servidor no necesita conocer el propósito de cada cliente. [1] | Confirmado | No se debe etiquetar una solicitud como humana, IA, bot o automatización sólo por llegar al endpoint. |
| El destino de la solicitud es observable en el request target/autoridad, pero la resolución DNS que hizo el cliente no es un campo estándar del mensaje HTTP. | RFC 9110 describe el target y los campos de solicitud; no define un campo que transporte el resolver, la caché DNS o la ruta de resolución del cliente. [1] | Inferido, con límite explícito | El catálogo registrará `dns_resolution: not_observable_over_http`; un cliente puede declarar metadatos, pero no se tratarán como prueba. |
| La información de un proxy es opcional, sensible y sólo es utilizable cuando la inserta una cadena confiable. | RFC 7239 define `Forwarded` como opcional, advierte su sensibilidad y pide configuración individual; identifica datos alterados o perdidos por proxies. [2] | Confirmado | Los encabezados `Forwarded`/`X-Forwarded-*` entrantes no se usarán como identidad, ubicación ni clase de cliente sin una frontera de proxy confiable configurada. |
| `User-Agent` y Client Hints son señales declaradas, no una prueba de identidad o intención. | UA-CH documenta tanto la reducción de entropía/fingerprinting como el uso de cabeceras de marca, plataforma y capacidades; datos detallados requieren opt-in mediante `Accept-CH`. [3] | Confirmado | Se catalogarán como capacidades declaradas, nunca como verificación de persona, IA, bot o automatización. |
| Un endpoint público necesita evitar ampliar la retención de datos por defecto. | RFC 7239 dedica consideraciones de privacidad a los campos de proxy; el contrato existente de ATI ya minimiza IPs, query strings y cuerpos. [2] | Confirmado para el riesgo y la implementación local | El servicio devuelve un resultado por solicitud, con datos agregados/derivados, sin escribir telemetría del visitante por defecto; Railway sigue pendiente de comprobación directa. |
| Una repetición controlada no permite demostrar una frecuencia histórica por cliente. | RFC 9110 establece que HTTP es sin estado y que una solicitud puede considerarse aislada, sin asociarla a una secuencia predeterminada. [1] | Confirmado | La iteración se tratará como declaración acotada de experimento; el número real de respuestas lo contará el ejecutor externo. |
| El modo de interacción declarado puede usarse para diseñar pruebas sin capturar contenido. | Es una decisión de contrato de ATI, no una propiedad demostrable de HTTP; las pruebas de contrato y el smoke test verificaron el vocabulario cerrado y la ausencia de reflexión. | Confirmado localmente | Sólo se acepta un vocabulario cerrado; no se envían ni devuelven texto, prompts, respuestas o argumentos. |
| Los nombres de campos HTTP no deben compararse con distinción de mayúsculas. | RFC 9110 define los nombres de campo como insensibles a mayúsculas; una comprobación externa mostró respuestas sin etiquetas cuando un intermediario pudo cambiar su capitalización. [1] | Corregido localmente; pendiente de contraste público | ATI compara sólo el nombre de tres campos opt-in con `casefold`, no devuelve su valor ni convierte una declaración en identidad verificada. |

## Criterio de clasificación

| Clase | Definición en ATI | Ejemplo |
|---|---|---|
| `measurable` | Derivada de la petición recibida sin retención adicional. | Método, Content-Type, protocolo del servidor, presencia de señal declarada. |
| `declared` | Afirmada por el cliente o un hint; no se verifica como identidad. | `User-Agent`, `Sec-CH-UA`, `X-ATI-Client-Class`. |
| `proxy_trusted_only` | Sólo se interpreta detrás de una frontera administrada y declarada. | `Forwarded`, `X-Forwarded-For`. |
| `not_observable` | El protocolo recibido no permite establecerla de forma fiable. | Resolver DNS del cliente, humanidad, intención real, agente subyacente. |
| `blocked` | Necesita una autorización, evidencia y perfil de entorno antes de entrar al pipeline. | Fingerprinting de transporte, JavaScript de dispositivo, eBPF, grafos y modelos aprendidos. |

## Referencias

[1] [RFC 9110: HTTP Semantics](https://datatracker.ietf.org/doc/html/rfc9110)
[2] [RFC 7239: Forwarded HTTP Extension](https://datatracker.ietf.org/doc/html/rfc7239)
[3] [User-Agent Client Hints](https://wicg.github.io/ua-client-hints/)
