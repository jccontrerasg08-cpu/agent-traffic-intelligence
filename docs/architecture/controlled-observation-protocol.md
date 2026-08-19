# Protocolo de observación controlada por repetición

**Fecha:** 2026-08-19
**Estado:** Diseño acotado para pruebas reproducibles; no identifica clientes ni mide frecuencia histórica.

## Propósito

Este protocolo permite que una persona, otra IA, un bot o una automatización repita solicitudes públicas contra `GET /v1/observe` y compruebe que ATI clasifica únicamente declaraciones permitidas. El operador que ejecuta el experimento cuenta las respuestas obtenidas; ATI no mantiene contadores por cliente, sesión, IP, cookie ni cualquier otro identificador.

> RFC 9110 define HTTP como un protocolo sin estado y señala que una solicitud puede considerarse aisladamente, sin asociarla a un tipo de cliente ni a una secuencia predeterminada. Por ello, una cabecera de repetición sólo puede expresar una **declaración de experimento** y no demostrar cuántas veces ha visitado un cliente el servicio. [1]

## Declaraciones acotadas

| Cabecera opt-in | Valores aceptados | Salida prevista | Interpretación correcta |
|---|---|---|---|
| `X-ATI-Client-Class` | `human`, `ai`, `bot`, `automation` | Clase declarada o `unspecified`. | No es identidad verificada. |
| `X-ATI-Observation-Iteration` | Una declaración de primera o repetición controlada. | Categoría `first_declared`, `repeat_declared`, `not_declared` o `invalid_declaration`. | No es un contador ni historial del cliente. |
| `X-ATI-Interaction-Mode` | `silent`, `text`, `tool_call`, `mixed`. | Modo declarado o `unspecified`. | No conserva texto, prompts, respuestas ni argumentos de herramientas. |

Las rutas públicas seguirán devolviendo sólo etiquetas normalizadas. Los valores de estas cabeceras, los parámetros de query, el User-Agent, las cookies, la IP y cualquier contenido de interacción quedan fuera de la respuesta y no se persisten.

## Secuencia de prueba

El operador define un número pequeño y explícito de rondas, por ejemplo tres. Cada actor que participe usa únicamente datos ficticios y las cabeceras normalizadas. La primera solicitud usa `X-ATI-Observation-Iteration: 1`; las siguientes usan un valor de repetición permitido. El recuento válido es el número de respuestas HTTP 200 recogidas por el ejecutor, no un número devuelto o conservado por ATI.

```bash
base_url="https://TU-SERVICIO-RAILWAY/v1/observe"

curl --fail --silent --show-error \
  --header 'X-ATI-Client-Class: ai' \
  --header 'X-ATI-Observation-Iteration: 1' \
  --header 'X-ATI-Interaction-Mode: text' \
  "$base_url"
```

Para la segunda y tercera ronda se cambia solamente `X-ATI-Observation-Iteration` a un valor de repetición. La IA externa puede describir una acción o responder texto fuera de ATI, pero no debe enviar ese contenido a la ruta: el modo `text` es una categoría y no un canal de captura. Si la IA no permite configurar cabeceras HTTP, puede probar la ruta sin ellas; el resultado correcto será `unspecified` o `not_declared`, no una clasificación inferida.

## Criterios de aceptación

| Comprobación | Resultado aceptable | Cobertura que no aporta |
|---|---|---|
| Cuatro clases declaradas | La respuesta normaliza las cuatro sin elevarlas a identidad. | No prueba el tipo real del cliente. |
| Primera y repetición | La respuesta distingue categorías válidas sin reflejar el número literal. | No mide visitas históricas. |
| Modos de interacción | La respuesta admite el vocabulario cerrado sin devolver contenido. | No analiza lenguaje, intención ni herramientas reales. |
| Valores inválidos | La respuesta los degrada a una categoría segura. | No previene abuso volumétrico en la red. |
| Repetición acotada | El ejecutor registra el número de HTTP 200 localmente. | No sustituye límites de tasa en Railway o un WAF. |

## Límites de operación

Este protocolo no prueba que Railway haya desplegado una revisión concreta ni que otra IA haya usado el flujo exactamente como se le indicó. Esas dos afirmaciones requieren, respectivamente, una comprobación del objetivo público con su URL real y el registro controlado del ejecutor. El límite de tasa y la protección volumétrica siguen siendo responsabilidad de la frontera administrada, no de un contador de ATI.

## Referencias

[1] [RFC 9110: HTTP Semantics](https://datatracker.ietf.org/doc/html/rfc9110)
