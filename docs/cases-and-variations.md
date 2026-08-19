# Catálogo de casos y variaciones de ATI

**Versión del catálogo:** 2026-08-19  
**Ámbito:** Flujos actualmente implementados, comportamientos de error relevantes, perfiles de operación y rutas de investigación propuestas por la conversación adjunta.  
**Lectura correcta:** Este catálogo enumera todas las variaciones dentro del alcance actual de ATI y de las recomendaciones recibidas. No afirma que cubra todas las formas posibles de tráfico de Internet.

## Casos activos de ingreso y privacidad

| ID | Variación | Entrada autorizada | Resultado esperado | Protección o límite | Perfil y pruebas |
|---|---|---|---|---|---|
| ING-01 | JSONL con `client_id` pseudonimizado | Evento válido sin IP cruda. | Se crea `RequestEvent` sin transformar la identidad de borde. | Query strings excluidos; sin bodies. | `test-core`, `tests/test_parser.py`. |
| ING-02 | JSONL con `remote_addr` y hash key | Evento válido con `ATI_HASH_KEY`. | La dirección se convierte en pseudónimo BLAKE2b. | La IP cruda no entra en la detección. | `test-core`, `test-controlled`. |
| ING-03 | IP cruda sin clave | Evento con dirección pero sin hash key. | Rechazo explícito. | No permite fuga accidental de dirección. | `test-core`. |
| ING-04 | Línea sobredimensionada | JSONL que excede el límite configurado. | Error de parseo o rechazo del servicio. | `ATI_MAX_LINE_CHARACTERS` o `--max-line-characters`. | `test-core`, `test-service`. |
| ING-05 | URI con query string | Solicitud válida con parámetros. | La ruta normalizada omite valores de query. | Ningún token/query llega a salida. | `test-core`, `test-service`. |
| ING-06 | Entrada corrupta o tipos inválidos | Línea JSONL no válida. | Error localizado; no output parcial corrupto. | Escrituras atómicas para la CLI. | `test-core`, `test-controlled`. |

## Casos de detección e identidad

| ID | Variación | Estado de evidencia | Resultado esperado | No se debe inferir | Perfil y pruebas |
|---|---|---|---|---|---|
| DET-01 | Claim de User-Agent conocido | Evidencia de claim curado. | Produce identidad reclamada y señales explainable. | Que la identidad sea auténtica. | `test-core`, `test-identity`. |
| DET-02 | Patrón conductual acotado | Conteos y ventanas de sesión locales. | Cambia la dimensión correspondiente con códigos de evidencia. | Que una sola señal pruebe automatización. | `test-core`. |
| DET-03 | Perfil de rango oficial en caché | Material de fuente explícitamente refrescado. | Puede resolver a identidad verificada. | Que el éxito de red altere los otros scores. | `test-identity`. |
| DET-04 | FCrDNS o firma criptográfica no disponible | Contexto de verificación incompleto. | Resultado operacional neutral o disponibilidad limitada. | Una identidad fallida por causa de infraestructura. | `test-identity`. |
| DET-05 | Evidencia de identidad en conflicto | Claim y evidencia independiente incompatibles. | Estado `conflicted` con explicación. | Que se borre o mezcle el conflicto. | `test-identity`. |
| DET-06 | Verificación deshabilitada | CLI/servicio sin modo de verificación. | No se consulta ni refresca fuente externa. | Que el User-Agent se convierta en verificación. | `test-core`, `test-service`. |

## Casos del adaptador técnico observe-only

| ID | Variación | Respuesta esperada | Límite de seguridad | Perfil y pruebas |
|---|---|---|---|---|
| SVC-01 | `GET /health` | `200` con estado, modo, versión y estado del endpoint. | Nunca expone token o hash key. | `test-service`, `smoke-service`. |
| SVC-02 | Análisis sin `ATI_SERVICE_TOKEN` | `503 analysis_endpoint_disabled`. | No acepta ningún log por defecto. | `test-service`. |
| SVC-03 | Token ausente o incorrecto | `401 unauthorized`. | Comparación en tiempo constante. | `test-service`, `smoke-service`. |
| SVC-04 | Tipo distinto de `application/x-ndjson` | `400 content_type_must_be_application_x_ndjson`. | No intenta reinterpretar cuerpos alternativos. | `test-service`, `smoke-service`. |
| SVC-05 | Cuerpo demasiado grande, no UTF-8 o sin longitud | `400` con código de contrato. | Límites de bytes, decodificación y lote. | `test-service`. |
| SVC-06 | Lote vacío, malformado o sobre límite de eventos | `400` o `422` con error explícito. | Sin estado persistente ni salida parcial. | `test-service`. |
| SVC-07 | Lote autorizado válido | `200` con detecciones privacy-safe. | No persiste bodies, etiquetas, caché ni detecciones. | `test-service`, `smoke-service`. |
| SVC-08 | Método/ruta no soportados | `404` o `405`. | No existe UI, proxy ni rutas implícitas. | `test-service`. |
| SVC-09 | `GET /v1/catalog` sin token | `200` con versión, rutas, dimensiones y límites del catálogo público. | No devuelve query strings ni crea estado de cliente. | `test-public`, `smoke-service`. |
| SVC-10 | `GET /v1/observe` con declaración humana, IA, bot, automatización o desconocida | `200` con etiquetas de presencia y clase declarada; clase desconocida como `unspecified`. | No trata declaraciones como identidad; no devuelve valores de cabecera, IP, DNS, query ni identidad real. | `test-public`, `smoke-service`. |
| SVC-11 | `GET /v1/observe` con primera/repetición y modo de interacción declarados | `200` con categorías cerradas de iteración y modo; valores inválidos degradados. | No cuenta visitas, no conserva historia y no devuelve números literales, prompts, texto ni argumentos. | `test-public`, `smoke-service`. |

## Casos de evaluación y corpus

| ID | Variación | Condición de entrada | Resultado esperado | Prohibición | Perfil y pruebas |
|---|---|---|---|---|---|
| EVAL-01 | Etiquetas autorizadas con cobertura completa | Manifest, detecciones y labels alineados por request ID. | Matriz de confusión, PR-AUC cuando está definida y calibración. | Entrenar o calibrar automáticamente. | `test-evaluation`, `test-controlled`. |
| EVAL-02 | Clase positiva o negativa ausente | Labels parciales por clase. | Métricas indefinidas se expresan como `null`. | Inventar una métrica de ranking. | `test-evaluation`. |
| EVAL-03 | Detecciones sin etiqueta | Cobertura incompleta. | Estado `review-required`. | Declarar preparación para producción. | `test-controlled`. |
| EVAL-04 | Campaña con marcador controlado | Target propio, hash key y manifest autorizado. | Labels trazables a la campaña y artefactos minimizados. | Etiquetar tráfico humano o no marcado por suposición. | `test-controlled`. |
| EVAL-05 | Benchmark real | Corpus con separación temporal/familiar, baseline y procedencia. | Evaluación comparable por métrica y umbral. | Reportar el fixture o tráfico sintético como benchmark real. | Documentado; requiere corpus. |

## Variaciones de investigación propuestas y su estado

| ID | Variación propuesta | Datos adicionales | Condición de activación | Métrica de aceptación | Estado |
|---|---|---|---|---|---|
| RES-01 | Fingerprints de red y JA4/JA4+ | Metadatos de transporte de infraestructura propia. | Fuente autorizada, pseudonimización y baseline. | Cobertura, FPR, estabilidad. | Contrato documentado; bloqueado. |
| RES-02 | Descubrimiento de desconocidos y clustering | Features con splits de familia/tiempo. | Corpus etiquetado y revisión humana. | PR-AUC, ECE, tasa de revisión. | Contrato documentado; bloqueado. |
| RES-03 | Benchmark adversarial de laboratorio | Variantes generadas contra target propio. | Reglas de alcance, manifest y negativos de control. | Precision, recall, F1, FPR, ECE, coste. | Documentado; no activo. |
| RES-04 | Grafo de infraestructura/atribución | ASN, dominio, certificado u orígenes equivalentes. | Política de retención y prevención de falsos agrupamientos. | Estabilidad temporal y calidad de aristas. | Contrato documentado; bloqueado. |
| RES-05 | Abuso API separado de automatización | Operación API y etiquetas de abuso. | Definición de abuso independiente de “bot”. | FPR por operación y coste. | Documentado; no activo. |
| RES-06 | Sensor eBPF | Eventos de kernel en host propio. | Revisión de privilegios y modelo de amenaza. | Pérdida, overhead, cobertura y privacidad. | Bloqueado; sin código kernel. |
| RES-07 | Laboratorio de navegador | Instrumentación de target/navegador propios. | Consentimiento, retención y plan de compatibilidad. | Degradación, cobertura y FPR. | Bloqueado; no captura navegador. |

## Mapa de perfiles a decisiones operativas

| Pregunta operativa | Perfil a ejecutar | Evidencia que produce | Decisión habilitada |
|---|---|---|---|
| ¿Se preserva el comportamiento base? | `make test-core` | Reglas, modelos, parsing y score. | Aceptar un cambio al núcleo. |
| ¿La identidad funciona sin depender de red real? | `make test-identity` | Fixtures, cachés y fallos controlados. | Cambiar perfiles o verificadores offline. |
| ¿El servicio técnico sigue cerrado y privacy-safe? | `make test-service` y `make smoke-service` | Auth, Content-Type, límites y ejecución empaquetada. | Desplegar la revisión técnica en Railway. |
| ¿Las rutas públicas informan capacidades sin perfilar al cliente? | `make test-public` y `make smoke-service` | Catálogo sin token, observación de presencia y ausencia de valores sensibles. | Exponer solamente observación response-only en Railway. |
| ¿Una prueba con otra IA puede repetir solicitudes sin perfilado? | `make test-public` y `make smoke-service` | Etiquetas declaradas de iteración/modo, valores inválidos no reflejados y cero contador por cliente. | Ejecutar el protocolo controlado sin capturar contenido. |
| ¿Una campaña está lista para evaluar? | `make test-controlled` y `make test-evaluation` | Cobertura, manifiesto y métricas. | Abrir revisión de corpus; no declarar producción aún. |
| ¿Una ruta propuesta puede empezar a implementarse? | `make test-research` más su contrato específico. | Declaración de owner, autorización, retención y métricas. | Revisar diseño; todavía no activar detector. |

## Regla de actualización

Cualquier cambio de comportamiento, nueva fuente de datos, nuevo entorno o nueva ruta de investigación debe añadir o modificar un caso de este catálogo, una prueba de perfil y una fila del registro de evidencia. Si el cambio procesa nuevas categorías de datos, debe además documentar autorización, minimización, retención y una métrica de falsa alarma antes de habilitarlo fuera de fixtures controlados.
