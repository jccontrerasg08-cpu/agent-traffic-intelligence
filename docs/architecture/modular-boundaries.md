# Límites modulares de ATI

ATI conserva una sola distribución Python y una política observe-only. La modularidad no significa ejecutar todos los caminos de investigación a la vez; significa que cada responsabilidad tiene un contrato, una superficie de datos y un perfil de prueba propios.

> **Regla de activación:** Un módulo que ingiera una nueva clase de datos o produzca una nueva señal debe declarar autorización, minimización, retención, versionado, evidencia y entorno de prueba antes de entrar en el pipeline activo.

## Mapa de responsabilidades

| Área | Responsabilidad | Datos permitidos | No responsabilidad | Estado |
|---|---|---|---|---|
| `models` | Contratos inmutables de solicitud, evidencia, identidad y detección. | Datos normalizados y pseudónimos. | I/O, red, almacenamiento o decisiones de bloqueo. | Activo. |
| `ingestion` | Normalizar JSONL, recortar query strings y pseudonimizar dirección de origen. | JSONL autorizado y clave de hash en memoria. | Captura de tráfico, persistencia de cuerpos o credenciales. | Activo; `parsers` conserva fachada de compatibilidad. |
| `detection` | Componer señales de request/sesión, identidad, evidencia y puntuación. | `RequestEvent`, contexto efímero y salidas explainable. | Obtener fuentes externas, imponer política o almacenar perfiles. | Activo; `engine` conserva fachada de compatibilidad. |
| `identity` | Resolver afirmaciones y verificación con perfiles, caché, red opcional y criptografía. | Material de fuente explícitamente actualizado y contexto efímero. | Tratar User-Agent como prueba o alterar los otros scores sin evidencia. | Activo. |
| `evaluation` | Calcular cobertura, matrices de confusión, PR-AUC y calibración. | Detecciones y etiquetas con manifiesto autorizado. | Entrenar modelos o aceptar corpus sin procedencia. | Activo. |
| `runtime.service` | Configuración, protocolo HTTP y ciclo de vida del adaptador Railway. | Lotes JSONL autenticados y limitados. | UI, proxy, bloqueo, persistencia o refresh de identidad. | Activo; `service` conserva fachada de compatibilidad. |
| `research.contracts` | Declarar contratos para señales futuras y sus restricciones. | Metadatos privacy-minimized y descriptores de evaluación. | Activar experimentos, recolectar tráfico o inferir identidad sin evidencia. | Activo como contrato, no como detector. |

## Flujo estable

```text
fuente autorizada
      |
      v
ingestion -> RequestEvent -> detection pipeline -> Detection
                    |                |                |
                    |                |                +-> evaluation (artefactos autorizados)
                    |                +-> identity (contexto efímero, opcional)
                    +-> research contracts (sólo cuando se habiliten con evidencia)
```

La puntuación mantiene dimensiones separadas: automatización, relación con IA, confianza de identidad y riesgo. Una extensión no puede cambiar una dimensión distinta de la declarada sin añadir un código de evidencia nombrado y una prueba de regresión.

## Rutas de investigación y condición de entrada

| Ruta propuesta | Contrato futuro | Precondición para implementar | Métricas mínimas | Estado actual |
|---|---|---|---|---|
| Fingerprint de red | `NetworkFingerprintObservation` | Logs propios con JA4/JA4+ u otro identificador, sin IP cruda. | Cobertura, FPR, degradación bajo variación. | Documentado; sin ingestión activa. |
| Descubrimiento de desconocidos | `UnknownClusterCandidate` | Corpus autorizado con división temporal y por familia. | PR-AUC, ECE, tasa de revisión. | Documentado; sin clustering activo. |
| Benchmark adversarial propio | `ControlledVariant` | Target propio y generadores autorizados. | Precisión, recall, F1, FPR, ECE, time-to-detection y coste por solicitud. | Documentado; sólo campañas controladas existentes. |
| Grafo de infraestructura | `AttributionEdge` | Política de retención y fuente autorizada de ASN, dominio o certificado. | Calidad de aristas, estabilidad temporal y falsos agrupamientos. | Documentado; sin grafo activo. |
| Inteligencia de abuso API | `AbuseEvidence` | Definición separada de abuso y automatización, además de etiquetas. | FPR por operación, coste y calibración. | Documentado; no mezcla abuso con bot. |
| Sensor eBPF | `KernelConnectionObservation` | Host propio, revisión de privilegios y modelo de amenaza. | Pérdida de eventos, overhead, cobertura y privacidad. | Bloqueado; no se añade código de kernel. |
| Laboratorio de navegador | `BrowserLabObservation` | Navegador/target propios, consentimiento y retención mínima. | Degradación, cobertura, FPR y compatibilidad. | Bloqueado; no captura tráfico de navegador. |

## Compatibilidad

Las rutas públicas `agent_traffic_intelligence.engine`, `agent_traffic_intelligence.parsers.jsonl` y `agent_traffic_intelligence.service` permanecen disponibles como fachadas. Los consumidores no deben importar implementaciones internas desde `detection`, `ingestion` o `runtime` salvo que acepten sus contratos versionados.
