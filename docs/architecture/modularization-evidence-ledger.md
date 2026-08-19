# Registro de evidencia — modularización y matriz de entornos

**Tarea:** Modularizar ATI y hacer reproducibles sus variantes de prueba.  
**Ámbito:** Paquete Python, CLI, servicio técnico observe-only, evaluación local y rutas de investigación.  
**Condición de éxito:** Las responsabilidades tienen límites explícitos, las interfaces públicas existentes siguen funcionando, los perfiles de prueba se pueden ejecutar de forma aislada y las extensiones de investigación quedan documentadas sin presentarse como capacidades activas.  
**Riesgo si se decide mal:** Alto, porque mezclar identidad, puntuación, red, datos de navegador o telemetría persistente puede degradar la privacidad, la explicación de resultados y la reproducibilidad.

## Evidencia y supuestos

| ID | Declaración o decisión | Estado | Evidencia o fuente | Alcance y fecha | Nota o contradicción |
|---|---|---|---|---|---|
| E-01 | `Detector` ya orquesta extracción de señales, identidad, verificación y puntuación en un único punto de composición. | Confirmado | `src/agent_traffic_intelligence/engine.py` | Árbol `main` antes de esta modularización | Es un límite de composición adecuado, pero no debe convertirse en un contenedor de implementaciones. |
| E-02 | La verificación de identidad ya separa perfiles, caché, red y criptografía. | Confirmado | `src/agent_traffic_intelligence/identity/` y sus pruebas | Árbol `main` antes de esta modularización | Se preserva esta estructura; no se duplica bajo una nueva taxonomía. |
| E-03 | El adaptador Railway mezcla configuración, protocolo HTTP y ciclo de vida de proceso. | Confirmado | `src/agent_traffic_intelligence/service.py` | Árbol `main` antes de esta modularización | Se divide con una fachada de compatibilidad para no romper `ati-service` ni importaciones existentes. |
| E-04 | Los escenarios de privacidad, corpus autorizado, evaluación y artefactos ya están cubiertos por pruebas CLI. | Confirmado | `tests/test_cli.py`, `tests/test_evaluation.py` | Árbol `main` antes de esta modularización | Los perfiles reutilizan escenarios existentes, no generan ni usan tráfico de terceros. |
| E-05 | La conversación adjunta propone fingerprints de red, descubrimiento de desconocidos, benchmarks adversariales, grafos, abuso API, eBPF y laboratorio de navegador. | Confirmado como recomendación, no como capacidad | `Pasted_content_01.txt` aportado por el usuario | Conversación adjunta, 2026-08-19 | Son rutas de investigación; no se implementan ni se afirman como disponibles en esta entrega. |
| I-01 | La modularización debe separar contratos estables de adaptadores opcionales y evitar diez aplicaciones o repositorios independientes. | Inferido | E-01 a E-05 | Esta entrega | Una monorepo modular reduce costes de integración y mantiene una sola política privacy-first. |
| A-01 | Los módulos de investigación necesitarán datos autorizados, métricas y revisión de amenazas antes de tener implementación. | No verificado para cada módulo | Política de privacidad existente y E-05 | Futuros módulos | La documentación los marca como bloqueados por diseño hasta tener corpus o entorno propio. |

## Calidad de fuentes

| Fuente | Directitud | Actualidad | Autoridad | Reproducibilidad | Afirmación adecuada |
|---|---|---|---|---|---|
| Código y pruebas de ATI | Directa | Revisión de trabajo actual | Alta | Inspección del árbol y `pytest` | Límites y contratos realmente implementados. |
| Conversación adjunta | Directa para intención del usuario | 2026-08-19 | Alta para alcance deseado | Archivo adjunto | Prioridades y variaciones a contemplar, no eficacia técnica. |
| Documentación de ATI | Directa | Revisión de trabajo actual | Alta | Archivos Markdown versionados | Operación, privacidad y no-objetivos. |

## Registro de decisiones

| Decisión | Opciones consideradas | Selección | Motivo | Verificación prevista |
|---|---|---|---|---|
| Organización de paquetes | Reescritura total; módulos paralelos sin migración; extracción con fachadas. | Extracción con fachadas de compatibilidad. | Conserva las interfaces `engine`, `parsers` y `service` mientras permite nuevos límites. | Pruebas completas y smoke test empaquetado. |
| Señales experimentales | Implementarlas como detectores activos; documentarlas únicamente; crear contratos aislados. | Contratos aislados y documentación de estado. | No hay corpus autorizado ni métricas para afirmar valor detector. | Pruebas de contrato y matriz de casos. |
| Entornos | Contenedores obligatorios; scripts privados; perfiles Makefile versionados. | Perfiles Makefile más archivos de entorno de ejemplo. | No añade infraestructura ni secretos y funciona localmente, en CI y Railway. | Ejecución de cada perfil desde un árbol limpio. |

## Elementos no resueltos

- La habilitación de fingerprints de red, análisis de grafos, eBPF o telemetría de navegador requiere un origen propio autorizado, una política de retención y métricas de evaluación antes de añadir ingestión real.
- La configuración del servicio remoto de Railway no está disponible en esta sesión; los perfiles validan el contrato del repositorio, no la infraestructura externa.
