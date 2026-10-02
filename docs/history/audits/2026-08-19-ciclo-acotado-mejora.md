# Ciclo acotado de mejora basado en evidencia

**Proyecto:** Agent Traffic Intelligence (ATI)
**Fecha:** 19 de agosto de 2026
**Autor:** Manus AI
**Estado:** mejora implementada y verificada localmente; no publicada ni desplegada

## Resultado

Se ejecutó un ciclo pequeño y reversible sobre el repositorio seleccionado. El material adjunto proponía avanzar desde reglas explicables hacia evaluación con **PR-AUC, falsos positivos, falsos negativos y calibración**, además de reservar proyectos más grandes —JA4+, detección de agentes desconocidos, grafos temporales y browser fingerprinting— para fases posteriores [A]. La inspección del repositorio confirmó una discrepancia concreta: `docs/evaluation.md` declaraba esas métricas como parte del marco de evaluación, pero el evaluador solo exponía matriz de confusión, precisión, recall, F1, accuracy, Brier y cobertura.

La mejora elegida fue, por tanto, **completar el contrato de evaluación sin cambiar el detector ni introducir dependencias nuevas**. El evaluador ahora calcula y serializa `false_positive_rate`, `false_negative_rate`, `pr_auc` y `expected_calibration_error`. Las métricas de tasa devuelven `null` cuando falta la clase correspondiente; PR-AUC devuelve `null` cuando no hay positivos. El cambio queda documentado, cubierto por pruebas unitarias y propagado a la salida de `ati evaluate` y a los artefactos de `ati run`.

> **Hipótesis acotada:** si el evaluador ya exige un corpus autorizado y documenta métricas de ranking, error y calibración, exponerlas en la salida permitirá detectar mejor degradación y sesgos sin alterar el comportamiento de scoring.

## Delimitación y criterios de éxito

El ciclo se limitó a cuatro archivos modificados: implementación del evaluador, anotaciones de propagación en la CLI, pruebas unitarias y documentación. No se añadieron modelos ML, fuentes externas, datos de producción, sensores TLS, fingerprints de navegador ni políticas de bloqueo.

| Criterio observable | Resultado esperado | Estado |
|---|---|---|
| Mantener el comportamiento existente | Las pruebas previas deben seguir pasando | **Confirmado**: 339 pruebas pasan después del cambio |
| Exponer métricas prometidas por la documentación | La salida JSON debe incluir PR-AUC, FPR, FNR y ECE | **Confirmado** por prueba unitaria y ejecución CLI |
| Manejar clases ausentes sin inventar valores | Usar `null` cuando una métrica no está definida | **Confirmado** por prueba específica |
| Mantener calidad estática | Ruff y mypy sin errores | **Confirmado** |
| Mantener empaquetado | Construir wheel y sdist | **Confirmado** tras corregir metadatos generados con propietario `root` |
| Demostrar rendimiento generalizable | Medir un corpus real autorizado | **No verificado**; el repositorio no contiene ese corpus |

## Evidencia y decisiones

| ID | Afirmación o decisión | Estado | Evidencia | Alcance y limitación |
|---|---|---|---|---|
| E-01 | El repositorio ya dispone de evaluación local sobre etiquetas autorizadas y documenta PR-AUC, FPR/FNR y calibración como métricas primarias | **Confirmada** | README y `docs/evaluation.md` inspeccionados; la implementación previa no las serializaba | Describe el contrato del repositorio, no la calidad estadística del detector |
| E-02 | Antes del cambio, la suite de regresión tenía 338 pruebas exitosas | **Confirmada** | `python -m pytest -q` después de instalar los extras declarados | El primer intento fue bloqueado porque `pytest` no estaba instalado en el entorno; se resolvió instalando `.[dev,verification]` |
| E-03 | La RFC 9421 estandariza firmas sobre componentes de mensajes HTTP, pero no constituye por sí sola una arquitectura completa de seguridad [1] | **Confirmada** | Lectura directa de la RFC 9421, publicada como documento Standards Track | Se usa para calibrar el alcance de la futura identidad criptográfica, no para afirmar que una firma resuelve el riesgo completo |
| E-04 | Cloudflare documenta Web Bot Auth como un mecanismo basado en firmas y en drafts de directorio/protocolo, con restricciones de integración específicas [2] | **Confirmada** | Documentación oficial leída directamente | La evidencia no implica adopción universal ni compatibilidad automática con todos los verificadores |
| E-05 | JA4+ ofrece una familia de fingerprints de red y casos de uso de threat hunting, pero su repositorio distingue licencias: JA4 bajo BSD 3-Clause y otros componentes bajo FoxIO License 1.1 [3] | **Confirmada** | README del repositorio oficial leído directamente | Cualquier integración futura requiere revisión jurídica y de compatibilidad de licencia |
| E-06 | BotD es una biblioteca open source client-side para detección básica; su propio README indica que su roadmap cercano es de estabilidad y que capacidades más amplias pertenecen a un producto comercial [4] | **Confirmada** | README oficial de FingerprintJS leído directamente | No debe presentarse como detector completo de agentes IA ni como prueba suficiente de automatización |
| E-07 | StrGNN es evidencia de investigación sobre anomalías en grafos dinámicos, no evidencia de que el enfoque sea válido para el tráfico de ATI [5] | **Inferida con cautela** | Abstract de arXiv y repositorio del proyecto | Requeriría corpus temporal autorizado, adaptación de entidades y evaluación independiente |
| D-01 | Se priorizó el evaluador sobre JA4+, browser fingerprinting o GNN | **Decisión confirmada** | Discrepancia E-01, menor superficie de cambio y ausencia de corpus/sensores necesarios | Es una mejora de instrumentación, no una validación del modelo |

## Implementación

La función `evaluate_automation_scores` conserva sus métricas existentes y añade cuatro salidas. `false_positive_rate` se calcula como `FP / (FP + TN)` y `false_negative_rate` como `FN / (FN + TP)`. PR-AUC se calcula ordenando los pares `(score, etiqueta)` de forma descendente y agrupando empates antes de integrar el área precisión–recall. Esto evita introducir una dependencia de ML para una métrica que puede calcularse con la biblioteca estándar.

El error esperado de calibración utiliza diez bins de ancho fijo en `[0, 1]`. Para cada bin se compara el promedio de los scores con la fracción positiva y se pondera por la proporción de observaciones del bin. Se documenta explícitamente que ECE y Brier son diagnósticos; **no prueban que los scores sean probabilidades calibradas**. Cuando no existe la clase necesaria, el resultado es `null` en lugar de convertir una ausencia de datos en cero.

La CLI se ajustó únicamente en sus anotaciones de tipos para permitir esos valores nulos en los artefactos JSON. Las pruebas cubren el caso normal, las métricas nuevas y el caso de corpus sin positivos. La documentación de evaluación ahora describe el contrato real y sus límites.

## Verificación ejecutada

La verificación se realizó primero sobre la versión previa y luego sobre la versión modificada. Los resultados observados fueron los siguientes:

| Comprobación | Resultado observado |
|---|---|
| Baseline de pruebas | `338 passed in 2.38s` |
| Pruebas focalizadas después del cambio | `8 passed in 0.70s` |
| Suite completa después del cambio | `339 passed in 1.84s` |
| Ruff sobre el repositorio | `All checks passed!` |
| Mypy sobre `src` | `Success: no issues found in 54 source files` |
| `git diff --check` | Sin errores de whitespace |
| Build de distribución | Wheel y sdist construidos correctamente |
| Ejecución CLI sobre fixture local | 2 detecciones evaluadas, cobertura completa, PR-AUC `1.0`, FPR `0.0`, FNR `0.0`, ECE `0.12080077701008643`, Brier `0.015035942346509401` |

La ejecución CLI utilizó únicamente `examples/data/access.jsonl`, que contiene dos registros de ejemplo: uno con User-Agent `GPTBot/1.0` y otro con User-Agent de navegador genérico. Las etiquetas temporales se asignaron directamente a esos dos registros de fixture para probar el contrato de extremo a extremo. El resultado es útil como **smoke test**, no como benchmark: con dos observaciones no se puede estimar rendimiento, calibración ni tasa de falsos positivos en tráfico real.

El primer intento de empaquetado falló porque la instalación editable realizada con privilegios elevados había creado `src/agent_traffic_intelligence.egg-info` con propietario `root`, impidiendo actualizar sus timestamps. Se eliminó únicamente ese metadato generado y se repitió el build como usuario del repositorio; el segundo intento produjo correctamente ambos artefactos. Este incidente es ambiental y no constituye un fallo del cambio fuente.

## Interpretación y límites

La evidencia confirma que la mejora **alinea la salida del evaluador con la documentación y no rompe la suite existente**. No confirma que los scores de ATI estén calibrados, que el detector generalice fuera del fixture, ni que alguna identidad reclamada sea auténtica. Tampoco confirma que JA4+, BotD, Web Bot Auth o StrGNN deban incorporarse ahora.

El uso futuro de PR-AUC y ECE debe respetar las salvaguardas ya definidas por ATI: corpus autorizado, separación por cliente/sesión, holdout temporal, familias no vistas, ablación de User-Agent y registro de sesgos de muestreo. La documentación de ATI también mantiene una postura correcta al separar `automation_score`, `ai_score`, `identity_confidence` y `risk_score`; esta mejora no los comprime en una única etiqueta.

## Siguiente ciclo mínimo recomendado

El siguiente experimento debería ser la recolección de un **corpus shadow-mode autorizado** mediante el procedimiento de `docs/controlled-observation.md`. El objetivo no sería entrenar todavía, sino obtener suficientes etiquetas para comparar, en holdout temporal, el baseline actual usando las cuatro métricas nuevas. Solo si el corpus es suficiente y representativo tendría sentido evaluar calibración posterior, una ablación de User-Agent o un primer modelo aprendido.

| Próximo paso | Evidencia mínima para aceptarlo | Condición de no avance |
|---|---|---|
| Crear corpus shadow-mode autorizado | Manifest completo, autorización, ventana temporal y sesgos declarados | Falta de autorización o mezcla de corpus |
| Ejecutar `ati run` con etiquetas | `quality status: ready`, cobertura cero y artefactos reproducibles | Detecciones o labels sin correspondencia |
| Comparar baseline | PR-AUC, FPR/FNR y ECE en holdout temporal y por familia | Solo métricas agregadas en el mismo periodo |
| Decidir sobre ML o fingerprints | Mejora reproducible y revisión de privacidad/licencia | Ganancia no estable o coste operativo no medido |

## Referencias

[1]: https://datatracker.ietf.org/doc/html/rfc9421 "RFC 9421 - HTTP Message Signatures"
[2]: https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/ "Cloudflare Web Bot Auth"
[3]: https://github.com/FoxIO-LLC/ja4 "FoxIO JA4+ Network Fingerprinting"
[4]: https://github.com/fingerprintjs/BotD "FingerprintJS BotD"
[5]: https://arxiv.org/abs/2005.07427 "Structural Temporal Graph Neural Networks for Anomaly Detection in Dynamic Graphs"
[A]: /home/ubuntu/upload/Pasted_content.txt "Material adjunto del usuario"
