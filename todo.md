# Auditoría Railway — tareas completadas

- [x] Inventariar archivos de despliegue, procesos de inicio, dependencias y superficies de red.
- [x] Contrastar los requisitos públicos de Railway para start command, `PORT`, health check y volúmenes; no hubo acceso a la configuración remota.
- [x] Revisar seguridad de secretos, datos de tráfico, límites de recursos y rutas de entrada.
- [x] Ejecutar pruebas, análisis estático, empaquetado, auditoría de dependencias y comprobaciones de comportamiento operativo.
- [x] Clasificar hallazgos por criticidad, reproducibilidad y acción correctiva verificable.

## Preparación de servicio Railway — tareas completadas

- [x] Definir el contrato mínimo del proceso persistente, la ruta de salud y los límites de observe-only.
- [x] Implementar el servicio técnico, su configuración Railway y las pruebas de salud sin crear una interfaz web.
- [x] Verificar el comportamiento sobre `PORT`, el empaquetado, la regresión y el cierre limpio del proceso.
- [x] Documentar las variables no secretas, el almacenamiento requerido y el procedimiento de despliegue.

## Modularización y matriz de entornos — tareas completadas localmente

- [x] Extraer los requisitos verificables de la conversación adjunta y contrastarlos con los módulos existentes.
- [x] Definir arquitectura modular, contratos de paquete y límites explícitos para identidad, fingerprint, comportamiento, descubrimiento y evaluación.
- [x] Reorganizar el código sin romper las interfaces públicas ni los contratos observe-only.
- [x] Crear perfiles de prueba aislados para unidad, integración de servicio, corpus controlado, regresión y empaquetado.
- [x] Documentar la matriz de casos, variables, retención, riesgos, resultados esperados y rutas de extensión no implementadas.
- [x] Ejecutar la matriz completa y conservar evidencia local; falta publicar la revisión protegida.

## Observación pública y catálogo de capacidades — preparación completada

- [x] Clasificar cada variable solicitada como medible, opt-in, no fiable o fuera de alcance, con fuente y límite de privacidad.
- [x] Diseñar el catálogo público de capacidades y las cabeceras de respuesta que no requieran token ni almacenen identificadores.
- [x] Implementar variantes de observación segura para clientes públicos, automatizados, directos y con metadatos explícitos.
- [x] Añadir entornos y casos de prueba para token presente/ausente, HTTP, identidad declarada y acceso sin señal DNS observable.
- [x] Ejecutar la matriz completa, registrar evidencia y preparar la publicación mediante revisión protegida.
