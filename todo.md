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

## Modularización y matriz de entornos — tareas completadas

- [x] Extraer los requisitos verificables de la conversación adjunta y contrastarlos con los módulos existentes.
- [x] Definir arquitectura modular, contratos de paquete y límites explícitos para identidad, fingerprint, comportamiento, descubrimiento y evaluación.
- [x] Reorganizar el código sin romper las interfaces públicas ni los contratos observe-only.
- [x] Crear perfiles de prueba aislados para unidad, integración de servicio, corpus controlado, regresión y empaquetado.
- [x] Documentar la matriz de casos, variables, retención, riesgos, resultados esperados y rutas de extensión no implementadas.
- [x] Ejecutar la matriz completa, conservar evidencia y publicar la revisión protegida mediante PR #29.

## Observación pública y catálogo de capacidades — publicación completada

- [x] Clasificar cada variable solicitada como medible, opt-in, no fiable o fuera de alcance, con fuente y límite de privacidad.
- [x] Diseñar el catálogo público de capacidades y las cabeceras de respuesta que no requieran token ni almacenen identificadores.
- [x] Implementar variantes de observación segura para clientes públicos, automatizados, directos y con metadatos explícitos.
- [x] Añadir entornos y casos de prueba para token presente/ausente, HTTP, identidad declarada y acceso sin señal DNS observable.
- [x] Ejecutar la matriz completa, registrar evidencia y publicar mediante la PR #30.

## Observación controlada de repetición — preparación completada localmente

- [x] Inventariar el contrato actual y separar la frecuencia observable por solicitud de cualquier identificador o perfil persistente.
- [x] Definir un protocolo de experimentos para clientes humanos, IA, bots y automatizaciones que use marcadores explícitos y repeticiones acotadas.
- [x] Implementar sólo las señales agregadas que puedan devolverse sin almacenar identidad, IP, valores de cabecera ni historial de cliente.
- [x] Añadir pruebas para repetición declarada, declaraciones inválidas y ausencia de datos sensibles en la respuesta.
- [x] Verificar el paquete y documentar cobertura y límites.
- [ ] Publicar la revisión protegida y comprobar por separado la URL activa de Railway.

## Incidencia Railway — ruta pública 404

- [ ] Registrar la evidencia del 404 externo y diferenciarla de los contratos verificados localmente.
- [ ] Inspeccionar el servicio, dominio y despliegue efectivos de Railway en modo de sólo lectura.
- [ ] Corregir únicamente la divergencia confirmada entre el código publicado y el servicio activo.
- [ ] Verificar la ruta pública activa sin cabeceras y conservar un registro de verificación.

## Topología Railway separada en un proyecto compartido — tareas pendientes

- [ ] Registrar la decisión de conservar `ati-observation-lab` como destino de pruebas independiente.
- [ ] Confirmar que la configuración versionada de ATI está lista para un segundo servicio sin reutilizar el dominio ni la retención del laboratorio.
- [ ] Crear un segundo servicio Railway, dentro del proyecto existente, vinculado a `jccontrerasg08-cpu/agent-traffic-intelligence` en `main`.
- [ ] Sustituir el ejecutable `ati-service` no encontrado en Railway por un módulo de arranque explícito y verificarlo antes del redespliegue.
- [ ] Verificar `/health`, `/v1/catalog` y `/v1/observe` en el nuevo dominio y documentar ambos contratos.
