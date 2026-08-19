# Auditoría de Railway y del repositorio

**Fecha:** 2026-08-19
**Revisión auditada:** `91c93ece38336851c6048b1207ad0edde2df5574` (`HEAD` = `origin/main`)
**Autor:** Manus AI

> **Actualización de seguimiento:** el árbol local posterior a esta auditoría incorpora `railway.toml`, el proceso `ati-service`, `GET /health`, un endpoint de análisis autenticado y pruebas de regresión. Esto resuelve localmente los hallazgos P0/P1 de proceso, puerto, salud y configuración versionada. No cambia el límite de acceso: todavía no se observó ni modificó el servicio remoto de Railway, y Railway no verá el cambio hasta que se revise, confirme y publique en la rama de despliegue. Véase [`railway-observe-only.md`](railway-observe-only.md).

## Dictamen ejecutivo

El repositorio está **sólidamente configurado como paquete y herramienta CLI de análisis por lote**, pero **no declara un servicio HTTP desplegable en Railway**. No contiene `Dockerfile`, `Procfile`, `railway.json`, `railway.toml`, `nixpacks.toml` ni un módulo que escuche `PORT`; el único punto de entrada publicado es el ejecutable `ati`. Railway necesita un proceso de inicio y, cuando se configura un health check, una aplicación que escuche el `PORT` inyectado y devuelva HTTP 200 desde una ruta de salud.[1] [2]

> **Conclusión operativa:** si actualmente existe un “servidor” en Railway, debe provenir de configuración externa al repositorio o de otro componente. Este repositorio, sin un adaptador adicional y sin una estrategia de ingestión/persistencia, no puede explicar por sí solo un servicio web saludable ni un sensor continuo.

| Estado | Aspecto | Evidencia principal | Implicación |
|---|---|---|---|
| **Bloqueante** | No hay proceso HTTP persistente ni health endpoint. | `pyproject.toml` define únicamente `ati = agent_traffic_intelligence.cli:main`; `cli.py` registra subcomandos de lote y no inicia listener. | Un despliegue web de Railway no tendrá ruta `200` ni proceso que permanezca vivo. |
| **Alto** | No hay configuración versionada específica de Railway. | Inventario sin `railway.*`, `Dockerfile`, `Procfile`, `nixpacks.toml` ni manifiesto de servicio. | El comando de inicio, health check, dominio, almacenamiento y variables quedan implícitos o externos; no son reproducibles desde Git. |
| **Alto** | La persistencia de entradas, salidas y caché no está definida para Railway. | `ati run` escribe directorios locales atómicos y la caché de identidad cae por defecto bajo `~/.cache`; el README exige explícitamente `ATI_SOURCE_CACHE` cuando se quiere controlar su ubicación. | Los resultados y fuentes verificadas pueden perderse en almacenamiento efímero si no se diseña un volumen o un backend externo. |
| **Medio** | El árbol local contiene cambios no confirmados y no rastreados. | Cuatro archivos modificados y siete archivos no rastreados; `HEAD` sí coincide con `origin/main`. | Railway conectado a GitHub no desplegará estos cambios locales hasta que pasen revisión, commit y push. |
| **Bajo** | El laboratorio local no cumple Ruff. | `lab/controlled_observer.py` tiene dos infracciones de Ruff; no pertenece al paquete `src/` ni a `origin/main`. | No afecta el paquete remoto actual, pero bloqueará CI si se añade sin corregirlo. |

## Alcance y límite de acceso

La auditoría cubrió el árbol Git, código Python, empaquetado, CI, documentación, seguridad y evidencia pública de Railway. La sesión **no tiene una integración configurada para Railway**; por ello no fue posible leer el servicio remoto, sus logs, variables, dominio, health check configurado, volumen ni historial de despliegues. Esa distinción importa: los hallazgos sobre el repositorio son verificables; el estado del servicio remoto sigue sin observarse.

## Hallazgos técnicos

### 1. El producto actual es un analizador por lote, no un servidor

El README describe ATI como un analizador local y origin-side, en estado pre-alpha y observe-only. Su arquitectura parte de JSONL de access logs y genera JSONL de detecciones; la hoja de ruta reserva el sensor en tiempo real para V3.[3] El `pyproject.toml` declara el entorno `Console` y solo publica el script `ati`; no declara dependencias runtime ni un framework web.[4]

La prueba de proceso confirmó el diseño: `ati analyze examples/data/access.jsonl` procesó dos eventos, generó dos líneas de salida y terminó con código 0 en menos de un segundo. No abrió un listener de ATI. Por tanto, usar `ati analyze ...` como `Start Command` de Railway produciría un job que termina; no un servicio web.

### 2. Falta un contrato de despliegue reproducible

Railway permite configurar un comando de inicio y requiere que una aplicación con health check escuche el `PORT` inyectado.[1] [2] El repositorio no versiona ninguna de esas decisiones. Tampoco existe una ruta `/health`, una aplicación ASGI/WSGI, ni un loop de ingestión que lea registros del reverse proxy o de una cola.

La ausencia puede ser correcta si el objetivo es ejecutar **jobs manuales de análisis**. No es correcta si el objetivo es un endpoint público o un agente siempre activo. En ese último caso, desplegar este repositorio como si fuera un servidor sería una incompatibilidad de arquitectura, no un fallo menor de configuración.

### 3. La persistencia y la ingestión real quedan fuera del contrato

`ati run` crea un directorio local de staging, escribe detecciones, evaluación y resumen, y finalmente lo reemplaza de forma atómica. La caché de fuentes de identidad usa `ATI_SOURCE_CACHE` o `~/.cache/agent-traffic-intelligence/identity-sources`. Estos comportamientos son seguros para ejecución local, pero no especifican dónde viven los access logs, las etiquetas, los artefactos de evaluación ni la caché en un entorno efímero.[3]

Si Railway se usa para análisis por lotes, el diseño mínimo requiere un origen de entrada autorizado y reproducible, un destino persistente para artefactos y una ubicación explícita para `ATI_SOURCE_CACHE`. Si se adjunta un volumen, Railway advierte que los redespliegues con el mismo volumen pueden tener una breve indisponibilidad.[2] El repositorio no documenta esta decisión ni provee la configuración para realizarla.

### 4. Controles de calidad y seguridad: base positiva

El núcleo rastreado pasó **339 pruebas**, Ruff para `src` y `tests`, y mypy estricto en **54 archivos fuente**. La suite con cobertura alcanzó **85.47%**, por encima del mínimo de 85%; el wheel y sdist se construyeron correctamente; `pip check` no detectó requisitos rotos y `pip-audit -r requirements-dev.txt` no informó vulnerabilidades conocidas. La política de seguridad documenta la pseudonimización obligatoria para IPs, la separación de `VerificationContext` y restricciones explícitas de red.[5]

La protección de cadena de suministro también es razonable: CI cubre Python 3.11, 3.12 y 3.13, instala las dependencias de desarrollo con hashes, compila el código, prueba CLI y valida wheel limpio. CodeQL, Dependency Review y OpenSSF Scorecard están presentes, y las acciones se fijan por SHA.[6] La consulta de ejecuciones remotas mostró CI, CodeQL, Dependency Review y Scorecard recientes con conclusión `success`. La API de alertas de Dependabot/Code Scanning respondió `403 Resource not accessible by integration`, por lo que **no se puede afirmar** desde esta sesión que no existan alertas abiertas.

### 5. Diferenciar `origin/main` del árbol local

La rama local coincide con `origin/main` en `91c93ec`, pero el directorio de trabajo no está limpio. Existen modificaciones locales en evaluación y CLI, junto con documentos, artefactos y un servidor de laboratorio no rastreado. El archivo de laboratorio generado durante la prueba tiene dos incidencias de Ruff (`RUF100` y `UP017`). No forma parte del paquete distribuido ni del commit remoto actual, pero debe corregirse o excluirse antes de incorporarlo a CI.

## Evidencia de verificación

| Comprobación | Resultado | Interpretación |
|---|---:|---|
| `ruff check src tests` | Correcto | El núcleo rastreado está limpio. |
| `mypy src` | Correcto, 54 archivos | El paquete conserva tipado estricto. |
| `pytest -q` | 339 correctas | La regresión principal pasó. |
| Cobertura | 85.47% | Supera el umbral configurado de 85%. |
| `python -m build` | Wheel y sdist correctos | El paquete puede construirse. |
| `python -m pip check` | Sin requisitos rotos | Entorno de prueba consistente. |
| `pip-audit -r requirements-dev.txt` | 0 vulnerabilidades conocidas | Señal de dependencias positiva, no garantía absoluta. |
| `ruff check .` | 2 errores, solo `lab/controlled_observer.py` no rastreado | Deuda local que no pertenece a `origin/main`. |
| Simulación de proceso `ati analyze` | Finaliza tras procesar el archivo | Confirma que no es un servidor persistente. |

## Acciones correctivas priorizadas

| Prioridad | Acción | Criterio de cierre verificable |
|---|---|---|
| **P0** | Elegir un modelo explícito: **job de lote** o **servicio/sensor continuo**. No tratar el CLI actual como aplicación web. | Existe una decisión en README/infra y un comando Railway que coincide con ella. |
| **P0** | Si el objetivo es servicio, crear un adaptador versionado que escuche `PORT`, exponga `/health` y mantenga una fuente de ingestión autorizada. | El health check de Railway recibe HTTP 200 y una prueba de despliegue confirma que el proceso no termina. |
| **P1** | Definir persistencia: origen de JSONL, destino de artefactos y ubicación de `ATI_SOURCE_CACHE`. | Se documentan variables, retención y un volumen o backend externo; una ejecución sobrevive al redeploy según el modelo elegido. |
| **P1** | Añadir configuración de Railway versionada o documentar precisamente la configuración externa. | Un operador nuevo puede reproducir build, start, health check, variables no secretas y almacenamiento sin inferencias. |
| **P1** | Llevar los cambios locales por revisión normal antes de esperar que Railway los use. | Árbol limpio; commit revisado y push a la rama configurada para despliegue. |
| **P2** | Corregir o retirar el laboratorio local antes de añadirlo a Git. | `ruff check .` correcto en un árbol limpio. |
| **P2** | Conceder acceso de solo lectura a las alertas de seguridad o revisarlas desde GitHub. | La auditoría puede registrar conteo y severidad de alertas abiertas. |

## Siguiente paso seguro

No recomiendo crear una página web. El siguiente paso depende del rol real que cumple el servicio de Railway:

> **Si Railway debe ejecutar análisis:** configúralo como job de lote y proporciona el log JSONL y el directorio persistente de resultados mediante un mecanismo autorizado.
>
> **Si Railway debe recibir tráfico:** este repositorio necesita un componente de ingestión/sensor separado, observe-only, que no altere tráfico ni mezcle la política de bloqueo con ATI.

Para cerrar la parte remota de la auditoría faltan el enlace del servicio Railway o los logs de build/start/health check, más los valores **no secretos** de start command, healthcheck path, puerto objetivo y si hay volumen. No se requieren ni se deben compartir claves, cookies, logs de acceso reales, encabezados `Authorization` ni `ATI_HASH_KEY`.

## Referencias

[1] [Railway Docs: Set a Start Command](https://docs.railway.com/deployments/start-command)
[2] [Railway Docs: Healthchecks](https://docs.railway.com/deployments/healthchecks)
[3] [ATI README, revisión auditada](https://github.com/jccontrerasg08-cpu/agent-traffic-intelligence/blob/91c93ece38336851c6048b1207ad0edde2df5574/README.md)
[4] [ATI pyproject.toml, revisión auditada](https://github.com/jccontrerasg08-cpu/agent-traffic-intelligence/blob/91c93ece38336851c6048b1207ad0edde2df5574/pyproject.toml)
[5] [ATI SECURITY.md, revisión auditada](https://github.com/jccontrerasg08-cpu/agent-traffic-intelligence/blob/91c93ece38336851c6048b1207ad0edde2df5574/SECURITY.md)
[6] [ATI CI workflow, revisión auditada](https://github.com/jccontrerasg08-cpu/agent-traffic-intelligence/blob/91c93ece38336851c6048b1207ad0edde2df5574/.github/workflows/ci.yml)
