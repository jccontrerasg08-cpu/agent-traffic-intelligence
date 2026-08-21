# Verificación independiente del perímetro Worker → Railway

**Estado:** en curso, evidencias recogidas el 2026-08-20.
**Alcance:** comprobaciones de sólo lectura sobre el Worker `ati-observation-proxy`, su URL `workers.dev`, el origen público de Railway y el repositorio `ati-observation-lab`. No se descargó el bundle desplegado, no se leyeron valores secretos, no se editaron recursos y no se accedió a registros de solicitudes.

> El archivo adjunto aportado por el usuario es una **fuente de hipótesis**. Cada conclusión de esta tabla se apoya en una observación directa indicada o queda explícitamente sin verificar.

| Afirmación o rama | Estado | Evidencia directa | Límite de la comprobación |
|---|---|---|---|
| Existe el Worker `ati-observation-proxy`. | **Confirmado.** | `GET /accounts/{account_id}/workers/scripts` respondió `200` y listó ese identificador, creado el 2026-08-20 y modificado posteriormente ese mismo día. | No demuestra por sí solo qué bundle concreto está sirviendo cada solicitud. |
| La cuenta tiene subdominio Workers.dev `jccontrerasg08`. | **Confirmado.** | `GET /accounts/{account_id}/workers/subdomain` respondió `200` con `jccontrerasg08`. | La asociación exacta de ese subdominio con el Worker se corroboró adicionalmente mediante la respuesta pública, no mediante una ruta de escritura o despliegue. |
| El endpoint público `https://ati-observation-proxy.jccontrerasg08.workers.dev/observe` está disponible. | **Confirmado.** | `GET /observe` y `HEAD /observe` devolvieron `200` y `Cache-Control: no-store`; el `GET` devolvió `{"status":"observed"}`. | Es una comprobación puntual desde una red; no acredita disponibilidad universal ni calidad de servicio sostenida. |
| El Worker rechaza query strings en la ruta de observación. | **Confirmado.** | `GET /observe?q=1` devolvió `400`, cuerpo vacío y `Cache-Control: no-store`. | La prueba no demuestra qué hace la plataforma Cloudflare con metadatos operativos fuera de la aplicación. |
| El origen Railway está separado del Worker y no acepta una observación anónima directa. | **Confirmado para GET.** | `GET https://ati-observation-lab-production.up.railway.app/healthz` devolvió `200`; `GET /observe` devolvió `503`, ambos con `Cache-Control: no-store`. | Una comprobación `HEAD` directa agotó el tiempo de negociación TLS; no se interpreta como caída ni como prueba del contrato `HEAD` del origen. |
| El proyecto Railway contiene los servicios ATI y laboratorio separados. | **Confirmado.** | El panel Railway mostró ambos servicios en estado `Online`. | La interfaz de proyecto no revela ni valida por sí misma las variables de entorno efectivas. |
| El Worker posee los secretos por nombre `ATI_CLIENT_PSEUDONYM_KEY` y `ATI_PROXY_ORIGIN_TOKEN`. | **Confirmado sin valores.** | `GET /workers/scripts/ati-observation-proxy/secrets` respondió `200` con ambos nombres y tipo `secret_text`. | No se leyó ningún valor. El listado tampoco permite concluir qué variables están configuradas en Railway. |
| El código versionado implementa el filtro `GET`/`HEAD`, la ruta exacta `/observe`, la prohibición de `Authorization`, cookies y query strings, y reenvía un identificador HMAC junto con un token de proxy. | **Confirmado para `origin/main` de `ati-observation-lab`.** | Revisión `154dbca` del repositorio, archivo `cloudflare-worker/src/index.mjs`; la PR #7 está fusionada en ese commit.[2] | No se recuperó el contenido del bundle desplegado desde Cloudflare, por lo que la identidad entre código versionado y bundle activo sigue sin verificación independiente. |
| Cloudflare mantiene una versión reciente desplegada al 100 %. | **Confirmado para los metadatos de despliegue.** | La lista de versiones incluyó la versión 4; la lista de despliegues incluyó posteriormente un despliegue de esa versión con estrategia de porcentaje al 100 %. | Los metadatos no contienen el hash de Git ni el contenido del bundle; no prueban que sea byte a byte el archivo de `origin/main`. |
| La variable `ATI_PROXY_ORIGIN_TOKEN` es redundante en Railway y puede eliminarse. | **No verificado; potencialmente ambiguo.** | El Worker activo enumera un secreto con ese nombre y el código versionado lo exige para autenticar el salto al origen. | Sólo podría ser redundante una variable homónima **adicional** en Railway; comprobarlo requiere inspeccionar nombres de variables del servicio y entender su configuración activa, nunca valores secretos. |
| El uso agregado de Workers fue cero durante las 24 horas consultadas. | **Confirmado como respuesta de API, no como ausencia de tráfico.** | La API de observabilidad devolvió `events: 0` y `breakdown: []`. | Esta métrica agregada puede tener retardo, una semántica distinta de las solicitudes HTTP o cobertura no configurada; no contradice ni invalida las respuestas públicas observadas. |
| La revisión de GitHub citada superó CI y el despliegue Railway actual la refiere. | **Confirmado.** | La PR #7 registró dos comprobaciones exitosas de CI; Railway mostró el despliegue `ACTIVE`, derivado de GitHub, y el mensaje de la corrección de configuración de Wrangler. | La API de GitHub confirmó que `main` no tiene protección de rama; el éxito de CI no equivale a una regla de fusión obligatoria. |
| Es posible verificar los nombres de variables del laboratorio desde Railway. | **Pendiente.** | La vista del servicio confirmó que existe una pestaña de Variables, pero el automatizador de navegador agotó el tiempo dos veces al abrirla. | No se infieren nombres ni valores de variables a partir de este bloqueo; no se deben revelar valores secretos para cerrar esta incertidumbre. |

## Implicaciones actuales

La evidencia disponible respalda una topología funcional en la que el Worker responde públicamente y el origen Railway rechaza una observación anónima directa. El código versionado explica ese comportamiento mediante un token de salto y un seudónimo HMAC, pero la correspondencia entre el bundle activo y el commit de GitHub continúa siendo una **inferencia razonable**, no una identidad demostrada.

La variable `ATI_PROXY_ORIGIN_TOKEN` requiere especial cautela. En Cloudflare aparece como secreto activo y el código de `origin/main` la utiliza. No debe eliminarse ni rotarse basándose sólo en el texto adjunto; primero debe comprobarse el inventario de nombres de variables en Railway y prepararse una rotación coordinada, con una prueba de extremo a extremo y un plan de reversión.

## Integraciones evaluadas

| Integración | Resultado | Decisión de alcance |
|---|---|---|
| Cloudflare | Aporta evidencia primaria de Worker, secretos por nombre, versiones, despliegues y uso agregado. | Utilizada sólo con operaciones `GET`; se excluyeron live-tail, consultas de eventos y cualquier escritura. |
| Playwright | Sería una segunda vía de navegador aislado. | No utilizable: el navegador Firefox configurado no está instalado. No se ejecutó código ni se alteró la instalación. |
| Cloudinary | Gestiona activos multimedia, no DNS, Workers, Railway ni contratos HTTP de este perímetro. | No se consultaron activos ni uso para evitar acceso innecesario a la biblioteca multimedia. |
| Gmail | Podría contener notificaciones, pero no constituye fuente primaria del estado técnico y conlleva acceso a comunicaciones privadas. | No se buscaron ni leyeron correos. |

Estas decisiones no equivalen a que las integraciones no puedan usarse en otros objetivos; indican únicamente que no aumentan de forma proporcional la certeza de esta verificación técnica.

## Fuentes y referencias

[1] [Cloudflare API — Workers](https://developers.cloudflare.com/api/resources/workers/)

[2] [PR #7 de ati-observation-lab](https://github.com/jccontrerasg08-cpu/ati-observation-lab/pull/7)
