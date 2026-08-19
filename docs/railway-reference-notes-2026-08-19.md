# Notas de referencia de Railway — 2026-08-19

Estas notas registran únicamente los requisitos externos usados para la auditoría; no sustituyen la configuración del servicio en Railway.

| Tema | Hallazgo documentado | Fuente oficial |
|---|---|---|
| Proceso de inicio | Railway ejecuta un comando de inicio para arrancar el código desplegado y permite sobrescribirlo. Para despliegues Railpack, el comando se ejecuta mediante un shell, por lo que puede expandir variables de entorno. | [Set a Start Command](https://docs.railway.com/deployments/start-command) |
| Puerto | Railway inyecta la variable `PORT`; la aplicación debe escuchar ese puerto para que el health check use el valor correcto. | [Healthchecks](https://docs.railway.com/deployments/healthchecks#configure-the-healthcheck-port) |
| Salud de despliegue | Si se configura un endpoint, Railway consulta la ruta hasta recibir HTTP 200 antes de activar la nueva versión. | [Healthchecks](https://docs.railway.com/deployments/healthchecks#how-it-works) |
| Volúmenes | Un volumen adjunto evita tener más de un despliegue activo montándolo al mismo tiempo; los redespliegues pueden tener una breve indisponibilidad. | [Healthchecks](https://docs.railway.com/deployments/healthchecks#services-with-attached-volumes) |
| Configuración versionada | Railway reconoce `railway.toml` o `railway.json` junto al código. La configuración en código prevalece sobre la del dashboard para ese despliegue, sin cambiar los ajustes persistentes del dashboard. | [Config as Code](https://docs.railway.com/config-as-code) |
| Campos de despliegue | La configuración admite `build.builder`, `build.buildCommand`, `deploy.startCommand`, `deploy.healthcheckPath`, `deploy.healthcheckTimeout`, `deploy.restartPolicyType` y `deploy.restartPolicyMaxRetries`. | [Config as Code Reference](https://docs.railway.com/config-as-code/reference) |

## Alcance de acceso

La sesión no tiene un conector configurado para Railway. Por tanto, esta auditoría puede verificar el repositorio y contrastarlo con la documentación pública, pero no puede leer configuraciones, variables, logs, dominio o estado del despliegue remoto sin una integración o información adicional proporcionada por el usuario.
