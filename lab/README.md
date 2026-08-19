# Laboratorio de corpus controlado

`controlled_observer.py` es un objetivo HTTP local, deliberadamente pequeño, para campañas autorizadas de shadow mode. No es parte del paquete instalable, no se despliega en Railway, no representa tráfico humano real y no se debe exponer a Internet.

El objetivo acepta solamente solicitudes `GET` y escribe un JSONL de acceso minimizado. Recorta query strings antes de escribirlas y usa los rangos reservados TEST-NET (`198.51.100.0/24`) exclusivamente para diferenciar los dos brazos de prueba. El encabezado `X-ATI-Experiment-ID` puede marcar solicitudes controladas; por sí solo no etiqueta el brazo navegador ni sustituye revisión humana.

```bash
python lab/controlled_observer.py --log /tmp/ati-controlled/access.jsonl
```

Ejecuta `make test-controlled` para cubrir el contrato de generación de registros, más los flujos de CLI y evaluación. Consulta `docs/cases-and-variations.md` antes de convertir cualquier ejecución de laboratorio en un corpus de evaluación.
