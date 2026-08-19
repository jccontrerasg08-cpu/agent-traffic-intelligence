# Arquitectura modular

| Documento | Propósito |
|---|---|
| [`modularization-evidence-ledger.md`](modularization-evidence-ledger.md) | Distingue requisitos confirmados, inferencias y rutas bloqueadas. |
| [`modular-boundaries.md`](modular-boundaries.md) | Define contratos, fachadas públicas y condiciones de entrada de cada módulo. |
| [`environment-matrix.md`](environment-matrix.md) | Describe perfiles locales, CI y servicio técnico, junto con sus restricciones. |
| [`../cases-and-variations.md`](../cases-and-variations.md) | Cataloga variaciones activas y propuestas, sus casos esperados y las pruebas que las cubren. |

La arquitectura conserva una distribución Python. Los paquetes nuevos expresan límites de responsabilidad; no despliegan componentes separados, no abren nuevas superficies de red y no activan rutas de investigación por defecto.
