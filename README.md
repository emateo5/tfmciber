# tfmciber

## Uso

El script analiza un reporte JSON de OWASP ZAP y genera un reporte HTML autocontenido:

```bash
python triage_vulner.py --report zap_report.json
```

El resultado se guarda en `verified_alerts.html`. Para indicar otra ruta:

```bash
python triage_vulner.py --report zap_report.json --output resultados/triage.html
```

## PoC experimental

El workflow de GitHub Actions ejecuta SAST y DAST sobre una instancia limpia de
OWASP Juice Shop. SAST usa Bandit y `pip-audit`; DAST usa OWASP ZAP. Los
eventos `push` y `pull_request` ejecutan el escenario `baseline` como control
operativo.

Para ejecutar un escenario experimental manualmente:

1. Abre **Actions > Automatizacion de Escaneo de Vulnerabilidad & Triaje con IA > Run workflow**.
2. Selecciona `experiment_scenario`.
3. Ejecuta uno de estos escenarios:

| Escenario | Escaneo ZAP | Politica | Triaje IA |
| --- | --- | --- | --- |
| `stock` | Active Scan | Predeterminada de ZAP | No |
| `tuned` | Active Scan | [`zap/active-scan.conf`](zap/active-scan.conf) | No |
| `tuned-ai` | Active Scan | [`zap/active-scan.conf`](zap/active-scan.conf) | Si |
| `baseline` | Baseline pasivo | Predeterminada de ZAP | Si |

La comparación principal del TFM es `stock` frente a `tuned` frente a
`tuned-ai`. `tuned` y `tuned-ai` ejecutan exactamente la misma política; la
única diferencia es el postprocesamiento con IA. La IA ayuda a priorizar y
revisar falsos positivos, pero no sustituye el resultado bruto de ZAP.

La política afinada incluye SQL Injection, XSS reflejado/DOM y comprobaciones
relacionadas con tokens CSRF. La comprobación CSRF estándar de ZAP detecta
principalmente la ausencia de protección anti-CSRF; no sustituye una prueba
completa de explotación CSRF autenticada.

Los artefactos se publican con el escenario en el nombre, junto con
`metadata.json`, los resultados SAST y los informes JSON/HTML de ZAP. Para
comparar ejecuciones deben mantenerse constantes la versión de Juice Shop, la
imagen de ZAP, el commit y la URL objetivo.

La política activa depende de los identificadores de reglas instalados en la
imagen de ZAP. Si se cambia la imagen o sus addons, hay que volver a validar
los IDs de [`zap/active-scan.conf`](zap/active-scan.conf).

## Usar otra URL

El objetivo predeterminado es `http://localhost:3000`, donde el workflow inicia
una instancia local de Juice Shop. Para analizar otra aplicación autorizada,
ejecuta el workflow manualmente:

1. Abre **Actions > Automatizacion de Escaneo de Vulnerabilidad & Triaje con IA > Run workflow**.
2. Selecciona el escenario experimental.
3. Introduce la URL en `target_url`, por ejemplo `https://staging.ejemplo.com`.
4. Descarga el artefacto generado al finalizar.

Cuando se usa una URL diferente no se inicia Juice Shop; el workflow espera que
la aplicación ya esté disponible y ejecuta ZAP contra esa dirección. La URL
debe ser HTTP o HTTPS, no puede contener credenciales ni fragmentos, y el
workflow rechaza hosts privados o internos. Usa únicamente aplicaciones
propias o aquellas para las que tengas autorización explícita. No se recomienda
ejecutar escaneos activos contra producción.

Los eventos automáticos `push` y `pull_request` siguen utilizando siempre
Juice Shop local. La URL externa solo se puede seleccionar desde
`workflow_dispatch`.