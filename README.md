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