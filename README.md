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

## Modos de escaneo en GitHub Actions

Los eventos `push` y `pull_request` ejecutan el modo `baseline`, que realiza un
escaneo pasivo sobre Juice Shop. Para lanzar manualmente un escaneo activo:

1. Abre **Actions > Automated Vulnerability & AI Triage Scan > Run workflow**.
2. Selecciona `active` en `scan_mode`.
3. Ejecuta el workflow únicamente contra una aplicación autorizada.

El modo activo usa [`zap/active-scan.conf`](zap/active-scan.conf) y está
limitado a SQL Injection, XSS reflejado/DOM y comprobaciones relacionadas con
tokens CSRF. La comprobación CSRF estándar de ZAP detecta principalmente la
ausencia de protección anti-CSRF; no sustituye una prueba completa de
explotación CSRF autenticada.

Los artefactos se publican bajo `artifacts/` y se separan por modo:

- `zap-baseline.json` y `verified-baseline.html`
- `zap-active.json` y `verified-active.html`

La política activa depende de los identificadores de reglas instalados en la
imagen de ZAP. Si se cambia la imagen o sus addons, hay que volver a validar
los IDs de [`zap/active-scan.conf`](zap/active-scan.conf).