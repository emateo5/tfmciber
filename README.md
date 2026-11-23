# Proyecto TFM
Automatización de la búsqueda de vulnerabilidades en una web (XSS, SQLi, CSRF, etc.)

## Requisitos

- Python 3.11 o posterior
- Las dependencias de Python de [`requirements.txt`](requirements.txt).
- Una clave `OPENAI_API_KEY` si se ejecuta el triaje con IA.
- Docker y una cuenta de GitHub con permisos para ejecutar Actions si se
  ejecuta el pipeline completo.

Instala la dependencia de Python con:

```bash
python -m pip install -r requirements.txt
```

## PoC experimental

El workflow de GitHub Actions ejecuta SAST y DAST sobre una instancia limpia de
OWASP Juice Shop. SAST usa Bandit y `pip-audit`; DAST usa OWASP ZAP. Los
eventos `push` y `pull_request` ejecutan el escenario `baseline` como control
operativo.

Para la ejecución manual
(`workflow_dispatch`) se puede seleccionar `stock`, `tuned` o
`tuned-ai` y proporcionar `target_url`. El escenario `tuned-ai` requieren además el secreto `OPENAI_API_KEY`; `tuned` y `tuned-ai`
pueden usar `TEST_USERNAME` y `TEST_PASSWORD` para habilitar el flujo
autenticado de Playwright.

Para ejecutar un escenario experimental manualmente:

1. Abre **Actions > Automatizacion de Escaneo de Vulnerabilidad & Triaje con IA > Run workflow**.
2. Selecciona `experiment_scenario`.
3. Ejecuta uno de estos escenarios:

| Escenario | Escaneo ZAP | Politica | Triaje IA |
| --- | --- | --- | --- |
| `stock` | Active Scan | Predeterminada de ZAP | No |
| `tuned` | Navegador Playwright + Active Scan | [`zap/active-scan.conf`](zap/active-scan.conf) | No |
| `tuned-ai` | Navegador Playwright + Active Scan | [`zap/active-scan.conf`](zap/active-scan.conf) | Si |

Los tres escenarios publican un artefacto `zap-experiment-<escenario>` con
`metadata.json`, los informes SAST y los resultados de ZAP disponibles. Los
escenarios `tuned` y `tuned-ai` guardan además `browser-workflow.json` y
`zap.log`; `stock` no ejecuta el descubrimiento con navegador.
El escenario `tuned-ai` genera también
`verified-<escenario>.html` cuando se ejecuta la etapa de IA. `stock` solo
genera los informes JSON/HTML bruto del escaneo y los resultados SAST; `tuned`
añade además los artefactos del descubrimiento y del Active Scan afinado.

Los archivos visibles en el artefacto de una ejecución `tuned-ai` pueden
incluir:

- `active-scanners.json`: escáneres habilitados por ZAP.
- `browser-workflow.json`: resultados de navegación, login, XSS, SQLi y CSRF.
- `challenges.json`: estado de los desafíos de Juice Shop utilizado como
  referencia externa.
- `chrome-*` y `chromedriver-*`: diagnósticos de Chromium, Chromedriver y su
  compatibilidad.
- `docker-containers.txt`, `zap-container-inspect.json` y
  `zap-image-inspect.json`: estado del entorno de contenedores.
- `metadata.json`: parámetros y resultados resumidos de la ejecución.
- `sast-bandit.json` y `sast-pip-audit.json`: informes SAST.
- `verified-tuned-ai.html`: reporte generado por el triaje de IA.
- `zap-tuned-ai.json` y `zap-tuned-ai.html`: informe bruto de ZAP en los dos
  formatos publicados.
- `zap.log`: registro consolidado del contenedor ZAP y sus eventos.

La comparación principal del TFM es `stock` frente a `tuned` frente a
`tuned-ai`. `tuned` y `tuned-ai` ejecutan exactamente la misma política; la
única diferencia es el postprocesamiento con IA. La IA ayuda a priorizar y
revisar falsos positivos, pero no sustituye el resultado bruto de ZAP.

La política afinada incluye SQL Injection y XSS reflejado/persistente.
DOM XSS se valida dinámicamente con Playwright/Chromium. 

La prueba reflejada diferencia respuesta servidor y ejecución cliente:
`responsePayloadReflected=false` con `payloadExecuted=true` se clasifica como
ejecución DOM, no como XSS reflejado. La prueba SQLi solo se marca como
confirmada si una consulta amplía los resultados o el login inyectado devuelve
un token; un HTTP 500 se conserva como indicio, no como explotación.

Los escenarios afinados ejecutan una comprobación dinámica de CSRF mediante
Playwright sobre el formulario de perfil de OWASP Juice Shop. Capturan el
nombre actual, envían `POST /profile` desde el origen externo
`http://htmledit.squarefree.com` utilizando las cookies de sesión existentes
y verifican si el nombre cambia. `artifacts/browser-workflow.json` registra
el origen, el estado HTTP, los nombres antes/después y si la prueba quedó
confirmada.

Una vulnerabilidad confirmada requiere que el cambio de nombre sea observable
desde el perfil autenticado después del envío externo. En ese caso
`csrfProven=true` y `csrfOutcome=vulnerable`. Los estados `failed`,
`indeterminate` y `skipped` no se interpretan como confirmación de protección.

Además de ZAP, los escenarios afinados ejecutan comprobaciones dinámicas de
XSS en Juice Shop: el payload oficial se usa en búsqueda para XSS reflejado,
en la ruta hash de búsqueda para DOM XSS y en una reseña persistente mediante
la API REST. Los resultados se publican como `reflectedXss`, `domXss` y
`persistentXss` en `browser-workflow.json`. DOM XSS no depende de la alerta
ZAP `40026`.

Los escenarios `tuned` y `tuned-ai` usan una imagen ZAP derivada con
Chromium/Chromedriver, además de un navegador Playwright a través del
proxy de ZAP para descubrir rutas y peticiones XHR generadas por JavaScript
antes del Active Scan. Esto mejora la cobertura de APIs de una SPA, aunque no
garantiza la cobertura completa
de estados autenticados, flujos de negocio ni endpoints que no sean accesibles
mediante la navegación automática. El `zap.log` se conserva como artefacto
para diagnosticar errores o ejecuciones incompletas. El Active Scan se limita
al origen de `target_url`; los recursos externos pueden aparecer como tráfico
del navegador, pero no se escanean activamente.

En los escenarios afinados, Playwright usa los secretos `TEST_USERNAME` y
`TEST_PASSWORD` para ejecutar un login de prueba, intenta añadir un producto al
carrito y ejecuta una prueba controlada de XSS reflejado. La modificación del
carrito demuestra cobertura de una acción autenticada, pero no constituye por
si sola una explotación CSRF. El workflow repite la petición de carrito desde
un contexto separado sin credenciales y guarda el resultado en
`artifacts/browser-workflow.json`: `csrfValidation=true` significa que la
petición no autenticada fue rechazada; `false` requiere investigar si la
prueba fue omitida o si la acción fue aceptada sin protección.

Los artefactos se publican con el escenario en el nombre, junto con
`metadata.json`, los resultados SAST y los informes JSON/HTML de ZAP. Para
comparar ejecuciones deben mantenerse constantes la versión de Juice Shop, la
imagen de ZAP, el commit y la URL objetivo.

La política activa depende de los identificadores de reglas instalados en la
imagen de ZAP. Si se cambia la imagen o sus addons, hay que volver a validar
los IDs de [`zap/active-scan.conf`](zap/active-scan.conf).

### Flujo de una ejecución

1. Se valida `target_url` y se ejecutan Bandit y `pip-audit`.
2. `baseline` usa el escaneo pasivo y `stock` el Active Scan predeterminado.
3. `tuned` y `tuned-ai` construyen la imagen de ZAP con Chromium,
   descubren rutas y peticiones SPA con Playwright y ejecutan el Active Scan
   configurado en [`zap/active-scan.conf`](zap/active-scan.conf).
4. `tuned-ai` procesa el JSON de ZAP con
   [`triage_vulner.py`](triage_vulner.py) y publica el HTML de triaje.
5. El workflow conserva los artefactos aunque una comprobación SAST o DAST
   encuentre hallazgos, para permitir su revisión posterior.

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

Para los escenarios `tuned` y `tuned-ai`, configura también los secretos
`TEST_USERNAME` y `TEST_PASSWORD` si quieres habilitar el flujo autenticado de
Playwright. Si faltan, el descubrimiento continúa, pero el login y las
comprobaciones que dependen del carrito se omiten. El navegador limita la
navegación al mismo origen de `target_url` y procesa como máximo 150 páginas
(`SPA_MAX_PAGES` permite cambiar ese límite).

## Uso

El script analiza un reporte JSON de OWASP ZAP y genera un reporte HTML autocontenido:

```bash
# Linux/macOS:
export OPENAI_API_KEY=tu_clave
# PowerShell:
# $env:OPENAI_API_KEY = "tu_clave"
python triage_vulner.py --report zap_report.json
```

Al ejecutar el script se genera `verified_alerts*.html` en el directorio actual.
Para indicar otra ruta:

```bash
python triage_vulner.py --report zap_report.json --output resultados/triage.html
```

El script no ejecuta ZAP ni realiza el escaneo: recibe un informe JSON ya
generado y envía cada alerta a `gpt-4o-mini` para obtener una valoración de
posible falso positivo. Si no se proporciona `OPENAI_API_KEY`, la ejecución no
puede completar el triaje.

El HTML incluye, para cada alerta, el veredicto (`confirmed_false_positive`,
`confirmed_vulnerability` o `inconclusive`), la confianza normalizada entre
0 y 100, el efecto dinámico observado, la evidencia disponible, la evidencia
que falta y la siguiente prueba recomendada. El resultado de la IA es una
ayuda para priorizar la revisión: no modifica ni sustituye el informe JSON
original de ZAP.