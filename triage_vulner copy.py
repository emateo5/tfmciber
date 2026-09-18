import json
import os
import argparse
from html import escape
from openai import OpenAI


def _html_value(value):
        return escape(str(value or ""))


def generate_html_report(alerts, output_file):
        false_positives = sum(
                alert.get("ai_triage", {}).get("is_false_positive") is True
                for alert in alerts
        )
        high_risk = sum(
                str(alert.get("riskdesc", "")).lower().startswith("high")
                for alert in alerts
        )

        rows = []
        for alert in alerts:
                triage = alert.get("ai_triage", {})
                verdict = triage.get("is_false_positive")
                verdict_label = "Sí" if verdict is True else "No" if verdict is False else "Sin veredicto"
                verdict_class = "positive" if verdict is True else "negative" if verdict is False else "unknown"
                confidence = triage.get("confidence_score", "-")
                instances = alert.get("instances", [])
                instance_rows = "".join(
                        f"<li><strong>URI:</strong> {_html_value(instance.get('uri'))} "
                        f"<strong>Parámetro:</strong> {_html_value(instance.get('param'))} "
                        f"<strong>Evidencia:</strong> {_html_value(instance.get('evidence'))}</li>"
                        for instance in instances[:3]
                ) or "<li>No hay instancias disponibles.</li>"

                rows.append(f"""
                <article class="finding">
                    <div class="finding-header">
                        <div>
                            <span class="risk">{_html_value(alert.get('riskdesc', 'No clasificado'))}</span>
                            <h2>{_html_value(alert.get('alert', 'Desconocida'))}</h2>
                        </div>
                        <span class="verdict {verdict_class}">{verdict_label}</span>
                    </div>
                    <div class="meta"><span>Confianza: <strong>{_html_value(confidence)}%</strong></span>
                        <span>Instancias: <strong>{len(instances)}</strong></span></div>
                    <p>{_html_value(alert.get('desc', 'Sin descripción técnica'))}</p>
                    <details>
                        <summary>Ver evidencia detectada</summary>
                        <ul>{instance_rows}</ul>
                    </details>
                    <div class="justification"><strong>Justificación de IA:</strong>
                        {_html_value(triage.get('justification', 'No disponible'))}</div>
                </article>
                """)

        document = f"""<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Reporte de triaje OWASP ZAP</title>
    <style>
        :root {{ color-scheme: light; font-family: system-ui, sans-serif; color: #172033; background: #f4f6f8; }}
        body {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px; }}
        header {{ margin-bottom: 24px; }} h1 {{ margin-bottom: 6px; }}
        .summary {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 24px; }}
        .metric, .finding {{ background: white; border: 1px solid #dce2e8; border-radius: 8px; padding: 18px; box-shadow: 0 2px 8px #1720330d; }}
        .metric strong {{ display: block; font-size: 1.8rem; margin-top: 4px; }}
        .finding {{ margin-bottom: 16px; }} .finding-header {{ display: flex; justify-content: space-between; gap: 16px; align-items: start; }}
        h2 {{ margin: 8px 0; font-size: 1.2rem; }} .risk {{ color: #8b3a00; font-size: .8rem; font-weight: 700; text-transform: uppercase; }}
        .verdict {{ border-radius: 999px; padding: 6px 10px; font-weight: 700; white-space: nowrap; }}
        .positive {{ color: #146c43; background: #d9f5e5; }} .negative {{ color: #a61b1b; background: #ffe0e0; }} .unknown {{ color: #56606d; background: #edf0f2; }}
        .meta {{ display: flex; gap: 20px; color: #56606d; font-size: .9rem; }} p {{ line-height: 1.5; }}
        details {{ margin: 14px 0; }} summary {{ cursor: pointer; font-weight: 600; }} li {{ margin: 8px 0; overflow-wrap: anywhere; }}
        .justification {{ border-left: 3px solid #2b6cb0; padding: 10px 12px; background: #f1f6fb; line-height: 1.5; }}
        @media (max-width: 650px) {{ .summary {{ grid-template-columns: 1fr; }} .finding-header {{ flex-direction: column; }} }}
    </style>
</head>
<body>
    <header><h1>Reporte de triaje OWASP ZAP</h1><p>Evaluación automatizada de alertas con OpenAI.</p></header>
    <section class="summary" aria-label="Resumen">
        <div class="metric">Alertas analizadas<strong>{len(alerts)}</strong></div>
        <div class="metric">Posibles falsos positivos<strong>{false_positives}</strong></div>
        <div class="metric">Alertas de alto riesgo<strong>{high_risk}</strong></div>
    </section>
    <main>{''.join(rows) or '<p>No se encontraron alertas.</p>'}</main>
</body>
</html>
"""
        with open(output_file, "w", encoding="utf-8") as out_f:
                out_f.write(document)

def analyze_alerts(report_path):
    # Inicializa el cliente oficial de OpenAI leyendo la variable del entorno
    client = OpenAI()
    
    # Obtener la ruta absoluta para evitar conflictos de ejecución
    absolute_path = os.path.abspath(report_path)
    print(f"📂 Buscando el reporte de ZAP en: {absolute_path}")
    
    if not os.path.exists(absolute_path):
        print(f"❌ Error Crítico: No se encontró el archivo {absolute_path}")
        return

    with open(absolute_path, 'r', encoding='utf-8') as f:
        zap_data = json.load(f)

    # Validar estructura estándar de reportes de OWASP ZAP
    sites = zap_data.get('site', [])
    if not sites:
        print("ℹ️ El escaneo terminó sin registrar alertas o sitios válidos.")
        return

    # Si viene como lista o diccionario, extraemos las alertas acumuladas
    all_alerts = []
    if isinstance(sites, list):
        for site in sites:
            all_alerts.extend(site.get('alerts', []))
    elif isinstance(sites, dict):
        all_alerts = sites.get('alerts', [])

    print(f"🔍 Alertas encontradas por OWASP ZAP: {len(all_alerts)}")
    verified_alerts = []

    for alert in all_alerts:
        alert_name = alert.get('alert', 'Desconocida')
        risk_desc = alert.get('riskdesc', 'No clasificado')
        desc = alert.get('desc', 'Sin descripción técnica')
        
        # Reducir instancias para no saturar el límite de tokens de contexto de la IA
        instances = alert.get('instances', [])
        sample_instances = [{"uri": i.get('uri'), "param": i.get('param'), "evidence": i.get('evidence')} for i in instances[:3]]

        # PROMPT MAESTRO CONSOLIDADO
        prompt = f"""
        Actúa como un experto senior en seguridad de aplicaciones web (Pentester / Ingeniero DevSecOps). 
        Tu tarea es auditar una alerta de seguridad generada por el escáner dinámico OWASP ZAP y dictaminar si existe una alta probabilidad de que sea un FALSO POSITIVO.

        Analiza cuidadosamente los datos del escaneo que se te proporcionan a continuación:

        =========================================
        DATOS DE LA ALERTA DE OWASP ZAP
        =========================================
        Vulnerabilidad: {alert_name}
        Nivel de Riesgo Técnico: {risk_desc}

        [Descripción Teórica del Fallo]:
        {desc}

        [Evidencia e Instancias Detectadas]:
        {json.dumps(sample_instances, indent=2)}
        =========================================

        Criterios de evaluación:
        1. Evalúa si el payload utilizado en la evidencia realmente representa una amenaza para una aplicación moderna o si el comportamiento del servidor web pudo haber confundido al escáner automatizado.
        2. Analiza el endpoint (URI) y el parámetro afectado. ¿Tiene sentido lógico que ocurra este tipo de vulnerabilidad ahí?
        3. Si la evidencia contiene códigos de estado HTTP comunes o payloads genéricos que no ejecutaron código real, aumenta la sospecha de Falso Positivo.

        Debes responder ESTRICTAMENTE con un objeto JSON válido. No agregues introducciones, saludos ni bloques de código de marcado (como ```json). Sigue rigurosamente esta estructura:

        {{
          "vulnerability": "{alert_name}",
          "is_false_positive": true/false,
          "confidence_score": 85,
          "justification": "Explicación técnica, concisa y clara basada en la evidencia proporcionada."
        }}
        """

        try:
            print(f"🤖 Procesando triaje de IA para: [{alert_name}]...")
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "Eres un asistente de seguridad automatizado de caja negra. Tu salida debe ser única y exclusivamente un string JSON válido."},
                    {"role": "user", "content": prompt}
                ],
                response_format={ "type": "json_object" }
            )
            
            # SOLUCIÓN EXPLICITA: Acceder de forma segura al objeto de la versión moderna de OpenAI
            ai_response_text = response.choices[0].message.content
            
            # Convertir la respuesta de texto estructurado de la IA a formato JSON nativo de Python
            ai_decision = json.loads(ai_response_text)
            print(f"   ↳ Veredicto -> ¿Falso Positivo?: {ai_decision.get('is_false_positive')} | Certeza: {ai_decision.get('confidence_score')}%")
            
            # Combinamos la alerta original con el análisis de la IA
            alert["ai_triage"] = ai_decision
            verified_alerts.append(alert)

        except Exception as e:
            print(f"⚠️ Error al conectar o procesar con OpenAI para la alerta {alert_name}: {e}")

    # Exportar el reporte auditado listo para su consumo
    output_file = "verified_alerts.json"
    with open(output_file, 'w', encoding='utf-8') as out_f:
        json.dump(verified_alerts, out_f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 ¡Triaje completado con éxito! El reporte consolidado se guardó en: {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Triage Tool para OWASP ZAP")
    parser.add_argument("--report", required=True, help="Nombre o ruta del archivo JSON de ZAP")
    args = parser.parse_args()
    
    analyze_alerts(args.report)
