import json
import os
import argparse
from html import escape
from openai import OpenAI


def _html_value(value):
    return escape(str("" if value is None else value))


def generate_html_report(alerts, output_file):
        verdict_counts = {
                "confirmed_false_positive": 0,
                "confirmed_vulnerability": 0,
                "inconclusive": 0,
        }
        for alert in alerts:
                verdict = alert.get("ai_triage", {}).get("verdict")
                if verdict in verdict_counts:
                        verdict_counts[verdict] += 1
        rows = []
        for alert in alerts:
                triage = alert.get("ai_triage", {})
                verdict = triage.get("verdict", "inconclusive")
                verdict_labels = {
                        "confirmed_false_positive": "Falso positivo confirmado",
                        "confirmed_vulnerability": "Vulnerabilidad confirmada",
                        "inconclusive": "No concluyente",
                }
                verdict_label = verdict_labels.get(verdict, "No concluyente")
                verdict_class = (
                        "positive" if verdict == "confirmed_false_positive"
                        else "negative" if verdict == "confirmed_vulnerability"
                        else "unknown"
                )
                confidence = triage.get("confidence_score", "-")
                instances = alert.get("instances", [])
                supporting_evidence = triage.get("supporting_evidence", [])
                missing_evidence = triage.get("missing_evidence", [])
                recommended_test = triage.get("recommended_test", "No disponible")
                dynamic_effect = triage.get("dynamic_effect_observed")
                supporting_text = "".join(
                        f"<li>{_html_value(item)}</li>" for item in supporting_evidence
                ) or "<li>No se indicó evidencia de soporte.</li>"
                missing_text = "".join(
                        f"<li>{_html_value(item)}</li>" for item in missing_evidence
                ) or "<li>No se indicó evidencia ausente.</li>"
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
                        <span>Instancias: <strong>{len(instances)}</strong></span>
                        <span>Efecto dinámico: <strong>{'Sí' if dynamic_effect is True else 'No' if dynamic_effect is False else 'No indicado'}</strong></span></div>
                    <p>{_html_value(alert.get('desc', 'Sin descripción técnica'))}</p>
                    <details>
                        <summary>Ver evidencia detectada</summary>
                        <ul>{instance_rows}</ul>
                    </details>
                    <div class="justification"><strong>Evidencia de soporte:</strong><ul>{supporting_text}</ul></div>
                    <div class="justification"><strong>Evidencia faltante:</strong><ul>{missing_text}</ul></div>
                    <div class="justification"><strong>Prueba recomendada:</strong> {_html_value(recommended_test)}</div>
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
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
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
        <div class="metric">Falsos positivos confirmados<strong>{verdict_counts["confirmed_false_positive"]}</strong></div>
        <div class="metric">Vulnerabilidades confirmadas<strong>{verdict_counts["confirmed_vulnerability"]}</strong></div>
        <div class="metric">No concluyente<strong>{verdict_counts["inconclusive"]}</strong></div>
    </section>
    <main>{''.join(rows) or '<p>No se encontraron alertas.</p>'}</main>
</body>
</html>
"""
        with open(output_file, "w", encoding="utf-8") as out_f:
                out_f.write(document)

def analyze_alerts(report_path, output_file):
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
        Actúa como experto senior en seguridad de aplicaciones web.
        Audita la alerta OWASP ZAP y asigna exactamente uno de estos estados:
        - confirmed_false_positive
        - confirmed_vulnerability
        - inconclusive

        No declares vulnerabilidad confirmada por un HTTP 500, un payload
genérico o la ausencia de una protección aislada. No declares falso positivo
confirmado si falta evidencia dinámica. Si no hay pruebas suficientes,
usa inconclusive.

        Analiza los datos siguientes:

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
        1. Prioriza efecto observable sobre evidencia teórica.
        2. Una reflexión o ejecución real debe identificar qué ocurrió.
        3. Un 500, payload genérico o modificación de cabecera no confirma explotación.
        4. La ausencia de evidencia debe producir inconclusive.

        Responde estrictamente con este JSON:

        {{
          "vulnerability": "{alert_name}",
          "verdict": "confirmed_false_positive|confirmed_vulnerability|inconclusive",
          "confidence_score": 0,
          "dynamic_effect_observed": true/false,
          "supporting_evidence": ["Evidencia concreta"],
          "missing_evidence": ["Evidencia necesaria"],
          "recommended_test": "Siguiente prueba segura",
          "justification": "Explicación técnica basada únicamente en los datos"
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
            allowed_verdicts = {
                "confirmed_false_positive",
                "confirmed_vulnerability",
                "inconclusive",
            }
            if ai_decision.get("verdict") not in allowed_verdicts:
                ai_decision["verdict"] = "inconclusive"
            confidence = ai_decision.get("confidence_score", 0)
            try:
                confidence = max(0, min(100, int(confidence)))
            except (TypeError, ValueError):
                confidence = 0
            ai_decision["confidence_score"] = confidence
            print(
                f"   ↳ Veredicto: {ai_decision.get('verdict')} "
                f"| Certeza: {ai_decision.get('confidence_score')}%"
            )
            
            # Combinamos la alerta original con el análisis de la IA
            alert["ai_triage"] = ai_decision
            verified_alerts.append(alert)

        except Exception as e:
            print(f"⚠️ Error al conectar o procesar con OpenAI para la alerta {alert_name}: {e}")

    # Exportar el reporte auditado como HTML autocontenido
    generate_html_report(verified_alerts, output_file)
    
    print(f"\n💾 ¡Triaje completado con éxito! El reporte consolidado se guardó en: {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Triage Tool para OWASP ZAP")
    parser.add_argument("--report", required=True, help="Nombre o ruta del archivo JSON de ZAP")
    parser.add_argument(
        "--output",
        default="verified_alerts.html",
        help="Ruta del reporte HTML de salida (por defecto: verified_alerts.html)",
    )
    args = parser.parse_args()
    
    analyze_alerts(args.report, args.output)
