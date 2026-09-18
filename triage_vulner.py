import json
import os
import argparse
from openai import OpenAI

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
