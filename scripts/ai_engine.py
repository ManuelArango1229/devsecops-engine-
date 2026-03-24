#!/usr/bin/env python3
"""
ai_engine.py – Motor de Evaluación Asistido por IA
Trabajo de Grado – Universidad del Valle 2026

Propósito académico: Demostrar cómo un LLM puede analizar hallazgos
de seguridad normalizados y generar una evaluación contextual que
supere el análisis por umbrales estáticos.

Soporta: OpenAI (GPT-4o-mini) y Anthropic (Claude Haiku)
"""

import json
import os
import argparse
import time
from datetime import datetime
from typing import Optional


# ============================================================
# PROMPT DE EVALUACIÓN – Diseño académico documentado
# ============================================================

SYSTEM_PROMPT = """Eres un experto en seguridad de aplicaciones y DevSecOps.
Tu tarea es analizar hallazgos de seguridad de un pipeline automatizado
y generar una evaluación estructurada para apoyar la decisión de despliegue.

Debes seguir el framework OWASP Top 10 e ISO/IEC 27034 para contextualizar
los hallazgos y priorizar según impacto real en el entorno de staging.

IMPORTANTE: Responde ÚNICAMENTE con el JSON especificado, sin texto adicional."""

EVALUATION_PROMPT_TEMPLATE = """Analiza los siguientes hallazgos de seguridad de un pipeline DevSecOps:

## CONTEXTO DEL SERVICIO
- Servicio: {service_name}
- Criticidad de negocio: {business_criticality}
- Entorno: {environment}
- Pipeline ejecutado: {pipeline_run}
- Timestamp: {timestamp}

## RESUMEN DE HALLAZGOS
{summary_json}

## HALLAZGOS CRÍTICOS Y ALTOS (top {max_findings})
{critical_findings_json}

## DISTRIBUCIÓN POR HERRAMIENTA
{tools_json}

## INSTRUCCIONES DE EVALUACIÓN

Evalúa los hallazgos considerando:
1. Severidad real vs severidad reportada (considera falsos positivos comunes en staging)
2. Explotabilidad en el entorno actual (staging, no producción)
3. Cobertura de herramientas (¿están los 4 tipos de análisis representados?)
4. Patrones de riesgo (¿hay concentración en una categoría OWASP?)
5. Impacto potencial si se desplegara a producción

## FORMATO DE RESPUESTA REQUERIDO (JSON estricto)

{{
  "decision": "PASS|FAIL|CONDITIONAL",
  "confidence": 0.0,
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "summary": "Resumen ejecutivo en 2-3 oraciones",
  "reasoning": "Explicación técnica detallada de la decisión (3-5 oraciones)",
  "key_findings": [
    {{
      "title": "Nombre del hallazgo principal",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "category": "Categoría OWASP",
      "why_important": "Por qué es relevante para la decisión"
    }}
  ],
  "conditions": ["Condición 1 si es CONDITIONAL", "Condición 2"],
  "remediation_priorities": [
    {{
      "priority": 1,
      "action": "Acción de remediación",
      "tool": "herramienta que lo detectó",
      "timeline": "inmediato|corto plazo|largo plazo"
    }}
  ],
  "coverage_analysis": {{
    "sast_coverage": "buena|parcial|ninguna",
    "sca_coverage": "buena|parcial|ninguna",
    "dast_coverage": "buena|parcial|ninguna",
    "pentest_coverage": "buena|parcial|ninguna",
    "overall_coverage": "Evaluación general de cobertura"
  }},
  "false_positive_estimate": "alta|media|baja",
  "owasp_top10_present": ["A01:2021", "A03:2021"],
  "deploy_recommendation": "Recomendación específica de acción para el equipo"
}}

CRITERIOS DE DECISIÓN:
- PASS: Sin hallazgos críticos/altos explotables, o solo INFO/LOW
- CONDITIONAL: Hallazgos medios que requieren mitigación antes de producción
- FAIL: Hallazgos críticos o múltiples altos que indican riesgo inaceptable"""


def build_prompt(findings_data: dict, service: str, criticality: str, environment: str) -> str:
    """Construye el prompt con los datos del findings.json."""
    
    summary = findings_data.get('summary', {})
    findings = findings_data.get('findings', [])
    tools = findings_data.get('tools_executed', {})
    
    # Filtrar solo críticos y altos para el prompt (limitar tokens)
    critical_and_high = [
        f for f in findings 
        if f.get('severity') in ['CRITICAL', 'HIGH']
    ][:15]  # Máximo 15 para no exceder tokens
    
    # Simplificar los hallazgos para el prompt
    simplified_findings = []
    for f in critical_and_high:
        simplified_findings.append({
            "id": f.get('id'),
            "tool": f.get('tool'),
            "tool_type": f.get('tool_type'),
            "severity": f.get('severity'),
            "title": f.get('title'),
            "category": f.get('category'),
            "description": f.get('description', '')[:200],  # Truncar descripción
            "location": f.get('location', {})
        })
    
    return EVALUATION_PROMPT_TEMPLATE.format(
        service_name=service,
        business_criticality=criticality,
        environment=environment,
        pipeline_run=findings_data.get('pipeline_run', 'local'),
        timestamp=findings_data.get('generated_at', datetime.now().isoformat()),
        summary_json=json.dumps(summary, indent=2),
        critical_findings_json=json.dumps(simplified_findings, indent=2),
        max_findings=len(simplified_findings),
        tools_json=json.dumps(tools, indent=2)
    )


# ============================================================
# CLIENTES DE API
# ============================================================

def call_openai(prompt: str, system_prompt: str) -> Optional[dict]:
    """Llama a la API de OpenAI."""
    try:
        from openai import OpenAI
        
        api_key = os.environ.get('OPENAI_API_KEY')
        if not api_key:
            print("  ⚠️  OPENAI_API_KEY no configurada")
            return None
        
        client = OpenAI(api_key=api_key)
        
        print("  → Llamando a OpenAI GPT-4o-mini...")
        
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,  # Baja temperatura para respuestas más consistentes
            max_tokens=2000,
            response_format={"type": "json_object"}  # Forzar respuesta JSON
        )
        
        content = response.choices[0].message.content
        result = json.loads(content)
        
        return {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "tokens_used": {
                "prompt": response.usage.prompt_tokens,
                "completion": response.usage.completion_tokens,
                "total": response.usage.total_tokens
            },
            "evaluation": result
        }
        
    except Exception as e:
        print(f"  ❌ Error OpenAI: {e}")
        return None


def call_anthropic(prompt: str, system_prompt: str) -> Optional[dict]:
    """Llama a la API de Anthropic (Claude)."""
    try:
        import anthropic
        
        api_key = os.environ.get('ANTHROPIC_API_KEY')
        if not api_key:
            print("  ⚠️  ANTHROPIC_API_KEY no configurada")
            return None
        
        client = anthropic.Anthropic(api_key=api_key)
        
        print("  → Llamando a Anthropic Claude Haiku...")
        
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=2000,
            system=system_prompt + "\n\nResponde ÚNICAMENTE con JSON válido, sin markdown ni texto adicional.",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        content = message.content[0].text
        
        # Limpiar respuesta si tiene backticks
        content = content.strip()
        if content.startswith('```json'):
            content = content[7:]
        if content.startswith('```'):
            content = content[3:]
        if content.endswith('```'):
            content = content[:-3]
        
        result = json.loads(content.strip())
        
        return {
            "provider": "anthropic",
            "model": "claude-haiku-4-5-20251001",
            "tokens_used": {
                "prompt": message.usage.input_tokens,
                "completion": message.usage.output_tokens,
                "total": message.usage.input_tokens + message.usage.output_tokens
            },
            "evaluation": result
        }
        
    except Exception as e:
        print(f"  ❌ Error Anthropic: {e}")
        return None


def call_groq(prompt: str, system_prompt: str) -> Optional[dict]:
    """Llama a la API de Groq (compatible con OpenAI SDK)."""
    try:
        from openai import OpenAI
        
        api_key = os.environ.get('GROQ_API_KEY')
        if not api_key:
            print("  ⚠️  GROQ_API_KEY no configurada")
            return None
        
        client = OpenAI(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1"
        )
        
        print("  → Llamando a Groq deepseek-r1-distill-llama-70b...")
        
        response = client.chat.completions.create(
            model="deepseek-r1-distill-llama-70b",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=2000
        )
        
        content = response.choices[0].message.content.strip()
        
        # DeepSeek R1 incluye bloque <think>...</think>, hay que limpiarlo
        if "<think>" in content:
            content = content.split("</think>")[-1].strip()
        
        # Limpiar markdown fences si las hay
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        
        result = json.loads(content.strip())
        
        return {
            "provider": "groq",
            "model": "deepseek-r1-distill-llama-70b",
            "tokens_used": {
                "prompt": response.usage.prompt_tokens,
                "completion": response.usage.completion_tokens,
                "total": response.usage.total_tokens
            },
            "evaluation": result
        }
        
    except Exception as e:
        print(f"  ❌ Error Groq: {e}")
        return None

def fallback_evaluation(findings_data: dict) -> dict:
    """
    Evaluación de respaldo cuando no hay API disponible.
    Usa reglas estáticas básicas.
    NOTA: Este es el método TRADICIONAL que la IA debe superar.
    """
    print("  ⚠️  Usando evaluación de respaldo (sin IA)")
    
    summary = findings_data.get('summary', {})
    by_severity = summary.get('by_severity', {})
    
    critical = by_severity.get('CRITICAL', 0)
    high = by_severity.get('HIGH', 0)
    medium = by_severity.get('MEDIUM', 0)
    
    # Lógica simple de threshold
    if critical > 0:
        decision = "FAIL"
        risk_level = "CRITICAL"
        reasoning = f"Se encontraron {critical} hallazgos críticos que representan riesgo inaceptable."
    elif high >= 5:
        decision = "FAIL"
        risk_level = "HIGH"
        reasoning = f"Se encontraron {high} hallazgos altos, superando el umbral de 5."
    elif high > 0 or medium >= 10:
        decision = "CONDITIONAL"
        risk_level = "MEDIUM"
        reasoning = f"Se encontraron {high} altos y {medium} medios que requieren atención."
    else:
        decision = "PASS"
        risk_level = "LOW"
        reasoning = "Sin hallazgos críticos o altos significativos."
    
    return {
        "provider": "fallback_static",
        "model": "threshold_rules_v1",
        "tokens_used": {"prompt": 0, "completion": 0, "total": 0},
        "evaluation": {
            "decision": decision,
            "confidence": 0.6,
            "risk_level": risk_level,
            "summary": f"Evaluación por umbrales estáticos: {decision}",
            "reasoning": reasoning,
            "key_findings": [],
            "conditions": [],
            "remediation_priorities": [],
            "coverage_analysis": {
                "sast_coverage": "parcial",
                "sca_coverage": "parcial",
                "dast_coverage": "parcial",
                "pentest_coverage": "parcial",
                "overall_coverage": "Evaluación básica sin contexto IA"
            },
            "false_positive_estimate": "media",
            "owasp_top10_present": [],
            "deploy_recommendation": "Revisar manualmente los hallazgos antes de proceder.",
            "_note": "Esta evaluación NO usa IA. Configura OPENAI_API_KEY para evaluación completa."
        }
    }


# ============================================================
# FUNCIÓN PRINCIPAL
# ============================================================

def evaluate(findings_path: str, output_path: str, service: str, 
             criticality: str, environment: str):
    """Función principal de evaluación con IA."""
    
    print("\n" + "="*60)
    print("  MOTOR DE EVALUACIÓN IA – DevSecOps TG")
    print("="*60)
    
    # Cargar findings normalizados
    with open(findings_path, 'r') as f:
        findings_data = json.load(f)
    
    total = findings_data.get('summary', {}).get('total', 0)
    print(f"  Hallazgos a evaluar: {total}")
    print(f"  Servicio: {service} | Criticidad: {criticality}")
    print()
    
    # Construir prompt
    prompt = build_prompt(findings_data, service, criticality, environment)
    
    print("🤖 Invocando evaluación IA:")
    
    # Intentar APIs en orden de preferencia
    ai_result = None
    
    if os.environ.get('GROQ_API_KEY'):
        ai_result = call_groq(prompt, SYSTEM_PROMPT)

    if not ai_result and os.environ.get('OPENAI_API_KEY'):
        ai_result = call_openai(prompt, SYSTEM_PROMPT)

    if not ai_result and os.environ.get('ANTHROPIC_API_KEY'):
        ai_result = call_anthropic(prompt, SYSTEM_PROMPT)
    # Construir output completo
    output = {
        "schema_version": "1.0",
        "generated_at": datetime.now().isoformat(),
        "findings_analyzed": total,
        "service": service,
        "environment": environment,
        "business_criticality": criticality,
        "ai_provider": ai_result.get('provider'),
        "ai_model": ai_result.get('model'),
        "tokens_used": ai_result.get('tokens_used', {}),
        "evaluation": ai_result.get('evaluation', {}),
        "prompt_version": "1.0",
        "_academic_note": "Evaluación generada por LLM para demostración académica. Requiere validación humana."
    }
    
    # Guardar
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    # Mostrar resultado
    evaluation = output.get('evaluation', {})
    decision = evaluation.get('decision', 'UNKNOWN')
    confidence = evaluation.get('confidence', 0)
    risk_level = evaluation.get('risk_level', 'UNKNOWN')
    
    print()
    print("="*60)
    print("  RESULTADO DE EVALUACIÓN IA")
    print("="*60)
    print(f"  🚦 DECISIÓN   : {decision}")
    print(f"  📊 CONFIANZA  : {confidence:.0%}")
    print(f"  ⚠️  RIESGO     : {risk_level}")
    print(f"  🤖 MODELO     : {ai_result.get('model', 'N/A')}")
    print(f"  💬 RESUMEN    : {evaluation.get('summary', 'N/A')[:80]}...")
    print(f"\n  Guardado en: {output_path}")
    print("="*60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Motor de evaluación IA para hallazgos de seguridad'
    )
    parser.add_argument('--findings', required=True, help='Ruta a findings.json normalizado')
    parser.add_argument('--output', required=True, help='Ruta de salida para ai_evaluation.json')
    parser.add_argument('--service', default='unknown', help='Nombre del servicio')
    parser.add_argument('--criticality', default='medium', help='Criticidad del negocio')
    parser.add_argument('--environment', default='staging', help='Entorno de despliegue')
    
    args = parser.parse_args()
    
    evaluate(
        findings_path=args.findings,
        output_path=args.output,
        service=args.service,
        criticality=args.criticality,
        environment=args.environment
    )
