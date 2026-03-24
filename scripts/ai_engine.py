#!/usr/bin/env python3
"""
ai_engine.py – Motor de Evaluación Asistido por IA
Trabajo de Grado – Universidad del Valle 2026

Soporta: Groq (LLaMA 3.3 70B), OpenAI (GPT-4o-mini) y Anthropic (Claude Haiku)
"""

import json
import os
import argparse
from datetime import datetime
from typing import Optional

SYSTEM_PROMPT = """Eres un experto en seguridad de aplicaciones, DevSecOps y pentesting con más de 10 años de experiencia.
Tu especialidad es el análisis profundo de vulnerabilidades, su explotabilidad real y la identificación de cadenas de ataque.
Conoces a fondo OWASP Top 10, CVSS v3.1, CWE, el modelo STRIDE y el framework ATT&CK de MITRE.

Tu tarea es analizar hallazgos de seguridad de un pipeline automatizado (SAST, SCA, DAST, Pentesting)
y generar una evaluación estructurada, técnicamente profunda y accionable para apoyar la decisión de despliegue.

IMPORTANTE: Responde ÚNICAMENTE con el JSON especificado. Sin texto adicional, sin markdown, sin explicaciones fuera del JSON."""

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

## INSTRUCCIONES DE ANÁLISIS PROFUNDO

Realiza un análisis exhaustivo considerando:

1. **Explotabilidad real**: Para cada hallazgo crítico/alto evalúa si existe exploit público,
   si es explotable remotamente sin autenticación, y cuál sería el vector más probable.

2. **Cadenas de ataque (Attack Chains)**: Identifica combinaciones de vulnerabilidades que juntas
   permiten un ataque más devastador. Describe el escenario completo paso a paso.

3. **Análisis de falsos positivos**: Distingue entre vulnerabilidades reales del código vs
   dependencias desactualizadas vs configuraciones de laboratorio.

4. **Impacto de negocio**: Traduce el impacto técnico a términos de negocio: pérdida de datos,
   interrupción de servicio, daño reputacional, cumplimiento regulatorio.

5. **Cobertura**: Evalúa qué riesgos podrían estar sin cubrir dado el conjunto de herramientas usado.

6. **Priorización por riesgo real**: No solo por CVSS. Considera: explotabilidad + impacto + exposición + fix disponible.

## FORMATO DE RESPUESTA REQUERIDO (JSON estricto)

{{
  "decision": "PASS|FAIL|CONDITIONAL",
  "confidence": 0.0,
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "summary": "Resumen ejecutivo en 2-3 oraciones orientado a stakeholders no técnicos",
  "reasoning": "Explicación técnica detallada de la decisión (4-6 oraciones con referencias a CVEs específicos)",
  "key_findings": [
    {{
      "title": "Nombre del hallazgo",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "cvss_score": 0.0,
      "category": "Categoría OWASP",
      "cwe": "CWE-XXX",
      "exploitability": "alta|media|baja",
      "remote_exploitable": true,
      "auth_required": false,
      "public_exploit": true,
      "why_important": "Por qué es crítico para la decisión de despliegue",
      "business_impact": "Impacto específico en el negocio"
    }}
  ],
  "attack_chains": [
    {{
      "chain_id": "CHAIN-001",
      "title": "Nombre descriptivo de la cadena de ataque",
      "severity": "CRITICAL|HIGH",
      "finding_ids": ["id1", "id2"],
      "steps": [
        "Paso 1: El atacante explota CVE-XXXX para...",
        "Paso 2: Con acceso obtenido, usa GHSA-XXXX para...",
        "Paso 3: Resultado final: RCE / Data breach / etc"
      ],
      "likelihood": "alta|media|baja",
      "combined_impact": "Descripción del impacto combinado vs individual"
    }}
  ],
  "conditions": ["Condición 1 si es CONDITIONAL"],
  "remediation_priorities": [
    {{
      "priority": 1,
      "finding_id": "ID del hallazgo",
      "action": "Acción específica y concreta de remediación",
      "tool": "herramienta que lo detectó",
      "timeline": "inmediato|corto plazo|largo plazo",
      "effort": "bajo|medio|alto",
      "fix_available": true,
      "fix_version": "versión que corrige el problema o null"
    }}
  ],
  "coverage_analysis": {{
    "sast_coverage": "buena|parcial|ninguna",
    "sca_coverage": "buena|parcial|ninguna",
    "dast_coverage": "buena|parcial|ninguna",
    "pentest_coverage": "buena|parcial|ninguna",
    "overall_coverage": "Evaluación general de cobertura",
    "blind_spots": ["Riesgo potencial no cubierto 1", "Riesgo potencial no cubierto 2"]
  }},
  "false_positive_estimate": "alta|media|baja",
  "false_positive_reasoning": "Explicación del nivel estimado de falsos positivos",
  "owasp_top10_present": ["A06:2021 – Vulnerable and Outdated Components"],
  "risk_score": 0.0,
  "deploy_recommendation": "Recomendación específica y accionable para el equipo"
}}

CRITERIOS DE DECISIÓN:
- PASS: Sin hallazgos críticos/altos explotables remotamente
- CONDITIONAL: Hallazgos que requieren mitigación antes de producción pero no bloquean staging
- FAIL: Hallazgos críticos explotables remotamente o cadenas de ataque identificadas"""


def build_prompt(findings_data: dict, service: str, criticality: str, environment: str) -> str:
    summary = findings_data.get('summary', {})
    findings = findings_data.get('findings', [])
    tools = findings_data.get('tools_executed', {})

    critical_and_high = [
        f for f in findings
        if f.get('severity') in ['CRITICAL', 'HIGH']
    ][:15]

    simplified_findings = []
    for f in critical_and_high:
        simplified_findings.append({
            "id": f.get('id'),
            "tool": f.get('tool'),
            "tool_type": f.get('tool_type'),
            "severity": f.get('severity'),
            "title": f.get('title'),
            "category": f.get('category'),
            "cwe": f.get('cwe'),
            "cvss_score": f.get('cvss_score'),
            "description": f.get('description', '')[:300],
            "remediation": f.get('remediation', '')[:150],
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


def call_groq(prompt: str, system_prompt: str) -> Optional[dict]:
    try:
        from openai import OpenAI
        api_key = os.environ.get('GROQ_API_KEY')
        if not api_key:
            print("  ⚠️  GROQ_API_KEY no configurada")
            return None

        client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
        print("  → Llamando a Groq llama-3.3-70b-versatile...")

        combined_prompt = f"{system_prompt}\n\n{prompt}"
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": combined_prompt}],
            temperature=0.1,
            max_tokens=3000
        )

        content = response.choices[0].message.content.strip()
        if content.startswith("```json"): content = content[7:]
        if content.startswith("```"): content = content[3:]
        if content.endswith("```"): content = content[:-3]

        result = json.loads(content.strip())
        return {
            "provider": "groq",
            "model": "llama-3.3-70b-versatile",
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


def call_openai(prompt: str, system_prompt: str) -> Optional[dict]:
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
            temperature=0.1,
            max_tokens=3000,
            response_format={"type": "json_object"}
        )
        result = json.loads(response.choices[0].message.content)
        return {
            "provider": "openai", "model": "gpt-4o-mini",
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
    try:
        import anthropic
        api_key = os.environ.get('ANTHROPIC_API_KEY')
        if not api_key:
            print("  ⚠️  ANTHROPIC_API_KEY no configurada")
            return None

        client = anthropic.Anthropic(api_key=api_key)
        print("  → Llamando a Anthropic Claude Haiku...")
        message = client.messages.create(
            model="claude-haiku-4-5-20251001", max_tokens=3000,
            system=system_prompt + "\n\nResponde ÚNICAMENTE con JSON válido.",
            messages=[{"role": "user", "content": prompt}]
        )
        content = message.content[0].text.strip()
        if content.startswith('```json'): content = content[7:]
        if content.startswith('```'): content = content[3:]
        if content.endswith('```'): content = content[:-3]
        result = json.loads(content.strip())
        return {
            "provider": "anthropic", "model": "claude-haiku-4-5-20251001",
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


def fallback_evaluation(findings_data: dict) -> dict:
    print("  ⚠️  Usando evaluación de respaldo (sin IA)")
    summary = findings_data.get('summary', {})
    by_severity = summary.get('by_severity', {})
    critical = by_severity.get('CRITICAL', 0)
    high = by_severity.get('HIGH', 0)
    medium = by_severity.get('MEDIUM', 0)

    if critical > 0:
        decision, risk_level = "FAIL", "CRITICAL"
        reasoning = f"Se encontraron {critical} hallazgos críticos que representan riesgo inaceptable."
    elif high >= 5:
        decision, risk_level = "FAIL", "HIGH"
        reasoning = f"Se encontraron {high} hallazgos altos, superando el umbral de 5."
    elif high > 0 or medium >= 10:
        decision, risk_level = "CONDITIONAL", "MEDIUM"
        reasoning = f"Se encontraron {high} altos y {medium} medios que requieren atención."
    else:
        decision, risk_level = "PASS", "LOW"
        reasoning = "Sin hallazgos críticos o altos significativos."

    return {
        "provider": "fallback_static", "model": "threshold_rules_v1",
        "tokens_used": {"prompt": 0, "completion": 0, "total": 0},
        "evaluation": {
            "decision": decision, "confidence": 0.6, "risk_level": risk_level,
            "summary": f"Evaluación por umbrales estáticos: {decision}",
            "reasoning": reasoning, "key_findings": [], "attack_chains": [],
            "conditions": [], "remediation_priorities": [],
            "coverage_analysis": {
                "sast_coverage": "parcial", "sca_coverage": "parcial",
                "dast_coverage": "parcial", "pentest_coverage": "parcial",
                "overall_coverage": "Evaluación básica sin contexto IA", "blind_spots": []
            },
            "false_positive_estimate": "media",
            "false_positive_reasoning": "Sin análisis contextual disponible.",
            "owasp_top10_present": [], "risk_score": 0.0,
            "deploy_recommendation": "Revisar manualmente los hallazgos antes de proceder.",
            "_note": "Esta evaluación NO usa IA. Configura GROQ_API_KEY para evaluación completa."
        }
    }


def evaluate(findings_path: str, output_path: str, service: str,
             criticality: str, environment: str):
    print("\n" + "="*60)
    print("  MOTOR DE EVALUACIÓN IA – DevSecOps TG")
    print("="*60)

    with open(findings_path, 'r') as f:
        findings_data = json.load(f)

    total = findings_data.get('summary', {}).get('total', 0)
    print(f"  Hallazgos a evaluar: {total}")
    print(f"  Servicio: {service} | Criticidad: {criticality}")
    print()

    groq_key = os.environ.get('GROQ_API_KEY', '')
    openai_key = os.environ.get('OPENAI_API_KEY', '')
    print(f"  🔑 GROQ_API_KEY   : {'configurada ✅' if groq_key else 'NO configurada ❌'}")
    print(f"  🔑 OPENAI_API_KEY : {'configurada ✅' if openai_key else 'NO configurada ❌'}")
    print()

    prompt = build_prompt(findings_data, service, criticality, environment)
    print("🤖 Invocando evaluación IA:")

    ai_result = None
    if os.environ.get('GROQ_API_KEY'):
        ai_result = call_groq(prompt, SYSTEM_PROMPT)
    if not ai_result and os.environ.get('OPENAI_API_KEY'):
        ai_result = call_openai(prompt, SYSTEM_PROMPT)
    if not ai_result and os.environ.get('ANTHROPIC_API_KEY'):
        ai_result = call_anthropic(prompt, SYSTEM_PROMPT)
    if not ai_result:
        ai_result = fallback_evaluation(findings_data)

    output = {
        "schema_version": "2.0",
        "generated_at": datetime.now().isoformat(),
        "findings_analyzed": total,
        "service": service,
        "environment": environment,
        "business_criticality": criticality,
        "ai_provider": ai_result.get('provider'),
        "ai_model": ai_result.get('model'),
        "tokens_used": ai_result.get('tokens_used', {}),
        "evaluation": ai_result.get('evaluation', {}),
        "prompt_version": "2.0",
        "_academic_note": "Evaluación generada por LLM para demostración académica. Requiere validación humana."
    }

    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    evaluation = output.get('evaluation', {})
    attack_chains = evaluation.get('attack_chains', [])

    print()
    print("="*60)
    print("  RESULTADO DE EVALUACIÓN IA")
    print("="*60)
    print(f"  🚦 DECISIÓN      : {evaluation.get('decision', 'UNKNOWN')}")
    print(f"  📊 CONFIANZA     : {evaluation.get('confidence', 0):.0%}")
    print(f"  ⚠️  RIESGO        : {evaluation.get('risk_level', 'UNKNOWN')}")
    print(f"  🤖 MODELO        : {ai_result.get('model', 'N/A')}")
    print(f"  🔗 CADENAS ATAQUE: {len(attack_chains)} identificadas")
    print(f"  💬 RESUMEN       : {evaluation.get('summary', 'N/A')[:80]}...")
    print(f"\n  Guardado en: {output_path}")
    print("="*60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--findings', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--service', default='unknown')
    parser.add_argument('--criticality', default='medium')
    parser.add_argument('--environment', default='staging')
    args = parser.parse_args()
    evaluate(args.findings, args.output, args.service, args.criticality, args.environment)