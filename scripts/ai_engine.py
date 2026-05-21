#!/usr/bin/env python3
"""
ai_engine.py – Motor de Evaluación Híbrida IA + SSVC/EPSS/KEV
Trabajo de Grado – Universidad del Valle 2026

Soporta: Groq (LLaMA 3.3 70B), OpenAI (GPT-4o-mini) y Anthropic (Claude Haiku)

Innovación académica:
  Integra datos empíricos SSVC + EPSS + CISA KEV como contexto enriquecido
  para el LLM, siguiendo la metodología de Al Haddad et al. (2025):
  "Prompting the Priorities: A First Look at Evaluating LLMs for
   Vulnerability Triage and Prioritization" (arXiv 2510.18508).
"""

import json
import os
import argparse
from datetime import datetime
from typing import Optional

# ── Importación opcional del gate SSVC ───────────────────────────────────────
try:
    from ssvc_gate import ssvc_gate as _ssvc_gate, fetch_cisa_kev, fetch_epss_scores
    SSVC_AVAILABLE = True
except ImportError:
    SSVC_AVAILABLE = False

SYSTEM_PROMPT = """Eres un experto en seguridad de aplicaciones, DevSecOps y pentesting
con más de 10 años de experiencia. Tu especialidad es el análisis profundo de
vulnerabilidades, su explotabilidad real y la identificación de cadenas de ataque.
Conoces a fondo OWASP Top 10, CVSS v3.1, CWE, el modelo STRIDE, el framework
ATT&CK de MITRE y el estándar SSVC (Stakeholder-Specific Vulnerability
Categorization) de CISA/SEI-CERT.

Tu tarea es analizar hallazgos de seguridad de un pipeline automatizado
(SAST, SCA, DAST, Pentesting) y generar una evaluación estructurada,
técnicamente profunda y accionable para apoyar la decisión de despliegue.

CONTEXTO SSVC/EPSS/KEV DISPONIBLE:
Cada hallazgo puede incluir clasificación SSVC preliminar con datos empíricos
de explotabilidad (EPSS de FIRST.org y CISA Known Exploited Vulnerabilities).
Usa estos datos como evidencia adicional, pero aplica tu razonamiento contextual
para VALIDAR o CORREGIR la clasificación según el sistema específico evaluado:
  - Si SSVC = Act pero EPSS < 0.10 y no está en KEV: probablemente sobreestimación
    por heurísticas CWE. Justifica si la clasificación es apropiada.
  - Si SSVC = Track pero la vulnerabilidad es explotable en el contexto de la app:
    considera escalar la prioridad con tu análisis contextual.
Esta validación cruzada IA↔SSVC es el aporte diferencial del gate híbrido.

IMPORTANTE: Responde ÚNICAMENTE con el JSON especificado. Sin texto adicional."""

EVALUATION_PROMPT_TEMPLATE = """Analiza los siguientes hallazgos de seguridad de un pipeline DevSecOps:

## CONTEXTO DEL SERVICIO
- Servicio: {service_name}
- Criticidad de negocio: {business_criticality}
- Entorno: {environment}
- Pipeline ejecutado: {pipeline_run}
- Timestamp: {timestamp}
- Gate SSVC/EPSS/KEV activo: {ssvc_active}

## RESUMEN DE HALLAZGOS
{summary_json}

## CONTEXTO DE EXPLOTABILIDAD EMPÍRICA (SSVC + EPSS + CISA KEV)
{ssvc_context_block}

## HALLAZGOS CRÍTICOS Y ALTOS ENRIQUECIDOS (top {max_findings})
{critical_findings_json}

## DISTRIBUCIÓN POR HERRAMIENTA
{tools_json}

## INSTRUCCIONES DE ANÁLISIS PROFUNDO

Realiza un análisis exhaustivo considerando:

1. **Validación cruzada SSVC**: Para hallazgos con clasificación SSVC Act, valida si
   el EPSS y KEV confirman la explotación activa. Si EPSS < 0.1 y no hay KEV, indica
   si es sobreestimación por heurísticas CWE vs riesgo real en este contexto.

2. **Explotabilidad real**: Para cada hallazgo crítico/alto evalúa si existe exploit
   público, si es explotable remotamente sin autenticación, y el vector más probable.

3. **Cadenas de ataque**: Identifica combinaciones de vulnerabilidades que juntas
   permiten un ataque más devastador. Describe el escenario completo paso a paso.

4. **Análisis de falsos positivos**: Distingue vulnerabilidades reales vs dependencias
   desactualizadas vs configuraciones de laboratorio. Usa EPSS como señal empírica.

5. **Impacto de negocio**: Traduce el impacto técnico a términos de negocio.

6. **Priorización por riesgo real**: No solo por CVSS. Considera: EPSS + KEV + impacto
   + exposición + fix disponible.

## FORMATO DE RESPUESTA REQUERIDO (JSON estricto)

{{
  "decision": "PASS|FAIL|CONDITIONAL",
  "confidence": 0.0,
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "summary": "Resumen ejecutivo en 2-3 oraciones orientado a stakeholders no técnicos",
  "reasoning": "Explicación técnica detallada (4-6 oraciones con referencias a CVEs)",
  "ssvc_validation": [
    {{
      "finding_id": "ID del hallazgo",
      "title": "Título del hallazgo",
      "ssvc_preliminary": "Act|Attend|Track*|Track",
      "epss_score": 0.0,
      "in_kev": false,
      "ai_assessment": "confirmed|overestimated|underestimated|not_applicable",
      "reasoning": "Por qué el LLM acuerda o difiere de la clasificación SSVC"
    }}
  ],
  "ssvc_context_used": true,
  "key_findings": [
    {{
      "title": "Nombre del hallazgo",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "cvss_score": 0.0,
      "category": "Categoría OWASP",
      "cwe": "CWE-XXX",
      "exploitability": "alta|media|baja",
      "epss_informed": true,
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
    "blind_spots": ["Riesgo potencial no cubierto 1"]
  }},
  "false_positive_estimate": "alta|media|baja",
  "false_positive_reasoning": "Explicación del nivel estimado de falsos positivos",
  "owasp_top10_present": ["A06:2021 – Vulnerable and Outdated Components"],
  "risk_score": 0.0,
  "deploy_recommendation": "Recomendación específica y accionable para el equipo"
}}

CRITERIOS DE DECISIÓN:
- PASS: Sin hallazgos críticos/altos explotables remotamente (confirmado por EPSS/KEV)
- CONDITIONAL: Hallazgos que requieren mitigación pero no bloquean staging
- FAIL: Hallazgos críticos explotables remotamente o cadenas de ataque identificadas"""


def _build_ssvc_context_block(ssvc_data: Optional[dict]) -> str:
    """
    Construye el bloque de contexto SSVC/EPSS/KEV para el prompt.
    Si no hay datos SSVC, devuelve un bloque vacío.
    """
    if not ssvc_data:
        return "No disponible (ssvc_gate no ejecutado).\n"

    ac       = ssvc_data.get("action_counts", {})
    ds       = ssvc_data.get("data_sources", {})
    f1m      = ssvc_data.get("f1_metrics", {})
    all_cf   = ssvc_data.get("all_classified_findings", [])

    # Resumen de distribución SSVC
    total_cf = sum(ac.values()) if ac else 0
    lines = [
        f"Distribución SSVC: Act={ac.get('Act',0)}, Attend={ac.get('Attend',0)}, "
        f"Track*={ac.get('Track*',0)}, Track={ac.get('Track',0)} "
        f"(total clasificados: {total_cf})",
        f"CISA KEV: {ds.get('cisa_kev_entries',0):,} entradas consultadas | "
        f"EPSS: {ds.get('epss_scores_fetched',0)} CVEs consultados",
    ]
    if f1m.get("cves_evaluated", 0) > 0:
        lines.append(
            f"F1 Exploitation (ground truth KEV+EPSS): "
            f"{f1m.get('f1_score',0):.3f} "
            f"(P={f1m.get('precision',0):.3f}, R={f1m.get('recall',0):.3f}, "
            f"n={f1m.get('cves_evaluated',0)})"
        )
    lines.append("")

    # Top 15 hallazgos con contexto SSVC (priorizando Act y Attend)
    priority_order = {"Act": 0, "Attend": 1, "Track*": 2, "Track": 3}
    sorted_cf = sorted(all_cf,
                       key=lambda x: priority_order.get(x.get("ssvc_action","Track"), 3))

    lines.append("Hallazgos con mayor prioridad SSVC:")
    for rec in sorted_cf[:15]:
        epss  = rec.get("epss_score", 0.0)
        kev   = "KEV:Sí" if rec.get("in_kev") else "KEV:No"
        action= rec.get("ssvc_action", "?")
        cve   = rec.get("cve_id", "sin-CVE")
        expl  = rec.get("exploitation", "?")
        auto  = rec.get("automatable", "?")
        impact= rec.get("tech_impact", "?")
        title = rec.get("title", "")[:55]
        lines.append(
            f"  [{action:6}] [{rec.get('severity','?'):8}] {title}...\n"
            f"           CVE:{cve} | EPSS:{epss:.3f} | {kev} | "
            f"expl={expl} auto={auto} impact={impact}"
        )

    return "\n".join(lines)


def build_prompt(findings_data: dict, service: str, criticality: str,
                 environment: str, ssvc_data: Optional[dict] = None) -> str:
    summary  = findings_data.get('summary', {})
    findings = findings_data.get('findings', [])
    tools    = findings_data.get('tools_executed', {})

    # Lookup SSVC por finding_id
    ssvc_lookup = {}
    if ssvc_data:
        for rec in ssvc_data.get("all_classified_findings", []):
            ssvc_lookup[rec.get("finding_id", "")] = rec

    critical_and_high = [
        f for f in findings
        if f.get('severity') in ['CRITICAL', 'HIGH']
    ][:15]

    simplified_findings = []
    for f in critical_and_high:
        fid  = f.get('id', '')
        ssvc = ssvc_lookup.get(fid, {})
        entry = {
            "id":          fid,
            "tool":        f.get('tool'),
            "tool_type":   f.get('tool_type'),
            "severity":    f.get('severity'),
            "title":       f.get('title'),
            "category":    f.get('category'),
            "cwe":         f.get('cwe'),
            "cvss_score":  f.get('cvss_score'),
            "description": f.get('description', '')[:300],
            "remediation": f.get('remediation', '')[:150],
            "location":    f.get('location', {}),
        }
        # Enriquecer con SSVC si disponible
        if ssvc:
            entry["ssvc_preliminary"] = {
                "action":      ssvc.get("ssvc_action"),
                "exploitation":ssvc.get("exploitation"),
                "automatable": ssvc.get("automatable"),
                "tech_impact": ssvc.get("tech_impact"),
                "epss_score":  ssvc.get("epss_score"),
                "in_kev":      ssvc.get("in_kev"),
                "cve_id":      ssvc.get("cve_id"),
            }
        simplified_findings.append(entry)

    ssvc_context = _build_ssvc_context_block(ssvc_data)
    ssvc_active  = "Sí (EPSS + CISA KEV integrados)" if ssvc_data else "No"

    return EVALUATION_PROMPT_TEMPLATE.format(
        service_name=service,
        business_criticality=criticality,
        environment=environment,
        pipeline_run=findings_data.get('pipeline_run', 'local'),
        timestamp=findings_data.get('generated_at', datetime.now().isoformat()),
        summary_json=json.dumps(summary, indent=2),
        ssvc_context_block=ssvc_context,
        critical_findings_json=json.dumps(simplified_findings, indent=2),
        max_findings=len(simplified_findings),
        tools_json=json.dumps(tools, indent=2),
        ssvc_active=ssvc_active,
    )


def call_groq(prompt: str, system_prompt: str) -> Optional[dict]:
    try:
        from openai import OpenAI
        api_key = os.environ.get('GROQ_API_KEY')
        if not api_key:
            print("  ⚠️  GROQ_API_KEY no configurada")
            return None
        client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
        print("  → Llamando a Groq llama-3.3-70b-versatile (con contexto SSVC/EPSS/KEV)...")
        combined_prompt = f"{system_prompt}\n\n{prompt}"
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": combined_prompt}],
            temperature=0.1,
            max_tokens=4000,
        )
        content = response.choices[0].message.content.strip()
        for prefix in ("```json", "```"):
            if content.startswith(prefix): content = content[len(prefix):]
        if content.endswith("```"): content = content[:-3]
        result = json.loads(content.strip())
        return {
            "provider": "groq", "model": "llama-3.3-70b-versatile",
            "tokens_used": {
                "prompt":     response.usage.prompt_tokens,
                "completion": response.usage.completion_tokens,
                "total":      response.usage.total_tokens,
            },
            "evaluation": result,
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
        print("  → Llamando a OpenAI GPT-4o-mini (con contexto SSVC/EPSS/KEV)...")
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": prompt},
            ],
            temperature=0.1, max_tokens=4000,
            response_format={"type": "json_object"},
        )
        result = json.loads(response.choices[0].message.content)
        return {
            "provider": "openai", "model": "gpt-4o-mini",
            "tokens_used": {
                "prompt":     response.usage.prompt_tokens,
                "completion": response.usage.completion_tokens,
                "total":      response.usage.total_tokens,
            },
            "evaluation": result,
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
        print("  → Llamando a Anthropic Claude Haiku (con contexto SSVC/EPSS/KEV)...")
        message = client.messages.create(
            model="claude-haiku-4-5-20251001", max_tokens=4000,
            system=system_prompt + "\n\nResponde ÚNICAMENTE con JSON válido.",
            messages=[{"role": "user", "content": prompt}],
        )
        content = message.content[0].text.strip()
        for prefix in ("```json", "```"):
            if content.startswith(prefix): content = content[len(prefix):]
        if content.endswith("```"): content = content[:-3]
        result = json.loads(content.strip())
        return {
            "provider": "anthropic", "model": "claude-haiku-4-5-20251001",
            "tokens_used": {
                "prompt":     message.usage.input_tokens,
                "completion": message.usage.output_tokens,
                "total":      message.usage.input_tokens + message.usage.output_tokens,
            },
            "evaluation": result,
        }
    except Exception as e:
        print(f"  ❌ Error Anthropic: {e}")
        return None


def fallback_evaluation(findings_data: dict) -> dict:
    print("  ⚠️  Usando evaluación de respaldo (sin IA)")
    summary  = findings_data.get('summary', {})
    by_sev   = summary.get('by_severity', {})
    critical = by_sev.get('CRITICAL', 0)
    high     = by_sev.get('HIGH', 0)
    medium   = by_sev.get('MEDIUM', 0)

    if critical > 0:
        decision, risk_level = "FAIL", "CRITICAL"
        reasoning = f"Se encontraron {critical} hallazgos críticos."
    elif high >= 5:
        decision, risk_level = "FAIL", "HIGH"
        reasoning = f"Se encontraron {high} hallazgos altos, superando el umbral de 5."
    elif high > 0 or medium >= 10:
        decision, risk_level = "CONDITIONAL", "MEDIUM"
        reasoning = f"Se encontraron {high} altos y {medium} medios."
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
            "ssvc_validation": [], "ssvc_context_used": False,
            "conditions": [], "remediation_priorities": [],
            "coverage_analysis": {
                "sast_coverage": "parcial", "sca_coverage": "parcial",
                "dast_coverage": "parcial", "pentest_coverage": "parcial",
                "overall_coverage": "Evaluación básica sin contexto IA",
                "blind_spots": [],
            },
            "false_positive_estimate": "media",
            "false_positive_reasoning": "Sin análisis contextual disponible.",
            "owasp_top10_present": [], "risk_score": 0.0,
            "deploy_recommendation": "Revisar manualmente antes de proceder.",
            "_note": "Esta evaluación NO usa IA. Configura GROQ_API_KEY.",
        },
    }


def evaluate(findings_path: str, output_path: str, service: str,
             criticality: str, environment: str):
    print("\n" + "="*65)
    print("  MOTOR DE EVALUACIÓN HÍBRIDA IA + SSVC/EPSS/KEV – DevSecOps TG")
    print("  Al Haddad et al. (2025) – arXiv 2510.18508")
    print("="*65)

    with open(findings_path, 'r') as f:
        findings_data = json.load(f)

    total    = findings_data.get('summary', {}).get('total', 0)
    crit_val = (findings_data.get('business_criticality')
                or os.environ.get('CRITICALITY', criticality))
    print(f"  Hallazgos: {total} | Servicio: {service} | Criticidad: {crit_val}")

    # ── Paso 1: Enriquecimiento SSVC/EPSS/KEV ─────────────────────────────────
    ssvc_data = None
    if SSVC_AVAILABLE:
        print("\n🔬 Ejecutando SSVC+EPSS+KEV para enriquecer el prompt IA...")
        try:
            ssvc_data = _ssvc_gate(findings_data, crit_val)
            ac = ssvc_data.get("action_counts", {})
            print(f"  SSVC enriquecido: Act={ac.get('Act',0)} "
                  f"Attend={ac.get('Attend',0)} "
                  f"Track*={ac.get('Track*',0)} Track={ac.get('Track',0)}")
        except Exception as e:
            print(f"  ⚠️  SSVC falló ({e}). Evaluación IA sin enriquecimiento.")
    else:
        print("  ⚠️  ssvc_gate.py no disponible. Evaluación sin enriquecimiento SSVC.")

    # ── Paso 2: Construir prompt enriquecido ──────────────────────────────────
    prompt = build_prompt(findings_data, service, crit_val, environment, ssvc_data)

    # ── Paso 3: Llamar al LLM ─────────────────────────────────────────────────
    groq_key   = os.environ.get('GROQ_API_KEY', '')
    openai_key = os.environ.get('OPENAI_API_KEY', '')
    print(f"\n  GROQ_API_KEY   : {'✅' if groq_key else '❌'}")
    print(f"  OPENAI_API_KEY : {'✅' if openai_key else '❌'}")
    print("\n🤖 Invocando LLM con contexto SSVC/EPSS/KEV:")

    ai_result = None
    if groq_key:
        ai_result = call_groq(prompt, SYSTEM_PROMPT)
    if not ai_result and openai_key:
        ai_result = call_openai(prompt, SYSTEM_PROMPT)
    if not ai_result and os.environ.get('ANTHROPIC_API_KEY'):
        ai_result = call_anthropic(prompt, SYSTEM_PROMPT)
    if not ai_result:
        ai_result = fallback_evaluation(findings_data)

    # Agregar metadatos de enriquecimiento al output
    evaluation = ai_result.get('evaluation', {})
    evaluation['ssvc_context_used'] = ssvc_data is not None

    output = {
        "schema_version":        "3.0",
        "generated_at":          datetime.now().isoformat(),
        "findings_analyzed":     total,
        "service":               service,
        "environment":           environment,
        "business_criticality":  crit_val,
        "ai_provider":           ai_result.get('provider'),
        "ai_model":              ai_result.get('model'),
        "tokens_used":           ai_result.get('tokens_used', {}),
        "evaluation":            evaluation,
        "ssvc_enrichment": {
            "used":              ssvc_data is not None,
            "action_counts":     ssvc_data.get("action_counts", {}) if ssvc_data else {},
            "kev_entries":       ssvc_data.get("data_sources",{}).get("cisa_kev_entries",0) if ssvc_data else 0,
            "epss_fetched":      ssvc_data.get("data_sources",{}).get("epss_scores_fetched",0) if ssvc_data else 0,
            "f1_metrics":        ssvc_data.get("f1_metrics", {}) if ssvc_data else {},
            "classified_count":  len(ssvc_data.get("all_classified_findings",[])) if ssvc_data else 0,
        },
        "prompt_version":        "3.0-ssvc-enriched",
        "_academic_reference":   "Al Haddad et al. (2025) – arXiv 2510.18508",
        "_academic_note": (
            "Evaluación híbrida: LLM enriquecido con clasificaciones SSVC preliminares "
            "y datos empíricos EPSS/CISA KEV. El LLM puede validar o corregir "
            "las clasificaciones SSVC con razonamiento contextual."
        ),
    }

    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    ev = output['evaluation']
    chains         = ev.get('attack_chains', [])
    ssvc_val       = ev.get('ssvc_validation', [])
    n_confirmed    = sum(1 for v in ssvc_val if v.get('ai_assessment') == 'confirmed')
    n_overest      = sum(1 for v in ssvc_val if v.get('ai_assessment') == 'overestimated')
    n_underest     = sum(1 for v in ssvc_val if v.get('ai_assessment') == 'underestimated')

    print()
    print("="*65)
    print("  RESULTADO EVALUACIÓN HÍBRIDA IA + SSVC/EPSS/KEV")
    print("="*65)
    print(f"  🚦 DECISIÓN          : {ev.get('decision','?')}")
    print(f"  📊 CONFIANZA         : {ev.get('confidence',0):.0%}")
    print(f"  ⚠️  RIESGO            : {ev.get('risk_level','?')}")
    print(f"  🔬 SSVC enriquecido  : {'Sí' if ssvc_data else 'No'}")
    if ssvc_val:
        print(f"  ✅ Validación SSVC   : confirmados={n_confirmed} "
              f"sobreestimados={n_overest} subestimados={n_underest}")
    print(f"  🔗 Cadenas ataque    : {len(chains)}")
    print(f"  💬 {ev.get('summary','')[:70]}...")
    print(f"\n  Guardado en: {output_path}")
    print("="*65 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Motor de evaluación híbrida IA + SSVC/EPSS/KEV"
    )
    parser.add_argument('--findings',    required=True)
    parser.add_argument('--output',      required=True)
    parser.add_argument('--service',     default='unknown')
    parser.add_argument('--criticality', default='medium')
    parser.add_argument('--environment', default='staging')
    args = parser.parse_args()
    evaluate(args.findings, args.output, args.service,
             args.criticality, args.environment)