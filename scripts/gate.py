#!/usr/bin/env python3
"""
gate.py – Security Gate Automatizado
Trabajo de Grado – Universidad del Valle 2026

Propósito académico: Implementar y COMPARAR tres enfoques de decisión:
  1. Gate tradicional (umbrales estáticos)
  2. Gate asistido por IA
  3. Validación normativa ISO/IEC 27034 (TLOT/ALOT)

Esta comparación es el ARGUMENTO CENTRAL de la tesis.
"""

import json
import sys
import argparse
import os
from datetime import datetime

try:
    from iso27034 import iso27034_decision, generate_iso27034_report_section
    ISO27034_AVAILABLE = True
except ImportError:
    ISO27034_AVAILABLE = False
    def iso27034_decision(findings_data, criticality):
        return {
            "decision": "UNKNOWN", "compliant": False,
            "iso_label": "Módulo iso27034.py no disponible",
            "reasoning": "Instalar iso27034.py en scripts/ para activar validación normativa.",
            "tlot": {"tlot_score": 0, "criticality": criticality, "required_ascs": []},
            "alot": {"alot_score": 0, "base_score": 0, "total_penalty": 0,
                     "asc_breakdown": [], "penalties_applied": [], "missing_ascs": []},
            "gap_to_tlot": 0, "gap_pct": 0, "conditions": [],
        }


def traditional_gate(findings_data: dict, policy: dict = None) -> dict:
    """
    Gate basado en umbrales estáticos.
    LIMITACIÓN ACADÉMICA: No considera contexto, falsos positivos
    ni explotabilidad real. Solo cuenta números.
    """
    if policy is None:
        policy = {
            "fail_on_critical":      True,
            "fail_on_high_count":    5,
            "fail_on_medium_count":  20,
        }

    summary    = findings_data.get("summary", {})
    by_sev     = summary.get("by_severity", {})
    critical   = by_sev.get("CRITICAL", 0)
    high       = by_sev.get("HIGH",     0)
    medium     = by_sev.get("MEDIUM",   0)

    reasons  = []
    decision = "PASS"

    if policy.get("fail_on_critical") and critical > 0:
        decision = "FAIL"
        reasons.append(f"Hallazgos CRÍTICOS: {critical} (umbral: 0)")

    if high >= policy.get("fail_on_high_count", 5):
        decision = "FAIL"
        reasons.append(f"Hallazgos ALTOS: {high} (umbral: {policy['fail_on_high_count']})")

    if medium >= policy.get("fail_on_medium_count", 20):
        if decision != "FAIL":
            decision = "CONDITIONAL"
        reasons.append(f"Hallazgos MEDIOS: {medium} (umbral: {policy['fail_on_medium_count']})")

    if not reasons:
        reasons.append("Dentro de umbrales aceptables")

    return {
        "method":             "traditional_threshold",
        "decision":           decision,
        "reasons":            reasons,
        "thresholds_applied": policy,
        "counts":             {"critical": critical, "high": high, "medium": medium},
        "limitation":         "No considera contexto, explotabilidad ni falsos positivos",
    }


def ai_gate(ai_evaluation_data: dict) -> dict:
    """Gate basado en la evaluación de la IA."""
    evaluation = ai_evaluation_data.get("evaluation", {})
    return {
        "method":                  "ai_assisted",
        "decision":                evaluation.get("decision", "FAIL"),
        "confidence":              evaluation.get("confidence", 0.5),
        "reasoning":               evaluation.get("reasoning", "No reasoning provided"),
        "conditions":              evaluation.get("conditions", []),
        "ai_model":                ai_evaluation_data.get("ai_model", "unknown"),
        "key_findings":            evaluation.get("key_findings", []),
        "owasp_categories":        evaluation.get("owasp_top10_present", []),
        "false_positive_estimate": evaluation.get("false_positive_estimate", "unknown"),
        "advantage":               "Considera contexto, explotabilidad, cobertura y patrones de riesgo",
    }


def compare_and_decide(trad_result: dict, ai_result: dict) -> dict:
    """Compara ambos enfoques y documenta las diferencias."""
    trad_decision = trad_result.get("decision")
    ai_decision   = ai_result.get("decision")
    agreement     = trad_decision == ai_decision

    severity_order = {"PASS": 0, "CONDITIONAL": 1, "FAIL": 2}
    trad_level = severity_order.get(trad_decision, 1)
    ai_level   = severity_order.get(ai_decision,   1)

    if ai_level < trad_level:
        comparison = "IA más permisiva (posiblemente menos falsos positivos)"
    elif ai_level > trad_level:
        comparison = "IA más restrictiva (detecta riesgos contextuales adicionales)"
    else:
        comparison = "Ambos métodos concuerdan"

    return {
        "agree":                agreement,
        "traditional_decision": trad_decision,
        "ai_decision":          ai_decision,
        "comparison":           comparison,
        "academic_insight": (
            "La IA y los umbrales concuerdan, validando la metodología."
            if agreement else
            f"Diferencia detectada: threshold='{trad_decision}' vs IA='{ai_decision}'. "
            "Esto ilustra el valor añadido del análisis contextual."
        ),
    }


def detect_empty_pipeline(findings_data: dict) -> bool:
    """
    Detecta si todos los reportes llegaron vacíos, lo que indica
    un fallo en la recolección de datos del pipeline (no ausencia real de vulns).
    """
    tools_executed = findings_data.get("tools_executed", {})
    total          = findings_data.get("summary", {}).get("total", 0)
    all_zeros      = all(v == 0 for v in tools_executed.values()) if tools_executed else True
    return all_zeros and total == 0


def run_gate(findings_path: str, ai_evaluation_path: str,
             output_path: str, enforce: bool = False, criticality: str = "medium):

    print("\n" + "="*60)
    print("  SECURITY GATE – DevSecOps TG")
    print("="*60)

    with open(findings_path) as f:
        findings_data = json.load(f)
    with open(ai_evaluation_path) as f:
        ai_evaluation_data = json.load(f)

    # ── Protección contra pipeline vacío ──────────────────────────────────
    pipeline_empty   = detect_empty_pipeline(findings_data)
    pipeline_warning = None

    if pipeline_empty:
        pipeline_warning = (
            "⚠️  ADVERTENCIA: todos los reportes tienen 0 hallazgos. "
            "Posible fallo en la recolección de datos del pipeline. "
            "Se fuerza CONDITIONAL para revisión manual."
        )
        print()
        print(pipeline_warning)
        print()

    # ── Ejecutar los tres gates ────────────────────────────────────────────
    print("📊 Ejecutando gate tradicional (umbrales)...")
    trad_result = traditional_gate(findings_data)

    print("🤖 Aplicando gate con evaluación IA...")
    ai_result = ai_gate(ai_evaluation_data)

    print("📋 Evaluando conformidad ISO/IEC 27034 (TLOT/ALOT)...")
    criticality = (
    findings_data.get("business_criticality")
    or os.environ.get("CRITICALITY", "medium")
)
    iso_result = iso27034_decision(findings_data, criticality)

    comparison = compare_and_decide(trad_result, ai_result)

    # ── Decisión final ─────────────────────────────────────────────────────
    ai_confidence  = ai_result.get("confidence", 0)
    severity_order = {"PASS": 0, "CONDITIONAL": 1, "FAIL": 2}

    if ai_confidence < 0.6:
        # Baja confianza IA: tomar la decisión más conservadora
        if severity_order.get(trad_result["decision"], 1) > severity_order.get(ai_result["decision"], 1):
            final_decision  = trad_result["decision"]
            decision_source = "traditional (baja confianza IA)"
        else:
            final_decision  = ai_result["decision"]
            decision_source = "ai_assisted (confianza baja, validado con traditional)"
    else:
        final_decision  = ai_result["decision"]
        decision_source = "ai_assisted"

    # ── OVERRIDE: ISO 27034 puede escalar PASS → CONDITIONAL ──────────────
    # Si el modelo normativo detecta que el ALOT no alcanza el TLOT pero
    # la IA dijo PASS (posible sobreconfianza), se escala a CONDITIONAL.
    if iso_result["decision"] == "FAIL" and final_decision == "PASS":
        final_decision  = "CONDITIONAL"
        decision_source = "iso27034_escalation"

    # ── OVERRIDE: pipeline vacío nunca puede ser PASS ──────────────────────
    if pipeline_empty and final_decision == "PASS":
        final_decision  = "CONDITIONAL"
        decision_source = "forced_conditional_empty_reports"

    output = {
        "schema_version":   "2.0",
        "generated_at":     datetime.now().isoformat(),
        "service":          findings_data.get("service", "unknown"),
        "environment":      findings_data.get("environment", "staging"),
        "pipeline_run":     findings_data.get("pipeline_run", "local"),
        "decision":         final_decision,
        "decision_source":  decision_source,
        "gate_comparison": {
            "traditional": trad_result,
            "ai_assisted": ai_result,
            "analysis":    comparison,
        },
        "iso27034_evaluation": iso_result,
        "iso27034_compliant":  iso_result.get("compliant", False),
        "findings_summary":    findings_data.get("summary", {}),
        "conditions_to_deploy": (
            ai_result.get("conditions", []) +
            iso_result.get("conditions", [])
        ) if final_decision == "CONDITIONAL" else [],
        "deploy_recommendation": ai_evaluation_data.get("evaluation", {}).get("deploy_recommendation", ""),
        "_pipeline_warning": pipeline_warning,
        "_academic_note":    (
            "Decisión basada en tres enfoques: gate tradicional (umbrales), "
            "gate IA (contextual) y validación normativa ISO/IEC 27034-1:2011 §7.3.6 (TLOT/ALOT). "
            "La comparación de estos tres enfoques es el core de la contribución del TG."
        ),
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # ── Resumen en consola ─────────────────────────────────────────────────
    print()
    print("="*60)
    print("  RESULTADO DEL SECURITY GATE")
    print("="*60)
    print(f"  🔴 Gate Tradicional : {trad_result['decision']}")
    print(f"  🤖 Gate con IA      : {ai_result['decision']}")
    print(f"  📋 ISO/IEC 27034    : "
          f"TLOT={iso_result['tlot']['tlot_score']:.3f} | "
          f"ALOT={iso_result['alot']['alot_score']:.3f} | "
          f"{'CONFORME ✅' if iso_result['compliant'] else 'NO CONFORME ❌'}")
    print(f"  ─────────────────────────────────────────────")
    print(f"  🚦 DECISIÓN FINAL   : {final_decision}")
    print(f"  📌 Fuente           : {decision_source}")

    if pipeline_warning:
        print(f"  ⚠️  {pipeline_warning[:80]}")

    print(f"\n  📊 {comparison['comparison']}")
    print(f"  💡 {comparison['academic_insight'][:80]}")

    if final_decision == "CONDITIONAL" and output.get("conditions_to_deploy"):
        print(f"\n  📋 Condiciones para desplegar:")
        for i, cond in enumerate(output["conditions_to_deploy"], 1):
            print(f"     {i}. {cond}")

    print(f"\n  Guardado en: {output_path}")
    print("="*60 + "\n")

    if enforce:
        if final_decision == "FAIL":
            print("❌ PIPELINE BLOQUEADO – Security Gate: FAIL")
            sys.exit(1)
        elif final_decision == "CONDITIONAL":
            print("⚠️  PIPELINE CONDICIONADO – Revisar antes de producción")
            sys.exit(0)
        else:
            print("✅ PIPELINE APROBADO – Security Gate: PASS")
            sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Security Gate – Comparación Traditional vs IA vs ISO/IEC 27034"
    )
    parser.add_argument("--criticality", default="medium",
                    help="Criticidad del servicio: low|medium|high|critical")
    parser.add_argument("--findings",      required=True)
    parser.add_argument("--ai-evaluation", required=True)
    parser.add_argument("--output",        required=True)
    parser.add_argument("--enforce",       action="store_true")
    args = parser.parse_args()

    run_gate(
        findings_path=args.findings,
        ai_evaluation_path=args.ai_evaluation,
        output_path=args.output,
        enforce=args.enforce,
        criticality=args.criticality,
    )