#!/usr/bin/env python3
"""
gate.py – Security Gate Automatizado
Trabajo de Grado – Universidad del Valle 2026

Propósito académico: Implementar y COMPARAR tres enfoques de decisión:
  1. Gate tradicional (umbrales estáticos)
  2. Gate asistido por IA (LLM contextual)
  3. Gate SSVC + EPSS + CISA KEV (reemplaza TLOT/ALOT)
     Elimina constantes arbitrarias. Permite F1 formal. Produce divergencia entre casos.
     Ref: Al Haddad et al. (2025), Kausar et al. (2025), Yoon et al. (2023)

ISO/IEC 27034 se conserva para trazabilidad normativa (asc_id por hallazgo)
pero no como mecanismo de puntuación del gate.
"""

import json
import sys
import argparse
import os
from datetime import datetime

# ── Importar gate SSVC (nuevo tercer gate) ────────────────────────────────────
try:
    from ssvc_gate import ssvc_gate
    SSVC_AVAILABLE = True
except ImportError:
    SSVC_AVAILABLE = False
    def ssvc_gate(findings_data, criticality):
        return {
            "method":    "ssvc_epss_kev",
            "decision":  "FAIL",
            "aggregate_action": "Act",
            "action_counts": {"Act": 0, "Attend": 0, "Track*": 0, "Track": 0},
            "reasoning": "Módulo ssvc_gate.py no disponible. Instalar en scripts/.",
            "f1_metrics": {},
            "data_sources": {},
        }

# ── Conservar ISO 27034 SOLO para trazabilidad normativa (asc_id) ─────────────
try:
    from iso27034 import (iso27034_decision,
                          generate_iso27034_report_section)
    ISO27034_AVAILABLE = True
except ImportError:
    ISO27034_AVAILABLE = False
    def iso27034_decision(findings_data, criticality):
        return {"decision": "UNKNOWN", "compliant": False,
                "iso_label": "iso27034.py no disponible",
                "reasoning": "", "tlot": {}, "alot": {}, "conditions": []}
    def generate_iso27034_report_section(r):
        return ""


def traditional_gate(findings_data: dict, policy: dict = None) -> dict:
    """
    Gate 1: umbrales estáticos.
    LIMITACIÓN ACADÉMICA: no considera explotabilidad, contexto ni FP.
    Sirve como línea base determinística para la comparación.
    """
    if policy is None:
        policy = {
            "fail_on_critical":   True,
            "fail_on_high_count": 5,
            "fail_on_medium_count": 20,
        }

    by_sev   = findings_data.get("summary", {}).get("by_severity", {})
    critical = by_sev.get("CRITICAL", 0)
    high     = by_sev.get("HIGH", 0)
    medium   = by_sev.get("MEDIUM", 0)

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
        "limitation":         "No considera explotabilidad, contexto ni falsos positivos",
    }


def ai_gate(ai_evaluation_data: dict) -> dict:
    """Gate 2: evaluación contextual por LLM."""
    evaluation = ai_evaluation_data.get("evaluation", {})
    return {
        "method":                  "ai_assisted",
        "decision":                evaluation.get("decision", "FAIL"),
        "confidence":              evaluation.get("confidence", 0.5),
        "reasoning":               evaluation.get("reasoning", ""),
        "conditions":              evaluation.get("conditions", []),
        "ai_model":                ai_evaluation_data.get("ai_model", "unknown"),
        "key_findings":            evaluation.get("key_findings", []),
        "owasp_categories":        evaluation.get("owasp_top10_present", []),
        "false_positive_estimate": evaluation.get("false_positive_estimate", "unknown"),
        "attack_chains":           evaluation.get("attack_chains", []),
        "advantage": (
            "Considera explotabilidad real, cadenas de ataque, "
            "falsos positivos y contexto de negocio"
        ),
    }


def compare_gates(trad: dict, ai: dict, ssvc: dict) -> dict:
    """Documenta diferencias entre los tres enfoques."""
    sev = {"PASS": 0, "CONDITIONAL": 1, "FAIL": 2}
    decisions = {
        "traditional": trad["decision"],
        "ai_assisted": ai["decision"],
        "ssvc":        ssvc["decision"],
    }
    levels = {k: sev.get(v, 1) for k, v in decisions.items()}
    all_agree = len(set(decisions.values())) == 1

    divergences = []
    if decisions["traditional"] != decisions["ssvc"]:
        divergences.append(
            f"Gate tradicional ({decisions['traditional']}) difiere de "
            f"SSVC ({decisions['ssvc']}): el análisis por explotabilidad real "
            f"produce una decisión diferente al conteo estático."
        )
    if decisions["ai_assisted"] != decisions["ssvc"]:
        divergences.append(
            f"Gate IA ({decisions['ai_assisted']}) difiere de "
            f"SSVC ({decisions['ssvc']}): el LLM aporta contexto adicional "
            f"sobre cadenas de ataque no capturadas por el árbol SSVC."
        )

    return {
        "all_agree":    all_agree,
        "decisions":    decisions,
        "divergences":  divergences,
        "academic_insight": (
            "Los tres gates concuerdan — validación metodológica."
            if all_agree else
            f"Divergencias detectadas entre {len(divergences)} pares de gates. "
            "Esto ilustra el valor diferencial del análisis por explotabilidad "
            "SSVC vs umbrales estáticos vs evaluación contextual LLM."
        ),
    }


def detect_empty_pipeline(findings_data: dict) -> bool:
    tools_executed = findings_data.get("tools_executed", {})
    total = findings_data.get("summary", {}).get("total", 0)
    all_zeros = all(v == 0 for v in tools_executed.values()) if tools_executed else True
    return all_zeros and total == 0


def run_gate(findings_path: str, ai_evaluation_path: str,
             output_path: str, enforce: bool = False, criticality: str = "medium"):

    print("\n" + "="*60)
    print("  SECURITY GATE – DevSecOps TG (SSVC + EPSS + CISA KEV)")
    print("="*60)

    with open(findings_path) as f:
        findings_data = json.load(f)
    with open(ai_evaluation_path) as f:
        ai_evaluation_data = json.load(f)

    # Criticality desde findings o entorno
    criticality = (
        findings_data.get("business_criticality")
        or os.environ.get("CRITICALITY", criticality)
    )

    # Protección pipeline vacío
    pipeline_empty   = detect_empty_pipeline(findings_data)
    pipeline_warning = None
    if pipeline_empty:
        pipeline_warning = (
            "⚠️  ADVERTENCIA: todos los reportes tienen 0 hallazgos. "
            "Posible fallo en la recolección. Se fuerza CONDITIONAL."
        )
        print(f"\n{pipeline_warning}\n")

    # ── Gate 1: Tradicional ────────────────────────────────────────────────
    print("📊 Gate 1: Tradicional (umbrales estáticos)...")
    trad_result = traditional_gate(findings_data)

    # ── Gate 2: IA ─────────────────────────────────────────────────────────
    print("🤖 Gate 2: IA (evaluación contextual LLM)...")
    ai_result = ai_gate(ai_evaluation_data)

    # ── Gate 3: SSVC + EPSS + CISA KEV ────────────────────────────────────
    print("🔬 Gate 3: SSVC + EPSS + CISA KEV...")
    ssvc_result = ssvc_gate(findings_data, criticality)

    # ── ISO 27034: solo trazabilidad normativa, NO como gate ──────────────
    print("📋 ISO/IEC 27034: registrando trazabilidad normativa (asc_id)...")
    iso_traceability = iso27034_decision(findings_data, criticality)

    comparison = compare_gates(trad_result, ai_result, ssvc_result)

    # ── Decisión final: Gate IA (si confianza >= 0.6), si no la más conservadora
    ai_confidence  = ai_result.get("confidence", 0)
    severity_order = {"PASS": 0, "CONDITIONAL": 1, "FAIL": 2}

    if ai_confidence >= 0.6:
        final_decision  = ai_result["decision"]
        decision_source = "ai_assisted"
    else:
        all_decisions = [
            trad_result["decision"],
            ai_result["decision"],
            ssvc_result["decision"],
        ]
        max_level = max(all_decisions, key=lambda d: severity_order.get(d, 1))
        final_decision  = max_level
        decision_source = "conservative_merge_low_ai_confidence"

    # SSVC puede escalar si detecta explotación activa que IA no captura
    ssvc_level = severity_order.get(ssvc_result["decision"], 0)
    final_level = severity_order.get(final_decision, 0)
    if ssvc_level > final_level:
        final_decision  = ssvc_result["decision"]
        decision_source = "ssvc_escalation_active_exploitation"

    if pipeline_empty and final_decision == "PASS":
        final_decision  = "CONDITIONAL"
        decision_source = "forced_conditional_empty_reports"

    output = {
        "schema_version":  "3.0",
        "generated_at":    datetime.now().isoformat(),
        "service":         findings_data.get("service", "unknown"),
        "environment":     findings_data.get("environment", "staging"),
        "criticality":     criticality,
        "decision":        final_decision,
        "decision_source": decision_source,
        "gate_comparison": {
            "traditional": trad_result,
            "ai_assisted": ai_result,
            "ssvc":        ssvc_result,
            "analysis":    comparison,
        },
        # ISO 27034: trazabilidad normativa solamente
        "iso27034_traceability": {
            "note": (
                "ISO/IEC 27034 se conserva para trazabilidad normativa (asc_id "
                "por hallazgo y registro de ASCs ejecutados). El modelo TLOT/ALOT "
                "fue reemplazado por SSVC+EPSS+KEV para eliminar constantes "
                "arbitrarias y habilitar métricas formales de precisión/recall."
            ),
            "asc_breakdown": iso_traceability.get("alot", {}).get("asc_breakdown", []),
            "ascs_executed": [
                a["asc_id"] for a in
                iso_traceability.get("alot", {}).get("asc_breakdown", [])
                if a.get("status") == "executed"
            ],
        },
        "findings_summary": findings_data.get("summary", {}),
        "conditions_to_deploy": (
            ai_result.get("conditions", [])
        ) if final_decision == "CONDITIONAL" else [],
        "deploy_recommendation": (
            ai_evaluation_data.get("evaluation", {}).get("deploy_recommendation", "")
        ),
        "_pipeline_warning": pipeline_warning,
        "_academic_note": (
            "Decisión basada en tres gates: (1) umbrales estáticos [línea base], "
            "(2) LLM contextual [explotabilidad + cadenas de ataque], "
            "(3) SSVC+EPSS+CISA KEV [métricas estandarizadas, sin constantes arbitrarias]. "
            "ISO/IEC 27034 conservado para trazabilidad normativa (asc_id). "
            "Ref: Al Haddad et al. (2025), Kausar et al. (2025), Yoon et al. (2023)."
        ),
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # ── Consola ────────────────────────────────────────────────────────────
    ac = ssvc_result.get("action_counts", {})
    f1 = ssvc_result.get("f1_metrics", {})
    print()
    print("="*60)
    print("  RESULTADO DEL SECURITY GATE")
    print("="*60)
    print(f"  🔴 Gate Tradicional     : {trad_result['decision']}")
    print(f"  🤖 Gate IA              : {ai_result['decision']} "
          f"(confianza: {ai_confidence:.2f})")
    print(f"  🔬 Gate SSVC+EPSS+KEV  : {ssvc_result['decision']} "
          f"({ssvc_result.get('aggregate_action','?')})")
    print(f"     Act={ac.get('Act',0)} Attend={ac.get('Attend',0)} "
          f"Track*={ac.get('Track*',0)} Track={ac.get('Track',0)}")
    if f1.get("cves_evaluated", 0) > 0:
        print(f"     F1(Exploitation)={f1.get('f1_score',0):.3f} "
              f"P={f1.get('precision',0):.3f} R={f1.get('recall',0):.3f} "
              f"n={f1.get('cves_evaluated',0)}")
    print(f"  ─────────────────────────────────────────────────────")
    print(f"  🚦 DECISIÓN FINAL       : {final_decision}")
    print(f"  📌 Fuente               : {decision_source}")

    if comparison["divergences"]:
        print(f"\n  ⚡ DIVERGENCIAS entre gates:")
        for d in comparison["divergences"]:
            print(f"     • {d[:80]}")
    else:
        print(f"\n  ✅ {comparison['academic_insight']}")

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
        description="Security Gate – Traditional vs IA vs SSVC+EPSS+KEV"
    )
    parser.add_argument("--criticality",   default="medium")
    parser.add_argument("--findings",      required=True)
    parser.add_argument("--ai-evaluation", required=True)
    parser.add_argument("--output",        required=True)
    parser.add_argument("--enforce",       action="store_true")
    args = parser.parse_args()

    run_gate(
        findings_path    = args.findings,
        ai_evaluation_path = args.ai_evaluation,
        output_path      = args.output,
        enforce          = args.enforce,
        criticality      = args.criticality,
    )