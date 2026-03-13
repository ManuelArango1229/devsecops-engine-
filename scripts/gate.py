#!/usr/bin/env python3
"""
gate.py – Security Gate Automatizado
Trabajo de Grado – Universidad del Valle 2026

Propósito académico: Implementar y COMPARAR dos enfoques de decisión:
  1. Gate tradicional (umbrales estáticos)
  2. Gate asistido por IA

Esta comparación es el ARGUMENTO CENTRAL de la tesis.
"""

import json
import sys
import argparse
import os
from datetime import datetime


# ============================================================
# GATE TRADICIONAL (UMBRALES ESTÁTICOS)
# Para demostrar limitaciones vs IA
# ============================================================

def traditional_gate(findings_data: dict, policy: dict = None) -> dict:
    """
    Gate basado en umbrales estáticos.
    LIMITACIÓN ACADÉMICA: No considera contexto, falsos positivos
    ni explotabilidad real. Solo cuenta números.
    """
    if policy is None:
        policy = {
            "fail_on_critical": True,
            "fail_on_high_count": 5,
            "fail_on_medium_count": 20
        }
    
    summary = findings_data.get('summary', {})
    by_severity = summary.get('by_severity', {})
    
    critical = by_severity.get('CRITICAL', 0)
    high = by_severity.get('HIGH', 0)
    medium = by_severity.get('MEDIUM', 0)
    
    reasons = []
    decision = "PASS"
    
    if policy.get('fail_on_critical') and critical > 0:
        decision = "FAIL"
        reasons.append(f"Hallazgos CRÍTICOS: {critical} (umbral: 0)")
    
    if high >= policy.get('fail_on_high_count', 5):
        decision = "FAIL"
        reasons.append(f"Hallazgos ALTOS: {high} (umbral: {policy['fail_on_high_count']})")
    
    if medium >= policy.get('fail_on_medium_count', 20):
        if decision != "FAIL":
            decision = "CONDITIONAL"
        reasons.append(f"Hallazgos MEDIOS: {medium} (umbral: {policy['fail_on_medium_count']})")
    
    if not reasons:
        reasons.append("Dentro de umbrales aceptables")
    
    return {
        "method": "traditional_threshold",
        "decision": decision,
        "reasons": reasons,
        "thresholds_applied": policy,
        "counts": {
            "critical": critical,
            "high": high,
            "medium": medium
        },
        "limitation": "No considera contexto, explotabilidad ni falsos positivos"
    }


# ============================================================
# GATE ASISTIDO POR IA
# ============================================================

def ai_gate(ai_evaluation_data: dict) -> dict:
    """
    Gate basado en la evaluación de la IA.
    VENTAJA: Considera contexto, explotabilidad y cobertura.
    """
    evaluation = ai_evaluation_data.get('evaluation', {})
    
    decision = evaluation.get('decision', 'FAIL')
    confidence = evaluation.get('confidence', 0.5)
    reasoning = evaluation.get('reasoning', 'No reasoning provided')
    conditions = evaluation.get('conditions', [])
    
    return {
        "method": "ai_assisted",
        "decision": decision,
        "confidence": confidence,
        "reasoning": reasoning,
        "conditions": conditions,
        "ai_model": ai_evaluation_data.get('ai_model', 'unknown'),
        "key_findings": evaluation.get('key_findings', []),
        "owasp_categories": evaluation.get('owasp_top10_present', []),
        "false_positive_estimate": evaluation.get('false_positive_estimate', 'unknown'),
        "advantage": "Considera contexto, explotabilidad, cobertura y patrones de riesgo"
    }


# ============================================================
# COMPARACIÓN Y DECISIÓN FINAL
# ============================================================

def compare_and_decide(trad_result: dict, ai_result: dict) -> dict:
    """
    Compara ambos enfoques y documenta las diferencias.
    Esto es lo que demuestras en la tesis.
    """
    trad_decision = trad_result.get('decision')
    ai_decision = ai_result.get('decision')
    
    agreement = trad_decision == ai_decision
    
    # Determinar si la IA es más o menos restrictiva
    severity_order = {"PASS": 0, "CONDITIONAL": 1, "FAIL": 2}
    trad_level = severity_order.get(trad_decision, 1)
    ai_level = severity_order.get(ai_decision, 1)
    
    if ai_level < trad_level:
        ai_vs_traditional = "IA más permisiva (posiblemente menos falsos positivos)"
    elif ai_level > trad_level:
        ai_vs_traditional = "IA más restrictiva (detecta riesgos contextuales adicionales)"
    else:
        ai_vs_traditional = "Ambos métodos concuerdan"
    
    return {
        "agree": agreement,
        "traditional_decision": trad_decision,
        "ai_decision": ai_decision,
        "comparison": ai_vs_traditional,
        "academic_insight": (
            "La IA y los umbrales concuerdan, validando la metodología." 
            if agreement else 
            f"Diferencia detectada: threshold='{trad_decision}' vs IA='{ai_decision}'. "
            "Esto ilustra el valor añadido del análisis contextual."
        )
    }


# ============================================================
# FUNCIÓN PRINCIPAL
# ============================================================

def run_gate(findings_path: str, ai_evaluation_path: str, 
             output_path: str, enforce: bool = False):
    """Ejecuta el Security Gate completo."""
    
    print("\n" + "="*60)
    print("  SECURITY GATE – DevSecOps TG")
    print("="*60)
    
    # Cargar datos
    with open(findings_path, 'r') as f:
        findings_data = json.load(f)
    
    with open(ai_evaluation_path, 'r') as f:
        ai_evaluation_data = json.load(f)
    
    # Ejecutar ambos gates
    print("\n📊 Ejecutando gate tradicional (umbrales)...")
    trad_result = traditional_gate(findings_data)
    
    print("🤖 Aplicando gate con evaluación IA...")
    ai_result = ai_gate(ai_evaluation_data)
    
    # Comparar
    comparison = compare_and_decide(trad_result, ai_result)
    
    # La decisión final usa la IA (con fallback al tradicional)
    # Esta es la hipótesis del proyecto
    final_decision = ai_result.get('decision', trad_result.get('decision', 'FAIL'))
    ai_confidence = ai_result.get('confidence', 0)
    
    # Si la confianza de IA es baja, usar el más conservador
    if ai_confidence < 0.6:
        severity_order = {"PASS": 0, "CONDITIONAL": 1, "FAIL": 2}
        if severity_order.get(trad_result['decision'], 1) > severity_order.get(ai_result['decision'], 1):
            final_decision = trad_result['decision']
            decision_source = "traditional (baja confianza IA)"
        else:
            decision_source = "ai_assisted (confianza baja, validado con traditional)"
    else:
        decision_source = "ai_assisted"
    
    # Construir output
    output = {
        "schema_version": "1.0",
        "generated_at": datetime.now().isoformat(),
        "service": findings_data.get('service', 'unknown'),
        "environment": findings_data.get('environment', 'staging'),
        "pipeline_run": findings_data.get('pipeline_run', 'local'),
        
        # DECISIÓN FINAL
        "decision": final_decision,
        "decision_source": decision_source,
        
        # Comparación académica
        "gate_comparison": {
            "traditional": trad_result,
            "ai_assisted": ai_result,
            "analysis": comparison
        },
        
        # Estadísticas
        "findings_summary": findings_data.get('summary', {}),
        
        # Condiciones (si es CONDITIONAL)
        "conditions_to_deploy": ai_result.get('conditions', []) if final_decision == "CONDITIONAL" else [],
        
        # Para el reporte
        "deploy_recommendation": ai_evaluation_data.get('evaluation', {}).get('deploy_recommendation', ''),
        
        "_academic_note": "Comparación entre gate tradicional e IA es el core de la contribución del TG"
    }
    
    # Guardar
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    # Mostrar en consola
    print()
    print("="*60)
    print("  RESULTADO DEL SECURITY GATE")
    print("="*60)
    print(f"  🔴 Gate Tradicional : {trad_result['decision']}")
    print(f"  🤖 Gate con IA      : {ai_result['decision']}")
    print(f"  ─────────────────────────────")
    print(f"  🚦 DECISIÓN FINAL   : {final_decision}")
    print(f"  📌 Fuente           : {decision_source}")
    print()
    print(f"  📊 {comparison['comparison']}")
    print(f"  💡 {comparison['academic_insight'][:80]}...")
    
    if final_decision == "CONDITIONAL" and output.get('conditions_to_deploy'):
        print(f"\n  📋 Condiciones para desplegar:")
        for i, cond in enumerate(output['conditions_to_deploy'], 1):
            print(f"     {i}. {cond}")
    
    print(f"\n  Guardado en: {output_path}")
    print("="*60 + "\n")
    
    # Si enforce está activo, fallar el pipeline según la decisión
    if enforce:
        if final_decision == "FAIL":
            print("❌ PIPELINE BLOQUEADO – Security Gate: FAIL")
            sys.exit(1)
        elif final_decision == "CONDITIONAL":
            print("⚠️  PIPELINE CONDICIONADO – Revisar condiciones antes de producción")
            sys.exit(0)  # No falla el pipeline pero queda documentado
        else:
            print("✅ PIPELINE APROBADO – Security Gate: PASS")
            sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Security Gate – Comparación Traditional vs IA'
    )
    parser.add_argument('--findings', required=True, help='Ruta a findings.json')
    parser.add_argument('--ai-evaluation', required=True, help='Ruta a ai_evaluation.json')
    parser.add_argument('--output', required=True, help='Ruta de salida gate_decision.json')
    parser.add_argument('--enforce', action='store_true', 
                       help='Si se activa, falla el proceso con exit(1) si FAIL')
    
    args = parser.parse_args()
    
    run_gate(
        findings_path=args.findings,
        ai_evaluation_path=args.ai_evaluation,
        output_path=args.output,
        enforce=args.enforce
    )
