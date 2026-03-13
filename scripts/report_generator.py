#!/usr/bin/env python3
"""
report_generator.py – Generador de Reporte Final en Markdown
Trabajo de Grado – Universidad del Valle 2026

Genera el reporte académico/técnico completo del pipeline DevSecOps.
"""

import json
import argparse
import os
from datetime import datetime


# ============================================================
# ICONOS Y CONSTANTES
# ============================================================

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFO": "⚪"
}

DECISION_ICONS = {
    "PASS": "✅",
    "FAIL": "❌",
    "CONDITIONAL": "⚠️"
}

TOOL_NAMES = {
    "semgrep": "Semgrep (SAST)",
    "trivy": "Trivy (SCA)",
    "zap": "OWASP ZAP (DAST)",
    "nuclei": "Nuclei (Pentesting)"
}


def format_severity_table(by_severity: dict) -> str:
    """Genera tabla de severidades en Markdown."""
    rows = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_severity.get(sev, 0)
        icon = SEVERITY_ICONS.get(sev, "⚪")
        rows.append(f"| {icon} {sev} | {count} |")
    return "\n".join(rows)


def format_tool_table(tools_data: dict) -> str:
    """Genera tabla de herramientas en Markdown."""
    rows = []
    for tool, count in tools_data.items():
        name = TOOL_NAMES.get(tool, tool)
        status = "✅ Ejecutado" if count > 0 else "⚠️ Sin hallazgos"
        rows.append(f"| {name} | {count} | {status} |")
    return "\n".join(rows)


def format_top_findings(findings: list, limit: int = 10) -> str:
    """Genera tabla de top hallazgos críticos/altos."""
    critical_high = [
        f for f in findings 
        if f.get('severity') in ['CRITICAL', 'HIGH']
    ][:limit]
    
    if not critical_high:
        return "_No se encontraron hallazgos críticos o altos._\n"
    
    rows = []
    for f in critical_high:
        icon = SEVERITY_ICONS.get(f.get('severity'), '⚪')
        tool = f.get('tool', '?').upper()
        title = f.get('title', 'Unknown')[:50]
        category = f.get('category', 'N/A')[:40]
        severity = f.get('severity', '?')
        rows.append(f"| {icon} {severity} | `{tool}` | {title} | {category} |")
    
    return "\n".join(rows)


def format_comparison_section(gate_comparison: dict) -> str:
    """Genera la sección de comparación Traditional vs IA."""
    trad = gate_comparison.get('traditional', {})
    ai = gate_comparison.get('ai_assisted', {})
    analysis = gate_comparison.get('analysis', {})
    
    trad_decision = trad.get('decision', 'UNKNOWN')
    ai_decision = ai.get('decision', 'UNKNOWN')
    
    trad_icon = DECISION_ICONS.get(trad_decision, '❓')
    ai_icon = DECISION_ICONS.get(ai_decision, '❓')
    
    # Tabla de comparación
    comparison_md = f"""
| Criterio | Gate Tradicional | Gate con IA |
|---|---|---|
| **Decisión** | {trad_icon} {trad_decision} | {ai_icon} {ai_decision} |
| **Método** | Umbrales estáticos | Evaluación contextual LLM |
| **Considera contexto** | ❌ No | ✅ Sí |
| **Falsos positivos** | ❌ No filtra | ✅ Estimados |
| **Explotabilidad** | ❌ No evalúa | ✅ Considera |
| **Modelo** | Reglas fijas | {ai.get('ai_model', 'N/A')} |
| **Confianza** | N/A | {ai.get('confidence', 0):.0%} |

**Análisis de la comparación:**
> {analysis.get('comparison', 'N/A')}

**Insight académico:**
> {analysis.get('academic_insight', 'N/A')}
"""
    
    # Razones del gate tradicional
    trad_reasons = trad.get('reasons', [])
    if trad_reasons:
        comparison_md += "\n**Razones del gate tradicional:**\n"
        for r in trad_reasons:
            comparison_md += f"- {r}\n"
    
    # Condiciones del gate IA
    ai_conditions = ai.get('conditions', [])
    if ai_conditions:
        comparison_md += "\n**Condiciones identificadas por IA:**\n"
        for c in ai_conditions:
            comparison_md += f"- {c}\n"
    
    return comparison_md


def generate_report(findings_path: str, ai_eval_path: str, 
                    gate_path: str, output_path: str):
    """Genera el reporte completo en Markdown."""
    
    print("\n" + "="*60)
    print("  GENERADOR DE REPORTE – DevSecOps TG")
    print("="*60)
    
    # Cargar datos
    with open(findings_path, 'r') as f:
        findings_data = json.load(f)
    
    with open(ai_eval_path, 'r') as f:
        ai_eval_data = json.load(f)
    
    with open(gate_path, 'r') as f:
        gate_data = json.load(f)
    
    # Extraer datos clave
    summary = findings_data.get('summary', {})
    findings = findings_data.get('findings', [])
    tools = findings_data.get('tools_executed', {})
    evaluation = ai_eval_data.get('evaluation', {})
    gate_comparison = gate_data.get('gate_comparison', {})
    
    final_decision = gate_data.get('decision', 'UNKNOWN')
    decision_icon = DECISION_ICONS.get(final_decision, '❓')
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pipeline_run = findings_data.get('pipeline_run', 'local')
    service = findings_data.get('service', 'unknown')
    environment = findings_data.get('environment', 'staging')
    
    # Construir reporte
    report = f"""# 🔐 Reporte de Seguridad – Pipeline DevSecOps
## {decision_icon} Decisión de Despliegue: **{final_decision}**

---

> **Generado automáticamente por el pipeline DevSecOps**
> 
> - **Servicio:** `{service}`
> - **Entorno:** `{environment}`
> - **Pipeline Run:** `{pipeline_run}`
> - **Timestamp:** `{timestamp}`
> - **Modelo IA:** `{ai_eval_data.get('ai_model', 'N/A')}`

---

## 📊 Resumen Ejecutivo

{evaluation.get('summary', 'No summary available')}

**Recomendación del sistema:**
> {gate_data.get('deploy_recommendation', evaluation.get('deploy_recommendation', 'Revisar hallazgos manualmente.'))}

---

## 🚦 Decisión Final del Security Gate

| Campo | Valor |
|---|---|
| **Decisión** | {decision_icon} **{final_decision}** |
| **Fuente de decisión** | {gate_data.get('decision_source', 'N/A')} |
| **Nivel de riesgo** | {evaluation.get('risk_level', 'N/A')} |
| **Confianza IA** | {evaluation.get('confidence', 0):.0%} |
| **Estimación falsos positivos** | {evaluation.get('false_positive_estimate', 'N/A')} |

{f"### ⚠️ Condiciones para despliegue{chr(10)}" + chr(10).join(f"- {c}" for c in gate_data.get('conditions_to_deploy', [])) if gate_data.get('conditions_to_deploy') else ""}

---

## 📈 Estadísticas de Hallazgos

### Por Severidad

| Severidad | Cantidad |
|---|---|
{format_severity_table(summary.get('by_severity', {}))}
| **Total** | **{summary.get('total', 0)}** |

### Por Herramienta

| Herramienta | Hallazgos | Estado |
|---|---|---|
{format_tool_table(tools)}

---

## 🔍 Evaluación Detallada por IA

### Razonamiento

{evaluation.get('reasoning', 'No reasoning provided')}

### Categorías OWASP Top 10 Detectadas

{chr(10).join(f"- `{cat}`" for cat in evaluation.get('owasp_top10_present', [])) or "- _No se identificaron categorías específicas_"}

### Análisis de Cobertura

| Tipo de Análisis | Cobertura |
|---|---|
| SAST (Código fuente) | {evaluation.get('coverage_analysis', {}).get('sast_coverage', 'N/A')} |
| SCA (Dependencias) | {evaluation.get('coverage_analysis', {}).get('sca_coverage', 'N/A')} |
| DAST (Tiempo de ejecución) | {evaluation.get('coverage_analysis', {}).get('dast_coverage', 'N/A')} |
| Pentesting automatizado | {evaluation.get('coverage_analysis', {}).get('pentest_coverage', 'N/A')} |

**Evaluación general:** {evaluation.get('coverage_analysis', {}).get('overall_coverage', 'N/A')}

---

## 🏆 Hallazgos Principales Identificados por IA

| Severidad | Herramienta | Título | Categoría OWASP |
|---|---|---|---|
{format_top_findings(findings)}

---

## 🔄 Comparación: Gate Tradicional vs Gate Asistido por IA

> Esta sección documenta la contribución principal del trabajo de grado:
> demostrar que la evaluación asistida por IA aporta valor sobre los umbrales estáticos.

{format_comparison_section(gate_comparison)}

---

## 🛠️ Prioridades de Remediación

"""
    
    # Agregar prioridades de remediación
    remediation = evaluation.get('remediation_priorities', [])
    if remediation:
        for item in remediation:
            priority = item.get('priority', '?')
            action = item.get('action', 'N/A')
            tool = item.get('tool', 'N/A')
            timeline = item.get('timeline', 'N/A')
            report += f"**{priority}.** {action}\n"
            report += f"   - Herramienta: `{tool}` | Plazo: _{timeline}_\n\n"
    else:
        report += "_No se identificaron prioridades específicas de remediación._\n"
    
    report += f"""
---

## 📋 Hallazgos Críticos y Altos (Detalle)

"""
    
    # Tabla detallada de críticos y altos
    critical_high = [f for f in findings if f.get('severity') in ['CRITICAL', 'HIGH']][:20]
    
    if critical_high:
        for f in critical_high:
            icon = SEVERITY_ICONS.get(f.get('severity'), '⚪')
            report += f"### {icon} [{f.get('severity')}] {f.get('title', 'Unknown')}\n\n"
            report += f"- **ID:** `{f.get('id', 'N/A')}`\n"
            report += f"- **Herramienta:** `{f.get('tool', 'N/A').upper()}` ({f.get('tool_type', 'N/A')})\n"
            report += f"- **Categoría:** {f.get('category', 'N/A')}\n"
            
            if f.get('cwe'):
                report += f"- **CWE:** `{f.get('cwe')}`\n"
            if f.get('cvss_score'):
                report += f"- **CVSS Score:** `{f.get('cvss_score')}`\n"
            
            location = f.get('location', {})
            if location.get('file'):
                report += f"- **Archivo:** `{location['file']}`:{location.get('line', '?')}\n"
            if location.get('endpoint'):
                report += f"- **Endpoint:** `{location['method']} {location['endpoint']}`\n"
            
            report += f"\n**Descripción:** {f.get('description', 'N/A')[:300]}\n\n"
            
            if f.get('remediation'):
                report += f"**Remediación sugerida:** {f.get('remediation', 'N/A')[:200]}\n\n"
            
            report += "---\n\n"
    else:
        report += "_No se encontraron hallazgos críticos o altos._\n\n"
    
    report += f"""
## 🎓 Notas Académicas

Este reporte fue generado automáticamente por el pipeline DevSecOps implementado como
Trabajo de Grado en la Universidad del Valle – Sede Tuluá.

### Marco de referencia
- **ISO/IEC 27034:** Principios de seguridad de aplicaciones
- **OWASP Top 10:** Categorización de riesgos web
- **CVSS:** Sistema de puntuación de vulnerabilidades

### Herramientas integradas
| Herramienta | Tipo | Propósito |
|---|---|---|
| Semgrep | SAST | Análisis estático del código fuente |
| Trivy | SCA | Análisis de componentes y dependencias |
| OWASP ZAP | DAST | Pruebas dinámicas en tiempo de ejecución |
| Nuclei | Pentesting | Validación activa de vulnerabilidades |

### Limitaciones
- Pipeline ejecutado en entorno de laboratorio con OWASP Juice Shop
- Evaluación IA requiere validación humana para decisiones críticas
- No reemplaza una auditoría de seguridad formal

---

_Reporte generado el {timestamp} | Pipeline: {pipeline_run}_

_Autores: Jhojan Stiven Castaño Jejen & Juan Manuel Arango Rodas_
_Universidad del Valle – Ingeniería de Sistemas – 2026_
"""
    
    # Guardar reporte
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"  ✅ Reporte generado: {output_path}")
    print(f"  📄 Tamaño: {len(report)} caracteres")
    print(f"  🚦 Decisión documentada: {final_decision}")
    print("="*60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Generador de reporte final Markdown'
    )
    parser.add_argument('--findings', required=True, help='Ruta a findings.json')
    parser.add_argument('--ai-evaluation', required=True, help='Ruta a ai_evaluation.json')
    parser.add_argument('--gate-decision', required=True, help='Ruta a gate_decision.json')
    parser.add_argument('--output', required=True, help='Ruta de salida SECURITY_REPORT.md')
    
    args = parser.parse_args()
    
    generate_report(
        findings_path=args.findings,
        ai_eval_path=args.ai_evaluation,
        gate_path=args.gate_decision,
        output_path=args.output
    )
