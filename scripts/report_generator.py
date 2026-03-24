#!/usr/bin/env python3
"""
report_generator.py – Generador de Reporte Final en Markdown
Trabajo de Grado – Universidad del Valle 2026
"""

import json
import argparse
import os
from datetime import datetime

SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}
DECISION_ICONS = {"PASS": "✅", "FAIL": "❌", "CONDITIONAL": "⚠️"}
TOOL_NAMES = {
    "semgrep": "Semgrep (SAST)", "trivy": "Trivy (SCA)",
    "zap": "OWASP ZAP (DAST)", "nuclei": "Nuclei (Pentesting)"
}
COVERAGE_ICONS = {"buena": "✅", "parcial": "🟡", "ninguna": "❌"}


def format_severity_table(by_severity: dict) -> str:
    rows = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_severity.get(sev, 0)
        rows.append(f"| {SEVERITY_ICONS.get(sev)} {sev} | {count} |")
    return "\n".join(rows)


def format_tool_table(tools_data: dict) -> str:
    rows = []
    for tool, count in tools_data.items():
        name = TOOL_NAMES.get(tool, tool)
        status = "✅ Ejecutado" if count > 0 else "⚠️ Sin hallazgos"
        rows.append(f"| {name} | {count} | {status} |")
    return "\n".join(rows)


def format_key_findings_table(key_findings: list) -> str:
    if not key_findings:
        return "_No se identificaron hallazgos principales._\n"
    rows = []
    for f in key_findings:
        icon = SEVERITY_ICONS.get(f.get('severity'), '⚪')
        sev = f.get('severity', '?')
        title = f.get('title', 'Unknown')[:45]
        cat = f.get('category', 'N/A')[:35]
        cvss = f.get('cvss_score', 'N/A')
        exploit = "🔴 Sí" if f.get('remote_exploitable') else "🟢 No"
        rows.append(f"| {icon} {sev} | {title} | {cvss} | {exploit} | {cat} |")
    header = "| Severidad | Hallazgo | CVSS | Remoto | Categoría OWASP |\n|---|---|---|---|---|"
    return header + "\n" + "\n".join(rows)


def format_attack_chains(attack_chains: list) -> str:
    if not attack_chains:
        return "_No se identificaron cadenas de ataque combinadas._\n"

    md = ""
    for chain in attack_chains:
        icon = SEVERITY_ICONS.get(chain.get('severity'), '⚪')
        likelihood_map = {"alta": "🔴 Alta", "media": "🟠 Media", "baja": "🟢 Baja"}
        likelihood = likelihood_map.get(chain.get('likelihood', ''), chain.get('likelihood', 'N/A'))

        md += f"#### {icon} {chain.get('chain_id', 'CHAIN')} – {chain.get('title', 'Sin título')}\n\n"
        md += f"- **Severidad combinada:** {chain.get('severity', 'N/A')}\n"
        md += f"- **Probabilidad:** {likelihood}\n"
        md += f"- **Vulnerabilidades involucradas:** `{'`, `'.join(chain.get('finding_ids', []))}`\n\n"
        md += f"**Secuencia del ataque:**\n\n"
        for i, step in enumerate(chain.get('steps', []), 1):
            md += f"{i}. {step}\n"
        md += f"\n**Impacto combinado:** {chain.get('combined_impact', 'N/A')}\n\n---\n\n"
    return md


def format_remediation_roadmap(remediation: list) -> str:
    if not remediation:
        return "_No se identificaron prioridades específicas._\n"

    immediate = [r for r in remediation if r.get('timeline') == 'inmediato']
    short = [r for r in remediation if r.get('timeline') == 'corto plazo']
    long_ = [r for r in remediation if r.get('timeline') == 'largo plazo']

    md = ""

    if immediate:
        md += "### 🚨 Inmediato (0–7 días)\n\n"
        for r in immediate:
            fix = f" → Fix: `{r.get('fix_version')}`" if r.get('fix_version') else ""
            effort = r.get('effort', 'N/A')
            md += f"**{r.get('priority', '?')}.** {r.get('action', 'N/A')}{fix}\n"
            md += f"   - Herramienta: `{r.get('tool', 'N/A')}` | Esfuerzo: _{effort}_ | Fix disponible: {'✅' if r.get('fix_available') else '❌'}\n\n"

    if short:
        md += "### ⚡ Corto plazo (1–4 semanas)\n\n"
        for r in short:
            fix = f" → Fix: `{r.get('fix_version')}`" if r.get('fix_version') else ""
            md += f"**{r.get('priority', '?')}.** {r.get('action', 'N/A')}{fix}\n"
            md += f"   - Herramienta: `{r.get('tool', 'N/A')}` | Esfuerzo: _{r.get('effort', 'N/A')}_ | Fix disponible: {'✅' if r.get('fix_available') else '❌'}\n\n"

    if long_:
        md += "### 🔧 Largo plazo (1–3 meses)\n\n"
        for r in long_:
            md += f"**{r.get('priority', '?')}.** {r.get('action', 'N/A')}\n"
            md += f"   - Herramienta: `{r.get('tool', 'N/A')}` | Esfuerzo: _{r.get('effort', 'N/A')}_\n\n"

    return md


def format_comparison_section(gate_comparison: dict, ai_eval: dict) -> str:
    trad = gate_comparison.get('traditional', {})
    ai = gate_comparison.get('ai_assisted', {})
    analysis = gate_comparison.get('analysis', {})

    trad_decision = trad.get('decision', 'UNKNOWN')
    ai_decision = ai.get('decision', 'UNKNOWN')
    trad_icon = DECISION_ICONS.get(trad_decision, '❓')
    ai_icon = DECISION_ICONS.get(ai_decision, '❓')

    md = f"""
| Criterio | Gate Tradicional | Gate con IA |
|---|---|---|
| **Decisión** | {trad_icon} {trad_decision} | {ai_icon} {ai_decision} |
| **Método** | Umbrales estáticos | Evaluación contextual LLM |
| **Considera contexto** | ❌ No | ✅ Sí |
| **Falsos positivos** | ❌ No filtra | ✅ Estimados ({ai_eval.get('evaluation', {}).get('false_positive_estimate', 'N/A')}) |
| **Explotabilidad** | ❌ No evalúa | ✅ Considera |
| **Cadenas de ataque** | ❌ No detecta | ✅ Identifica |
| **Blind spots** | ❌ No reporta | ✅ Documenta |
| **Modelo** | Reglas fijas | {ai.get('ai_model', 'N/A')} |
| **Confianza** | N/A | {ai.get('confidence', 0):.0%} |

**Análisis:** {analysis.get('comparison', 'N/A')}

**Insight académico:** {analysis.get('academic_insight', 'N/A')}
"""
    trad_reasons = trad.get('reasons', [])
    if trad_reasons:
        md += "\n**Razones del gate tradicional:**\n"
        for r in trad_reasons:
            md += f"- {r}\n"

    fp_reasoning = ai_eval.get('evaluation', {}).get('false_positive_reasoning', '')
    if fp_reasoning:
        md += f"\n**Análisis de falsos positivos (IA):** {fp_reasoning}\n"

    return md


def generate_report(findings_path: str, ai_eval_path: str,
                    gate_path: str, output_path: str):
    print("\n" + "="*60)
    print("  GENERADOR DE REPORTE – DevSecOps TG")
    print("="*60)

    with open(findings_path, 'r') as f:
        findings_data = json.load(f)
    with open(ai_eval_path, 'r') as f:
        ai_eval_data = json.load(f)
    with open(gate_path, 'r') as f:
        gate_data = json.load(f)

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
    ai_model = ai_eval_data.get('ai_model', 'N/A')
    tokens = ai_eval_data.get('tokens_used', {})

    attack_chains = evaluation.get('attack_chains', [])
    key_findings = evaluation.get('key_findings', [])
    coverage = evaluation.get('coverage_analysis', {})
    blind_spots = coverage.get('blind_spots', [])
    risk_score = evaluation.get('risk_score', 0.0)

    report = f"""# 🔐 Reporte de Seguridad – Pipeline DevSecOps
## {decision_icon} Decisión de Despliegue: **{final_decision}**

---

> **Generado automáticamente por el pipeline DevSecOps**
>
> | Campo | Valor |
> |---|---|
> | **Servicio** | `{service}` |
> | **Entorno** | `{environment}` |
> | **Pipeline Run** | `{pipeline_run}` |
> | **Timestamp** | `{timestamp}` |
> | **Modelo IA** | `{ai_model}` |
> | **Tokens utilizados** | `{tokens.get('total', 0):,}` |
> | **Versión del prompt** | `{ai_eval_data.get('prompt_version', '1.0')}` |

---

## 📊 Resumen Ejecutivo

{evaluation.get('summary', 'No hay resumen disponible.')}

> **Recomendación:** {gate_data.get('deploy_recommendation', evaluation.get('deploy_recommendation', 'Revisar hallazgos manualmente.'))}

---

## 🚦 Decisión Final del Security Gate

| Campo | Valor |
|---|---|
| **Decisión** | {decision_icon} **{final_decision}** |
| **Fuente** | {gate_data.get('decision_source', 'N/A')} |
| **Nivel de riesgo** | {evaluation.get('risk_level', 'N/A')} |
| **Risk Score** | {risk_score:.1f} / 10.0 |
| **Confianza IA** | {evaluation.get('confidence', 0):.0%} |
| **Falsos positivos estimados** | {evaluation.get('false_positive_estimate', 'N/A')} |

"""

    conditions = gate_data.get('conditions_to_deploy', evaluation.get('conditions', []))
    if conditions:
        report += "### ⚠️ Condiciones para despliegue\n\n"
        for c in conditions:
            report += f"- {c}\n"
        report += "\n"

    report += f"""---

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

### Razonamiento Técnico

{evaluation.get('reasoning', 'No hay razonamiento disponible.')}

### Categorías OWASP Top 10 Detectadas

"""
    owasp = evaluation.get('owasp_top10_present', [])
    if owasp:
        for cat in owasp:
            report += f"- `{cat}`\n"
    else:
        report += "- _No se identificaron categorías específicas_\n"

    report += f"""
### Análisis de Cobertura

| Tipo de Análisis | Cobertura | Estado |
|---|---|---|
| SAST – Código fuente | {coverage.get('sast_coverage', 'N/A')} | {COVERAGE_ICONS.get(coverage.get('sast_coverage', ''), '❓')} |
| SCA – Dependencias | {coverage.get('sca_coverage', 'N/A')} | {COVERAGE_ICONS.get(coverage.get('sca_coverage', ''), '❓')} |
| DAST – Tiempo de ejecución | {coverage.get('dast_coverage', 'N/A')} | {COVERAGE_ICONS.get(coverage.get('dast_coverage', ''), '❓')} |
| Pentesting automatizado | {coverage.get('pentest_coverage', 'N/A')} | {COVERAGE_ICONS.get(coverage.get('pentest_coverage', ''), '❓')} |

**Evaluación general:** {coverage.get('overall_coverage', 'N/A')}

"""
    if blind_spots:
        report += "### ⚠️ Áreas sin cobertura (Blind Spots)\n\n"
        for bs in blind_spots:
            report += f"- {bs}\n"
        report += "\n"

    report += f"""---

## 🏆 Hallazgos Principales Identificados por IA

{format_key_findings_table(key_findings)}

---

## 🔗 Análisis de Cadenas de Ataque

> Esta sección identifica combinaciones de vulnerabilidades que, explotadas en secuencia,
> producen un impacto mayor al de cada vulnerabilidad de forma individual.

"""
    report += format_attack_chains(attack_chains)

    report += f"""---

## 🛠️ Hoja de Ruta de Remediación

{format_remediation_roadmap(evaluation.get('remediation_priorities', []))}

---

## 🔄 Comparación: Gate Tradicional vs Gate Asistido por IA

> Esta sección documenta la contribución principal del trabajo de grado:
> demostrar que la evaluación asistida por IA aporta valor sobre los umbrales estáticos.

{format_comparison_section(gate_comparison, ai_eval_data)}

---

## 📋 Hallazgos Críticos y Altos (Detalle Técnico)

"""

    critical_high = [f for f in findings if f.get('severity') in ['CRITICAL', 'HIGH']][:20]

    if critical_high:
        for f in critical_high:
            icon = SEVERITY_ICONS.get(f.get('severity'), '⚪')
            report += f"### {icon} [{f.get('severity')}] {f.get('title', 'Unknown')}\n\n"
            report += f"| Campo | Valor |\n|---|---|\n"
            report += f"| **ID** | `{f.get('id', 'N/A')}` |\n"
            report += f"| **Herramienta** | `{f.get('tool', 'N/A').upper()}` ({f.get('tool_type', 'N/A')}) |\n"
            report += f"| **Categoría** | {f.get('category', 'N/A')} |\n"
            if f.get('cwe'):
                report += f"| **CWE** | `{f.get('cwe')}` |\n"
            if f.get('cvss_score'):
                report += f"| **CVSS Score** | `{f.get('cvss_score')}` |\n"
            location = f.get('location', {})
            if location.get('file'):
                report += f"| **Archivo** | `{location['file']}:{location.get('line', '?')}` |\n"
            if location.get('endpoint'):
                report += f"| **Endpoint** | `{location.get('method', 'GET')} {location['endpoint']}` |\n"
            report += f"\n**Descripción:** {f.get('description', 'N/A')[:400]}\n\n"
            if f.get('remediation'):
                report += f"**✅ Remediación:** {f.get('remediation', 'N/A')[:250]}\n\n"
            report += "---\n\n"
    else:
        report += "_No se encontraron hallazgos críticos o altos._\n\n"

    report += f"""---

## 🎓 Notas Académicas

Este reporte fue generado automáticamente por el pipeline DevSecOps implementado como
Trabajo de Grado en la Universidad del Valle – Sede Tuluá.

### Marco de referencia
- **ISO/IEC 27034:** Principios de seguridad de aplicaciones
- **OWASP Top 10 (2021):** Categorización de riesgos web
- **CVSS v3.1:** Sistema de puntuación de vulnerabilidades
- **CWE/SANS Top 25:** Debilidades más peligrosas del software
- **MITRE ATT&CK:** Framework de tácticas y técnicas de ataque

### Herramientas integradas

| Herramienta | Tipo | Propósito |
|---|---|---|
| Semgrep | SAST | Análisis estático del código fuente |
| Trivy | SCA | Análisis de componentes y dependencias |
| OWASP ZAP | DAST | Pruebas dinámicas en tiempo de ejecución |
| Nuclei | Pentesting | Validación activa de vulnerabilidades conocidas |

### Contribución del componente IA

| Capacidad | Gate Tradicional | Gate con IA |
|---|---|---|
| Detección de falsos positivos | ❌ | ✅ |
| Análisis de explotabilidad | ❌ | ✅ |
| Cadenas de ataque | ❌ | ✅ |
| Blind spots de cobertura | ❌ | ✅ |
| Impacto de negocio | ❌ | ✅ |
| Priorización contextual | ❌ | ✅ |

### Limitaciones
- Pipeline ejecutado en entorno de laboratorio con OWASP Juice Shop
- La evaluación IA requiere validación humana para decisiones críticas
- No reemplaza una auditoría de seguridad formal
- Los hallazgos de Juice Shop son deliberados (aplicación intencionalmente vulnerable)

---

_Reporte generado el {timestamp} | Pipeline: {pipeline_run}_

_Autores: Jhojan Stiven Castaño Jejen & Juan Manuel Arango Rodas_
_Universidad del Valle – Ingeniería de Sistemas – 2026_
"""

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"  ✅ Reporte generado: {output_path}")
    print(f"  📄 Tamaño: {len(report):,} caracteres")
    print(f"  🔗 Cadenas de ataque: {len(attack_chains)}")
    print(f"  🚦 Decisión: {final_decision}")
    print("="*60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--findings', required=True)
    parser.add_argument('--ai-evaluation', required=True)
    parser.add_argument('--gate-decision', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    generate_report(args.findings, args.ai_evaluation, args.gate_decision, args.output)