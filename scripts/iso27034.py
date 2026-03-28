#!/usr/bin/env python3
"""
iso27034.py – Operacionalización de ISO/IEC 27034 en el pipeline DevSecOps
Trabajo de Grado – Universidad del Valle 2026

Este módulo implementa los conceptos centrales de la norma ISO/IEC 27034-1:2011:

  - Application Normative Framework (ANF) §7.3.3
  - Application Security Controls (ASC)  §7.3.5
  - Target Level of Trust (TLOT)          §7.3.4
  - Actual Level of Trust (ALOT)          §7.3.4
  - ANF Validation (ALOT >= TLOT?)        §7.3.6
  - ASC Verification Report               §7.3.7

La decisión de despliegue del gate.py se fundamenta en este modelo de confianza,
siendo esta operacionalización la contribución normativa central del Trabajo de Grado.
"""

import json
import os
from typing import Optional

# ── ASC trust contributions (peso de cada control en el ALOT) ─────────────────
ASC_CONTRIBUTIONS = {
    "semgrep": {"asc_id": "ASC-SAST-001",   "name": "Static Application Security Testing",    "contribution": 0.25},
    "trivy":   {"asc_id": "ASC-SCA-001",    "name": "Software Composition Analysis",           "contribution": 0.25},
    "zap":     {"asc_id": "ASC-DAST-001",   "name": "Dynamic Application Security Testing",    "contribution": 0.25},
    "nuclei":  {"asc_id": "ASC-PENTEST-001","name": "Automated Penetration Testing",           "contribution": 0.25},
}

# ── TLOT por criticidad (ISO/IEC 27034-1 §7.3.4) ─────────────────────────────
TLOT_BY_CRITICALITY = {
    "low":      {"score": 0.50, "required_ascs": ["semgrep", "trivy"]},
    "medium":   {"score": 0.65, "required_ascs": ["semgrep", "trivy", "zap", "nuclei"]},
    "high":     {"score": 0.80, "required_ascs": ["semgrep", "trivy", "zap", "nuclei"]},
    "critical": {"score": 0.95, "required_ascs": ["semgrep", "trivy", "zap", "nuclei"]},
}

# ── Penalizaciones al ALOT ─────────────────────────────────────────────────────
PENALTIES = [
    {"condition": "critical > 0",         "penalty": 0.40, "ref": "§7.3.4 — CRITICAL findings"},
    {"condition": "high >= 5",            "penalty": 0.25, "ref": "§7.3.4 — HIGH findings ≥ 5"},
    {"condition": "0 < high < 5",         "penalty": 0.10, "ref": "§7.3.4 — HIGH findings 1-4"},
    {"condition": "missing_asc",          "penalty": 0.15, "ref": "§7.3.5 — ASC not executed (per ASC)"},
]


def calculate_tlot(criticality: str) -> dict:
    """
    Determina el Target Level of Trust (TLOT) para el servicio.
    ISO/IEC 27034-1 §7.3.4

    Args:
        criticality: 'low' | 'medium' | 'high' | 'critical'

    Returns:
        dict con score TLOT y ASCs requeridos.
    """
    c = criticality.lower() if criticality else "medium"
    tlot = TLOT_BY_CRITICALITY.get(c, TLOT_BY_CRITICALITY["medium"])
    return {
        "criticality": c,
        "tlot_score": tlot["score"],
        "required_ascs": tlot["required_ascs"],
        "ref": "ISO/IEC 27034-1 §7.3.4",
    }


def calculate_alot(findings_data: dict, criticality: str) -> dict:
    """
    Calcula el Actual Level of Trust (ALOT) alcanzado por el pipeline.
    ISO/IEC 27034-1 §7.3.4

    El ALOT = sum(contribution_i * execution_i) * (1 - total_penalty)

    Args:
        findings_data: dict del findings.json normalizado
        criticality:   criticidad del servicio

    Returns:
        dict con ALOT score, desglose de contribuciones y penalizaciones aplicadas.
    """
    summary       = findings_data.get("summary", {})
    by_sev        = summary.get("by_severity", {})
    tools_executed= findings_data.get("tools_executed", {})

    critical = by_sev.get("CRITICAL", 0)
    high     = by_sev.get("HIGH", 0)

    tlot_data = calculate_tlot(criticality)
    required_ascs = tlot_data["required_ascs"]

    # ── Contribución base por ASC ejecutado ───────────────────────────────────
    asc_breakdown = []
    base_score    = 0.0
    missing_ascs  = []

    for tool, asc_meta in ASC_CONTRIBUTIONS.items():
        executed = tools_executed.get(tool, 0) > 0
        required = tool in required_ascs

        if executed:
            contribution = asc_meta["contribution"]
            base_score  += contribution
            asc_breakdown.append({
                "asc_id":       asc_meta["asc_id"],
                "tool":         tool,
                "name":         asc_meta["name"],
                "status":       "executed",
                "contribution": contribution,
                "required":     required,
            })
        else:
            asc_breakdown.append({
                "asc_id":       asc_meta["asc_id"],
                "tool":         tool,
                "name":         asc_meta["name"],
                "status":       "not_executed",
                "contribution": 0.0,
                "required":     required,
            })
            if required:
                missing_ascs.append(tool)

    # ── Penalizaciones ─────────────────────────────────────────────────────────
    penalties_applied = []
    total_penalty     = 0.0

    if critical > 0:
        p = 0.40
        total_penalty += p
        penalties_applied.append({
            "reason":  f"{critical} hallazgo(s) CRITICAL detectado(s)",
            "penalty": p,
            "ref":     "ISO/IEC 27034-1 §7.3.4",
        })

    if high >= 5:
        p = 0.25
        total_penalty += p
        penalties_applied.append({
            "reason":  f"{high} hallazgos HIGH (≥ 5)",
            "penalty": p,
            "ref":     "ISO/IEC 27034-1 §7.3.4",
        })
    elif high >= 1:
        p = 0.10
        total_penalty += p
        penalties_applied.append({
            "reason":  f"{high} hallazgo(s) HIGH (1–4)",
            "penalty": p,
            "ref":     "ISO/IEC 27034-1 §7.3.4",
        })

    for missing in missing_ascs:
        p = 0.15
        total_penalty += p
        penalties_applied.append({
            "reason":  f"ASC obligatorio no ejecutado: {ASC_CONTRIBUTIONS[missing]['asc_id']} ({missing})",
            "penalty": p,
            "ref":     "ISO/IEC 27034-1 §7.3.5",
        })

    # Penalización máxima = 1.0 (no puede ser negativo)
    total_penalty = min(total_penalty, 1.0)

    alot_score = round(base_score * (1.0 - total_penalty), 4)
    alot_score = max(0.0, alot_score)

    return {
        "alot_score":         alot_score,
        "base_score":         round(base_score, 4),
        "total_penalty":      round(total_penalty, 4),
        "asc_breakdown":      asc_breakdown,
        "penalties_applied":  penalties_applied,
        "missing_ascs":       missing_ascs,
        "ref":                "ISO/IEC 27034-1 §7.3.4",
    }


def iso27034_decision(findings_data: dict, criticality: str) -> dict:
    """
    Toma la decisión de despliegue según la validación ANF de ISO/IEC 27034.
    ISO/IEC 27034-1 §7.3.6 — Application Security Validation

    Reglas:
      - ALOT >= TLOT  AND  critical == 0  →  PASS
      - ALOT >= TLOT * 0.85  AND  critical == 0  →  CONDITIONAL
      - ALOT < TLOT * 0.85   OR   critical > 0   →  FAIL

    Returns:
        dict con decisión, TLOT, ALOT y justificación normativa completa.
    """
    by_sev   = findings_data.get("summary", {}).get("by_severity", {})
    critical = by_sev.get("CRITICAL", 0)

    tlot_data = calculate_tlot(criticality)
    alot_data = calculate_alot(findings_data, criticality)

    tlot_score = tlot_data["tlot_score"]
    alot_score = alot_data["alot_score"]
    gap        = round(tlot_score - alot_score, 4)
    gap_pct    = round((gap / tlot_score) * 100, 1) if tlot_score > 0 else 0

    # ── Decisión según §7.3.6 ─────────────────────────────────────────────────
    if alot_score >= tlot_score and critical == 0:
        decision  = "PASS"
        iso_label = "Nivel de confianza alcanzado (ALOT ≥ TLOT)"
        reasoning = (
            f"El pipeline alcanzó ALOT={alot_score:.3f} ≥ TLOT={tlot_score:.3f} "
            f"para criticidad '{criticality}', con 0 hallazgos CRITICAL. "
            f"La aplicación cumple el nivel de confianza objetivo de la norma ISO/IEC 27034-1 §7.3.6."
        )
    elif alot_score >= tlot_score * 0.85 and critical == 0:
        decision  = "CONDITIONAL"
        iso_label = "Nivel de confianza parcial (ALOT ≥ 85% del TLOT)"
        reasoning = (
            f"El pipeline alcanzó ALOT={alot_score:.3f}, que es ≥85% del "
            f"TLOT={tlot_score:.3f} ({gap_pct:.1f}% de brecha). "
            f"No hay hallazgos CRITICAL pero existen condiciones de remediación antes del despliegue."
        )
    else:
        decision  = "FAIL"
        if critical > 0:
            iso_label = "Hallazgos CRITICAL — nivel de confianza inaceptable"
            reasoning = (
                f"Se detectaron {critical} hallazgo(s) CRITICAL. "
                f"Bajo ISO/IEC 27034-1 §7.3.4, la presencia de hallazgos CRITICAL "
                f"es incompatible con cualquier nivel de confianza objetivo. "
                f"ALOT={alot_score:.3f} vs TLOT={tlot_score:.3f}."
            )
        else:
            iso_label = "Nivel de confianza insuficiente (ALOT < 85% del TLOT)"
            reasoning = (
                f"El pipeline alcanzó ALOT={alot_score:.3f}, inferior al 85% del "
                f"TLOT={tlot_score:.3f} requerido para criticidad '{criticality}' "
                f"(brecha: {gap_pct:.1f}%). Se requiere remediación de hallazgos "
                f"y posiblemente ejecución de ASCs faltantes."
            )

    return {
        "schema":          "ISO/IEC 27034-1:2011 — Application Security Validation §7.3.6",
        "decision":        decision,
        "iso_label":       iso_label,
        "reasoning":       reasoning,
        "tlot":            tlot_data,
        "alot":            alot_data,
        "gap_to_tlot":     gap,
        "gap_pct":         gap_pct,
        "compliant":       decision == "PASS",
        "conditions": (
            [
                f"Remediar los {critical} hallazgo(s) CRITICAL antes del despliegue",
            ] if critical > 0 else []
        ) + (
            [f"Ejecutar ASC obligatorio faltante: {a}" for a in alot_data.get("missing_ascs", [])]
        ),
    }


def generate_iso27034_report_section(iso_result: dict) -> str:
    """
    Genera la sección Markdown del reporte de auditoría ISO/IEC 27034.
    ISO/IEC 27034-1 §7.3.7 — ASC Verification Report
    """
    tlot   = iso_result["tlot"]
    alot   = iso_result["alot"]
    dec    = iso_result["decision"]
    icons  = {"PASS": "✅", "CONDITIONAL": "⚠️", "FAIL": "❌"}
    icon   = icons.get(dec, "❓")

    lines = [
        "---",
        "",
        "## 📋 Evaluación de Conformidad ISO/IEC 27034",
        "",
        "> **Norma:** ISO/IEC 27034-1:2011 — Application Security  ",
        "> **Sección aplicada:** §7.3.4 (TLOT/ALOT), §7.3.5 (ASCs), §7.3.6 (Validación ANF)",
        "",
        "### Modelo de Niveles de Confianza",
        "",
        f"| Indicador | Valor | Referencia norma |",
        f"|---|---|---|",
        f"| **TLOT** (Target Level of Trust) | `{tlot['tlot_score']:.3f}` | ISO/IEC 27034-1 §7.3.4 |",
        f"| **ALOT** (Actual Level of Trust) | `{alot['alot_score']:.3f}` | ISO/IEC 27034-1 §7.3.4 |",
        f"| **Brecha TLOT − ALOT** | `{iso_result['gap_to_tlot']:.3f}` ({iso_result['gap_pct']:.1f}%) | — |",
        f"| **Decisión ANF** | {icon} **{dec}** — {iso_result['iso_label']} | ISO/IEC 27034-1 §7.3.6 |",
        f"| **Criticidad del servicio** | `{tlot['criticality']}` | — |",
        "",
        "**Justificación normativa:** " + iso_result["reasoning"],
        "",
        "### Estado de Ejecución de ASCs (Application Security Controls)",
        "",
        "| ASC ID | Control | Herramienta | Estado | Contribución al ALOT | Obligatorio |",
        "|---|---|---|---|---|---|",
    ]

    for asc in alot["asc_breakdown"]:
        status_icon = "✅" if asc["status"] == "executed" else "❌"
        req_icon    = "✓" if asc["required"] else "—"
        contrib     = f"`{asc['contribution']:.2f}`" if asc["status"] == "executed" else "`0.00`"
        lines.append(
            f"| `{asc['asc_id']}` | {asc['name']} | `{asc['tool']}` "
            f"| {status_icon} {asc['status'].replace('_',' ').title()} "
            f"| {contrib} | {req_icon} |"
        )

    lines += [
        "",
        "### Penalizaciones aplicadas al ALOT",
        "",
    ]

    if alot["penalties_applied"]:
        lines += [
            "| Razón | Penalización | Referencia |",
            "|---|---|---|",
        ]
        for p in alot["penalties_applied"]:
            lines.append(f"| {p['reason']} | `−{p['penalty']:.2f}` | {p['ref']} |")
    else:
        lines.append("_No se aplicaron penalizaciones — pipeline sin hallazgos críticos/altos y todos los ASCs ejecutados._")

    if iso_result.get("conditions"):
        lines += ["", "### Condiciones para alcanzar TLOT", ""]
        for c in iso_result["conditions"]:
            lines.append(f"- {c}")

    lines += [
        "",
        "### Cálculo del ALOT",
        "",
        f"```",
        f"Score base   = {alot['base_score']:.4f}  (suma de contribuciones de ASCs ejecutados)",
        f"Penalización = {alot['total_penalty']:.4f}",
        f"ALOT         = {alot['base_score']:.4f} × (1 − {alot['total_penalty']:.4f}) = {alot['alot_score']:.4f}",
        f"TLOT         = {tlot['tlot_score']:.4f}",
        f"ALOT ≥ TLOT? → {'SÍ' if alot['alot_score'] >= tlot['tlot_score'] else 'NO'} → Decisión: {dec}",
        f"```",
        "",
        "_Este reporte constituye el Registro de Verificación de ASCs requerido por ISO/IEC 27034-1 §7.3.7._",
        "",
    ]

    return "\n".join(lines)


if __name__ == "__main__":
    # Demo: cargar findings.json y calcular TLOT/ALOT
    import sys
    if len(sys.argv) < 3:
        print("Uso: python3 iso27034.py <findings.json> <criticality>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        findings = json.load(f)

    result = iso27034_decision(findings, sys.argv[2])

    print(f"\n{'='*60}")
    print(f"  ISO/IEC 27034 — Validación ANF")
    print(f"{'='*60}")
    print(f"  TLOT     : {result['tlot']['tlot_score']:.3f}")
    print(f"  ALOT     : {result['alot']['alot_score']:.3f}")
    print(f"  Decisión : {result['decision']} — {result['iso_label']}")
    print(f"{'='*60}\n")
    print(generate_iso27034_report_section(result))