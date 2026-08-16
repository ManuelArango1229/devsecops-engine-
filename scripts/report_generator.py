#!/usr/bin/env python3
"""
report_generator.py — Generador de Reporte Final en Markdown
DevSecOps Engine v1.3 — Trabajo de Grado — Universidad del Valle 2026
Jhojan Stiven Castaño Jejen & Juan Manuel Arango Rodas
"""

import json
import argparse
import os
from datetime import datetime

# ── Constantes de presentación ────────────────────────────────────────────────
SEVERITY_ICONS = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"
}
DECISION_ICONS = {"PASS": "✅", "FAIL": "❌", "CONDITIONAL": "⚠️"}
COVERAGE_ICONS = {"buena": "✅", "parcial": "🟡", "ninguna": "❌"}

# ASCs canónicos que el pipeline puede ejecutar, con su descripción
ASC_CATALOG = {
    "ASC-SAST-001":    ("Semgrep OSS",   "Análisis estático de código fuente"),
    "ASC-SCA-001":     ("Trivy",         "Análisis de componentes y dependencias (CVEs)"),
    "ASC-DAST-001":    ("OWASP ZAP",     "Análisis dinámico en tiempo de ejecución"),
    "ASC-PENTEST-001": ("Nuclei v3",     "Validación activa con templates de pentest"),
}

TOOL_META = {
    "semgrep": {
        "name": "Semgrep (SAST)", "type": "Análisis Estático de Código",
        "icon": "🔐", "asc": "ASC-SAST-001",
        "dedup_reason": (
            "Semgrep analiza el código fuente del repositorio consumidor. "
            "La deduplicación elimina la misma regla disparada en múltiples archivos "
            "del mismo módulo, conservando solo la primera ocurrencia por regla + ruta."
        ),
    },
    "trivy": {
        "name": "Trivy (SCA)", "type": "Análisis de Componentes de Software",
        "icon": "🔬", "asc": "ASC-SCA-001",
        "dedup_reason": (
            "La misma CVE sobre el mismo paquete puede aparecer una vez por ruta de "
            "instalación. Tras deduplicar por CVE + paquete + target queda una sola "
            "entrada. Los removidos son instancias duplicadas, no falsos positivos."
        ),
    },
    "zap": {
        "name": "OWASP ZAP (DAST)", "type": "Análisis Dinámico en Ejecución",
        "icon": "🌐", "asc": "ASC-DAST-001",
        "dedup_reason": (
            "ZAP realiza escaneo baseline pasivo. Cada alerta representa un tipo de "
            "misconfiguration único — por eso la deduplicación raramente elimina "
            "hallazgos: todas las alertas suelen tener títulos distintos."
        ),
    },
    "nuclei": {
        "name": "Nuclei (Pentesting)", "type": "Validación Activa de Templates",
        "icon": "🎯", "asc": "ASC-PENTEST-001",
        "dedup_reason": (
            "Nuclei puede disparar el mismo template en el mismo endpoint varias veces "
            "dentro del mismo run. Tras deduplicar por template + endpoint se conserva "
            "solo una entrada por hallazgo único."
        ),
    },
}


# ── Utilidades ────────────────────────────────────────────────────────────────
def sev_order(s):
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    return order.index(s) if s in order else 99

def pct(part, total):
    return f"{part / total * 100:.1f}%" if total else "0.0%"

def bar(part, total, width=20):
    filled = int(part / total * width) if total else 0
    return "█" * filled + "░" * (width - filled)


# ── Construcción del bloque ISO 27034 ─────────────────────────────────────────
def build_iso27034_traceability(scan_config, findings_list):
    """
    Construye el bloque de trazabilidad ISO/IEC 27034 directamente desde
    scan_config.json y findings.json.
    gate.py no escribe este bloque, así que lo calculamos aquí.
    """
    anf          = scan_config.get("iso27034_anf", {})
    required_ids = anf.get("required_ascs", [])
    optional_ids = anf.get("optional_ascs", [])

    # Si el detector no generó el ANF, usamos los 4 ASCs canónicos como requeridos
    if not required_ids:
        required_ids = list(ASC_CATALOG.keys())

    all_asc_ids  = required_ids + [a for a in optional_ids if a not in required_ids]
    executed_set = {f.get("asc_id") for f in findings_list if f.get("asc_id")}

    breakdown = []
    for asc in all_asc_ids:
        tool_name, tool_desc = ASC_CATALOG.get(asc, ("Herramienta", "Control de seguridad"))
        findings_for_asc = [f for f in findings_list if f.get("asc_id") == asc]
        breakdown.append({
            "asc_id":          asc,
            "required":        asc in required_ids,
            "status":          "executed" if asc in executed_set else "not_executed",
            "tool":            tool_name,
            "description":     tool_desc,
            "findings_count":  len(findings_for_asc),
            "severity_dist":   {
                sev: sum(1 for f in findings_for_asc if f.get("severity") == sev)
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                if any(f.get("severity") == sev for f in findings_for_asc)
            },
        })

    return {
        "ascs_executed":  list(executed_set),
        "asc_breakdown":  breakdown,
        "language":       scan_config.get("language", "unknown"),
        "criticality":    scan_config.get("business_criticality", "medium"),
        "scan_mode":      scan_config.get("scan_mode", "unknown"),
        "anf_defined":    bool(anf),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  SECCIONES DEL REPORTE
# ══════════════════════════════════════════════════════════════════════════════

def section_header(findings_data, ai_eval_data, gate_data):
    final_decision = gate_data.get("decision", "UNKNOWN")
    decision_icon  = DECISION_ICONS.get(final_decision, "❓")
    timestamp      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    service        = findings_data.get("service", "unknown")
    environment    = findings_data.get("environment", "staging")
    criticality    = findings_data.get("business_criticality", "medium")
    pipeline_run   = findings_data.get("pipeline_run", "local")
    ai_model       = ai_eval_data.get("ai_model", "N/A")
    tokens         = ai_eval_data.get("tokens_used", {})
    evaluation     = ai_eval_data.get("evaluation", {})

    tra         = gate_data.get("iso27034_traceability", {})
    breakdown   = tra.get("asc_breakdown", [])
    req         = [b for b in breakdown if b.get("required")]
    exec_req    = [b for b in req if b.get("status") == "executed"]
    if breakdown:
        iso_line = f"✅ {len(exec_req)}/{len(req)} ASC obligatorios ejecutados"
    else:
        iso_line = "⚠️ Sin datos de trazabilidad en esta corrida"

    enrichment      = ai_eval_data.get("ssvc_enrichment", {})
    hybrid_status   = "✅ Motor híbrido activo" if enrichment.get("used") else "⚠️ Evaluador estático (fallback)"

    return f"""# 🔐 Reporte de Seguridad DevSecOps
## {decision_icon} Decisión de Despliegue: **{final_decision}**

---

> **Generado automáticamente por el DevSecOps Engine v1.3 — Universidad del Valle 2026**

| Campo | Valor |
|---|---|
| **Servicio** | `{service}` |
| **Entorno** | `{environment}` |
| **Criticidad de negocio** | `{criticality}` |
| **Pipeline Run** | `{pipeline_run}` |
| **Timestamp** | `{timestamp}` |
| **Modelo IA** | `{ai_model}` |
| **Tokens utilizados** | `{tokens.get('total', 0):,}` (prompt: {tokens.get('prompt', 0):,} / completion: {tokens.get('completion', 0):,}) |
| **Motor IA híbrido** | {hybrid_status} |
| **ISO/IEC 27034 — Trazabilidad** | {iso_line} |

---

## 📊 Resumen Ejecutivo

{evaluation.get('summary', 'No hay resumen disponible.')}

> **Recomendación del sistema:** {gate_data.get('deploy_recommendation', evaluation.get('deploy_recommendation', 'Revisar hallazgos manualmente.'))}

"""


def section_gate(gate_data, ai_eval_data):
    evaluation     = ai_eval_data.get("evaluation", {})
    final_decision = gate_data.get("decision", "UNKNOWN")
    decision_icon  = DECISION_ICONS.get(final_decision, "❓")
    risk_score     = evaluation.get("risk_score", 0.0)
    confidence     = evaluation.get("confidence", 0)
    risk_level     = evaluation.get("risk_level", "N/A")
    fp_estimate    = evaluation.get("false_positive_estimate", "N/A")

    tra       = gate_data.get("iso27034_traceability", {})
    breakdown = tra.get("asc_breakdown", [])
    req       = [b for b in breakdown if b.get("required")]
    exec_req  = [b for b in req if b.get("status") == "executed"]
    if breakdown:
        iso_line = f"`{len(exec_req)}/{len(req)}` ASC obligatorios ejecutados (ver sección ISO/IEC 27034)"
    else:
        iso_line = "Sin datos de trazabilidad para esta corrida"

    md = f"""---

## 🚦 Decisión Final del Security Gate

| Campo | Valor |
|---|---|
| **Decisión** | {decision_icon} **{final_decision}** |
| **Fuente** | `{gate_data.get('decision_source', 'N/A')}` |
| **Nivel de riesgo (IA)** | `{risk_level}` |
| **Risk Score (IA)** | `{risk_score:.1f} / 10.0` |
| **Confianza IA** | `{confidence:.0%}` |
| **Falsos positivos estimados** | `{fp_estimate}` |
| **ISO/IEC 27034 — Trazabilidad ANF** | {iso_line} |

"""
    conditions = gate_data.get("conditions_to_deploy", evaluation.get("conditions", []))
    if conditions:
        md += "### ⚠️ Condiciones para despliegue\n\n"
        for c in conditions:
            md += f"- {c}\n"
        md += "\n"

    warning = gate_data.get("_pipeline_warning")
    if warning:
        md += f"> ⚠️ **Advertencia de pipeline:** {warning}\n\n"

    return md


def section_stats(summary, tools_executed):
    by_sev  = summary.get("by_severity", {})
    by_tool = summary.get("by_tool", {})
    total   = summary.get("total", 0)
    by_cat  = summary.get("by_category", {})

    sev_rows = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_sev.get(sev, 0)
        sev_rows += f"| {SEVERITY_ICONS.get(sev)} {sev} | {count} | {pct(count, total)} | `{bar(count, total, 15)}` |\n"

    tool_rows = ""
    for tool in ["semgrep", "trivy", "zap", "nuclei"]:
        meta    = TOOL_META.get(tool, {})
        raw     = tools_executed.get(tool, 0)
        dedup   = by_tool.get(tool, 0)
        removed = raw - dedup
        status  = "✅ Ejecutado" if raw > 0 else "⚠️ Sin hallazgos"
        tool_rows += (
            f"| {meta.get('icon','')} {meta.get('name', tool)} "
            f"| `{meta.get('asc','')}` "
            f"| {raw} | {dedup} | {removed} | {pct(removed, raw) if raw else '—'} | {status} |\n"
        )

    cat_rows = ""
    for cat, count in sorted(by_cat.items(), key=lambda x: x[1], reverse=True)[:5]:
        cat_rows += f"| `{cat}` | {count} | {pct(count, total)} | `{bar(count, total, 12)}` |\n"

    return f"""---

## 📈 Estadísticas Globales de Hallazgos

### Distribución por Severidad

| Severidad | Hallazgos | % del total | Proporción |
|---|---|---|---|
{sev_rows}| ─ | **{total}** | **100%** | |

### Cobertura por Herramienta y ASC ISO/IEC 27034

> Cada herramienta tiene asignado un ASC (Application Security Control) de ISO/IEC 27034.
> La columna **Removidos** indica duplicados eliminados, no falsos positivos.

| Herramienta | ASC ISO 27034 | Raw | Únicos | Removidos | % Dedup | Estado |
|---|---|---|---|---|---|---|
{tool_rows}
### Top 5 Categorías OWASP Top 10

| Categoría | Hallazgos | % del total | Proporción |
|---|---|---|---|
{cat_rows}
"""


def section_dedup_explanation(tools_executed, summary):
    by_tool     = summary.get("by_tool", {})
    total_raw   = sum(tools_executed.values())
    total_dedup = sum(by_tool.values())
    removed     = total_raw - total_dedup

    md = f"""---

## 🔄 Metodología de Deduplicación

> El normalizador aplica deduplicación para evitar el doble conteo de vulnerabilidades
> detectadas por múltiples instancias de la misma herramienta.
>
> **Total raw:** {total_raw} hallazgos → **Total único:** {total_dedup} → **Eliminados:** {removed} ({pct(removed, total_raw)} de reducción)

"""
    for tool in ["trivy", "zap", "nuclei", "semgrep"]:
        meta      = TOOL_META.get(tool, {})
        raw       = tools_executed.get(tool, 0)
        dedup     = by_tool.get(tool, 0)
        removed_t = raw - dedup
        md += f"### {meta.get('icon','')} {meta.get('name', tool)} — {meta.get('type','')}\n\n"
        md += f"- **Raw:** {raw} | **Únicos:** {dedup} | **Removidos:** {removed_t} ({pct(removed_t, raw) if raw else '0%'})\n"
        md += f"- **Criterio:** `tool + título + endpoint/archivo`\n\n"
        md += f"> {meta.get('dedup_reason', '')}\n\n"

    return md


def section_recon(recon_data):
    if not recon_data or not recon_data.get("target_url"):
        return ""

    target_url  = recon_data.get("target_url", "N/A")
    nmap        = recon_data.get("nmap", {})
    routes      = recon_data.get("route_discovery", {})
    fingerprint = recon_data.get("fingerprint", {})
    waf         = recon_data.get("waf", {})
    recon_sum   = recon_data.get("summary", {})

    open_ports   = recon_sum.get("open_ports", [])
    technologies = recon_sum.get("technologies", [])
    missing_hdrs = recon_sum.get("missing_security_headers", [])
    waf_present  = recon_sum.get("waf_present", False)

    services = nmap.get("services", {})
    if services:
        ports_table = "| Puerto | Servicio | Versión | Interesante |\n|---|---|---|---|\n"
        for port, info in services.items():
            interesting  = "⚠️ Sí" if info.get("interesting") else "No"
            ports_table += f"| `{port}` | {info.get('service','?')} | {info.get('version','N/A')[:40]} | {interesting} |\n"
    else:
        ports_table = f"_Puerto {open_ports[0] if open_ports else 'N/A'} detectado._\n"

    discovered_routes  = routes.get("discovered_routes", [])
    interesting_routes = routes.get("interesting_routes", [])

    if discovered_routes:
        routes_section  = f"Se descubrieron **{len(discovered_routes)} rutas** activas, "
        routes_section += f"**{len(interesting_routes)} de interés**.\n\n"
        if interesting_routes:
            routes_section += "| Ruta | Estado |\n|---|---|\n"
            for r in interesting_routes[:15]:
                flag = "⚠️" if any(
                    k in r.lower() for k in
                    ["admin","env","git","backup","debug","actuator","swagger","api-docs","metrics"]
                ) else "ℹ️"
                routes_section += f"| `{r}` | {flag} Accesible |\n"
    else:
        routes_section = "_No se ejecutó descubrimiento de rutas._\n"

    present_hdrs  = fingerprint.get("security_headers", {}).get("present", [])
    all_headers   = [
        "content-security-policy","strict-transport-security","x-frame-options",
        "x-content-type-options","referrer-policy","permissions-policy",
        "cross-origin-embedder-policy","cross-origin-opener-policy",
    ]
    headers_table = "| Header de Seguridad | Estado |\n|---|---|\n"
    for h in all_headers:
        if h in present_hdrs:
            headers_table += f"| `{h}` | ✅ Presente |\n"
        elif h in missing_hdrs:
            headers_table += f"| `{h}` | ❌ Faltante |\n"
        else:
            headers_table += f"| `{h}` | ⚪ No verificado |\n"

    attack_surf     = recon_data.get("attack_surface", {})
    attack_findings = attack_surf.get("findings", [])
    if attack_findings:
        attack_section = "| Severidad | Tipo | Detalle |\n|---|---|---|\n"
        for f in attack_findings:
            icon = SEVERITY_ICONS.get(f.get("severity","INFO"), "⚪")
            attack_section += (
                f"| {icon} {f.get('severity')} "
                f"| `{f.get('type','')}` "
                f"| {f.get('detail','')[:100]} |\n"
            )
    else:
        attack_section = "_No se identificaron hallazgos en la superficie de ataque._\n"

    return f"""---

## 🕵️ Fase de Reconocimiento Activo

> El reconocimiento activo descubre la superficie de ataque real antes del escaneo
> dinámico, enriqueciendo los targets de Nuclei y ZAP.

| Campo | Valor |
|---|---|
| **URL objetivo** | `{target_url}` |
| **Host** | `{recon_data.get('host', 'N/A')}` |
| **Puerto** | `{recon_data.get('port', 'N/A')}` |
| **WAF detectado** | {'✅ Sí — ' + str(waf.get('waf_name','desconocido')) if waf_present else '❌ No detectado'} |
| **Servidor** | `{fingerprint.get('server', 'N/A') or 'No detectado'}` |
| **Tecnologías** | {', '.join(f'`{t}`' for t in technologies[:6]) if technologies else '_No detectadas_'} |
| **Targets generados para Nuclei** | {len(recon_data.get('nuclei_targets', []))} URLs |

### Puertos detectados (nmap)

{ports_table}

### Rutas descubiertas

{routes_section}

### Headers de seguridad HTTP

{headers_table}

### Superficie de ataque

{attack_section}

"""


def section_ai_analysis(evaluation, ai_eval_data):
    coverage    = evaluation.get("coverage_analysis", {})
    blind_spots = coverage.get("blind_spots", [])
    owasp       = evaluation.get("owasp_top10_present", [])

    owasp_rows = (
        "\n".join(f"- `{cat}`" for cat in owasp)
        if owasp else
        "- _No se identificaron categorías específicas_"
    )

    cov_rows = (
        f"| SAST – Código fuente | {coverage.get('sast_coverage','N/A')} | {COVERAGE_ICONS.get(coverage.get('sast_coverage',''),'❓')} |\n"
        f"| SCA – Dependencias | {coverage.get('sca_coverage','N/A')} | {COVERAGE_ICONS.get(coverage.get('sca_coverage',''),'❓')} |\n"
        f"| DAST – Tiempo de ejecución | {coverage.get('dast_coverage','N/A')} | {COVERAGE_ICONS.get(coverage.get('dast_coverage',''),'❓')} |\n"
        f"| Pentesting automatizado | {coverage.get('pentest_coverage','N/A')} | {COVERAGE_ICONS.get(coverage.get('pentest_coverage',''),'❓')} |"
    )

    blind_md = ""
    if blind_spots:
        blind_md = "### ⚠️ Áreas sin cobertura (Blind Spots)\n\n"
        for bs in blind_spots:
            blind_md += f"- {bs}\n"
        blind_md += "\n"

    key_findings = evaluation.get("key_findings", [])
    if key_findings:
        kf_rows = "| Severidad | Hallazgo | CVSS | Remoto | Auth | Exploit | Categoría |\n|---|---|---|---|---|---|---|\n"
        for f in key_findings:
            icon    = SEVERITY_ICONS.get(f.get("severity"), "⚪")
            title   = f.get("title", "Unknown")[:45]
            cvss    = f.get("cvss_score", "N/A")
            remote  = "🔴 Sí" if f.get("remote_exploitable") else "🟢 No"
            auth    = "🟢 No" if not f.get("auth_required") else "🔵 Sí"
            pub_exp = "⚠️ Sí" if f.get("public_exploit") else "No"
            cat     = f.get("category", "N/A")[:35]
            kf_rows += f"| {icon} {f.get('severity')} | {title} | `{cvss}` | {remote} | {auth} | {pub_exp} | {cat} |\n"
    else:
        kf_rows = "_No se identificaron hallazgos principales._\n"

    return f"""---

## 🤖 Evaluación Detallada por IA

### Razonamiento Técnico

{evaluation.get('reasoning', 'No hay razonamiento disponible.')}

**Análisis de falsos positivos:** {evaluation.get('false_positive_reasoning', 'N/A')}

### Categorías OWASP Top 10 Detectadas

{owasp_rows}

### Cobertura por Tipo de Herramienta

| Tipo de análisis | Cobertura | Estado |
|---|---|---|
{cov_rows}

**Evaluación general:** {coverage.get('overall_coverage', 'N/A')}

{blind_md}
### 🏆 Hallazgos Principales Identificados por IA

{kf_rows}
"""


def section_attack_chains(attack_chains):
    if not attack_chains:
        return """---

## 🔗 Análisis de Cadenas de Ataque

> Esta sección identifica combinaciones de vulnerabilidades que, explotadas en secuencia,
> producen un impacto mayor al de cada vulnerabilidad de forma individual.

_No se identificaron cadenas de ataque combinadas._

"""
    likelihood_map = {"alta": "🔴 Alta", "media": "🟠 Media", "baja": "🟢 Baja"}
    md = """---

## 🔗 Análisis de Cadenas de Ataque

> Esta sección identifica combinaciones de vulnerabilidades que, explotadas en secuencia,
> producen un impacto mayor al de cada vulnerabilidad de forma individual.

"""
    for chain in attack_chains:
        icon       = SEVERITY_ICONS.get(chain.get("severity"), "⚪")
        likelihood = likelihood_map.get(chain.get("likelihood",""), chain.get("likelihood","N/A"))
        md += f"### {icon} {chain.get('chain_id','CHAIN')} — {chain.get('title','Sin título')}\n\n"
        md += "| Campo | Valor |\n|---|---|\n"
        md += f"| **Severidad combinada** | {chain.get('severity','N/A')} |\n"
        md += f"| **Probabilidad** | {likelihood} |\n"
        md += f"| **Vulnerabilidades involucradas** | `{'`, `'.join(chain.get('finding_ids', []))}` |\n\n"
        md += "**Secuencia del ataque:**\n\n"
        for i, step in enumerate(chain.get("steps", []), 1):
            md += f"{i}. {step}\n"
        md += f"\n**Impacto combinado:** {chain.get('combined_impact','N/A')}\n\n---\n\n"
    return md


def section_remediation(remediation_priorities):
    if not remediation_priorities:
        return """---

## 🛠️ Hoja de Ruta de Remediación

_No se identificaron prioridades específicas._

"""
    immediate = [r for r in remediation_priorities if r.get("timeline") == "inmediato"]
    short     = [r for r in remediation_priorities if r.get("timeline") == "corto plazo"]
    long_     = [r for r in remediation_priorities if r.get("timeline") == "largo plazo"]

    md = "---\n\n## 🛠️ Hoja de Ruta de Remediación\n\n"

    if immediate:
        md += f"### 🚨 Inmediato (0–7 días) — {len(immediate)} acciones\n\n"
        for r in immediate:
            fix  = f" → Fix: `{r.get('fix_version')}`" if r.get("fix_version") else ""
            md  += f"**{r.get('priority','?')}.** {r.get('action','N/A')}{fix}\n"
            md  += f"   - `{r.get('tool','N/A')}` | Esfuerzo: _{r.get('effort','N/A')}_ | Fix disponible: {'✅' if r.get('fix_available') else '❌'}\n\n"

    if short:
        md += f"### ⚡ Corto plazo (1–4 semanas) — {len(short)} acciones\n\n"
        for r in short:
            fix  = f" → Fix: `{r.get('fix_version')}`" if r.get("fix_version") else ""
            md  += f"**{r.get('priority','?')}.** {r.get('action','N/A')}{fix}\n"
            md  += f"   - `{r.get('tool','N/A')}` | Esfuerzo: _{r.get('effort','N/A')}_ | Fix disponible: {'✅' if r.get('fix_available') else '❌'}\n\n"

    if long_:
        md += f"### 🔧 Largo plazo (1–3 meses) — {len(long_)} acciones\n\n"
        for r in long_:
            md += f"**{r.get('priority','?')}.** {r.get('action','N/A')}\n"
            md += f"   - `{r.get('tool','N/A')}` | Esfuerzo: _{r.get('effort','N/A')}_\n\n"

    return md


def section_ssvc(gate_data):
    gc   = gate_data.get("gate_comparison", {})
    ssvc = gc.get("ssvc", {})
    if not ssvc or ssvc.get("method") != "ssvc_epss_kev":
        return ""

    dec          = ssvc.get("decision", "?")
    agg          = ssvc.get("aggregate_action", "?")
    ac           = ssvc.get("action_counts", {})
    f1m          = ssvc.get("f1_metrics", {})
    ds           = ssvc.get("data_sources", {})
    mw           = ssvc.get("mission_wellbeing", "?")
    crit         = ssvc.get("criticality", "?")
    dec_icon     = DECISION_ICONS.get(dec, "❓")
    total_class  = sum(ac.values()) if ac else 0

    def pct_ac(k):
        return f"{ac.get(k,0)/total_class*100:.1f}%" if total_class else "0%"

    act_rows = ""
    for a in ssvc.get("top_act_findings", [])[:8]:
        act_rows += (
            f"| `{a.get('tool','')}` "
            f"| {a.get('title','')[:65]} "
            f"| {a.get('exploitation','?')} "
            f"| {a.get('automatable','?')} "
            f"| {a.get('tech_impact','?')} "
            f"| **Act** |\n"
        )
    if not act_rows:
        act_rows = "| — | Sin hallazgos Act — bajo perfil de explotación | — | — | — | PASS |\n"

    n_eval = f1m.get("cves_evaluated", 0)
    if n_eval and n_eval > 0:
        f1_block = f"""
### 📊 Métricas Formales — Dimensión Exploitation (F1 Score)

> Calculadas sobre CVEs con CISA KEV o EPSS disponible como *ground truth*.
> Metodología: Al Haddad et al. (2025) — arXiv 2510.18508.

| Métrica | Valor | Descripción |
|---|---|---|
| **Precisión** | `{f1m.get('precision', 0):.4f}` | TP / (TP + FP) |
| **Recall** | `{f1m.get('recall', 0):.4f}` | TP / (TP + FN) |
| **F1 Score** | `{f1m.get('f1_score', 0):.4f}` | Media armónica precisión/recall |
| **Accuracy** | `{f1m.get('accuracy', 0):.4f}` | (TP + TN) / total |
| CVEs evaluados | `{f1m.get('cves_evaluated', 0)}` | Solo CVEs con EPSS/KEV disponible |
| Verdaderos positivos | `{f1m.get('true_positives', 0)}` | Clasificados active, ground truth active |
| Falsos positivos | `{f1m.get('false_positives', 0)}` | Clasificados active, ground truth not_active |
| Falsos negativos | `{f1m.get('false_negatives', 0)}` | Clasificados not_active, ground truth active |

> **Ground truth:** CVE en CISA KEV **o** EPSS ≥ 0.5 → activo.
> **Nota:** hallazgos sin CVE ID (Semgrep/ZAP) excluidos del cálculo formal por ausencia
> de ground truth verificable en EPSS/KEV.
"""
    else:
        f1_block = """
### 📊 Métricas Formales — Dimensión Exploitation

> No se encontraron CVEs con EPSS disponible para calcular F1 en este caso.
> Esto es esperado cuando los hallazgos provienen principalmente de Semgrep/ZAP
> (sin CVE ID) o cuando todos los CVEs tienen EPSS bajo (paradoja de clases
> desbalanceadas: todos son verdaderos negativos → accuracy = 1.00, F1 = 0.00).
"""

    return f"""---

## 🔬 Gate SSVC + EPSS + CISA KEV

> **Tercer mecanismo de decisión del pipeline.** Reemplaza el modelo TLOT/ALOT que
> dependía de constantes arbitrarias (0.50/0.65/0.80/0.95) y saturaba en ALOT=0.35
> en todos los casos evaluados. SSVC v2.1 fue publicado por CISA/SEI-CERT y no
> requiere constantes propias.
>
> **Referencias:** Al Haddad et al. (2025), Kausar et al. (2025), Yoon et al. (2023).

### Resultado del Gate SSVC

| Indicador | Valor |
|---|---|
| **Decisión** | {dec_icon} **{dec}** |
| **Acción agregada** | `{agg}` (máximo sobre todos los hallazgos evaluados) |
| **Mission & Wellbeing** | `{mw}` (derivado de `criticality={crit}`) |
| **CISA KEV** | {ds.get('cisa_kev_entries', 0):,} entradas consultadas |
| **EPSS** | {ds.get('epss_scores_fetched', 0)} CVEs consultados vía FIRST.org API |

### Distribución de Acciones SSVC

| Acción | Hallazgos | % | Gate | Significado operativo |
|---|---|---|---|---|
| **Act** | `{ac.get('Act', 0)}` | {pct_ac('Act')} | ❌ FAIL | Explotación activa o automatizable con impacto total |
| **Attend** | `{ac.get('Attend', 0)}` | {pct_ac('Attend')} | ⚠️ CONDITIONAL | Explotación probable a corto plazo |
| **Track*** | `{ac.get('Track*', 0)}` | {pct_ac('Track*')} | ⚠️ CONDITIONAL | Monitoreo activo — riesgo controlado |
| **Track** | `{ac.get('Track', 0)}` | {pct_ac('Track')} | ✅ PASS | Sin explotación activa conocida |
| **Total evaluados** | `{total_class}` | 100% | {dec_icon} **{dec}** | Decisión = acción máxima |

### Hallazgos que requieren acción inmediata (Act)

| Herramienta | Vulnerabilidad | Explotación | Automatizable | Impacto | Acción |
|---|---|---|---|---|---|
{act_rows}
{f1_block}

### Por qué SSVC reemplaza a TLOT/ALOT

| Aspecto | TLOT/ALOT (reemplazado) | SSVC + EPSS + KEV (actual) |
|---|---|---|
| Constantes | 0.50/0.65/0.80/0.95 definidas por autores | Árbol publicado por CISA — sin constantes propias |
| Saturación | ALOT = 0.35 idéntico en todos los casos | Track/Attend/Act varían por hallazgo |
| Métricas formales | Imposible (sin ground truth) | F1, precisión, recall vs CISA KEV + EPSS |
| Respaldo normativo | ISO/IEC 27034 §7.3.4 (sin valores) | SSVC v2.1 CISA/SEI-CERT (publicado) |

"""


def section_ssvc_enrichment(ai_eval_data):
    enrichment = ai_eval_data.get("ssvc_enrichment", {})
    if not enrichment.get("used"):
        return ""

    ev       = ai_eval_data.get("evaluation", {})
    ssvc_val = ev.get("ssvc_validation", [])
    f1m      = enrichment.get("f1_metrics", {})
    ac       = enrichment.get("action_counts", {})

    n_conf  = sum(1 for v in ssvc_val if v.get("ai_assessment") == "confirmed")
    n_over  = sum(1 for v in ssvc_val if v.get("ai_assessment") == "overestimated")
    n_under = sum(1 for v in ssvc_val if v.get("ai_assessment") == "underestimated")

    val_rows = ""
    for v in ssvc_val[:8]:
        assessment = v.get("ai_assessment", "")
        icon = {"confirmed": "✅", "overestimated": "⚠️", "underestimated": "🔴"}.get(assessment, "❓")
        epss = v.get("epss_score", 0)
        kev  = "Sí" if v.get("in_kev") else "No"
        val_rows += (
            f"| `{v.get('ssvc_preliminary','?')}` "
            f"| {icon} {assessment} "
            f"| EPSS: {epss:.3f} / KEV: {kev} "
            f"| {v.get('reasoning','')[:70]}... |\n"
        )

    f1_line = ""
    if f1m.get("cves_evaluated", 0) > 0:
        f1_line = (
            f"\n> **F1 Exploitation (ground truth KEV+EPSS):** "
            f"`{f1m.get('f1_score',0):.3f}` "
            f"(P={f1m.get('precision',0):.3f}, R={f1m.get('recall',0):.3f}, "
            f"n={f1m.get('cves_evaluated',0)} CVEs)"
        )

    if ssvc_val:
        val_block = (
            f"### Validación Cruzada LLM ↔ SSVC ({len(ssvc_val)} hallazgos)\n\n"
            f"**{n_conf} confirmados**, **{n_over} sobreestimados**, **{n_under} subestimados**.\n\n"
            "| SSVC Preliminar | Juicio IA | Evidencia Empírica | Razonamiento |\n"
            "|---|---|---|---|\n"
            f"{val_rows}"
        )
    else:
        val_block = ""

    return f"""
### 🔬 Contexto SSVC/EPSS/KEV Usado en el Gate IA (Motor Híbrido v1.3)

> Antes de invocar al LLM, el motor ejecuta `ssvc_gate.py` y enriquece el prompt
> con clasificaciones SSVC, scores EPSS y estado KEV por hallazgo. El LLM puede
> confirmar o corregir las clasificaciones con razonamiento contextual.
> **Ref:** Al Haddad et al. (2025) — arXiv 2510.18508.

| Métrica | Valor |
|---|---|
| **CISA KEV consultado** | {enrichment.get('kev_entries', 0):,} entradas |
| **EPSS scores obtenidos** | {enrichment.get('epss_fetched', 0)} CVEs |
| **Hallazgos clasificados SSVC** | {enrichment.get('classified_count', 0)} |
| **Distribución** | Act={ac.get('Act',0)}, Attend={ac.get('Attend',0)}, Track*={ac.get('Track*',0)}, Track={ac.get('Track',0)} |{f1_line}

{val_block}
"""


def section_gate_comparison(gate_comparison, ai_eval_data, gate_data):
    trad       = gate_comparison.get("traditional", {})
    ai         = gate_comparison.get("ai_assisted", {})
    gc_analysis = gate_comparison.get("analysis", {})
    evaluation = ai_eval_data.get("evaluation", {})

    trad_decision = trad.get("decision", "UNKNOWN")
    ai_decision   = ai.get("decision", "UNKNOWN")
    trad_icon     = DECISION_ICONS.get(trad_decision, "❓")
    ai_icon       = DECISION_ICONS.get(ai_decision, "❓")

    ssvc     = gate_comparison.get("ssvc", {})
    ssvc_dec = ssvc.get("decision", "N/A")
    ssvc_agg = ssvc.get("aggregate_action", "N/A")
    ssvc_icon = DECISION_ICONS.get(ssvc_dec, "❓")
    f1m      = ssvc.get("f1_metrics", {})
    f1_str   = f"`{f1m.get('f1_score',0):.3f}`" if f1m.get("cves_evaluated",0) > 0 else "N/A"

    divergences = gc_analysis.get("divergences", [])
    divergence_block = (
        "\n".join(f"- {d}" for d in divergences)
        if divergences else
        "- Los tres gates concuerdan en la decisión final."
    )

    trad_reasons = "\n".join(f"- {r}" for r in trad.get("reasons", []))

    return f"""---

## 🔄 Comparación: Tres Enfoques del Security Gate

> **Contribución central del Trabajo de Grado:** comparar empíricamente tres mecanismos
> de decisión de despliegue sobre los mismos hallazgos normalizados. ISO/IEC 27034 se
> conserva exclusivamente para trazabilidad normativa (campo `asc_id`) — ver sección
> siguiente. No opera como cuarto gate de decisión.

| Criterio | Gate Tradicional | Gate con IA | Gate SSVC+EPSS+KEV |
|---|---|---|---|
| **Decisión** | {trad_icon} {trad_decision} | {ai_icon} {ai_decision} | {ssvc_icon} {ssvc_dec} |
| **Método** | Umbrales numéricos fijos | LLM con contexto SSVC/EPSS/KEV | Árbol SSVC v2.1 + EPSS + CISA KEV |
| **Acción agregada SSVC** | N/A | N/A | `{ssvc_agg}` |
| **Métricas formales** | ❌ No | ❌ No | ✅ F1 = {f1_str} |
| **Evalúa explotabilidad real** | ❌ No | ✅ Semántica LLM | ✅ CISA KEV + EPSS empírico |
| **Detecta cadenas de ataque** | ❌ No | ✅ Sí | ❌ Por hallazgo individual |
| **Considera falsos positivos** | ❌ No | ✅ Estimados ({evaluation.get('false_positive_estimate','N/A')}) | ✅ EPSS filtra low-risk |
| **Constantes arbitrarias** | ✅ Umbrales fijos | N/A | ❌ Ninguna |
| **Determinístico** | ✅ Sí | ❌ No | ✅ Sí |
| **Costo por run** | ~$0 | ~$0.005 | ~$0 (APIs gratuitas) |
| **Trazabilidad ISO/IEC 27034** | ❌ No | ❌ No | ✅ Vía `asc_id` (ver sección siguiente) |

### Divergencias entre gates

{divergence_block}

**Insight académico:** {gc_analysis.get('academic_insight','N/A')}

**Análisis comparativo:** {gc_analysis.get('comparison','N/A')}

**Razones del gate tradicional:**
{trad_reasons if trad_reasons else '- No disponibles'}

"""


def section_iso27034(gate_data):
    """
    Sección de trazabilidad normativa ISO/IEC 27034.
    Lee gate_data["iso27034_traceability"] construido en generate_report()
    desde scan_config.json + findings.json.
    """
    tra = gate_data.get("iso27034_traceability", {})
    if not tra:
        return """---

## 📋 Trazabilidad Normativa ISO/IEC 27034

> ⚠️ No se encontró el bloque `iso27034_traceability` en esta corrida.
> Verifica que `detector.py` haya generado el campo `iso27034_anf` en
> `scan_config.json` y que se pase `--scan-config` al invocar este script.

"""

    executed  = tra.get("ascs_executed", [])
    breakdown = tra.get("asc_breakdown", [])
    language  = tra.get("language", "unknown")
    criticality = tra.get("criticality", "medium")
    scan_mode = tra.get("scan_mode", "unknown")
    anf_defined = tra.get("anf_defined", False)

    required = [b for b in breakdown if b.get("required")]
    exec_req = [b for b in required if b.get("status") == "executed"]

    gap = [b for b in required if b.get("status") != "executed"]

    rows = ""
    for b in breakdown:
        asc        = b.get("asc_id", "?")
        tool       = b.get("tool", "—")
        desc       = b.get("description", "—")
        req_label  = "✅ Obligatorio" if b.get("required") else "⚪ Opcional"
        status     = "✅ Ejecutado" if b.get("status") == "executed" else "⚠️ No ejecutado"
        count      = b.get("findings_count", 0)
        sev_dist   = b.get("severity_dist", {})
        sev_str    = ", ".join(
            f"{SEVERITY_ICONS.get(s,'')} {s}:{n}" for s, n in sev_dist.items()
        ) if sev_dist else "—"
        rows += f"| `{asc}` | {tool} | {desc} | {req_label} | {status} | {count} | {sev_str} |\n"

    if not rows:
        rows = "| — | — | — | — | Sin desglose disponible | — | — |\n"

    if gap:
        gap_block = (
            "### ⚠️ Brechas de cobertura detectadas\n\n"
            "Los siguientes ASC son obligatorios según el ANF pero no ejecutaron "
            "hallazgos en esta corrida:\n\n"
            + "\n".join(f"- `{b.get('asc_id')}` — {b.get('tool','?')}: {b.get('description','')}" for b in gap)
            + "\n\n"
        )
    else:
        gap_block = (
            "### ✅ Cobertura completa\n\n"
            "Todos los ASC obligatorios según el ANF se ejecutaron en esta corrida "
            "y registraron hallazgos.\n\n"
        )

    return f"""---

## 📋 Trazabilidad Normativa ISO/IEC 27034

> ### ¿Cómo opera ISO/IEC 27034 en este pipeline?
>
> La norma **no actúa como gate de decisión** — ese rol lo cumple SSVC+EPSS+KEV.
> ISO/IEC 27034-1:2011 se materializa en **tres puntos operativos concretos**:
>
> | Punto | Componente | Qué hace |
> |---|---|---|
> | **1. ANF** | `detector.py` → `scan_config.json` | Define qué ASC son obligatorios según el lenguaje y la criticidad declarada del servicio |
> | **2. asc_id** | `normalizer.py` → `findings.json` | Etiqueta cada hallazgo individual con el ASC que lo detectó |
> | **3. Auditoría** | `report_generator.py` → este reporte | Registra qué ASC se ejecutaron frente a los requeridos por el ANF |
>
> Esto permite responder: *¿el pipeline ejecutó todos los controles que la norma
> requiere para este servicio?* y auditar brechas de cobertura por corrida.

### Contexto de esta corrida

| Campo | Valor |
|---|---|
| **Lenguaje detectado** | `{language}` |
| **Criticidad declarada** | `{criticality}` |
| **Modo de escaneo** | `{scan_mode}` |
| **ANF definido por detector** | {'✅ Sí' if anf_defined else '⚠️ No — se usaron ASC canónicos por defecto'} |
| **ASC obligatorios requeridos** | {len(required)} |
| **ASC obligatorios ejecutados** | {len(exec_req)} / {len(required)} |

### ASC ejecutados frente a los requeridos por el ANF

| ASC | Herramienta | Descripción | Obligatorio | Estado | Hallazgos | Distribución de severidad |
|---|---|---|---|---|---|---|
{rows}

{gap_block}

**ASC ejecutados en esta corrida:** `{', '.join(sorted(executed)) if executed else 'ninguno registrado'}`

> **Nota sobre TLOT/ALOT:** el modelo de puntuación TLOT/ALOT usado en versiones
> anteriores del pipeline fue reemplazado por el gate SSVC+EPSS+KEV (sección anterior)
> porque dependía de constantes numéricas (0.50/0.65/0.80/0.95) que no están prescritas
> por ISO/IEC 27034-1:2011. La norma define los conceptos TLOT/ALOT en §7.3.4 pero no
> asigna valores concretos. El reemplazo eliminó la saturación (ALOT=0.35 idéntico en
> todos los casos) y habilitó las métricas F1 formales que el modelo anterior no permitía.

"""


def section_findings_detail(findings, tools_executed):
    def finding_card(f):
        icon  = SEVERITY_ICONS.get(f.get("severity"), "⚪")
        sev   = f.get("severity", "?")
        title = f.get("title", "Unknown")
        md    = f"#### {icon} [{sev}] {title}\n\n"
        md   += "| Campo | Valor |\n|---|---|\n"
        md   += f"| **ID** | `{f.get('id','N/A')}` |\n"
        md   += f"| **Herramienta** | `{f.get('tool','N/A').upper()}` ({f.get('tool_type','N/A')}) |\n"
        md   += f"| **ASC ISO/IEC 27034** | `{f.get('asc_id','N/A')}` |\n"
        md   += f"| **Categoría OWASP** | {f.get('category','N/A')} |\n"
        if f.get("cwe"):
            md += f"| **CWE** | `{f.get('cwe')}` |\n"
        if f.get("cvss_score"):
            md += f"| **CVSS Score** | `{f.get('cvss_score')}` |\n"
        loc = f.get("location", {})
        if loc.get("file"):
            md += f"| **Archivo** | `{loc['file']}:{loc.get('line','?')}` |\n"
        if loc.get("endpoint"):
            md += f"| **Endpoint** | `{loc.get('method','GET')} {loc['endpoint']}` |\n"
        if f.get("instances_count", 0) > 1:
            md += f"| **Instancias** | {f.get('instances_count')} URLs afectadas |\n"
        md += f"\n**Descripción:** {f.get('description','N/A')[:400]}\n\n"
        if f.get("evidence","").strip():
            md += f"**Evidencia:** `{f.get('evidence','')[:200]}`\n\n"
        if f.get("remediation"):
            md += f"**✅ Remediación:** {f.get('remediation','')[:300]}\n\n"
        md += "---\n\n"
        return md

    md = "---\n\n## 📋 Hallazgos Detallados por Herramienta\n\n"

    for tool_key in ["trivy", "zap", "nuclei", "semgrep"]:
        meta          = TOOL_META.get(tool_key, {})
        tool_findings = [f for f in findings if f.get("tool") == tool_key]
        raw           = tools_executed.get(tool_key, 0)
        unique        = len(tool_findings)
        removed       = raw - unique

        md += f"### {meta.get('icon','')} {meta.get('name', tool_key)} — `{meta.get('asc','')}`\n\n"
        md += f"> **Tipo:** {meta.get('type','')}  \n"
        md += f"> **Raw:** {raw} | **Únicos:** {unique} | **Deduplicados:** {removed} ({pct(removed, raw) if raw else '0%'})\n\n"

        if not tool_findings:
            md += "_No se encontraron hallazgos para esta herramienta._\n\n"
            continue

        sev_count = {}
        for f in tool_findings:
            s = f.get("severity", "INFO")
            sev_count[s] = sev_count.get(s, 0) + 1

        sev_line = " | ".join(
            f"{SEVERITY_ICONS.get(s,'')} {s}: **{sev_count[s]}**"
            for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
            if sev_count.get(s, 0) > 0
        )
        md += f"**Distribución:** {sev_line}\n\n"

        critical_high = [f for f in tool_findings if f.get("severity") in ["CRITICAL","HIGH"]]
        if critical_high:
            md += f"#### 🔴🟠 Críticos y Altos ({len(critical_high)})\n\n"
            for f in sorted(critical_high, key=lambda x: sev_order(x.get("severity","INFO"))):
                md += finding_card(f)

        medium_low = [f for f in tool_findings if f.get("severity") in ["MEDIUM","LOW","INFO"]]
        if medium_low:
            md += f"#### 🟡🟢⚪ Medios, Bajos e Info ({len(medium_low)})\n\n"
            if tool_key == "trivy":
                md += "| Severidad | CVE / Advisory | CVSS | Remediación |\n|---|---|---|---|\n"
                for f in sorted(medium_low, key=lambda x: sev_order(x.get("severity","INFO"))):
                    icon  = SEVERITY_ICONS.get(f.get("severity"),"⚪")
                    title = f.get("title","N/A")[:55]
                    cvss  = f.get("cvss_score","N/A")
                    rem   = f.get("remediation","Ver advisory")[:70]
                    md   += f"| {icon} {f.get('severity')} | {title} | {cvss} | {rem} |\n"
                md += "\n"
            else:
                md += "| Severidad | Hallazgo | Endpoint | Remediación |\n|---|---|---|---|\n"
                for f in sorted(medium_low, key=lambda x: sev_order(x.get("severity","INFO"))):
                    icon     = SEVERITY_ICONS.get(f.get("severity"),"⚪")
                    title    = f.get("title","N/A")[:50]
                    endpoint = f.get("location",{}).get("endpoint","N/A")
                    if endpoint and len(endpoint) > 50:
                        endpoint = endpoint[:50] + "..."
                    rem = f.get("remediation","Ver documentación")[:70]
                    md += f"| {icon} {f.get('severity')} | {title} | `{endpoint}` | {rem} |\n"
                md += "\n"

    return md


def section_academic(timestamp, pipeline_run, attack_chains, tools, service="este servicio"):
    chains = len(attack_chains)
    return f"""---

## 🎓 Notas Académicas y Marco de Referencia

Este reporte fue generado automáticamente por el pipeline DevSecOps implementado como
Trabajo de Grado en la **Universidad del Valle — Sede Tuluá**.

### Marco normativo y técnico

| Estándar / Framework | Aplicación en este pipeline |
|---|---|
| **ISO/IEC 27034-1:2011** | Trazabilidad en tres puntos: ANF en `scan_config.json`, `asc_id` en cada hallazgo, auditoría de ASC en este reporte |
| **SSVC v2.1 (CISA/SEI-CERT)** | Árbol de decisión del tercer gate con EPSS y CISA KEV |
| **OWASP Top 10 (2021)** | Categorización de todos los hallazgos normalizados |
| **CVSS v3.1 (NIST)** | Puntuación de severidad para hallazgos de Trivy |
| **CWE/SANS Top 25** | Clasificación de debilidades en SAST y DAST |
| **MITRE ATT&CK** | Referencia para cadenas de ataque identificadas por la IA |
| **EPSS (FIRST.org)** | Probabilidad de explotación en 30 días por CVE ID |
| **CISA KEV** | Catálogo de CVEs con explotación activa confirmada |

### Herramientas y su ASC ISO/IEC 27034

| Herramienta | Tipo | ASC ISO/IEC 27034 | Hallazgos únicos |
|---|---|---|---|
| Semgrep OSS | SAST | `ASC-SAST-001` | {tools.get('semgrep',0)} |
| Trivy | SCA | `ASC-SCA-001` | {tools.get('trivy',0)} |
| OWASP ZAP | DAST | `ASC-DAST-001` | {tools.get('zap',0)} |
| Nuclei v3 | Pentesting | `ASC-PENTEST-001` | {tools.get('nuclei',0)} |

### Contribución diferencial por tipo de gate

| Capacidad | Tradicional | Gate IA | SSVC+EPSS+KEV |
|---|---|---|---|
| Falsos positivos | ❌ | ✅ | ✅ |
| Explotabilidad real | ❌ | ✅ | ✅ |
| Cadenas de ataque ({chains} en este run) | ❌ | ✅ | ❌ |
| Métricas formales F1 | ❌ | ❌ | ✅ |
| Trazabilidad ISO/IEC 27034 | ❌ | ❌ | ✅ (vía `asc_id`) |
| Impacto de negocio | ❌ | ✅ | ❌ |
| Determinístico | ✅ | ❌ | ✅ |

### Limitaciones

- Este reporte corresponde a una única corrida sobre `{service}`. La validación completa
  abarca nueve casos de estudio documentados en la tesis (Capítulo 5).
- La evaluación IA requiere validación humana antes de decisiones en producción.
- No reemplaza una auditoría de seguridad formal ni un pentest manual.
- El gate SSVC prioriza la cautela ante hallazgos críticos — ver tesis sección 5.6.3.

---

_Reporte generado el {timestamp} | Pipeline Run: `{pipeline_run}`_

_**Autores:** Jhojan Stiven Castaño Jejen & Juan Manuel Arango Rodas_
_**Universidad del Valle** — Ingeniería de Sistemas — 2026_
"""


# ══════════════════════════════════════════════════════════════════════════════
#  ORQUESTADOR PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def generate_report(findings_path, ai_eval_path, gate_path, output_path,
                    recon_path=None, scan_config_path=None):

    print("\n" + "=" * 60)
    print("  GENERADOR DE REPORTE — DevSecOps Engine v1.3")
    print("=" * 60)

    with open(findings_path,  "r") as f: findings_data  = json.load(f)
    with open(ai_eval_path,   "r") as f: ai_eval_data   = json.load(f)
    with open(gate_path,      "r") as f: gate_data      = json.load(f)

    recon_data = {}
    if recon_path and os.path.exists(recon_path):
        with open(recon_path, "r") as f:
            recon_data = json.load(f)

    # ── Construir trazabilidad ISO/IEC 27034 ──────────────────────────────────
    # gate.py no escribe este bloque; lo calculamos aquí desde scan_config.json
    # y findings.json, que sí contienen los datos necesarios (asc_id, iso27034_anf).
    if not gate_data.get("iso27034_traceability"):
        scan_cfg = {}
        if scan_config_path and os.path.exists(scan_config_path):
            with open(scan_config_path, "r") as f:
                scan_cfg = json.load(f)
        gate_data["iso27034_traceability"] = build_iso27034_traceability(
            scan_cfg, findings_data.get("findings", [])
        )

    # ── Variables compartidas ─────────────────────────────────────────────────
    summary        = findings_data.get("summary", {})
    findings       = findings_data.get("findings", [])
    tools_executed = findings_data.get("tools_executed", {})
    evaluation     = ai_eval_data.get("evaluation", {})
    gate_comparison = gate_data.get("gate_comparison", {})
    attack_chains  = evaluation.get("attack_chains", [])
    timestamp      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pipeline_run   = findings_data.get("pipeline_run", "local")
    service_name   = findings_data.get("service", "este servicio")
    by_tool_dedup  = summary.get("by_tool", {})

    # ── Composición del reporte ───────────────────────────────────────────────
    report  = section_header(findings_data, ai_eval_data, gate_data)
    report += section_gate(gate_data, ai_eval_data)
    report += section_stats(summary, tools_executed)
    report += section_dedup_explanation(tools_executed, summary)
    report += section_recon(recon_data)
    report += section_ai_analysis(evaluation, ai_eval_data)
    report += section_attack_chains(attack_chains)
    report += section_remediation(evaluation.get("remediation_priorities", []))
    report += section_ssvc(gate_data)
    report += section_ssvc_enrichment(ai_eval_data)
    report += section_gate_comparison(gate_comparison, ai_eval_data, gate_data)
    report += section_iso27034(gate_data)
    report += section_findings_detail(findings, tools_executed)
    report += section_academic(timestamp, pipeline_run, attack_chains, by_tool_dedup, service_name)

    os.makedirs(
        os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
        exist_ok=True
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)

    tra       = gate_data.get("iso27034_traceability", {})
    breakdown = tra.get("asc_breakdown", [])
    n_req     = len([b for b in breakdown if b.get("required")])
    n_exec    = len([b for b in breakdown if b.get("required") and b.get("status") == "executed"])

    ssvc_r  = gate_data.get("gate_comparison", {}).get("ssvc", {})
    f1_val  = ssvc_r.get("f1_metrics", {}).get("f1_score", "N/A")
    enrich  = ai_eval_data.get("ssvc_enrichment", {})

    print(f"  ✅ Reporte generado : {output_path}")
    print(f"  📄 Tamaño          : {len(report):,} caracteres")
    print(f"  🚦 Decisión final  : {gate_data.get('decision','UNKNOWN')}")
    print(f"  🔬 SSVC decision   : {ssvc_r.get('decision','N/A')} ({ssvc_r.get('aggregate_action','?')})")
    print(f"  📊 SSVC F1         : {f1_val}")
    print(f"  🤖 IA híbrida      : {'✅ Activa (SSVC/EPSS/KEV)' if enrich.get('used') else '⚠️ Fallback estático'}")
    print(f"  📋 ISO/IEC 27034   : {n_exec}/{n_req} ASC obligatorios ejecutados")
    print(f"  🔗 Cadenas ataque  : {len(attack_chains)}")
    print(f"  📊 Hallazgos       : {summary.get('total',0)} únicos de {sum(tools_executed.values())} raw")
    print("=" * 60 + "\n")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generador de reporte SECURITY_REPORT.md — DevSecOps Engine v1.3"
    )
    parser.add_argument("--findings",      required=True,
                        help="Ruta a findings.json (normalizer.py)")
    parser.add_argument("--ai-evaluation", required=True,
                        help="Ruta a ai_evaluation.json (ai_engine.py)")
    parser.add_argument("--gate-decision", required=True,
                        help="Ruta a gate_decision.json (gate.py)")
    parser.add_argument("--output",        required=True,
                        help="Ruta de salida del reporte Markdown")
    parser.add_argument("--recon",         default=None,
                        help="Ruta opcional a recon_context.json (recon.py)")
    parser.add_argument("--scan-config",   default=None,
                        help="Ruta a scan_config.json (detector.py) — necesario para trazabilidad ISO/IEC 27034")
    args = parser.parse_args()

    generate_report(
        findings_path=args.findings,
        ai_eval_path=args.ai_evaluation,
        gate_path=args.gate_decision,
        output_path=args.output,
        recon_path=args.recon,
        scan_config_path=args.scan_config,
    )