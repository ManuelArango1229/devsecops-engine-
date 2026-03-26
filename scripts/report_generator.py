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
COVERAGE_ICONS = {"buena": "✅", "parcial": "🟡", "ninguna": "❌"}

TOOL_META = {
    "semgrep": {
        "name":     "Semgrep (SAST)",
        "type":     "Análisis Estático de Código",
        "icon":     "🔐",
        "dedup_reason": (
            "Semgrep analiza el código fuente del repositorio del engine. "
            "Las deduplicaciones eliminan la misma regla disparada en múltiples "
            "archivos del mismo módulo, conservando solo la primera ocurrencia por "
            "regla + ruta de archivo."
        ),
    },
    "trivy": {
        "name":     "Trivy (SCA)",
        "type":     "Análisis de Componentes de Software",
        "icon":     "🔬",
        "dedup_reason": (
            "Juice Shop instala dependencias en múltiples subdirectorios de "
            "`node_modules` (por ejemplo, `express-jwt/node_modules/lodash` y "
            "`sanitize-html/node_modules/lodash`). La misma CVE sobre el mismo "
            "paquete y versión aparece una vez por ruta, pero tras deduplicar "
            "por `CVE + paquete + target` queda una sola entrada. "
            "Los hallazgos removidos no son falsos positivos sino instancias "
            "duplicadas de la misma vulnerabilidad real."
        ),
    },
    "zap": {
        "name":     "OWASP ZAP (DAST)",
        "type":     "Análisis Dinámico en Tiempo de Ejecución",
        "icon":     "🌐",
        "dedup_reason": (
            "ZAP realiza un escaneo baseline pasivo. Cada alerta representa un "
            "tipo de misconfiguration o header faltante único — por eso la "
            "deduplicación no elimina ningún hallazgo: todas las alertas tienen "
            "títulos distintos. El conteo de instancias dentro de cada alerta "
            "indica cuántas URLs presentan el mismo problema."
        ),
    },
    "nuclei": {
        "name":     "Nuclei (Pentesting)",
        "type":     "Validación Activa de Templates",
        "icon":     "🎯",
        "dedup_reason": (
            "Nuclei ejecuta sus templates contra la URL base más todas las rutas "
            "descubiertas por el reconocimiento. El mismo template puede disparar "
            "en el mismo endpoint más de una vez dentro del mismo run, generando "
            "entradas duplicadas en el JSON de salida. Tras deduplicar por "
            "`template + endpoint`, se conserva solo una entrada por hallazgo único."
        ),
    },
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def sev_order(s):
    return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(s) if s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 99

def pct(part, total):
    return f"{part/total*100:.1f}%" if total else "0.0%"

def bar(part, total, width=20):
    filled = int(part / total * width) if total else 0
    return "█" * filled + "░" * (width - filled)

def clean_html(text):
    for tag in ["<p>","</p>","<ul>","</ul>","<li>","</li>","<br>","<br/>"]:
        text = text.replace(tag, " " if tag in ["<p>","</p>","<li>"] else "")
    return text.strip()

def format_severity_badge(sev):
    return f"{SEVERITY_ICONS.get(sev,'⚪')} **{sev}**"


# ── Secciones del reporte ─────────────────────────────────────────────────────

def section_header(findings_data, ai_eval_data, gate_data):
    final_decision = gate_data.get("decision", "UNKNOWN")
    decision_icon  = DECISION_ICONS.get(final_decision, "❓")
    timestamp      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    service        = findings_data.get("service", "unknown")
    environment    = findings_data.get("environment", "staging")
    pipeline_run   = findings_data.get("pipeline_run", "local")
    ai_model       = ai_eval_data.get("ai_model", "N/A")
    tokens         = ai_eval_data.get("tokens_used", {})
    evaluation     = ai_eval_data.get("evaluation", {})

    return f"""# 🔐 Reporte de Seguridad DevSecOps
## {decision_icon} Decisión de Despliegue: **{final_decision}**

---

> **Generado automáticamente por el pipeline DevSecOps – Universidad del Valle 2026**

| Campo | Valor |
|---|---|
| **Servicio** | `{service}` |
| **Entorno** | `{environment}` |
| **Pipeline Run** | `{pipeline_run}` |
| **Timestamp** | `{timestamp}` |
| **Modelo IA** | `{ai_model}` |
| **Tokens utilizados** | `{tokens.get('total', 0):,}` (prompt: {tokens.get('prompt',0):,} / completion: {tokens.get('completion',0):,}) |
| **Versión del prompt** | `{ai_eval_data.get('prompt_version', '2.0')}` |

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

    md = f"""---

## 🚦 Decisión Final del Security Gate

| Campo | Valor |
|---|---|
| **Decisión** | {decision_icon} **{final_decision}** |
| **Fuente** | `{gate_data.get('decision_source', 'N/A')}` |
| **Nivel de riesgo** | `{risk_level}` |
| **Risk Score** | `{risk_score:.1f} / 10.0` |
| **Confianza IA** | `{confidence:.0%}` |
| **Falsos positivos estimados** | `{fp_estimate}` |

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
    by_sev   = summary.get("by_severity", {})
    by_tool  = summary.get("by_tool", {})
    total    = summary.get("total", 0)
    by_cat   = summary.get("by_category", {})

    # Severidades
    sev_rows = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_sev.get(sev, 0)
        p     = pct(count, total)
        b     = bar(count, total, 15)
        sev_rows += f"| {SEVERITY_ICONS.get(sev)} {sev} | {count} | {p} | `{b}` |\n"

    # Herramientas — raw vs dedup
    tool_rows = ""
    for tool in ["semgrep", "trivy", "zap", "nuclei"]:
        meta    = TOOL_META.get(tool, {})
        raw     = tools_executed.get(tool, 0)
        dedup   = by_tool.get(tool, 0)
        removed = raw - dedup
        p_rm    = pct(removed, raw) if raw > 0 else "—"
        status  = "✅ Ejecutado" if raw > 0 else "⚠️ Sin hallazgos"
        tool_rows += (
            f"| {meta.get('icon','')} {meta.get('name', tool)} "
            f"| {raw} | {dedup} | {removed} | {p_rm} | {status} |\n"
        )

    # Top categorías OWASP
    cat_rows = ""
    sorted_cats = sorted(by_cat.items(), key=lambda x: x[1], reverse=True)
    for cat, count in sorted_cats[:5]:
        p = pct(count, total)
        b = bar(count, total, 12)
        cat_rows += f"| `{cat}` | {count} | {p} | `{b}` |\n"

    return f"""---

## 📈 Estadísticas Globales de Hallazgos

### Distribución por Severidad

| Severidad | Hallazgos | % del total | Proporción |
|---|---|---|---|
{sev_rows}| ─ | **{total}** | **100%** | |

### Cobertura por Herramienta

> La columna **"Removidos"** indica hallazgos eliminados por deduplicación (no son falsos positivos — son instancias duplicadas de la misma vulnerabilidad).

| Herramienta | Raw | Únicos | Removidos | % Removidos | Estado |
|---|---|---|---|---|---|
{tool_rows}
### Top Categorías OWASP Top 10

| Categoría | Hallazgos | % del total | Proporción |
|---|---|---|---|
{cat_rows}
"""


def section_dedup_explanation(tools_executed, summary):
    by_tool = summary.get("by_tool", {})
    total_raw   = sum(tools_executed.values())
    total_dedup = sum(by_tool.values())
    removed     = total_raw - total_dedup

    md = f"""---

## 🔄 Metodología de Deduplicación

> El normalizador aplica deduplicación para evitar el doble conteo de vulnerabilidades detectadas por múltiples instancias de la misma herramienta.
> **Total raw:** {total_raw} hallazgos → **Total único:** {total_dedup} hallazgos → **Eliminados:** {removed} ({pct(removed, total_raw)} de reducción)

"""
    for tool in ["trivy", "zap", "nuclei", "semgrep"]:
        meta    = TOOL_META.get(tool, {})
        raw     = tools_executed.get(tool, 0)
        dedup   = by_tool.get(tool, 0)
        removed_t = raw - dedup
        p_rm    = pct(removed_t, raw) if raw > 0 else "0%"

        md += f"### {meta.get('icon','')} {meta.get('name', tool)} — {meta.get('type','')}\n\n"
        md += f"- **Raw:** {raw} hallazgos detectados | **Únicos tras dedup:** {dedup} | **Removidos:** {removed_t} ({p_rm})\n"
        md += f"- **Criterio de dedup aplicado:** `tool + título + endpoint/archivo`\n\n"
        md += f"> {meta.get('dedup_reason', '')}\n\n"

    return md


def section_recon(recon_data):
    if not recon_data or recon_data.get("schema_version") == "1.0" and not recon_data.get("target_url"):
        return ""

    target_url  = recon_data.get("target_url", "N/A")
    nmap        = recon_data.get("nmap", {})
    routes      = recon_data.get("route_discovery", {})
    fingerprint = recon_data.get("fingerprint", {})
    waf         = recon_data.get("waf", {})
    attack_surf = recon_data.get("attack_surface", {})
    recon_sum   = recon_data.get("summary", {})

    open_ports  = recon_sum.get("open_ports", [])
    technologies = recon_sum.get("technologies", [])
    missing_hdrs = recon_sum.get("missing_security_headers", [])
    discovered   = recon_sum.get("discovered_routes_count", 0)
    waf_present  = recon_sum.get("waf_present", False)
    attack_findings = attack_surf.get("findings", [])

    # Tabla de puertos
    ports_table = ""
    services = nmap.get("services", {})
    if services:
        ports_table = "| Puerto | Servicio | Versión | Interesante |\n|---|---|---|---|\n"
        for port, info in services.items():
            interesting = "⚠️ Sí" if info.get("interesting") else "No"
            ports_table += f"| `{port}` | {info.get('service','?')} | {info.get('version','N/A')[:40]} | {interesting} |\n"
    else:
        ports_table = f"_Puerto {open_ports[0] if open_ports else 'N/A'} detectado (nmap no disponible o bloqueado en CI)_\n"

    # Rutas descubiertas
    discovered_routes = routes.get("discovered_routes", [])
    interesting_routes = routes.get("interesting_routes", [])

    routes_section = ""
    if discovered_routes:
        routes_section = f"Se descubrieron **{len(discovered_routes)} rutas** activas. "
        routes_section += f"De estas, **{len(interesting_routes)} son de interés** (retornaron 200/201).\n\n"
        if interesting_routes:
            routes_section += "| Ruta sensible | Estado |\n|---|---|\n"
            for r in interesting_routes[:15]:
                flag = "⚠️" if any(k in r.lower() for k in ["admin","env","git","backup","debug","actuator","swagger","api-docs","metrics"]) else "ℹ️"
                routes_section += f"| `{r}` | {flag} Accesible |\n"
    else:
        routes_section = "_No se ejecutó descubrimiento de rutas (ffuf/gobuster no disponible)._\n"

    # Headers faltantes
    present_hdrs = fingerprint.get("security_headers", {}).get("present", [])
    headers_table = "| Header de Seguridad | Estado |\n|---|---|\n"
    all_headers = [
        "content-security-policy", "strict-transport-security",
        "x-frame-options", "x-content-type-options",
        "referrer-policy", "permissions-policy",
        "cross-origin-embedder-policy", "cross-origin-opener-policy",
    ]
    for h in all_headers:
        if h in present_hdrs:
            headers_table += f"| `{h}` | ✅ Presente |\n"
        elif h in missing_hdrs:
            headers_table += f"| `{h}` | ❌ Faltante |\n"
        else:
            headers_table += f"| `{h}` | ⚪ No verificado |\n"

    # Hallazgos de superficie de ataque
    attack_section = ""
    if attack_findings:
        attack_section = "| Severidad | Tipo | Detalle |\n|---|---|---|\n"
        for f in attack_findings:
            icon = SEVERITY_ICONS.get(f.get("severity","INFO"), "⚪")
            attack_section += f"| {icon} {f.get('severity')} | `{f.get('type','')}` | {f.get('detail','')[:100]} |\n"
    else:
        attack_section = "_No se identificaron hallazgos en la superficie de ataque._\n"

    return f"""---

## 🕵️ Fase de Reconocimiento Activo

> El reconocimiento activo se ejecuta antes del escaneo dinámico para descubrir la superficie de ataque real y enriquecer los targets de Nuclei y ZAP.

### Objetivo analizado

| Campo | Valor |
|---|---|
| **URL objetivo** | `{target_url}` |
| **Host** | `{recon_data.get('host', 'N/A')}` |
| **Puerto** | `{recon_data.get('port', 'N/A')}` |
| **WAF detectado** | {'✅ Sí — ' + str(waf.get('waf_name','desconocido')) if waf_present else '❌ No detectado'} |
| **Servidor** | `{fingerprint.get('server', 'N/A') or 'No detectado'}` |
| **Título de la app** | `{fingerprint.get('title', 'N/A') or 'N/A'}` |
| **Tecnologías detectadas** | {', '.join(f'`{t}`' for t in technologies[:6]) if technologies else '_No detectadas_'} |
| **Targets generados para Nuclei** | {len(recon_data.get('nuclei_targets', []))} URLs |

### Escaneo de Puertos (nmap)

{ports_table}

### Descubrimiento de Rutas

{routes_section}

### Headers de Seguridad HTTP

{headers_table}

> Los headers faltantes son confirmados por los hallazgos de ZAP y Nuclei.

### Hallazgos de Superficie de Ataque

{attack_section}

"""


def section_ai_analysis(evaluation, ai_eval_data):
    coverage    = evaluation.get("coverage_analysis", {})
    blind_spots = coverage.get("blind_spots", [])
    owasp       = evaluation.get("owasp_top10_present", [])

    owasp_rows = "\n".join(f"- `{cat}`" for cat in owasp) if owasp else "- _No se identificaron categorías específicas_"

    cov_rows = f"""| SAST – Código fuente | {coverage.get('sast_coverage','N/A')} | {COVERAGE_ICONS.get(coverage.get('sast_coverage',''),'❓')} |
| SCA – Dependencias | {coverage.get('sca_coverage','N/A')} | {COVERAGE_ICONS.get(coverage.get('sca_coverage',''),'❓')} |
| DAST – Tiempo de ejecución | {coverage.get('dast_coverage','N/A')} | {COVERAGE_ICONS.get(coverage.get('dast_coverage',''),'❓')} |
| Pentesting automatizado | {coverage.get('pentest_coverage','N/A')} | {COVERAGE_ICONS.get(coverage.get('pentest_coverage',''),'❓')} |"""

    blind_md = ""
    if blind_spots:
        blind_md = "### ⚠️ Áreas sin cobertura (Blind Spots)\n\n"
        for bs in blind_spots:
            blind_md += f"- {bs}\n"
        blind_md += "\n"

    # Hallazgos principales IA
    key_findings = evaluation.get("key_findings", [])
    kf_rows = ""
    if key_findings:
        kf_rows = "| Severidad | Hallazgo | CVSS | Explotable remoto | Auth requerida | Exploit público | Categoría |\n|---|---|---|---|---|---|---|\n"
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

### Análisis de Cobertura por Tipo de Herramienta

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
        md += f"### {icon} {chain.get('chain_id','CHAIN')} – {chain.get('title','Sin título')}\n\n"
        md += f"| Campo | Valor |\n|---|---|\n"
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
            fix    = f" → Fix: `{r.get('fix_version')}`" if r.get("fix_version") else ""
            md += f"**{r.get('priority','?')}.** {r.get('action','N/A')}{fix}\n"
            md += f"   - `{r.get('tool','N/A')}` | Esfuerzo: _{r.get('effort','N/A')}_ | Fix disponible: {'✅' if r.get('fix_available') else '❌'}\n\n"
    if short:
        md += f"### ⚡ Corto plazo (1–4 semanas) — {len(short)} acciones\n\n"
        for r in short:
            fix = f" → Fix: `{r.get('fix_version')}`" if r.get("fix_version") else ""
            md += f"**{r.get('priority','?')}.** {r.get('action','N/A')}{fix}\n"
            md += f"   - `{r.get('tool','N/A')}` | Esfuerzo: _{r.get('effort','N/A')}_ | Fix disponible: {'✅' if r.get('fix_available') else '❌'}\n\n"
    if long_:
        md += f"### 🔧 Largo plazo (1–3 meses) — {len(long_)} acciones\n\n"
        for r in long_:
            md += f"**{r.get('priority','?')}.** {r.get('action','N/A')}\n"
            md += f"   - `{r.get('tool','N/A')}` | Esfuerzo: _{r.get('effort','N/A')}_\n\n"
    return md


def section_gate_comparison(gate_comparison, ai_eval_data):
    trad     = gate_comparison.get("traditional", {})
    ai       = gate_comparison.get("ai_assisted", {})
    analysis = gate_comparison.get("analysis", {})
    evaluation = ai_eval_data.get("evaluation", {})

    trad_decision = trad.get("decision", "UNKNOWN")
    ai_decision   = ai.get("decision", "UNKNOWN")
    trad_icon     = DECISION_ICONS.get(trad_decision, "❓")
    ai_icon       = DECISION_ICONS.get(ai_decision, "❓")

    trad_reasons = "\n".join(f"- {r}" for r in trad.get("reasons", []))

    return f"""---

## 🔄 Comparación: Gate Tradicional vs Gate Asistido por IA

> **Contribución central del Trabajo de Grado:** demostrar que la evaluación asistida por IA
> aporta valor diferencial sobre los umbrales estáticos mediante análisis contextual,
> detección de explotabilidad real y cadenas de ataque.

| Criterio | Gate Tradicional | Gate con IA |
|---|---|---|
| **Decisión** | {trad_icon} {trad_decision} | {ai_icon} {ai_decision} |
| **Método** | Umbrales estáticos | Evaluación contextual LLM |
| **Considera contexto de negocio** | ❌ No | ✅ Sí |
| **Filtra falsos positivos** | ❌ No | ✅ Estimados ({evaluation.get('false_positive_estimate','N/A')}) |
| **Evalúa explotabilidad real** | ❌ No | ✅ Sí |
| **Detecta cadenas de ataque** | ❌ No | ✅ Sí |
| **Documenta blind spots** | ❌ No | ✅ Sí |
| **Traduce a impacto de negocio** | ❌ No | ✅ Sí |
| **Priorización contextual** | ❌ No | ✅ Sí |
| **Modelo / método** | Reglas fijas | `{ai.get('ai_model','N/A')}` |
| **Nivel de confianza** | N/A (determinístico) | {ai.get('confidence',0):.0%} |

**Análisis:** {analysis.get('comparison','N/A')}

**Insight académico:** {analysis.get('academic_insight','N/A')}

**Razones del gate tradicional:**
{trad_reasons}

**Análisis de falsos positivos (IA):** {evaluation.get('false_positive_reasoning','N/A')}

"""


def section_findings_detail(findings, tools_executed):
    """Sección detallada por herramienta con todos los hallazgos."""

    def finding_card(f):
        icon = SEVERITY_ICONS.get(f.get("severity"), "⚪")
        sev  = f.get("severity", "?")
        title = f.get("title", "Unknown")
        md  = f"#### {icon} [{sev}] {title}\n\n"
        md += f"| Campo | Valor |\n|---|---|\n"
        md += f"| **ID** | `{f.get('id','N/A')}` |\n"
        md += f"| **Herramienta** | `{f.get('tool','N/A').upper()}` ({f.get('tool_type','N/A')}) |\n"
        md += f"| **Categoría OWASP** | {f.get('category','N/A')} |\n"
        if f.get("cwe"):
            md += f"| **CWE** | `{f.get('cwe')}` |\n"
        if f.get("cvss_score"):
            md += f"| **CVSS Score** | `{f.get('cvss_score')}` |\n"
        loc = f.get("location", {})
        if loc.get("file"):
            md += f"| **Archivo** | `{loc['file']}:{loc.get('line','?')}` |\n"
        if loc.get("endpoint"):
            md += f"| **Endpoint** | `{loc.get('method','GET')} {loc['endpoint']}` |\n"
        if f.get("instances_count") and f.get("instances_count",0) > 1:
            md += f"| **Instancias** | {f.get('instances_count')} URLs afectadas |\n"
        md += f"\n**Descripción:** {f.get('description','N/A')[:400]}\n\n"
        if f.get("evidence") and f.get("evidence","").strip():
            md += f"**Evidencia:** `{f.get('evidence','')[:200]}`\n\n"
        if f.get("remediation"):
            md += f"**✅ Remediación:** {f.get('remediation','')[:300]}\n\n"
        md += "---\n\n"
        return md

    md = "---\n\n## 📋 Hallazgos Detallados por Herramienta\n\n"

    for tool_key in ["trivy", "zap", "nuclei", "semgrep"]:
        meta     = TOOL_META.get(tool_key, {})
        tool_findings = [f for f in findings if f.get("tool") == tool_key]
        raw      = tools_executed.get(tool_key, 0)
        unique   = len(tool_findings)
        removed  = raw - unique

        md += f"### {meta.get('icon','')} {meta.get('name', tool_key)}\n\n"
        md += f"> **Tipo:** {meta.get('type','')}  \n"
        md += f"> **Raw:** {raw} | **Únicos:** {unique} | **Deduplicados:** {removed} ({pct(removed, raw) if raw else '0%'})\n\n"

        if not tool_findings:
            md += "_No se encontraron hallazgos para esta herramienta._\n\n"
            continue

        # Conteo por severidad
        sev_count = {}
        for f in tool_findings:
            s = f.get("severity","INFO")
            sev_count[s] = sev_count.get(s,0) + 1

        sev_line = " | ".join(
            f"{SEVERITY_ICONS.get(s,'')} {s}: **{sev_count[s]}**"
            for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
            if sev_count.get(s,0) > 0
        )
        md += f"**Distribución:** {sev_line}\n\n"

        # CRÍTICOS Y ALTOS con detalle completo
        critical_high = [f for f in tool_findings if f.get("severity") in ["CRITICAL","HIGH"]]
        if critical_high:
            md += f"#### 🔴🟠 Críticos y Altos ({len(critical_high)})\n\n"
            for f in sorted(critical_high, key=lambda x: sev_order(x.get("severity","INFO"))):
                md += finding_card(f)

        # MEDIOS, BAJOS E INFO en tabla compacta
        medium_low = [f for f in tool_findings if f.get("severity") in ["MEDIUM","LOW","INFO"]]
        if medium_low:
            md += f"#### 🟡🟢⚪ Medios, Bajos e Info ({len(medium_low)})\n\n"
            if tool_key == "trivy":
                md += "| Severidad | CVE / Advisory | Paquete | CVSS | Remediación |\n|---|---|---|---|---|\n"
                for f in sorted(medium_low, key=lambda x: sev_order(x.get("severity","INFO"))):
                    icon  = SEVERITY_ICONS.get(f.get("severity"),"⚪")
                    title = f.get("title","N/A")[:55]
                    cvss  = f.get("cvss_score","N/A")
                    rem   = f.get("remediation","Ver advisory")[:70]
                    md += f"| {icon} {f.get('severity')} | {title} | {cvss} | {rem} |\n"
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


def section_academic(timestamp, pipeline_run, attack_chains, tools):
    chains = len(attack_chains)
    return f"""---

## 🎓 Notas Académicas y Marco de Referencia

Este reporte fue generado automáticamente por el pipeline DevSecOps implementado como
Trabajo de Grado en la **Universidad del Valle – Sede Tuluá**.

### Marco normativo y técnico

| Estándar / Framework | Aplicación en este pipeline |
|---|---|
| **ISO/IEC 27034** | Principios de seguridad de aplicaciones — gobierno del pipeline |
| **OWASP Top 10 (2021)** | Categorización de todos los hallazgos normalizados |
| **CVSS v3.1** | Puntuación de severidad para hallazgos de Trivy |
| **CWE/SANS Top 25** | Clasificación de debilidades en SAST y DAST |
| **MITRE ATT&CK** | Referencia para cadenas de ataque identificadas por la IA |

### Herramientas integradas en el pipeline

| Herramienta | Tipo | Propósito principal | Hallazgos únicos |
|---|---|---|---|
| Semgrep | SAST | Análisis estático del código fuente | {tools.get('semgrep',0)} |
| Trivy | SCA | Vulnerabilidades en dependencias de la imagen Docker | {tools.get('trivy',0)} |
| OWASP ZAP | DAST | Escaneo dinámico de la aplicación en ejecución | {tools.get('zap',0)} |
| Nuclei | Pentesting | Validación activa con templates de vulnerabilidades conocidas | {tools.get('nuclei',0)} |

### Contribución diferencial del componente IA

| Capacidad | Gate Tradicional | Gate con IA | Impacto académico |
|---|---|---|---|
| Detección de falsos positivos | ❌ | ✅ | Reduce ruido en la decisión |
| Análisis de explotabilidad real | ❌ | ✅ | Priorización basada en riesgo real |
| Cadenas de ataque | ❌ | ✅ | {chains} cadenas identificadas en este run |
| Blind spots de cobertura | ❌ | ✅ | Documenta qué no cubre el pipeline |
| Impacto de negocio | ❌ | ✅ | Traduce CVEs a términos ejecutivos |
| Priorización contextual | ❌ | ✅ | Ordena por urgencia real, no solo por CVSS |

### Limitaciones del estudio

- Pipeline ejecutado en entorno de laboratorio con OWASP Juice Shop (aplicación intencionalmente vulnerable)
- La evaluación IA utiliza LLaMA 3.3 70B vía Groq y requiere validación humana para decisiones en producción
- Semgrep analiza el código del engine (no el de Juice Shop) ya que la app target se consume como imagen Docker
- No reemplaza una auditoría de seguridad formal ni un pentest manual

---

_Reporte generado el {timestamp} | Pipeline Run: `{pipeline_run}`_

_**Autores:** Jhojan Stiven Castaño Jejen & Juan Manuel Arango Rodas_
_**Universidad del Valle** – Ingeniería de Sistemas – 2026_
"""


# ── Orquestador principal ─────────────────────────────────────────────────────

def generate_report(findings_path, ai_eval_path, gate_path, output_path,
                    recon_path=None):

    print("\n" + "="*60)
    print("  GENERADOR DE REPORTE – DevSecOps TG")
    print("="*60)

    with open(findings_path,  "r") as f: findings_data  = json.load(f)
    with open(ai_eval_path,   "r") as f: ai_eval_data   = json.load(f)
    with open(gate_path,      "r") as f: gate_data      = json.load(f)

    recon_data = {}
    if recon_path and os.path.exists(recon_path):
        with open(recon_path, "r") as f:
            recon_data = json.load(f)

    summary         = findings_data.get("summary", {})
    findings        = findings_data.get("findings", [])
    tools_executed  = findings_data.get("tools_executed", {})
    evaluation      = ai_eval_data.get("evaluation", {})
    gate_comparison = gate_data.get("gate_comparison", {})
    attack_chains   = evaluation.get("attack_chains", [])
    timestamp       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pipeline_run    = findings_data.get("pipeline_run", "local")
    by_tool_dedup   = summary.get("by_tool", {})

    report = ""
    report += section_header(findings_data, ai_eval_data, gate_data)
    report += section_gate(gate_data, ai_eval_data)
    report += section_stats(summary, tools_executed)
    report += section_dedup_explanation(tools_executed, summary)
    report += section_recon(recon_data)
    report += section_ai_analysis(evaluation, ai_eval_data)
    report += section_attack_chains(attack_chains)
    report += section_remediation(evaluation.get("remediation_priorities", []))
    report += section_gate_comparison(gate_comparison, ai_eval_data)
    report += section_findings_detail(findings, tools_executed)
    report += section_academic(timestamp, pipeline_run, attack_chains, by_tool_dedup)

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)

    total_findings = summary.get("total", 0)
    print(f"  ✅ Reporte generado: {output_path}")
    print(f"  📄 Tamaño         : {len(report):,} caracteres")
    print(f"  🔗 Cadenas ataque : {len(attack_chains)}")
    print(f"  🚦 Decisión       : {gate_data.get('decision','UNKNOWN')}")
    print(f"  📊 Hallazgos      : {total_findings} únicos de {sum(tools_executed.values())} raw")
    print("="*60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings",       required=True)
    parser.add_argument("--ai-evaluation",  required=True)
    parser.add_argument("--gate-decision",  required=True)
    parser.add_argument("--output",         required=True)
    parser.add_argument("--recon",          default=None,
                        help="Ruta opcional a recon_context.json")
    args = parser.parse_args()

    generate_report(
        findings_path=args.findings,
        ai_eval_path=args.ai_evaluation,
        gate_path=args.gate_decision,
        output_path=args.output,
        recon_path=args.recon,
    )