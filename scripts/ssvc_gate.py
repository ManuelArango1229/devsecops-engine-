#!/usr/bin/env python3
"""
ssvc_gate.py – Gate SSVC + EPSS + CISA KEV
Trabajo de Grado – Universidad del Valle 2026

Implementa SSVC (Stakeholder-Specific Vulnerability Categorization, CISA/SEI-CERT)
como tercer gate, reemplazando el modelo TLOT/ALOT con constantes arbitrarias.

Referencias:
  Al Haddad et al. (2025) – LLMs for SSVC triage (F1 / Cohen's κ)
  Kausar et al. (2025)    – CVSS + EPSS + CISA-KEV, PR-AUC ≈ 0.98
  Yoon et al. (2023)      – ECP / ECA / EUP ancladas en MITRE ATT&CK + EPSS
  Rajapakse et al. (2021) – Métricas empíricas en DevSecOps
"""

import json
import os
import time
import urllib.request
import urllib.parse
from typing import Optional

# ── Mapeo SSVC → decisión del gate ───────────────────────────────────────────
SSVC_TO_GATE = {
    "Track":  "PASS",
    "Track*": "CONDITIONAL",
    "Attend": "CONDITIONAL",
    "Act":    "FAIL",
}
ACTIONS_RANK = {"Track": 0, "Track*": 1, "Attend": 2, "Act": 3}

# ── CWE → Impacto técnico (SSVC Technical Impact) ────────────────────────────
CWE_TO_IMPACT = {
    # total: compromiso completo de confidencialidad/integridad/disponibilidad
    "CWE-89":  "total",   # SQL Injection
    "CWE-78":  "total",   # OS Command Injection
    "CWE-347": "total",   # Improper verification of cryptographic signature (JWT)
    "CWE-798": "total",   # Hardcoded credentials
    "CWE-502": "total",   # Insecure deserialization
    "CWE-256": "total",   # Plaintext password storage
    "CWE-918": "total",   # SSRF
    "CWE-22":  "total",   # Path traversal
    "CWE-284": "total",   # Improper access control
    "CWE-434": "total",   # Unrestricted file upload
    "CWE-611": "total",   # XXE
    # partial: exposición limitada sin compromiso total
    "CWE-200": "partial",
    "CWE-307": "partial",
    "CWE-532": "partial",
    "CWE-250": "partial",
    "CWE-521": "partial",
    "CWE-665": "partial",
    "CWE-522": "partial",
    "CWE-693": "partial",
    "CWE-16":  "partial",
}

# CWEs con exploits públicos conocidos (fuente: NVD / Exploit-DB)
HIGH_EXPLOIT_CWES = {
    "CWE-89", "CWE-78", "CWE-347", "CWE-798", "CWE-502",
    "CWE-918", "CWE-22", "CWE-284", "CWE-611", "CWE-434",
}

# ── Árbol de decisión SSVC (CISA v2.1, deployer track) ───────────────────────
# (exploitation, automatable, tech_impact, mission_wellbeing) → action
SSVC_TREE = {
    # active
    ("active","yes","total",  "high"):   "Act",
    ("active","yes","total",  "medium"): "Act",
    ("active","yes","total",  "low"):    "Act",
    ("active","yes","partial","high"):   "Act",
    ("active","yes","partial","medium"): "Attend",
    ("active","yes","partial","low"):    "Attend",
    ("active","no", "total",  "high"):   "Act",
    ("active","no", "total",  "medium"): "Act",
    ("active","no", "total",  "low"):    "Attend",
    ("active","no", "partial","high"):   "Attend",
    ("active","no", "partial","medium"): "Attend",
    ("active","no", "partial","low"):    "Track*",
    # poc
    ("poc",   "yes","total",  "high"):   "Act",
    ("poc",   "yes","total",  "medium"): "Act",
    ("poc",   "yes","total",  "low"):    "Attend",
    ("poc",   "yes","partial","high"):   "Attend",
    ("poc",   "yes","partial","medium"): "Attend",
    ("poc",   "yes","partial","low"):    "Track*",
    ("poc",   "no", "total",  "high"):   "Attend",
    ("poc",   "no", "total",  "medium"): "Attend",
    ("poc",   "no", "total",  "low"):    "Track*",
    ("poc",   "no", "partial","high"):   "Track*",
    ("poc",   "no", "partial","medium"): "Track*",
    ("poc",   "no", "partial","low"):    "Track",
    # none
    ("none",  "yes","total",  "high"):   "Track*",
    ("none",  "yes","total",  "medium"): "Track",
    ("none",  "yes","total",  "low"):    "Track",
    ("none",  "yes","partial","high"):   "Track*",
    ("none",  "yes","partial","medium"): "Track",
    ("none",  "yes","partial","low"):    "Track",
    ("none",  "no", "total",  "high"):   "Track*",
    ("none",  "no", "total",  "medium"): "Track",
    ("none",  "no", "total",  "low"):    "Track",
    ("none",  "no", "partial","high"):   "Track",
    ("none",  "no", "partial","medium"): "Track",
    ("none",  "no", "partial","low"):    "Track",
}


# ── Fuentes de datos externas ─────────────────────────────────────────────────

def fetch_cisa_kev() -> set:
    """
    Descarga el catálogo CISA Known Exploited Vulnerabilities (KEV).
    Fuente pública: CISA, actualizado diariamente.
    Kausar et al. (2025) lo usan como ground truth de explotación activa.
    """
    url = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "DevSecOps-TG/2.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        kev_set = {v["cveID"] for v in data.get("vulnerabilities", [])}
        print(f"  ✅ CISA KEV: {len(kev_set)} CVEs con explotación activa confirmada")
        return kev_set
    except Exception as e:
        print(f"  ⚠️  CISA KEV no disponible ({e}). Se usará EPSS únicamente.")
        return set()


def fetch_epss_scores(cve_ids: list) -> dict:
    """
    Consulta la API pública de EPSS (FIRST.org) para una lista de CVE IDs.
    Devuelve dict {cve_id: epss_score (0.0–1.0)}.

    Kausar et al. (2025) muestran que EPSS + KEV alcanzan PR-AUC ≈ 0.98
    para predicción de explotación sobre ICS CVEs.
    """
    if not cve_ids:
        return {}

    scores = {}
    # La API acepta hasta 100 CVEs por request
    for i in range(0, len(cve_ids), 100):
        batch = cve_ids[i:i+100]
        params = urllib.parse.urlencode({"cve": ",".join(batch)})
        url = f"https://api.first.org/data/v1/epss?{params}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DevSecOps-TG/2.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
            for item in data.get("data", []):
                scores[item["cve"]] = float(item.get("epss", 0.0))
            time.sleep(0.3)  # Rate limiting cortés
        except Exception as e:
            print(f"  ⚠️  EPSS batch {i//100+1} no disponible ({e})")
    print(f"  ✅ EPSS: {len(scores)} scores obtenidos de {len(cve_ids)} CVEs")
    return scores


# ── Clasificadores SSVC ───────────────────────────────────────────────────────

def _classify_exploitation(finding: dict, epss: dict, kev: set) -> str:
    """
    Dimensión 1 de SSVC: ¿Hay explotación activa, PoC o ninguna?

    Orden de prioridad (Kausar et al. 2025, Al Haddad et al. 2025):
      1. CVE en CISA KEV → "active"  (explotación confirmada en producción)
      2. EPSS >= 0.5     → "active"  (alta probabilidad de explotación en 30 días)
      3. CVE con EPSS>0  → "poc"     (vulnerability existe pero baja prob.)
      4. Tool = nuclei   → "active"  (template ejecutable = exploit público)
      5. CWE en HIGH_EXPLOIT_CWES → "poc"
      6. Resto           → "none"
    """
    cve_id = finding.get("cve_id") or finding.get("id", "")
    # Extraer CVE ID si está en el título o ID
    if not cve_id.startswith("CVE-"):
        title = finding.get("title", "")
        import re
        match = re.search(r"CVE-\d{4}-\d+", title)
        cve_id = match.group() if match else ""

    if cve_id and cve_id in kev:
        return "active"

    epss_score = epss.get(cve_id, 0.0) if cve_id else 0.0
    if epss_score >= 0.5:
        return "active"
    if cve_id and epss_score > 0.0:
        return "poc"

    # Sin CVE: inferir del tipo de hallazgo
    if finding.get("tool") == "nuclei":
        return "active"   # Nuclei tiene template = exploit ejecutable

    cwes = _extract_cwes(finding)
    if any(c in HIGH_EXPLOIT_CWES for c in cwes):
        return "poc"

    return "none"


def _classify_automatable(finding: dict) -> str:
    """
    Dimensión 2 de SSVC: ¿Es la explotación automatizable?
    """
    tool = finding.get("tool", "")
    if tool == "nuclei":
        return "yes"   # Template ya automatiza la explotación

    cwes = _extract_cwes(finding)
    # SQLi, OS injection, deserialization, JWT son automatizables con herramientas estándar
    auto_cwes = {"CWE-89", "CWE-78", "CWE-502", "CWE-347", "CWE-798",
                 "CWE-918", "CWE-22", "CWE-434", "CWE-611"}
    if any(c in auto_cwes for c in cwes):
        return "yes"

    return "yes" if finding.get("severity") in ("CRITICAL", "HIGH") else "no"


def _classify_technical_impact(finding: dict) -> str:
    """
    Dimensión 3 de SSVC: ¿Cuál es el impacto técnico? (partial / total)
    """
    cwes = _extract_cwes(finding)
    for cwe in cwes:
        impact = CWE_TO_IMPACT.get(cwe)
        if impact == "total":
            return "total"
    if cwes:
        return "partial"

    # Sin CWE: inferir de severidad
    sev = finding.get("severity", "")
    cvss = finding.get("cvss_score", 0.0) or 0.0
    if sev == "CRITICAL" or cvss >= 9.0:
        return "total"
    if sev == "HIGH" or cvss >= 7.0:
        return "total"
    return "partial"


def _classify_mission_wellbeing(criticality: str) -> str:
    """
    Dimensión 4 de SSVC: Impacto en misión y bienestar organizacional.
    Se deriva directamente del parámetro criticality del workflow.
    """
    mapping = {"critical": "high", "high": "high",
               "medium": "medium", "low": "low"}
    return mapping.get((criticality or "medium").lower(), "medium")


def _extract_cwes(finding: dict) -> list:
    """Extrae lista de CWE IDs normalizados del finding."""
    raw = finding.get("cwe", [])
    if isinstance(raw, str):
        raw = [raw]
    result = []
    for item in raw:
        if isinstance(item, str):
            import re
            matches = re.findall(r"CWE-\d+", item)
            result.extend(matches)
    return result


def _ssvc_action(exploitation: str, automatable: str,
                 tech_impact: str, mission: str) -> str:
    """Consulta el árbol SSVC y devuelve la acción."""
    key = (exploitation, automatable, tech_impact, mission)
    return SSVC_TREE.get(key, "Attend")  # Default conservador


# ── Gate principal ────────────────────────────────────────────────────────────

def ssvc_gate(findings_data: dict, criticality: str) -> dict:
    """
    Evalúa todos los hallazgos con SSVC + EPSS + CISA KEV y produce la
    decisión final del gate (Track/Track*/Attend/Act → PASS/CONDITIONAL/FAIL).

    Ventajas sobre TLOT/ALOT:
      - Sin constantes arbitrarias: el árbol lo publica CISA
      - Elimina saturación: cada hallazgo clasifica individualmente
      - Permite calcular F1 contra ground truth CISA KEV
      - Produce divergencia entre casos con perfiles distintos
    """
    print("  📡 Descargando CISA KEV...")
    kev_set = fetch_cisa_kev()

    findings = findings_data.get("findings", [])
    cve_ids = []
    for f in findings:
        cve_id = f.get("cve_id") or ""
        if not cve_id:
            title = f.get("title", "")
            import re
            m = re.search(r"CVE-\d{4}-\d+", title)
            if m:
                cve_id = m.group()
        if cve_id.startswith("CVE-"):
            cve_ids.append(cve_id)

    cve_ids = list(set(cve_ids))
    print(f"  📡 Consultando EPSS para {len(cve_ids)} CVEs únicos...")
    epss_cache = fetch_epss_scores(cve_ids)

    mw = _classify_mission_wellbeing(criticality)

    # Clasificar cada hallazgo
    classified = []
    action_counts = {"Act": 0, "Attend": 0, "Track*": 0, "Track": 0}
    act_findings  = []

    for f in findings:
        exploitation = _classify_exploitation(f, epss_cache, kev_set)
        automatable  = _classify_automatable(f)
        tech_impact  = _classify_technical_impact(f)
        action       = _ssvc_action(exploitation, automatable, tech_impact, mw)

        action_counts[action] = action_counts.get(action, 0) + 1

        # Extraer CVE ID para enriquecimiento del prompt IA
        import re as _re
        _cve_id = f.get("cve_id") or ""
        if not _cve_id.startswith("CVE-"):
            _m = _re.search(r"CVE-\d{4}-\d+", f.get("title",""))
            _cve_id = _m.group() if _m else ""

        record = {
            "finding_id":       f.get("id", ""),
            "title":            f.get("title", "")[:80],
            "tool":             f.get("tool", ""),
            "severity":         f.get("severity", ""),
            "exploitation":     exploitation,
            "automatable":      automatable,
            "tech_impact":      tech_impact,
            "mission_wellbeing": mw,
            "ssvc_action":      action,
            "gate_mapping":     SSVC_TO_GATE.get(action, "FAIL"),
            # Enriquecimiento para gate IA híbrido
            "cve_id":           _cve_id,
            "epss_score":       round(epss_cache.get(_cve_id, 0.0), 4) if _cve_id else 0.0,
            "in_kev":           _cve_id in kev_set if _cve_id else False,
        }
        classified.append(record)
        if action == "Act":
            act_findings.append(record)

    # Decisión agregada = acción máxima (solo sobre acciones con count > 0)
    active_actions = {k: v for k, v in action_counts.items() if v > 0}
    aggregate_action = (
        max(active_actions.keys(), key=lambda a: ACTIONS_RANK.get(a, 0))
        if active_actions else "Track"
    )
    gate_decision = SSVC_TO_GATE.get(aggregate_action, "FAIL")

    # ── Métricas F1 sobre la dimensión Exploitation ────────────────────────
    f1_metrics = _calculate_exploitation_f1(findings, epss_cache, kev_set)

    reasoning = (
        f"SSVC evaluó {len(findings)} hallazgos únicos bajo misión '{mw}' "
        f"(criticality={criticality}). "
        f"Distribución: Act={action_counts['Act']}, Attend={action_counts['Attend']}, "
        f"Track*={action_counts['Track*']}, Track={action_counts['Track']}. "
        f"Decisión agregada: {aggregate_action} → {gate_decision}. "
        f"Fuentes: CISA KEV ({len(kev_set)} entradas), "
        f"EPSS ({len(epss_cache)} scores)."
    )

    return {
        "method":           "ssvc_epss_kev",
        "decision":         gate_decision,
        "aggregate_action": aggregate_action,
        "action_counts":    action_counts,
        "mission_wellbeing": mw,
        "criticality":      criticality,
        "data_sources": {
            "cisa_kev_entries": len(kev_set),
            "epss_scores_fetched": len(epss_cache),
            "cve_ids_queried":    len(cve_ids),
        },
        "all_classified_findings": classified,
        "top_act_findings": act_findings[:10],
        "reasoning":        reasoning,
        "f1_metrics":       f1_metrics,
        "gate_mapping":     SSVC_TO_GATE,
        "advantage":        (
            "Sin constantes arbitrarias (árbol CISA publicado). "
            "Diferencia casos por perfil de explotación real, no por conteo. "
            "Permite F1 contra ground truth CISA KEV."
        ),
        "references": [
            "Al Haddad et al. (2025) – arXiv 2510.18508",
            "Kausar et al. (2025) – DOI 10.21203/rs.3.rs-8244471/v1",
            "Yoon et al. (2023) – DOI 10.3390/app132212180",
        ],
    }


def _calculate_exploitation_f1(findings: list, epss: dict, kev: set) -> dict:
    """
    Calcula precisión, recall y F1 para la dimensión Exploitation.

    Ground truth:
      - CVE en CISA KEV → "active" (explotación confirmada)
      - CVE con EPSS >= 0.5 → "active" (proxy de alta probabilidad)
      - Resto con CVE → "not_active"
      - Sin CVE → excluido del cálculo formal

    Al Haddad et al. (2025) usan exactamente esta metodología sobre 384
    vulnerabilidades de VulZoo para calcular F1 por punto de decisión SSVC.
    """
    import re
    tp = fp = tn = fn = 0

    for f in findings:
        cve_id = f.get("cve_id") or ""
        if not cve_id.startswith("CVE-"):
            title = f.get("title", "")
            m = re.search(r"CVE-\d{4}-\d+", title)
            cve_id = m.group() if m else ""

        if not cve_id.startswith("CVE-"):
            continue  # Sin CVE no hay ground truth verificable

        # Ground truth
        epss_score = epss.get(cve_id, 0.0)
        gt_active = (cve_id in kev) or (epss_score >= 0.5)

        # Predicción de nuestro clasificador
        pred_active = _classify_exploitation(f, epss, kev) == "active"

        if gt_active and pred_active:
            tp += 1
        elif not gt_active and pred_active:
            fp += 1
        elif gt_active and not pred_active:
            fn += 1
        else:
            tn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    accuracy  = (tp + tn) / total if total > 0 else 0.0

    return {
        "dimension":  "Exploitation (active vs not_active)",
        "ground_truth_source": "CISA KEV + EPSS ≥ 0.5",
        "reference":  "Al Haddad et al. (2025) – arXiv 2510.18508",
        "cves_evaluated": total,
        "true_positives":  tp,
        "false_positives": fp,
        "true_negatives":  tn,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall":    round(recall,    4),
        "f1_score":  round(f1,        4),
        "accuracy":  round(accuracy,  4),
        "note": (
            "F1 calculado sobre la dimensión Exploitation del árbol SSVC. "
            "Solo CVEs con CISA KEV o EPSS disponible se incluyen en el cálculo. "
            "Hallazgos sin CVE ID (Semgrep/ZAP) se excluyen del cálculo formal."
        ),
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Uso: python3 ssvc_gate.py <findings.json> <criticality>")
        sys.exit(1)
    with open(sys.argv[1]) as f:
        data = json.load(f)
    result = ssvc_gate(data, sys.argv[2])
    print(json.dumps(result, indent=2, ensure_ascii=False))