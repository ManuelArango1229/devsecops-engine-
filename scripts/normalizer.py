#!/usr/bin/env python3
"""
normalizer.py – Normalizador de hallazgos de seguridad
Trabajo de Grado – Universidad del Valle 2026
"""

import json
import argparse
import hashlib
import os
from datetime import datetime


# ============================================================
# MAPEO DE SEVERIDADES AL ESQUEMA UNIFICADO
# ============================================================

SEVERITY_MAP = {
    "ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW",
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
    "LOW": "LOW", "UNKNOWN": "INFO",
    "3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO",
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFO", "unknown": "INFO",
}

OWASP_CATEGORIES = {
    "injection": "A03:2021 – Injection",
    "sql": "A03:2021 – Injection",
    "xss": "A03:2021 – Injection",
    "cross-site": "A03:2021 – Injection",
    "authentication": "A07:2021 – Identification and Authentication Failures",
    "auth": "A07:2021 – Identification and Authentication Failures",
    "jwt": "A07:2021 – Identification and Authentication Failures",
    "token": "A07:2021 – Identification and Authentication Failures",
    "broken access": "A01:2021 – Broken Access Control",
    "access control": "A01:2021 – Broken Access Control",
    "idor": "A01:2021 – Broken Access Control",
    "crypto": "A02:2021 – Cryptographic Failures",
    "sensitive data": "A02:2021 – Cryptographic Failures",
    "password": "A02:2021 – Cryptographic Failures",
    "component": "A06:2021 – Vulnerable and Outdated Components",
    "dependency": "A06:2021 – Vulnerable and Outdated Components",
    "cve": "A06:2021 – Vulnerable and Outdated Components",
    "misconfiguration": "A05:2021 – Security Misconfiguration",
    "header": "A05:2021 – Security Misconfiguration",
    "cors": "A05:2021 – Security Misconfiguration",
    "exposure": "A05:2021 – Security Misconfiguration",
    "logging": "A09:2021 – Security Logging and Monitoring Failures",
    "ssrf": "A10:2021 – Server-Side Request Forgery",
    "deserialization": "A08:2021 – Software and Data Integrity Failures",
}


def normalize_severity(raw_severity: str) -> str:
    if raw_severity is None:
        return "INFO"
    return SEVERITY_MAP.get(str(raw_severity).upper(),
           SEVERITY_MAP.get(str(raw_severity).lower(), "INFO"))


def infer_owasp_category(title: str, description: str) -> str:
    text = f"{title} {description}".lower()
    for keyword, category in OWASP_CATEGORIES.items():
        if keyword in text:
            return category
    return "A05:2021 – Security Misconfiguration"


def generate_id(tool: str, title: str, location: str) -> str:
    content = f"{tool}:{title}:{location}"
    return f"{tool[:3].upper()}-{hashlib.md5(content.encode()).hexdigest()[:8].upper()}"


# ============================================================
# PARSERS POR HERRAMIENTA
# ============================================================

def parse_semgrep(filepath: str) -> list:
    findings = []
    if not filepath or not os.path.exists(filepath):
        print(f"  ⚠️  Semgrep: archivo no encontrado ({filepath})")
        return findings
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"  ⚠️  Semgrep: error al leer archivo – {e}")
        return findings

    results = data.get('results', [])
    print(f"  → Semgrep: {len(results)} hallazgos raw")

    for result in results:
        severity_raw = result.get('extra', {}).get('severity', 'WARNING')
        title        = result.get('check_id', 'Unknown Rule').split('.')[-1]
        file_path    = result.get('path', 'unknown')
        line         = result.get('start', {}).get('line', 0)
        description  = result.get('extra', {}).get('message', 'No description')
        fix          = result.get('extra', {}).get('metadata', {}).get('fix', '')
        remediation  = fix if fix else f"Revisar y corregir el patrón identificado en {file_path}:{line}"

        finding = {
            "id":          generate_id("semgrep", title, f"{file_path}:{line}"),
            "tool":        "semgrep",
            "tool_type":   "SAST",
            "severity":    normalize_severity(severity_raw),
            "cvss_score":  None,
            "title":       title.replace('-', ' ').replace('_', ' ').title(),
            "description": description,
            "category":    infer_owasp_category(title, description),
            "cwe":         result.get('extra', {}).get('metadata', {}).get('cwe', None),
            "location": {
                "file":     file_path,
                "line":     line,
                "endpoint": None,
                "method":   None,
            },
            "evidence":    result.get('extra', {}).get('lines', ''),
            "remediation": remediation,
            "raw":         result,
        }
        findings.append(finding)
    return findings


def parse_trivy(filepath: str) -> list:
    findings = []
    if not filepath or not os.path.exists(filepath):
        print(f"  ⚠️  Trivy: archivo no encontrado ({filepath})")
        return findings
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"  ⚠️  Trivy: error al leer archivo – {e}")
        return findings

    total_raw = 0
    for result in data.get('Results', []):
        vulnerabilities = result.get('Vulnerabilities') or []
        total_raw += len(vulnerabilities)

        for vuln in vulnerabilities:
            severity_raw     = vuln.get('Severity', 'UNKNOWN')
            cve_id           = vuln.get('VulnerabilityID', 'UNKNOWN')
            pkg_name         = vuln.get('PkgName', 'unknown-package')
            installed_version = vuln.get('InstalledVersion', 'unknown')
            fixed_version    = vuln.get('FixedVersion', 'Not available')
            title            = vuln.get('Title', f'Vulnerability in {pkg_name}')
            description      = vuln.get('Description', 'No description available')

            cvss_score = None
            for source in ['nvd', 'redhat', 'ghsa']:
                v3 = vuln.get('CVSS', {}).get(source, {}).get('V3Score')
                if v3:
                    cvss_score = float(v3)
                    break

            if fixed_version and fixed_version != 'Not available':
                remediation = f"Actualizar {pkg_name} de {installed_version} a {fixed_version}"
            else:
                remediation = f"No hay fix disponible para {pkg_name} {installed_version} — considerar alternativa"

            finding = {
                "id":          generate_id("trivy", cve_id, pkg_name),
                "tool":        "trivy",
                "tool_type":   "SCA",
                "severity":    normalize_severity(severity_raw),
                "cvss_score":  cvss_score,
                "title":       f"{cve_id} – {title}",
                "description": description,
                "category":    "A06:2021 – Vulnerable and Outdated Components",
                "cwe":         None,
                "location": {
                    "file":     result.get('Target', 'docker-image'),
                    "line":     None,
                    "endpoint": None,
                    "method":   None,
                },
                "evidence":    f"Paquete: {pkg_name} v{installed_version} | Fix: {fixed_version}",
                "remediation": remediation,
                "raw":         vuln,
            }
            findings.append(finding)

    print(f"  → Trivy: {total_raw} hallazgos raw")
    return findings


def parse_zap(filepath: str) -> list:
    findings = []
    if not filepath or not os.path.exists(filepath):
        print(f"  ⚠️  ZAP: archivo no encontrado ({filepath})")
        return findings
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"  ⚠️  ZAP: error al leer archivo – {e}")
        return findings

    total_raw = 0
    for site in data.get('site', []):
        alerts = site.get('alerts', [])
        total_raw += len(alerts)

        for alert in alerts:
            severity_raw = str(alert.get('riskcode', '1'))
            name         = alert.get('name', 'Unknown Alert')
            desc         = alert.get('desc', 'No description')
            solution     = alert.get('solution', '')
            instances    = alert.get('instances', [])
            endpoint     = instances[0].get('uri', '') if instances else ''
            method       = instances[0].get('method', 'GET') if instances else 'GET'

            # Limpiar HTML de descripción y solución
            def clean_html(text):
                return text.replace('<p>', '').replace('</p>', ' ') \
                           .replace('<ul>', '').replace('</ul>', '') \
                           .replace('<li>', '• ').replace('</li>', ' ') \
                           .replace('<br>', ' ').replace('<br/>', ' ').strip()

            desc_clean     = clean_html(desc)
            solution_clean = clean_html(solution) if solution else f"Revisar y corregir la alerta: {name}"

            # Construir evidencia con todas las instancias
            if len(instances) > 1:
                urls = [i.get('uri', '') for i in instances[:5]]
                evidence = f"Detectado en {len(instances)} URLs: " + ", ".join(urls)
            else:
                evidence = alert.get('evidence', instances[0].get('evidence', '') if instances else '')

            finding = {
                "id":          generate_id("zap", name, endpoint),
                "tool":        "zap",
                "tool_type":   "DAST",
                "severity":    normalize_severity(severity_raw),
                "cvss_score":  None,
                "title":       name,
                "description": desc_clean[:500],
                "category":    infer_owasp_category(name, desc),
                "cwe":         alert.get('cweid', None),
                "location": {
                    "file":     None,
                    "line":     None,
                    "endpoint": endpoint,
                    "method":   method,
                },
                "evidence":    evidence[:300],
                "remediation": solution_clean[:400],
                "instances_count": len(instances),
                "raw": {
                    "alert_id":       alert.get('pluginid'),
                    "instances_count": len(instances),
                    "confidence":     alert.get('confidence'),
                    "reference":      alert.get('reference', ''),
                    "all_urls":       [i.get('uri', '') for i in instances],
                },
            }
            findings.append(finding)

    print(f"  → ZAP: {total_raw} hallazgos raw")
    return findings


def parse_nuclei(filepath: str) -> list:
    findings = []
    if not filepath or not os.path.exists(filepath):
        print(f"  ⚠️  Nuclei: archivo no encontrado ({filepath})")
        return findings
    try:
        with open(filepath, 'r') as f:
            content = f.read().strip()
        if not content or content == '[]':
            print(f"  → Nuclei: 0 hallazgos raw (reporte vacío)")
            return findings

        try:
            results = json.loads(content)
            if not isinstance(results, list):
                results = [results]
        except json.JSONDecodeError:
            results = []
            for line in content.splitlines():
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except IOError as e:
        print(f"  ⚠️  Nuclei: error al leer archivo – {e}")
        return findings

    print(f"  → Nuclei: {len(results)} hallazgos raw")

    for result in results:
        info         = result.get('info', {})
        severity_raw = info.get('severity', 'info')
        template_id  = result.get('template-id', 'unknown')
        name         = info.get('name', template_id)
        description  = info.get('description', 'No description')
        matched_url  = result.get('matched-at', result.get('host', ''))
        tags         = info.get('tags', [])

        # Extraer remediación de múltiples campos posibles
        remediation = (
            info.get('remediation') or
            info.get('fix') or
            info.get('solution') or
            ''
        )
        if not remediation and description:
            # Usar los primeros 200 chars de descripción como guía
            remediation = f"Revisar: {description[:200]}"
        if not remediation:
            remediation = f"Revisar configuración relacionada con: {name}"

        # Construir referencia
        references = info.get('reference', [])
        if isinstance(references, str):
            references = [references]
        ref_str = references[0] if references else ''

        # Evidencia enriquecida
        extracted = result.get('extracted-results', [])
        curl_cmd   = result.get('curl-command', '')
        if extracted:
            evidence = f"Datos extraídos: {', '.join(str(e) for e in extracted[:3])}"
        elif curl_cmd:
            evidence = curl_cmd[:200]
        else:
            evidence = f"Template: {template_id} | URL: {matched_url}"

        finding = {
            "id":          generate_id("nuclei", template_id, matched_url),
            "tool":        "nuclei",
            "tool_type":   "PENTEST",
            "severity":    normalize_severity(severity_raw),
            "cvss_score":  None,
            "title":       name,
            "description": description[:500],
            "category":    infer_owasp_category(name, description),
            "cwe":         None,
            "location": {
                "file":     None,
                "line":     None,
                "endpoint": matched_url,
                "method":   result.get('type', 'http').upper(),
            },
            "evidence":    evidence,
            "remediation": remediation[:400],
            "raw": {
                "template_id":   template_id,
                "matcher_name":  result.get('matcher-name', ''),
                "tags":          tags,
                "reference":     ref_str,
                "timestamp":     result.get('timestamp', ''),
            },
        }
        findings.append(finding)

    return findings


# ============================================================
# DEDUPLICACIÓN Y RESUMEN
# ============================================================

def deduplicate(findings: list) -> list:
    seen   = set()
    unique = []
    for finding in findings:
        key = (
            f"{finding['tool']}:"
            f"{finding['title']}:"
            f"{finding['location'].get('endpoint', '')}:"
            f"{finding['location'].get('file', '')}"
        )
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def calculate_summary(findings: list) -> dict:
    summary = {
        "total":       len(findings),
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "by_tool":     {"semgrep": 0, "trivy": 0, "zap": 0, "nuclei": 0},
        "by_category": {},
        "critical_and_high": 0,
    }
    for f in findings:
        sev  = f.get('severity', 'INFO')
        tool = f.get('tool', 'unknown')
        cat  = f.get('category', 'Unknown')
        if sev in summary["by_severity"]:
            summary["by_severity"][sev] += 1
        if tool in summary["by_tool"]:
            summary["by_tool"][tool] += 1
        summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1

    summary["critical_and_high"] = (
        summary["by_severity"]["CRITICAL"] + summary["by_severity"]["HIGH"]
    )
    return summary


# ============================================================
# FUNCIÓN PRINCIPAL
# ============================================================

def normalize(semgrep_path, trivy_path, zap_path, nuclei_path, output_path):
    print("\n" + "="*60)
    print("  NORMALIZADOR DE HALLAZGOS – DevSecOps TG")
    print("="*60)
    print(f"  Timestamp: {datetime.now().isoformat()}")
    print()
    print("📥 Procesando reportes:")

    semgrep_findings = parse_semgrep(semgrep_path)
    trivy_findings   = parse_trivy(trivy_path)
    zap_findings     = parse_zap(zap_path)
    nuclei_findings  = parse_nuclei(nuclei_path)

    all_findings = semgrep_findings + trivy_findings + zap_findings + nuclei_findings
    print(f"\n📊 Total antes de deduplicación: {len(all_findings)}")

    unique_findings = deduplicate(all_findings)
    print(f"📊 Total después de deduplicación: {len(unique_findings)}")

    summary = calculate_summary(unique_findings)

    output = {
        "schema_version": "1.0",
        "generated_at":   datetime.now().isoformat(),
        "pipeline_run":   os.environ.get('GITHUB_RUN_ID', 'local'),
        "environment":    os.environ.get('ENVIRONMENT', 'staging'),
        "service":        os.environ.get('SERVICE_NAME', 'unknown'),
        "summary":        summary,
        "findings":       unique_findings,
        "tools_executed": {
            "semgrep": len(semgrep_findings),
            "trivy":   len(trivy_findings),
            "zap":     len(zap_findings),
            "nuclei":  len(nuclei_findings),
        },
    }

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print("\n" + "="*60)
    print("  RESUMEN FINAL")
    print("="*60)
    print(f"  CRITICAL : {summary['by_severity']['CRITICAL']}")
    print(f"  HIGH     : {summary['by_severity']['HIGH']}")
    print(f"  MEDIUM   : {summary['by_severity']['MEDIUM']}")
    print(f"  LOW      : {summary['by_severity']['LOW']}")
    print(f"  INFO     : {summary['by_severity']['INFO']}")
    print(f"  ─────────────────")
    print(f"  TOTAL    : {summary['total']}")
    print(f"  Por herramienta: {summary['by_tool']}")
    print(f"\n  Reporte guardado en: {output_path}")
    print("="*60 + "\n")

    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Normalizador de hallazgos DevSecOps')
    parser.add_argument('--semgrep', help='Ruta al reporte de Semgrep (JSON)')
    parser.add_argument('--trivy',   help='Ruta al reporte de Trivy (JSON)')
    parser.add_argument('--zap',     help='Ruta al reporte de ZAP (JSON)')
    parser.add_argument('--nuclei',  help='Ruta al reporte de Nuclei (JSON)')
    parser.add_argument('--output',  required=True, help='Ruta del archivo de salida')
    args = parser.parse_args()

    normalize(
        semgrep_path=args.semgrep,
        trivy_path=args.trivy,
        zap_path=args.zap,
        nuclei_path=args.nuclei,
        output_path=args.output,
    )