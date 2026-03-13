#!/usr/bin/env python3
"""
normalizer.py – Normalizador de hallazgos de seguridad
Trabajo de Grado – Universidad del Valle 2026

Propósito académico: Demostrar cómo unificar resultados heterogéneos
de múltiples herramientas de seguridad en un esquema común.

Herramientas soportadas:
  - Semgrep (SAST)
  - Trivy (SCA)
  - OWASP ZAP (DAST)
  - Nuclei (Pentesting automatizado)
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
    # Semgrep
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    # Trivy
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNKNOWN": "INFO",
    # ZAP
    "3": "HIGH",
    "2": "MEDIUM",
    "1": "LOW",
    "0": "INFO",
    # Nuclei
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "unknown": "INFO",
}

# Mapeo OWASP Top 10 por tipo de vulnerabilidad
OWASP_CATEGORIES = {
    "injection": "A03:2021 – Injection",
    "sql": "A03:2021 – Injection",
    "xss": "A03:2021 – Injection",
    "cross-site": "A03:2021 – Injection",
    "authentication": "A07:2021 – Identification and Authentication Failures",
    "auth": "A07:2021 – Identification and Authentication Failures",
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
    "logging": "A09:2021 – Security Logging and Monitoring Failures",
    "ssrf": "A10:2021 – Server-Side Request Forgery",
    "deserialization": "A08:2021 – Software and Data Integrity Failures",
}


def normalize_severity(raw_severity: str) -> str:
    """Normaliza la severidad al esquema unificado."""
    if raw_severity is None:
        return "INFO"
    return SEVERITY_MAP.get(str(raw_severity).upper(), 
           SEVERITY_MAP.get(str(raw_severity).lower(), "INFO"))


def infer_owasp_category(title: str, description: str) -> str:
    """Infiere la categoría OWASP basándose en título y descripción."""
    text = f"{title} {description}".lower()
    for keyword, category in OWASP_CATEGORIES.items():
        if keyword in text:
            return category
    return "A05:2021 – Security Misconfiguration"  # Default más común


def generate_id(tool: str, title: str, location: str) -> str:
    """Genera un ID único reproducible para cada hallazgo."""
    content = f"{tool}:{title}:{location}"
    return f"{tool[:3].upper()}-{hashlib.md5(content.encode()).hexdigest()[:8].upper()}"


# ============================================================
# PARSERS POR HERRAMIENTA
# ============================================================

def parse_semgrep(filepath: str) -> list:
    """
    Parser para reportes Semgrep (SAST).
    Formato: JSON con campo 'results' que contiene array de hallazgos.
    """
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
        title = result.get('check_id', 'Unknown Rule').split('.')[-1]
        file_path = result.get('path', 'unknown')
        line = result.get('start', {}).get('line', 0)
        description = result.get('extra', {}).get('message', 'No description')
        
        finding = {
            "id": generate_id("semgrep", title, f"{file_path}:{line}"),
            "tool": "semgrep",
            "tool_type": "SAST",
            "severity": normalize_severity(severity_raw),
            "cvss_score": None,
            "title": title.replace('-', ' ').replace('_', ' ').title(),
            "description": description,
            "category": infer_owasp_category(title, description),
            "cwe": result.get('extra', {}).get('metadata', {}).get('cwe', None),
            "location": {
                "file": file_path,
                "line": line,
                "endpoint": None,
                "method": None
            },
            "evidence": result.get('extra', {}).get('lines', ''),
            "remediation": result.get('extra', {}).get('metadata', {}).get('fix', 'Review and fix the identified pattern'),
            "raw": result
        }
        findings.append(finding)
    
    return findings


def parse_trivy(filepath: str) -> list:
    """
    Parser para reportes Trivy (SCA).
    Formato: JSON con campo 'Results' que contiene array de resultados por target.
    """
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
    results = data.get('Results', [])
    
    for result in results:
        vulnerabilities = result.get('Vulnerabilities') or []
        total_raw += len(vulnerabilities)
        
        for vuln in vulnerabilities:
            severity_raw = vuln.get('Severity', 'UNKNOWN')
            cve_id = vuln.get('VulnerabilityID', 'UNKNOWN')
            pkg_name = vuln.get('PkgName', 'unknown-package')
            installed_version = vuln.get('InstalledVersion', 'unknown')
            fixed_version = vuln.get('FixedVersion', 'Not available')
            title = vuln.get('Title', f'Vulnerability in {pkg_name}')
            description = vuln.get('Description', 'No description available')
            
            # CVSS score
            cvss_score = None
            cvss_data = vuln.get('CVSS', {})
            for source in ['nvd', 'redhat', 'ghsa']:
                if source in cvss_data:
                    v3 = cvss_data[source].get('V3Score')
                    if v3:
                        cvss_score = float(v3)
                        break
            
            finding = {
                "id": generate_id("trivy", cve_id, pkg_name),
                "tool": "trivy",
                "tool_type": "SCA",
                "severity": normalize_severity(severity_raw),
                "cvss_score": cvss_score,
                "title": f"{cve_id} – {title}",
                "description": description,
                "category": "A06:2021 – Vulnerable and Outdated Components",
                "cwe": None,
                "location": {
                    "file": result.get('Target', 'docker-image'),
                    "line": None,
                    "endpoint": None,
                    "method": None
                },
                "evidence": f"Package: {pkg_name} v{installed_version} | Fix: {fixed_version}",
                "remediation": f"Update {pkg_name} from {installed_version} to {fixed_version}" if fixed_version != 'Not available' else f"No fix available for {pkg_name} {installed_version}",
                "raw": vuln
            }
            findings.append(finding)
    
    print(f"  → Trivy: {total_raw} hallazgos raw")
    return findings


def parse_zap(filepath: str) -> list:
    """
    Parser para reportes OWASP ZAP (DAST).
    Formato: JSON con campo 'site' que contiene array de sitios con alertas.
    """
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
    sites = data.get('site', [])
    
    for site in sites:
        alerts = site.get('alerts', [])
        total_raw += len(alerts)
        
        for alert in alerts:
            severity_raw = str(alert.get('riskcode', '1'))
            name = alert.get('name', 'Unknown Alert')
            desc = alert.get('desc', 'No description')
            solution = alert.get('solution', 'No solution provided')
            instances = alert.get('instances', [])
            
            # Tomar primera instancia para la ubicación
            endpoint = instances[0].get('uri', '') if instances else ''
            method = instances[0].get('method', 'GET') if instances else 'GET'
            
            finding = {
                "id": generate_id("zap", name, endpoint),
                "tool": "zap",
                "tool_type": "DAST",
                "severity": normalize_severity(severity_raw),
                "cvss_score": None,
                "title": name,
                "description": desc.replace('<p>', '').replace('</p>', ' ').strip(),
                "category": infer_owasp_category(name, desc),
                "cwe": alert.get('cweid', None),
                "location": {
                    "file": None,
                    "line": None,
                    "endpoint": endpoint,
                    "method": method
                },
                "evidence": alert.get('evidence', instances[0].get('evidence', '') if instances else ''),
                "remediation": solution.replace('<p>', '').replace('</p>', ' ').strip(),
                "raw": {
                    "alert_id": alert.get('pluginid'),
                    "instances_count": len(instances),
                    "confidence": alert.get('confidence'),
                    "reference": alert.get('reference', '')
                }
            }
            findings.append(finding)
    
    print(f"  → ZAP: {total_raw} hallazgos raw")
    return findings


def parse_nuclei(filepath: str) -> list:
    """
    Parser para reportes Nuclei (Pentesting automatizado).
    Formato: JSON Lines (un objeto JSON por línea) o array JSON.
    """
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
        
        # Intentar como array JSON
        try:
            results = json.loads(content)
            if not isinstance(results, list):
                results = [results]
        except json.JSONDecodeError:
            # Intentar como JSON Lines
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
        severity_raw = result.get('info', {}).get('severity', 'info')
        template_id = result.get('template-id', 'unknown')
        name = result.get('info', {}).get('name', template_id)
        description = result.get('info', {}).get('description', 'No description')
        matched_url = result.get('matched-at', result.get('host', ''))
        
        finding = {
            "id": generate_id("nuclei", template_id, matched_url),
            "tool": "nuclei",
            "tool_type": "PENTEST",
            "severity": normalize_severity(severity_raw),
            "cvss_score": None,
            "title": name,
            "description": description,
            "category": infer_owasp_category(name, description),
            "cwe": None,
            "location": {
                "file": None,
                "line": None,
                "endpoint": matched_url,
                "method": result.get('type', 'http').upper()
            },
            "evidence": result.get('extracted-results', result.get('curl-command', '')),
            "remediation": result.get('info', {}).get('remediation', 'Review and remediate the identified issue'),
            "raw": {
                "template_id": template_id,
                "matcher_name": result.get('matcher-name', ''),
                "tags": result.get('info', {}).get('tags', []),
                "timestamp": result.get('timestamp', '')
            }
        }
        findings.append(finding)
    
    return findings


# ============================================================
# FUNCIÓN PRINCIPAL DE NORMALIZACIÓN
# ============================================================

def deduplicate(findings: list) -> list:
    """
    Deduplicación simple: elimina hallazgos con el mismo título
    encontrados por la misma herramienta en la misma ubicación.
    """
    seen = set()
    unique = []
    for finding in findings:
        key = f"{finding['tool']}:{finding['title']}:{finding['location'].get('endpoint', '')}:{finding['location'].get('file', '')}"
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def calculate_summary(findings: list) -> dict:
    """Calcula estadísticas del conjunto de hallazgos."""
    summary = {
        "total": len(findings),
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "by_tool": {"semgrep": 0, "trivy": 0, "zap": 0, "nuclei": 0},
        "by_category": {},
        "critical_and_high": 0
    }
    
    for f in findings:
        sev = f.get('severity', 'INFO')
        tool = f.get('tool', 'unknown')
        cat = f.get('category', 'Unknown')
        
        if sev in summary["by_severity"]:
            summary["by_severity"][sev] += 1
        if tool in summary["by_tool"]:
            summary["by_tool"][tool] += 1
        summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1
    
    summary["critical_and_high"] = (
        summary["by_severity"]["CRITICAL"] + 
        summary["by_severity"]["HIGH"]
    )
    
    return summary


def normalize(semgrep_path, trivy_path, zap_path, nuclei_path, output_path):
    """Función principal de normalización."""
    
    print("\n" + "="*60)
    print("  NORMALIZADOR DE HALLAZGOS – DevSecOps TG")
    print("="*60)
    print(f"  Timestamp: {datetime.now().isoformat()}")
    print()
    
    print("📥 Procesando reportes:")
    
    # Parsear cada herramienta
    semgrep_findings = parse_semgrep(semgrep_path)
    trivy_findings = parse_trivy(trivy_path)
    zap_findings = parse_zap(zap_path)
    nuclei_findings = parse_nuclei(nuclei_path)
    
    # Combinar todos los hallazgos
    all_findings = semgrep_findings + trivy_findings + zap_findings + nuclei_findings
    
    print(f"\n📊 Total antes de deduplicación: {len(all_findings)}")
    
    # Deduplicar
    unique_findings = deduplicate(all_findings)
    print(f"📊 Total después de deduplicación: {len(unique_findings)}")
    
    # Calcular resumen
    summary = calculate_summary(unique_findings)
    
    # Construir output final
    output = {
        "schema_version": "1.0",
        "generated_at": datetime.now().isoformat(),
        "pipeline_run": os.environ.get('GITHUB_RUN_ID', 'local'),
        "environment": os.environ.get('ENVIRONMENT', 'staging'),
        "service": os.environ.get('SERVICE_NAME', 'unknown'),
        "summary": summary,
        "findings": unique_findings,
        "tools_executed": {
            "semgrep": len(semgrep_findings),
            "trivy": len(trivy_findings),
            "zap": len(zap_findings),
            "nuclei": len(nuclei_findings)
        }
    }
    
    # Guardar output
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    # Resumen en consola
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
    print(f"\n  Reporte guardado en: {output_path}")
    print("="*60 + "\n")
    
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Normalizador de hallazgos de seguridad DevSecOps'
    )
    parser.add_argument('--semgrep', help='Ruta al reporte de Semgrep (JSON)')
    parser.add_argument('--trivy', help='Ruta al reporte de Trivy (JSON)')
    parser.add_argument('--zap', help='Ruta al reporte de ZAP (JSON)')
    parser.add_argument('--nuclei', help='Ruta al reporte de Nuclei (JSON)')
    parser.add_argument('--output', required=True, help='Ruta del archivo de salida (findings.json)')
    
    args = parser.parse_args()
    
    normalize(
        semgrep_path=args.semgrep,
        trivy_path=args.trivy,
        zap_path=args.zap,
        nuclei_path=args.nuclei,
        output_path=args.output
    )
