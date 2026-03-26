#!/usr/bin/env python3
"""
recon.py – Fase de Reconocimiento Activo
Trabajo de Grado – Universidad del Valle 2026

Ejecuta nmap, ffuf, httpx y wafw00f contra la app en ejecución
y genera recon_context.json que alimenta a Nuclei, ZAP y ai_engine.
"""

import json
import os
import subprocess
import argparse
import sys
from datetime import datetime
from urllib.parse import urlparse


def run_cmd(cmd: list, timeout: int = 60) -> tuple:
    """Ejecuta un comando y retorna (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, check=False
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout después de {timeout}s", 1
    except FileNotFoundError:
        return "", f"Herramienta no encontrada: {cmd[0]}", 127


def run_nmap(host: str, port: int) -> dict:
    """Escaneo de puertos y detección de servicios con nmap."""
    print("  🔍 nmap: escaneando puertos y servicios...")

    # Rango reducido (1-1000) para que no supere el timeout de CI
    stdout, stderr, rc = run_cmd([
        "nmap", "-sV", "-T4",
        "--open",
        "-p", f"1-1000,{port}",
        host
    ], timeout=60)

    if rc == 127:
        print("  ⚠️  nmap no disponible, saltando...")
        return {"available": False, "open_ports": [port], "services": {}, "interesting_ports": []}

    open_ports = []
    services = {}
    lines = stdout.split("\n")

    for line in lines:
        if "/tcp" in line and "open" in line:
            parts = line.split()
            if parts:
                try:
                    port_num = int(parts[0].split("/")[0])
                    service  = parts[2] if len(parts) > 2 else "unknown"
                    version  = " ".join(parts[3:]) if len(parts) > 3 else ""
                    open_ports.append(port_num)
                    services[str(port_num)] = {
                        "service": service,
                        "version": version.strip(),
                        "interesting": any(kw in service.lower() for kw in
                                           ["debug", "admin", "mongo", "redis", "mysql", "postgres"])
                    }
                except (ValueError, IndexError):
                    continue

    interesting = [p for p, info in services.items() if info.get("interesting")]
    print(f"  ✅ nmap: {len(open_ports)} puertos abiertos, {len(interesting)} interesantes")

    return {
        "available": True,
        "open_ports": open_ports or [port],
        "services": services,
        "interesting_ports": interesting,
        "raw_summary": "\n".join(l for l in lines if "/tcp" in l or "SERVICE" in l)
    }


def run_ffuf(target_url: str) -> dict:
    """Descubrimiento de rutas y endpoints con ffuf."""
    print("  🔍 ffuf: descubriendo rutas y endpoints...")

    common_paths = [
        "api", "api/v1", "api/v2", "api/v3",
        "admin", "administration", "dashboard",
        "login", "logout", "register", "signup",
        "user", "users", "profile",
        "health", "status", "ping", "ready",
        "swagger", "swagger.json", "openapi.json", "api-docs",
        "v3/api-docs", "swagger-ui", "swagger-ui.html",
        "metrics", "actuator", "actuator/health",
        "graphql", "graphiql",
        "upload", "uploads", "files",
        "backup", "backups", "dump",
        ".env", ".git", ".git/config",
        "robots.txt", "sitemap.xml", "security.txt",
        "rest", "rest/user", "rest/products",
        "ws", "socket.io",
    ]

    wordlist_path = "/tmp/devsecops_wordlist.txt"
    with open(wordlist_path, "w") as f:
        f.write("\n".join(common_paths))

    stdout, stderr, rc = run_cmd([
        "ffuf",
        "-u", f"{target_url}/FUZZ",
        "-w", wordlist_path,
        "-mc", "200,201,301,302,307,401,403",
        "-t", "20",
        "-timeout", "5",
        "-json",
        "-silent",
    ], timeout=90)

    if rc == 127:
        print("  ⚠️  ffuf no disponible, usando gobuster si existe...")
        return run_gobuster(target_url, common_paths)

    discovered = []
    try:
        data = json.loads(stdout)
        for result in data.get("results", []):
            discovered.append({
                "path": "/" + result.get("input", {}).get("FUZZ", ""),
                "status": result.get("status"),
                "length": result.get("length"),
                "interesting": result.get("status") in [200, 201],
            })
    except (json.JSONDecodeError, KeyError):
        pass

    print(f"  ✅ ffuf: {len(discovered)} rutas descubiertas")
    return {
        "available": True,
        "discovered_routes": [r["path"] for r in discovered],
        "routes_detail": discovered,
        "interesting_routes": [r["path"] for r in discovered if r.get("interesting")],
    }


def run_gobuster(target_url: str, paths: list) -> dict:
    """Fallback a gobuster si ffuf no está disponible."""
    wordlist_path = "/tmp/devsecops_wordlist.txt"

    stdout, stderr, rc = run_cmd([
        "gobuster", "dir",
        "-u", target_url,
        "-w", wordlist_path,
        "-s", "200,201,301,302,307,401,403",
        "-t", "20",
        "--no-error",
        "-q",
    ], timeout=90)

    if rc == 127:
        print("  ⚠️  gobuster tampoco disponible, usando lista base...")
        return {
            "available": False,
            "discovered_routes": [f"/{p}" for p in paths[:10]],
            "routes_detail": [],
            "interesting_routes": [],
        }

    discovered = []
    for line in stdout.split("\n"):
        if line.strip() and "/" in line:
            parts = line.split()
            if parts:
                path = parts[0].strip()
                try:
                    status = int(parts[1].strip("()")) if len(parts) > 1 else 200
                except ValueError:
                    status = 200
                discovered.append({"path": path, "status": status, "interesting": status == 200})

    return {
        "available": True,
        "discovered_routes": [r["path"] for r in discovered],
        "routes_detail": discovered,
        "interesting_routes": [r["path"] for r in discovered if r.get("interesting")],
    }


def run_httpx(target_url: str) -> dict:
    """Fingerprinting de tecnologías y headers con httpx."""
    print("  🔍 httpx: fingerprinting de tecnologías...")

    stdout, stderr, rc = run_cmd([
        "httpx",
        "-u", target_url,
        "-tech-detect",
        "-status-code",
        "-title",
        "-server",
        "-content-type",
        "-json",
        "-silent",
    ], timeout=30)

    if rc == 127:
        return run_curl_headers(target_url)

    try:
        data = json.loads(stdout.strip().split("\n")[0] if stdout.strip() else "{}")
        technologies = data.get("tech", [])
        server       = data.get("webserver", "")
        title        = data.get("title", "")

        headers = data.get("headers", {})
        security_headers = {"present": [], "missing": []}
        important_headers = [
            "content-security-policy", "strict-transport-security",
            "x-frame-options", "x-content-type-options",
            "referrer-policy", "permissions-policy",
        ]
        for h in important_headers:
            if h in {k.lower() for k in headers.keys()}:
                security_headers["present"].append(h)
            else:
                security_headers["missing"].append(h)

        print(f"  ✅ httpx: {len(technologies)} tecnologías, "
              f"{len(security_headers['missing'])} headers faltantes")

        return {
            "available": True,
            "technologies": technologies,
            "server": server,
            "title": title,
            "security_headers": security_headers,
            "status_code": data.get("status-code", 0),
        }
    except Exception:
        return run_curl_headers(target_url)


def run_curl_headers(target_url: str) -> dict:
    """Fallback: obtiene headers con curl."""
    stdout, _, rc = run_cmd([
        "curl", "-sI", "--max-time", "10", target_url
    ], timeout=15)

    headers_present = []
    headers_missing = []
    important = [
        "content-security-policy", "strict-transport-security",
        "x-frame-options", "x-content-type-options",
    ]
    server       = ""
    stdout_lower = stdout.lower()

    for h in important:
        if h in stdout_lower:
            headers_present.append(h)
        else:
            headers_missing.append(h)

    for line in stdout.split("\n"):
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()

    print(f"  ✅ curl headers: {len(headers_present)} seguros, {len(headers_missing)} faltantes")

    return {
        "available": True,
        "technologies": [],
        "server": server,
        "title": "",
        "security_headers": {"present": headers_present, "missing": headers_missing},
        "status_code": 200 if rc == 0 else 0,
    }


def run_wafw00f(target_url: str) -> dict:
    """Detección de WAF con wafw00f."""
    print("  🔍 wafw00f: detectando WAF...")

    stdout, stderr, rc = run_cmd([
        "wafw00f", target_url, "-o", "-", "-f", "json"
    ], timeout=30)

    if rc == 127:
        print("  ⚠️  wafw00f no disponible, saltando...")
        return {"available": False, "waf_detected": False, "waf_name": None}

    try:
        data    = json.loads(stdout)
        waf     = data[0] if data else {}
        detected = bool(waf.get("detected"))
        name    = waf.get("firewall") if detected else None
        print(f"  ✅ wafw00f: WAF {'detectado: ' + str(name) if detected else 'no detectado'}")
        return {"available": True, "waf_detected": detected, "waf_name": name}
    except Exception:
        detected = "is behind" in stdout.lower()
        print(f"  ✅ wafw00f: WAF {'detectado' if detected else 'no detectado'}")
        return {"available": True, "waf_detected": detected, "waf_name": None}


def analyze_attack_surface(nmap_r: dict, ffuf_r: dict,
                            httpx_r: dict, wafw_r: dict) -> dict:
    """Genera un análisis de superficie de ataque."""
    findings = []

    for port in nmap_r.get("interesting_ports", []):
        svc = nmap_r.get("services", {}).get(str(port), {})
        findings.append({
            "type": "interesting_port",
            "severity": "HIGH",
            "detail": f"Puerto {port} ({svc.get('service', '?')}) expuesto — "
                      f"{svc.get('version', '')}",
        })

    missing = httpx_r.get("security_headers", {}).get("missing", [])
    if missing:
        findings.append({
            "type": "missing_security_headers",
            "severity": "MEDIUM",
            "detail": f"Headers faltantes: {', '.join(missing)}",
        })

    sensitive_keywords = [
        "admin", "backup", "dump", ".env", ".git",
        "actuator", "debug", "test", "dev"
    ]
    for route in ffuf_r.get("interesting_routes", []):
        if any(kw in route.lower() for kw in sensitive_keywords):
            findings.append({
                "type": "sensitive_route",
                "severity": "HIGH",
                "detail": f"Ruta sensible accesible: {route}",
            })

    if not wafw_r.get("waf_detected"):
        findings.append({
            "type": "no_waf",
            "severity": "INFO",
            "detail": "No se detectó WAF — tráfico malicioso llega directo a la app",
        })

    return {
        "total_findings": len(findings),
        "high":   len([f for f in findings if f["severity"] == "HIGH"]),
        "medium": len([f for f in findings if f["severity"] == "MEDIUM"]),
        "info":   len([f for f in findings if f["severity"] == "INFO"]),
        "findings": findings,
    }


def recon(target_url: str, output_path: str):
    """Orquesta el reconocimiento completo."""

    print("\n" + "="*60)
    print("  FASE DE RECONOCIMIENTO – DevSecOps TG")
    print("="*60)
    print(f"  Target: {target_url}")
    print()

    parsed = urlparse(target_url)
    host   = parsed.hostname or "localhost"
    port   = parsed.port or 80

    nmap_result  = run_nmap(host, port)
    ffuf_result  = run_ffuf(target_url)
    httpx_result = run_httpx(target_url)
    wafw_result  = run_wafw00f(target_url)

    attack_surface = analyze_attack_surface(
        nmap_result, ffuf_result, httpx_result, wafw_result
    )

    # Construir lista de targets para Nuclei — siempre incluir el target base
    nuclei_targets = [target_url]
    extra_routes   = ffuf_result.get("discovered_routes", [])
    if extra_routes:
        nuclei_targets += [target_url.rstrip("/") + r for r in extra_routes]
    # Deduplicar
    nuclei_targets = list(dict.fromkeys(nuclei_targets))

    context = {
        "schema_version": "1.0",
        "generated_at": datetime.now().isoformat(),
        "target_url": target_url,
        "host": host,
        "port": port,
        "nmap": nmap_result,
        "route_discovery": ffuf_result,
        "fingerprint": httpx_result,
        "waf": wafw_result,
        "attack_surface": attack_surface,
        "nuclei_targets": nuclei_targets,
        "summary": {
            "open_ports": nmap_result.get("open_ports", [port]),
            "discovered_routes_count": len(ffuf_result.get("discovered_routes", [])),
            "technologies": httpx_result.get("technologies", []),
            "waf_present": wafw_result.get("waf_detected", False),
            "missing_security_headers": httpx_result.get(
                "security_headers", {}).get("missing", []),
            "attack_surface_findings": attack_surface["total_findings"],
        }
    }

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(context, f, indent=2, ensure_ascii=False)

    print()
    print("="*60)
    print("  RESULTADO DEL RECONOCIMIENTO")
    print("="*60)
    print(f"  🌐 Puertos abiertos    : {len(context['summary']['open_ports'])}")
    print(f"  🛣️  Rutas descubiertas  : {context['summary']['discovered_routes_count']}")
    print(f"  🔧 Tecnologías         : {', '.join(context['summary']['technologies'][:3]) or 'N/A'}")
    print(f"  🛡️  WAF detectado       : {'✅' if context['summary']['waf_present'] else '❌'}")
    print(f"  ⚠️  Headers faltantes   : {len(context['summary']['missing_security_headers'])}")
    print(f"  🎯 Targets para Nuclei : {len(context['nuclei_targets'])}")
    print(f"\n  Guardado en: {output_path}")
    print("="*60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reconocimiento activo DevSecOps")
    parser.add_argument("--target", required=True, help="URL del target (ej: http://localhost:3000)")
    parser.add_argument("--output", required=True, help="Ruta de salida para recon_context.json")
    args = parser.parse_args()
    recon(args.target, args.output)