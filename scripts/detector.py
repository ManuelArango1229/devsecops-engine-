#!/usr/bin/env python3
"""
detector.py – Auto-detector de lenguaje, modo de escaneo y APIs
Trabajo de Grado – Universidad del Valle 2026

Corre como primer job del pipeline y genera scan_config.json
que todos los demás jobs consumen. El usuario nunca toca este archivo.
"""

import json
import os
import sys
import argparse
from pathlib import Path


# ── Marcadores por lenguaje ───────────────────────────────────────────────────
LANGUAGE_MARKERS = {
    "nodejs":  ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    "python":  ["requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"],
    "java":    ["pom.xml", "build.gradle", "build.gradle.kts", "gradlew"],
    "go":      ["go.mod", "go.sum"],
    "dotnet":  ["*.csproj", "*.sln", "packages.config", "global.json"],
    "php":     ["composer.json", "composer.lock", "artisan"],
}

# ── Reglas Semgrep por lenguaje (solo rulesets válidos en OSS 2025) ───────────
SEMGREP_RULESETS = {
    "nodejs":  "p/nodejs p/javascript p/typescript p/jwt p/xss p/sql-injection p/secrets",
    "python":  "p/python p/django p/flask p/bandit p/secrets",
    "java":    "p/java p/spring p/secrets",
    "go":      "p/golang p/gosec p/secrets",
    "dotnet":  "p/csharp p/secrets",
    "php":     "p/php p/secrets",
    "generic": "p/secrets p/default",
}

# ── Archivos de spec de API ───────────────────────────────────────────────────
API_SPEC_FILES = [
    "swagger.json", "swagger.yaml", "swagger.yml",
    "openapi.json", "openapi.yaml", "openapi.yml",
    "docs/swagger.json", "docs/openapi.yaml",
    "api/swagger.json", "api/openapi.yaml",
    "src/main/resources/swagger.yaml",
]

# ── Dockerfiles ───────────────────────────────────────────────────────────────
DOCKERFILE_NAMES = ["Dockerfile", "dockerfile", "Dockerfile.prod", "docker-compose.yml"]


def find_files(base: Path, patterns: list) -> list:
    """Busca archivos por nombre exacto o glob en el directorio base."""
    found = []
    for pattern in patterns:
        if "*" in pattern:
            found.extend(base.glob(f"**/{pattern}"))
        else:
            p = base / pattern
            if p.exists():
                found.append(p)
    return found


def detect_language(base: Path) -> dict:
    """Detecta el lenguaje principal del repositorio."""
    scores = {}
    detected_files = {}

    for lang, markers in LANGUAGE_MARKERS.items():
        found = find_files(base, markers)
        if found:
            scores[lang] = len(found)
            detected_files[lang] = [str(f.relative_to(base)) for f in found]

    if not scores:
        return {"primary": "generic", "all": [], "markers_found": {}}

    primary = max(scores, key=scores.get)
    return {
        "primary": primary,
        "all": list(scores.keys()),
        "markers_found": detected_files,
    }


def detect_scan_mode(base: Path, target_image: str, target_url: str) -> dict:
    """Detecta cómo se debe hacer el escaneo dinámico."""
    has_dockerfile = bool(find_files(base, DOCKERFILE_NAMES))

    if target_url:
        return {
            "mode": "url",
            "description": "App ya desplegada — apuntar directo a URL",
            "target_url": target_url,
            "requires_docker": False,
        }
    elif target_image:
        return {
            "mode": "image",
            "description": "Imagen Docker proporcionada — pull y levantar",
            "target_image": target_image,
            "requires_docker": True,
        }
    elif has_dockerfile:
        return {
            "mode": "build",
            "description": "Dockerfile encontrado — build y levantar",
            "dockerfile": "Dockerfile",
            "requires_docker": True,
        }
    else:
        return {
            "mode": "static",
            "description": "Sin Docker ni URL — solo SAST + SCA",
            "requires_docker": False,
        }


def detect_api_spec(base: Path, target_url: str) -> dict:
    """Detecta si hay un spec de API (OpenAPI/Swagger)."""
    found = find_files(base, API_SPEC_FILES)

    if found:
        spec_path = str(found[0].relative_to(base))
        return {
            "detected": True,
            "spec_file": spec_path,
            "spec_url": None,
            "enable_api_scan": True,
        }

    if target_url:
        common_spec_paths = ["/swagger.json", "/openapi.json", "/api-docs", "/v3/api-docs"]
        return {
            "detected": False,
            "spec_file": None,
            "spec_url_candidates": [target_url.rstrip("/") + p for p in common_spec_paths],
            "enable_api_scan": False,
        }

    return {"detected": False, "spec_file": None, "enable_api_scan": False}


def detect_secrets_config(base: Path) -> dict:
    """Detecta archivos de configuración que podrían tener secretos."""
    secret_files = [
        ".env", ".env.example", ".env.local", ".env.production",
        "config/database.yml", "config/secrets.yml",
        "application.properties", "application.yml",
        "appsettings.json", "appsettings.Development.json",
    ]
    found = find_files(base, secret_files)
    return {
        "config_files_found": [str(f.relative_to(base)) for f in found],
        "scan_for_secrets": True,
    }


def build_semgrep_config(language_info: dict) -> dict:
    """Construye la configuración de Semgrep según el lenguaje."""
    primary = language_info.get("primary", "generic")
    rulesets = SEMGREP_RULESETS.get(primary, SEMGREP_RULESETS["generic"])
    return {
        "rulesets": rulesets,
        "language": primary,
        "extra_configs": [],
    }


def build_trivy_config(scan_mode: dict) -> dict:
    """Construye la configuración de Trivy."""
    mode = scan_mode.get("mode")

    if mode in ["image", "build"]:
        return {
            "scan_type": "image",
            "target": scan_mode.get("target_image", ""),
            "extra_flags": "--scanners vuln,secret,misconfig",
        }
    else:
        return {
            "scan_type": "filesystem",
            "target": ".",
            "extra_flags": "--scanners vuln,secret,misconfig",
        }


def build_nuclei_config(scan_mode: dict, api_spec: dict) -> dict:
    """Construye la configuración de Nuclei."""
    mode = scan_mode.get("mode")

    if mode == "static":
        return {
            "enabled": False,
            "reason": "Sin app en ejecución — Nuclei requiere target activo",
        }

    base_tags = "owasp,jwt,sqli,xss,exposure,misconfig,cve,token,auth,api,swagger"

    config = {
        "enabled": True,
        "version": "v3.3.8",
        "tags": base_tags,
        "rate_limit": 50,
        "timeout": 30,
        "use_discovered_routes": True,
    }

    if api_spec.get("enable_api_scan") and api_spec.get("spec_file"):
        config["api_spec"] = api_spec["spec_file"]
        config["tags"] += ",openapi"

    return config


def detect(base_path: str, target_image: str, target_url: str,
           service: str, criticality: str, environment: str) -> dict:
    """Función principal de detección."""

    base = Path(base_path)

    print("\n" + "="*60)
    print("  DETECTOR DE CONTEXTO – DevSecOps TG")
    print("="*60)
    print(f"  Analizando: {base_path}")
    print()

    language     = detect_language(base)
    scan_mode    = detect_scan_mode(base, target_image, target_url)
    api_spec     = detect_api_spec(base, target_url or "")
    secrets_config = detect_secrets_config(base)

    semgrep_config = build_semgrep_config(language)
    trivy_config   = build_trivy_config(scan_mode)
    nuclei_config  = build_nuclei_config(scan_mode, api_spec)

    dast_enabled = scan_mode.get("mode") != "static"

    config = {
        "schema_version": "1.0",
        "detected_at": str(Path(base_path).resolve()),
        "service": service,
        "criticality": criticality,
        "environment": environment,
        "language": language,
        "scan_mode": scan_mode,
        "api_spec": api_spec,
        "secrets_config": secrets_config,
        "tools": {
            "semgrep": semgrep_config,
            "trivy": trivy_config,
            "zap": {
                "enabled": dast_enabled,
                "scan_type": "baseline" if environment == "staging" else "full",
            },
            "nuclei": nuclei_config,
            "recon": {
                "enabled": dast_enabled,
                "tools": ["nmap", "ffuf", "httpx", "wafw00f"],
            },
        },
        "summary": {
            "language": language["primary"],
            "scan_mode": scan_mode["mode"],
            "dast_enabled": dast_enabled,
            "api_scan_enabled": api_spec.get("enable_api_scan", False),
            "recon_enabled": dast_enabled,
        }
    }

    print(f"  🔤 Lenguaje detectado  : {language['primary'].upper()}")
    print(f"  🐳 Modo de escaneo     : {scan_mode['mode'].upper()}")
    print(f"  🌐 DAST habilitado     : {'✅' if dast_enabled else '❌'}")
    print(f"  🔍 API spec detectada  : {'✅ ' + api_spec.get('spec_file', '') if api_spec.get('detected') else '❌'}")
    print(f"  🔐 Reglas Semgrep      : {semgrep_config['rulesets']}")
    print(f"  🎯 Nuclei habilitado   : {'✅' if nuclei_config.get('enabled') else '❌'}")
    print("="*60 + "\n")

    return config


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auto-detector de contexto DevSecOps")
    parser.add_argument("--path",           default=".",  help="Ruta del repositorio a analizar")
    parser.add_argument("--output",         required=True, help="Ruta de salida para scan_config.json")
    parser.add_argument("--target-image",   default="",   help="Imagen Docker (opcional)")
    parser.add_argument("--target-url",     default="",   help="URL externa (opcional)")
    parser.add_argument("--service",        default="unknown")
    parser.add_argument("--criticality",    default="medium")
    parser.add_argument("--environment",    default="staging")

    args = parser.parse_args()

    config = detect(
        base_path=args.path,
        target_image=args.target_image,
        target_url=args.target_url,
        service=args.service,
        criticality=args.criticality,
        environment=args.environment,
    )

    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    # Validar que el output es completo antes de terminar
    with open(args.output) as f:
        check = json.load(f)
    assert "language" in check and "scan_mode" in check and "summary" in check, \
        "❌ scan_config.json incompleto — falta language, scan_mode o summary"

    print(f"✅ scan_config.json generado en: {args.output}")
    print(f"   Lenguaje: {check['language']['primary']} | Modo: {check['scan_mode']['mode']}")