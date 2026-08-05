<div align="center">

# 🔐 DevSecOps Engine

**Pipeline de evaluación continua de seguridad, reutilizable y asistido por IA**

[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-workflow__call-2088FF?logo=github-actions&logoColor=white)](https://github.com/ManuelArango1229/devsecops-engine-)
[![Version](https://img.shields.io/badge/version-1.3-navy)](https://github.com/ManuelArango1229/devsecops-engine-/releases)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Universidad del Valle](https://img.shields.io/badge/Universidad%20del%20Valle-Trabajo%20de%20Grado%202026-red)](https://univalle.edu.co)

*Trabajo de Grado · Ingeniería de Sistemas · Universidad del Valle · 2026*
*Jhojan Stiven Castaño Jejen & Juan Manuel Arango Rodas*

</div>

---

## ¿Qué es?

DevSecOps Engine es un pipeline GitHub Actions reutilizable que incorpora cuatro técnicas de análisis de seguridad — SAST, SCA, DAST y pentesting — y aplica **tres mecanismos independientes de decisión de despliegue**:

| Gate | Criterio | Métrica |
|---|---|---|
| 🔢 **Tradicional** | Umbrales de severidad fijos | — |
| 🤖 **IA híbrida** | LLM con contexto SSVC + EPSS + CISA KEV | Confianza (0.0–1.0) |
| 📊 **SSVC v2.1** | Árbol CISA/SEI-CERT + explotabilidad empírica | F1 / Precision / Recall |

La decisión final es **PASS / CONDITIONAL / FAIL**. Un repositorio consumidor invoca el engine con un `workflow_call`; el resto del análisis lo gestiona el engine de forma centralizada.

---

## Arquitectura del pipeline

```
Job 0 ── Auto-detector          detector.py      → scan_config.json
    ├── Job 1 ── SAST           Semgrep OSS
    ├── Job 2 ── SCA            Trivy
    └── Job 3 ── Reconocimiento recon.py
            ├── Job 4 ── DAST       OWASP ZAP
            └── Job 5 ── Pentesting Nuclei v3.3.8
                    └── Job 6 ── Evaluación
                            normalizer.py     → findings.json
                            ssvc_gate.py      → gate SSVC + EPSS + KEV
                            ai_engine.py      → ai_evaluation.json  (motor híbrido v1.3)
                            gate.py           → gate_decision.json
                            report_generator  → SECURITY_REPORT.md
```

---

## Uso rápido

### 1. Configura el secreto

En tu repositorio → **Settings → Secrets → Actions**:

```
GROQ_API_KEY = <tu API key de Groq>
```

### 2. Añade el workflow

Crea `.github/workflows/devsecops.yml` en tu repositorio:

```yaml
name: DevSecOps Analysis

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      image: ${{ steps.meta.outputs.tags }}
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - id: meta
        uses: docker/metadata-action@v5
        with:
          images: ghcr.io/${{ github.repository_owner }}/myapp
          tags: type=sha,prefix=
      - uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}

  security:
    needs: build
    uses: ManuelArango1229/devsecops-engine-/.github/workflows/reusable-devsecops.yml@main
    with:
      target_image:  ${{ needs.build.outputs.image }}
      target_port:   "3000"
      service_name:  "mi-servicio"
      criticality:   "high"
      environment:   "staging"
      source_repo:   "miorg/mirepo"
      language:      "nodejs"
      use_ghcr:      true
    secrets:
      GROQ_API_KEY:  ${{ secrets.GROQ_API_KEY }}
      GHCR_TOKEN:    ${{ secrets.GITHUB_TOKEN }}
```

---

## Parámetros de configuración

| Parámetro | Req. | Default | Descripción |
|---|---|---|---|
| `target_image` | No | — | Imagen Docker completa (`ghcr.io/org/app:sha`) |
| `target_url` | No | — | URL de la app desplegada (alternativa a imagen) |
| `target_port` | No | `8080` | Puerto expuesto por el contenedor |
| `service_name` | **Sí** | — | Nombre del servicio; aparece en el reporte |
| `criticality` | No | `medium` | `low` · `medium` · `high` · `critical` |
| `environment` | No | `staging` | `staging` · `pre-prod` |
| `source_repo` | No | — | Repositorio a escanear con Semgrep (`org/repo`) |
| `source_repo_ref` | No | `main` | Rama del repositorio fuente |
| `language` | No | `auto` | `nodejs` · `python` · `java` · `php` · `golang` |
| `use_ghcr` | No | `false` | `true` si la imagen está en GHCR privado |

> **`criticality`** determina la dimensión *Mission & Wellbeing* del árbol SSVC. A mayor criticidad, más hallazgos clasificarán como **Act → FAIL**.

---

## Herramientas integradas

<table>
<tr>
<td align="center"><b>SAST</b><br>Semgrep OSS</td>
<td>Análisis estático del código fuente. Rulesets automáticos por lenguaje detectado.</td>
</tr>
<tr>
<td align="center"><b>SCA</b><br>Trivy</td>
<td>CVEs en dependencias e imagen Docker. Fuente principal de CVE IDs para SSVC/EPSS.</td>
</tr>
<tr>
<td align="center"><b>DAST</b><br>OWASP ZAP</td>
<td>Pruebas dinámicas sobre la aplicación en ejecución.</td>
</tr>
<tr>
<td align="center"><b>Pentest</b><br>Nuclei v3.3.8</td>
<td>Validación activa con templates de vulnerabilidades conocidas.</td>
</tr>
<tr>
<td align="center"><b>IA</b><br>LLaMA 3.3 70B</td>
<td>Evaluación contextual vía Groq → fallback GPT-4o-mini → Claude Haiku → estático.</td>
</tr>
</table>

---

## Archivos de salida

Los artefactos se publican en **Actions → workflow ejecutado → Artifacts**:

| Archivo | Descripción |
|---|---|
| `scan_config.json` | Lenguaje detectado, modo de escaneo, ASCs ISO/IEC 27034 |
| `findings.json` | Hallazgos normalizados y deduplicados con `asc_id` |
| `ai_evaluation.json` | Decisión IA, confianza, `ssvc_validation`, cadenas de ataque |
| `gate_decision.json` | Comparación de los tres gates con divergencias y F1 |
| `SECURITY_REPORT.md` | Reporte ejecutivo completo |

---

## Decisiones de despliegue

| Decisión | Significado | Acción |
|---|---|---|
| ✅ **PASS** | Sin explotación activa confirmada. Riesgo aceptable. | Despliegue autorizado. |
| ⚠️ **CONDITIONAL** | EPSS bajo y ausencia en CISA KEV. Riesgo controlado. | Revisar antes de promover a producción. |
| ❌ **FAIL** | Explotación activa confirmada o volumen crítico. | Bloquear hasta remediar. |

---

## Casos de validación

| Caso | Lenguaje | Tradicional | Gate IA | SSVC | F1 |
|---|---|---|---|---|---|
| OWASP Juice Shop | Node.js | FAIL | FAIL | FAIL | 0.00 |
| FitFusion Backend | Node.js/TS | FAIL | FAIL | FAIL | 0.00 |
| WebGoat | Java | FAIL | FAIL | FAIL | 1.00 |
| DVWA | PHP | FAIL | FAIL | FAIL | 1.00 |
| PyGoat | Python | FAIL | FAIL | FAIL | 1.00 |
| SecureTaskAPI | Node.js | FAIL | **CONDITIONAL** | FAIL | 0.00 |
| SimpleHealthAPI | Node.js | FAIL | **CONDITIONAL** | **CONDITIONAL** | 0.00 |

La divergencia en los casos 6 y 7 es el resultado empírico central del trabajo: EPSS < 0.001 y ausencia en CISA KEV demuestran que el gate tradicional sobreestima el riesgo en aplicaciones con deuda de dependencias pero sin explotación activa real.

---

## Trazabilidad normativa ISO/IEC 27034

Cada hallazgo incluye el campo `asc_id` que identifica el control de seguridad de aplicación (ASC) que lo detectó. El auto-detector genera el bloque `iso27034_anf` en `scan_config.json` con los ASCs aplicables según el lenguaje y la criticidad del servicio.

---

## Documentación

- 📄 [Manual técnico v1.3](https://drive.google.com/file/d/1PBkfRz_UobJLrXDUd7XhGWrILXWF4YA0/view?usp=sharing)
- 📋 [Releases](https://github.com/ManuelArango1229/devsecops-engine-/releases)

---

## Repositorios de validación

| Caso | Repositorio |
|---|---|
| OWASP Juice Shop | `ManuelArango1229/juice-shopForkTG` |
| FitFusion Backend | `ManuelArango1229/Backend-FitFusion` |
| WebGoat | `ManuelArango1229/WebGoatForkTG` |
| DVWA | `ManuelArango1229/DVWAForkTG` |
| PyGoat | `ManuelArango1229/PyGoatForkTG` |
| SecureTaskAPI | `ManuelArango1229/SecureTaskAPI` |
| SimpleHealthAPI | `ManuelArango1229/SimpleHealthAPI` |

---

<div align="center">

**Escuela de Ingeniería de Sistemas y Computación · Facultad de Ingeniería**
Universidad del Valle · Cali, Colombia · 2026

*Jhojan Stiven Castaño Jejen · Juan Manuel Arango Rodas*
*Director: Carlos Andrés Delgado Saavedra*

</div>
