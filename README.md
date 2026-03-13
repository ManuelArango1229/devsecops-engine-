# DevSecOps Engine

Pipeline reutilizable de seguridad con evaluación asistida por IA.

## Uso desde cualquier repositorio
```yaml
jobs:
  security:
    uses: TU_USUARIO/devsecops-engine/.github/workflows/reusable-devsecops.yml@main
    with:
      target_image: 'mi-imagen:latest'
      target_port: '8080'
      service_name: 'mi-servicio'
      criticality: 'medium'
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

## Parámetros

| Parámetro | Requerido | Default | Descripción |
|---|---|---|---|
| target_image | SI | - | Imagen Docker del target |
| target_port | SI | - | Puerto de la app |
| service_name | SI | - | Nombre para el reporte |
| criticality | NO | medium | high, medium, low |
| environment | NO | staging | staging, pre-prod |
| build_context | NO | '' | Carpeta Dockerfile si es local |

## Herramientas integradas
- SAST: Semgrep
- SCA: Trivy
- DAST: OWASP ZAP
- Pentesting: Nuclei
- IA: GPT-4o-mini

## Autores
Jhojan Stiven Castaño Jejen & Juan Manuel Arango Rodas
Universidad del Valle – 2026
