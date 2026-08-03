#!/usr/bin/env python3
"""
MALINFO — SBOM Generator
Generates Software Bill of Materials (CycloneDX) for all components
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


def run_cmd(cmd: list[str], cwd: Path = None) -> tuple[int, str, str]:
    """Run command and return (exit_code, stdout, stderr)"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=300)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def generate_python_sbom(project_root: Path, output: Path) -> bool:
    """Generate SBOM for Python backend using cyclonedx-bom"""
    print(f"[SBOM] Generating Python SBOM for {project_root}...")
    
    # Try cyclonedx-bom first
    code, stdout, stderr = run_cmd([
        sys.executable, "-m", "cyclonedx_py", "-o", str(output), "--format", "json"
    ], cwd=project_root / "backend")
    
    if code == 0:
        print(f"[SBOM] Python SBOM generated: {output}")
        return True
    
    # Fallback: pipdeptree + manual construction
    print("[SBOM] cyclonedx-bom failed, trying pipdeptree fallback...")
    code, stdout, stderr = run_cmd([
        sys.executable, "-m", "pipdeptree", "--json"
    ], cwd=project_root / "backend")
    
    if code == 0:
        # Convert pipdeptree output to CycloneDX
        try:
            deps = json.loads(stdout)
            sbom = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "serialNumber": f"urn:uuid:{__import__('uuid').uuid4()}",
                "version": 1,
                "metadata": {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "tools": [{"name": "malinfo-sbom-generator", "version": "1.0"}],
                    "component": {
                        "type": "application",
                        "name": "malinfo-backend",
                        "version": "1.0.0-pilot",
                        "purl": "pkg:generic/malinfo/backend@1.0.0-pilot"
                    }
                },
                "components": []
            }
            
            for dep in deps:
                if "package" in dep:
                    pkg = dep["package"]
                    sbom["components"].append({
                        "type": "library",
                        "name": pkg.get("package_name", ""),
                        "version": pkg.get("installed_version", ""),
                        "purl": f"pkg:pypi/{pkg.get('package_name', '')}@{pkg.get('installed_version', '')}",
                    })
            
            output.write_text(json.dumps(sbom, indent=2))
            print(f"[SBOM] Python SBOM generated (fallback): {output}")
            return True
        except Exception as e:
            print(f"[SBOM] Fallback conversion failed: {e}")
    
    return False


def generate_container_sbom(image: str, output: Path) -> bool:
    """Generate SBOM for container image using syft"""
    print(f"[SBOM] Generating container SBOM for {image}...")
    
    code, stdout, stderr = run_cmd([
        "syft", image, "-o", "cyclonedx-json"
    ])
    
    if code == 0:
        output.write_text(stdout)
        print(f"[SBOM] Container SBOM generated: {output}")
        return True
    
    print(f"[SBOM] syft failed: {stderr}")
    return False


def generate_full_sbom(project_root: Path, output_dir: Path) -> dict[str, Any]:
    """Generate comprehensive SBOM for entire project"""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    
    results = {
        "project": "MALINFO",
        "version": "1.0.0-pilot",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "components": {}
    }
    
    # Backend Python SBOM
    backend_sbom = output_dir / f"sbom-backend-{timestamp}.json"
    if generate_python_sbom(project_root, backend_sbom):
        results["components"]["backend"] = str(backend_sbom)
    
    # Frontend (if Node.js project exists)
    frontend_package = project_root / "frontend" / "package.json"
    if frontend_package.exists():
        frontend_sbom = output_dir / f"sbom-frontend-{timestamp}.json"
        code, stdout, stderr = run_cmd(["npm", "audit", "--json"], cwd=project_root / "frontend")
        if code in (0, 1):  # npm audit returns 1 for vulnerabilities found
            frontend_sbom.write_text(stdout)
            results["components"]["frontend"] = str(frontend_sbom)
    
    # Container images
    images = [
        ("malinfo/backend:latest", output_dir / f"sbom-container-backend-{timestamp}.json"),
        ("malinfo/nginx:latest", output_dir / f"sbom-container-nginx-{timestamp}.json"),
    ]
    
    for image, out_file in images:
        if generate_container_sbom(image, out_file):
            results["components"][f"container-{image.split('/')[-1].split(':')[0]}"] = str(out_file)
    
    # Write summary
    summary_file = output_dir / f"sbom-summary-{timestamp}.json"
    summary_file.write_text(json.dumps(results, indent=2))
    
    print(f"\n[SBOM] Complete! Summary: {summary_file}")
    return results


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate MALINFO SBOMs")
    parser.add_argument("--project-root", default=".", help="Project root directory")
    parser.add_argument("--output-dir", default="./sbom-output", help="Output directory")
    parser.add_argument("--component", choices=["all", "backend", "frontend", "containers"], default="all")
    args = parser.parse_args()
    
    project_root = Path(args.project_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    
    if not (project_root / "backend").exists():
        print(f"[ERROR] Backend not found at {project_root}/backend")
        sys.exit(1)
    
    generate_full_sbom(project_root, output_dir)


if __name__ == "__main__":
    main()