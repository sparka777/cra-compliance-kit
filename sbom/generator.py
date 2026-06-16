"""SBOM Generator - CycloneDX 1.5 for CRA Compliance Kit.

Generates Software Bill of Materials for Python-based IoT/edge firmware.
Integrates with FirmwareHealthService for CVE cross-referencing.

CLI: python -m sbom.generator --output sbom.xml
"""

import uuid, argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


COMPONENT_XML = """    <component type="{t}">
      <name>{n}</name>
      <version>{v}</version>
      <purl>{p}</purl>
    </component>"""


SBOM = """<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1" serialNumber="urn:uuid:{s}">
  <metadata>
    <timestamp>{t}</timestamp>
    <tools><tool><vendor>StarTeQ Ltd</vendor><name>cra-compliance-kit</name><version>1.0.0</version></tool></tools>
    <properties>
      <property name="manufacturer">{m}</property>
      <property name="product">{p}</property>
      <property name="productVersion">{v}</property>
    </properties>
  </metadata>
  <components>
{c}
  </components>
  <vulnerabilities>
{vulns}
  </vulnerabilities>
</bom>"""


def parse_requirements(path):
    req_path = Path(path)
    if not req_path.exists():
        return []
    components = []
    for line in req_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
        elif ">=" in line:
            name, version = line.split(">=", 1)
        else:
            name = line.split()[0]
            version = "unknown"
        components.append({"name": name.strip(), "version": version.strip(), "purl": "pkg:pypi/" + name.strip() + "@" + version.strip()})
    return components


def scan_installed():
    import importlib.metadata as md
    components = []
    for dist in md.distributions():
        try:
            name = dist.metadata["Name"] or dist.name
            version = dist.version
            components.append({"name": name, "version": version, "purl": "pkg:pypi/" + name + "@" + version})
        except Exception:
            continue
    return sorted(components, key=lambda c: c["name"].lower())


def render_components(components):
    return "\n".join(
        COMPONENT_XML.format(t=c.get("type", "library"), n=c["name"], v=c["version"], p=c.get("purl", ""))
        for c in components
    )


def render_vulnerabilities(cve_list):
    if not cve_list:
        return ""
    parts = []
    for cve in cve_list:
        parts.append(
            '    <vulnerability ref="' + cve["cve_id"] + '">\n'
            '      <id>' + cve["cve_id"] + '</id>\n'
            '      <description>' + cve["description"] + '</description>\n'
            '      <ratings>\n'
            '        <rating>\n'
            '          <score>' + str(cve["cvss_score"]) + '</score>\n'
            '          <severity>' + cve.get("severity", "medium") + '</severity>\n'
            '          <method>CVSSv31</method>\n'
            '        </rating>\n'
            '      </ratings>\n'
            '    </vulnerability>'
        )
    return "\n".join(parts)


def load_firmware_health_cves():
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "prism_security"))
        from firmware_health import CVEDatabase
        db = CVEDatabase()
        return [{"cve_id": cve.cve_id, "description": cve.description,
                  "cvss_score": cve.cvss_score, "severity": cve.severity} for cve in db.list_all()]
    except Exception:
        return None


def generate(manufacturer="StarTeQ Ltd", product="IoT Firmware",
             product_version="1.0.0", requirements_path=None, cve_list=None):
    if requirements_path:
        components = parse_requirements(requirements_path)
    else:
        components = scan_installed()
    components.insert(0, {
        "name": product.replace(" ", "-"),
        "version": product_version,
        "type": "application",
        "purl": "pkg:pypi/" + product.lower().replace(" ", "-") + "@" + product_version,
    })
    cves = cve_list or load_firmware_health_cves()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = str(uuid.uuid4())
    return SBOM.format(
        s=serial, t=ts, m=manufacturer, p=product, v=product_version,
        c=render_components(components),
        vulns=render_vulnerabilities(cves),
    )


def main():
    parser = argparse.ArgumentParser(description="CycloneDX 1.5 SBOM Generator")
    parser.add_argument("--output", "-o", default="sbom.xml")
    parser.add_argument("--requirements", "-r", help="Path to requirements.txt")
    parser.add_argument("--manufacturer", "-m", default="StarTeQ Ltd")
    parser.add_argument("--product", "-p", default="IoT Firmware")
    parser.add_argument("--version", "-v", default="1.0.0")
    args = parser.parse_args()
    sbom = generate(args.manufacturer, args.product, args.version, args.requirements)
    Path(args.output).write_text(sbom, encoding="utf-8")
    print("SBOM written:", args.output)
    print("Components:", sbom.count("<component "))
    print("Vulnerabilities:", max(0, sbom.count("<vulnerability") - 1))


if __name__ == "__main__":
    main()
