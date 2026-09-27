"""Require a complete Trivy JSON report with no HIGH/CRITICAL findings."""
import json
import sys


def check(report):
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2:
        raise ValueError("Missing or unsupported Trivy report")
    results = report.get("Results")
    if not isinstance(results, list):
        raise ValueError("Trivy Results must be present")
    findings = []
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Invalid result")
        for key in ("Vulnerabilities", "Secrets"):
            items = result.get(key) or []
            if not isinstance(items, list):
                raise ValueError("Invalid findings")
            for item in items:
                if not isinstance(item, dict) or item.get("Severity") not in (
                        "UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
                    raise ValueError("Invalid finding severity")
                if item["Severity"] in ("HIGH", "CRITICAL"):
                    findings.append(item)
    if findings:
        raise ValueError(f"Trivy found {len(findings)} HIGH/CRITICAL vulnerabilities or secrets")


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as stream:
        check(json.load(stream))
