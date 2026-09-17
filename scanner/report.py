import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


S3_REPORT_PATH = Path("reports/s3_scan.json")
IAM_REPORT_PATH = Path("reports/iam_scan.json")
REPORT_PATH = Path("reports/cspm_report.json")


def load_report(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def normalize_resource_type(resource_type):
    if resource_type == "IAM Role":
        return "IAM"

    if resource_type == "IAM User":
        return "IAM"

    return resource_type


def build_summary(findings):
    status_counts = Counter(
        finding["status"]
        for finding in findings
    )

    severity_counts = Counter(
        finding["severity"]
        for finding in findings
    )

    resource_type_counts = Counter(
        normalize_resource_type(finding["resource_type"])
        for finding in findings
    )

    return {
        "findings": len(findings),
        "passed": status_counts.get("PASS", 0),
        "failed": status_counts.get("FAIL", 0),
        "severity": {
            "HIGH": severity_counts.get("HIGH", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "LOW": severity_counts.get("LOW", 0),
            "INFO": severity_counts.get("INFO", 0),
        },
        "resource_types": dict(
            sorted(resource_type_counts.items())
        ),
    }


def build_combined_report(s3_report, iam_report):
    findings = []

    findings.extend(s3_report.get("findings", []))
    findings.extend(iam_report.get("findings", []))

    return {
        "scan_time": datetime.now(
            timezone.utc
        ).isoformat(),

        "resource_type": "CSPM",

        "summary": build_summary(findings),

        "service_summaries": {
            "S3": s3_report.get("summary", {}),
            "IAM": iam_report.get("summary", {}),
        },

        "findings": findings,
    }


def save_report(report):
    REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with REPORT_PATH.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
        )


def print_summary(report):
    summary = report["summary"]
    severity = summary["severity"]
    resource_types = summary["resource_types"]

    print("\nCSPM COMBINED SECURITY REPORT")
    print("============================")

    print(f"Total findings: {summary['findings']}")
    print(f"Passed:         {summary['passed']}")
    print(f"Failed:         {summary['failed']}")

    print("\nSEVERITY SUMMARY")
    print("----------------")
    print(f"HIGH:   {severity['HIGH']}")
    print(f"MEDIUM: {severity['MEDIUM']}")
    print(f"LOW:    {severity['LOW']}")
    print(f"INFO:   {severity['INFO']}")

    print("\nRESOURCE TYPE SUMMARY")
    print("---------------------")

    for resource_type, count in resource_types.items():
        print(f"{resource_type}: {count}")

    print("\nSERVICE SUMMARY")
    print("----------------")

    for service_name, service_summary in report[
        "service_summaries"
    ].items():
        print(
            f"{service_name}: "
            f"{service_summary.get('findings', 0)} findings, "
            f"{service_summary.get('failed', 0)} failed"
        )

    print(f"\nReport: {REPORT_PATH}")


def main():
    if not S3_REPORT_PATH.exists():
        print(
            f"Missing report: {S3_REPORT_PATH}"
        )
        print(
            "Run the S3 scan first."
        )
        return

    if not IAM_REPORT_PATH.exists():
        print(
            f"Missing report: {IAM_REPORT_PATH}"
        )
        print(
            "Run the IAM scan first."
        )
        return

    s3_report = load_report(
        S3_REPORT_PATH
    )

    iam_report = load_report(
        IAM_REPORT_PATH
    )

    combined_report = build_combined_report(
        s3_report,
        iam_report,
    )

    save_report(combined_report)
    print_summary(combined_report)


if __name__ == "__main__":
    main()