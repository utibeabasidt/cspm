import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


S3_REPORT_PATH = Path("reports/s3_scan.json")
IAM_REPORT_PATH = Path("reports/iam_scan.json")
REPORT_PATH = Path("reports/cspm_report.json")


def load_report(path):
    if not path.exists():
        return None

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def collect_findings(reports):
    findings = []

    for report in reports:
        if report is None:
            continue

        findings.extend(
            report.get("findings", [])
        )

    return findings


def build_summary(findings):
    status_counts = Counter(
        finding["status"]
        for finding in findings
    )

    severity_counts = Counter(
        finding["severity"]
        for finding in findings
    )

    resource_counts = Counter()

    for finding in findings:
        resource_type = finding["resource_type"]

        if resource_type == "IAM Role":
            resource_type = "IAM"

        resource_counts[resource_type] += 1

    return {
        "findings": len(findings),
        "passed": status_counts.get(
            "PASS",
            0,
        ),
        "failed": status_counts.get(
            "FAIL",
            0,
        ),
        "severity": {
            "HIGH": severity_counts.get(
                "HIGH",
                0,
            ),
            "MEDIUM": severity_counts.get(
                "MEDIUM",
                0,
            ),
            "LOW": severity_counts.get(
                "LOW",
                0,
            ),
            "INFO": severity_counts.get(
                "INFO",
                0,
            ),
        },
        "resource_types": {
            "S3": resource_counts.get(
                "S3",
                0,
            ),
            "IAM": resource_counts.get(
                "IAM",
                0,
            ),
        },
    }


def save_combined_report(
    s3_report,
    iam_report,
):
    reports = [
        s3_report,
        iam_report,
    ]

    findings = collect_findings(
        reports
    )

    report = {
        "scan_time": datetime.now(
            timezone.utc
        ).isoformat(),
        "resource_types": [
            "S3",
            "IAM",
        ],
        "summary": build_summary(
            findings
        ),
        "sources": {
            "s3": str(
                S3_REPORT_PATH
            ),
            "iam": str(
                IAM_REPORT_PATH
            ),
        },
        "findings": findings,
    }

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

    print("\nCSPM COMBINED SECURITY REPORT")
    print("=============================")

    print("\nSUMMARY")
    print("-------")
    print(
        f"Total findings: "
        f"{summary['findings']}"
    )
    print(
        f"Passed:         "
        f"{summary['passed']}"
    )
    print(
        f"Failed:         "
        f"{summary['failed']}"
    )

    print("\nSEVERITY SUMMARY")
    print("----------------")
    print(
        f"HIGH:   "
        f"{summary['severity']['HIGH']}"
    )
    print(
        f"MEDIUM: "
        f"{summary['severity']['MEDIUM']}"
    )
    print(
        f"LOW:    "
        f"{summary['severity']['LOW']}"
    )
    print(
        f"INFO:   "
        f"{summary['severity']['INFO']}"
    )

    print("\nRESOURCE SUMMARY")
    print("----------------")
    print(
        f"S3 findings:  "
        f"{summary['resource_types']['S3']}"
    )
    print(
        f"IAM findings: "
        f"{summary['resource_types']['IAM']}"
    )

    print(
        f"\nReport: {REPORT_PATH}"
    )


def main():
    s3_report = load_report(
        S3_REPORT_PATH
    )

    iam_report = load_report(
        IAM_REPORT_PATH
    )

    if s3_report is None:
        print(
            "S3 report not found:"
            f" {S3_REPORT_PATH}"
        )

    if iam_report is None:
        print(
            "IAM report not found:"
            f" {IAM_REPORT_PATH}"
        )

    if (
        s3_report is None
        and iam_report is None
    ):
        print(
            "No CSPM scan reports are available."
        )
        return

    save_combined_report(
        s3_report,
        iam_report,
    )

    combined_report = load_report(
        REPORT_PATH
    )

    print_summary(
        combined_report
    )


if __name__ == "__main__":
    main()