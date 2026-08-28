import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import boto3

from scanner.finding import Finding


PROFILE = "CSPM-Administrator-831744285700"
REGION = "us-east-1"

REPORT_PATH = Path("reports/s3_scan.json")


def get_s3_client():
    session = boto3.Session(
        profile_name=PROFILE,
        region_name=REGION,
    )

    return session.client("s3")


def discover_buckets(s3):
    response = s3.list_buckets()

    return [
        bucket["Name"]
        for bucket in response.get("Buckets", [])
    ]


def evaluate_public_access(bucket_name, config):
    checks = {
        "BlockPublicAcls": config.get("BlockPublicAcls", False),
        "IgnorePublicAcls": config.get("IgnorePublicAcls", False),
        "BlockPublicPolicy": config.get("BlockPublicPolicy", False),
        "RestrictPublicBuckets": config.get(
            "RestrictPublicBuckets", False
        ),
    }

    if all(checks.values()):
        return Finding(
            rule_id="S3-001",
            resource=bucket_name,
            resource_type="S3",
            status="PASS",
            severity="INFO",
            description="S3 Block Public Access is fully enabled.",
            recommendation=(
                "Keep all S3 Block Public Access settings enabled."
            ),
        )

    return Finding(
        rule_id="S3-001",
        resource=bucket_name,
        resource_type="S3",
        status="FAIL",
        severity="HIGH",
        description="S3 Block Public Access is not fully enabled.",
        recommendation="Enable all S3 Block Public Access settings.",
    )


def check_public_access(s3, bucket_name):
    try:
        response = s3.get_public_access_block(
            Bucket=bucket_name
        )

        return evaluate_public_access(
            bucket_name,
            response["PublicAccessBlockConfiguration"],
        )

    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        return Finding(
            rule_id="S3-001",
            resource=bucket_name,
            resource_type="S3",
            status="FAIL",
            severity="HIGH",
            description=(
                "S3 Block Public Access configuration is missing."
            ),
            recommendation="Enable S3 Block Public Access.",
        )


def save_report(findings):
    REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "resource_type": "S3",
        "findings": [
            asdict(finding)
            for finding in findings
        ],
    }

    with REPORT_PATH.open("w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
        )


def main():
    s3 = get_s3_client()

    buckets = discover_buckets(s3)

    print("\nCSPM S3 SCAN")
    print("============")

    if not buckets:
        print("No S3 buckets discovered.")
        return

    findings = []

    for bucket in buckets:
        finding = check_public_access(
            s3,
            bucket,
        )

        findings.append(finding)

        print(f"\nResource: {finding.resource}")
        print(f"Status:   {finding.status}")
        print(f"Severity: {finding.severity}")
        print(f"Finding:  {finding.description}")

    passed = sum(
        1
        for finding in findings
        if finding.status == "PASS"
    )

    failed = sum(
        1
        for finding in findings
        if finding.status == "FAIL"
    )

    save_report(findings)

    print("\nSUMMARY")
    print("-------")
    print(f"Buckets scanned: {len(buckets)}")
    print(f"Passed:          {passed}")
    print(f"Failed:          {failed}")
    print(f"Report:          {REPORT_PATH}")


if __name__ == "__main__":
    main()