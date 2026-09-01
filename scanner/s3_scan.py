import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

from scanner.engine import RuleEngine
from rules.s3_bucket_policy import S3BucketPolicyRule
from rules.s3_encryption import S3EncryptionRule
from rules.s3_logging import S3LoggingRule
from rules.s3_public_access import S3PublicAccessRule
from rules.s3_versioning import S3VersioningRule


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


def is_policy_public(policy_document):
    """
    Check whether an S3 bucket policy contains
    an Allow statement with Principal set to '*'.
    """

    statements = policy_document.get(
        "Statement",
        [],
    )

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        effect = statement.get("Effect")
        principal = statement.get("Principal")

        if effect != "Allow":
            continue

        if principal == "*":
            return True

        if isinstance(principal, dict):
            aws_principal = principal.get("AWS")

            if aws_principal == "*":
                return True

    return False


def get_bucket_config(s3, bucket_name):
    """
    Collect the S3 security configuration required
    by the registered S3 rules.
    """

    config = {
        "public_access": {},
        "encryption_enabled": False,
        "versioning_enabled": False,
        "logging_enabled": False,
        "public_policy": False,
    }

    # S3 Block Public Access
    try:
        response = s3.get_public_access_block(
            Bucket=bucket_name
        )

        config["public_access"] = response[
            "PublicAccessBlockConfiguration"
        ]

    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        pass

    # S3 Default Encryption
    try:
        s3.get_bucket_encryption(
            Bucket=bucket_name
        )

        config["encryption_enabled"] = True

    except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
        pass

    # S3 Versioning
    response = s3.get_bucket_versioning(
        Bucket=bucket_name
    )

    config["versioning_enabled"] = (
        response.get("Status") == "Enabled"
    )

    # S3 Server Access Logging
    response = s3.get_bucket_logging(
        Bucket=bucket_name
    )

    config["logging_enabled"] = (
        "LoggingEnabled" in response
    )

    # S3 Bucket Policy
    try:
        response = s3.get_bucket_policy(
            Bucket=bucket_name
        )

        policy_document = json.loads(
            response["Policy"]
        )

        config["public_policy"] = is_policy_public(
            policy_document
        )

    except ClientError as error:
        error_code = error.response["Error"]["Code"]

        if error_code != "NoSuchBucketPolicy":
            raise

    return config


def save_report(findings):
    """
    Save scan findings as a JSON report.
    """

    REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    severity_counts = Counter(
        finding.severity
        for finding in findings
    )

    status_counts = Counter(
        finding.status
        for finding in findings
    )

    report = {
        "scan_time": datetime.now(
            timezone.utc
        ).isoformat(),
        "resource_type": "S3",
        "summary": {
            "findings": len(findings),
            "passed": status_counts.get("PASS", 0),
            "failed": status_counts.get("FAIL", 0),
            "severity": {
                "HIGH": severity_counts.get("HIGH", 0),
                "MEDIUM": severity_counts.get("MEDIUM", 0),
                "LOW": severity_counts.get("LOW", 0),
                "INFO": severity_counts.get("INFO", 0),
            },
        },
        "findings": [
            asdict(finding)
            for finding in findings
        ],
    }

    with REPORT_PATH.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
        )


def print_summary(findings, bucket_count):
    """
    Print scan and severity summaries.
    """

    status_counts = Counter(
        finding.status
        for finding in findings
    )

    severity_counts = Counter(
        finding.severity
        for finding in findings
    )

    print("\nSUMMARY")
    print("-------")
    print(f"Buckets scanned: {bucket_count}")
    print(f"Findings:        {len(findings)}")
    print(
        f"Passed:          "
        f"{status_counts.get('PASS', 0)}"
    )
    print(
        f"Failed:          "
        f"{status_counts.get('FAIL', 0)}"
    )

    print("\nSEVERITY SUMMARY")
    print("----------------")
    print(
        f"HIGH:            "
        f"{severity_counts.get('HIGH', 0)}"
    )
    print(
        f"MEDIUM:          "
        f"{severity_counts.get('MEDIUM', 0)}"
    )
    print(
        f"LOW:             "
        f"{severity_counts.get('LOW', 0)}"
    )
    print(
        f"INFO:            "
        f"{severity_counts.get('INFO', 0)}"
    )

    print(f"\nReport:          {REPORT_PATH}")


def main():
    s3 = get_s3_client()

    engine = RuleEngine()

    # Register S3 security rules
    engine.register(S3PublicAccessRule())
    engine.register(S3EncryptionRule())
    engine.register(S3VersioningRule())
    engine.register(S3LoggingRule())
    engine.register(S3BucketPolicyRule())

    buckets = discover_buckets(s3)

    print("\nCSPM S3 SCAN")
    print("============")

    if not buckets:
        print("No S3 buckets discovered.")
        return

    findings = []

    for bucket in buckets:
        bucket_config = get_bucket_config(
            s3,
            bucket,
        )

        bucket_findings = engine.evaluate(
            bucket,
            bucket_config,
        )

        findings.extend(bucket_findings)

        for finding in bucket_findings:
            print(f"\nResource: {finding.resource}")
            print(f"Rule:     {finding.rule_id}")
            print(f"Status:   {finding.status}")
            print(f"Severity: {finding.severity}")
            print(f"Finding:  {finding.description}")

    save_report(findings)

    print_summary(
        findings,
        len(buckets),
    )


if __name__ == "__main__":
    main()