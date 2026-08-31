import json
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

    # Get Block Public Access configuration
    try:
        response = s3.get_public_access_block(
            Bucket=bucket_name
        )

        config["public_access"] = response[
            "PublicAccessBlockConfiguration"
        ]

    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        pass

    # Get default encryption configuration
    try:
        s3.get_bucket_encryption(
            Bucket=bucket_name
        )

        config["encryption_enabled"] = True

    except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
        pass

    # Get bucket versioning configuration
    response = s3.get_bucket_versioning(
        Bucket=bucket_name
    )

    config["versioning_enabled"] = (
        response.get("Status") == "Enabled"
    )

    # Get bucket logging configuration
    response = s3.get_bucket_logging(
        Bucket=bucket_name
    )

    config["logging_enabled"] = (
        "LoggingEnabled" in response
    )

    # Get bucket policy and check for public access
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
        error_code = error.response[
            "Error"
        ]["Code"]

        if error_code != "NoSuchBucketPolicy":
            raise

    return config


def save_report(findings):
    REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    report = {
        "scan_time": datetime.now(
            timezone.utc
        ).isoformat(),
        "resource_type": "S3",
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

        for finding in bucket_findings:
            findings.append(finding)

            print(f"\nResource: {finding.resource}")
            print(f"Rule:     {finding.rule_id}")
            print(f"Status:   {finding.status}")
            print(f"Severity: {finding.severity}")
            print(
                f"Finding:  {finding.description}"
            )

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
    print(f"Findings:        {len(findings)}")
    print(f"Passed:          {passed}")
    print(f"Failed:          {failed}")
    print(f"Report:          {REPORT_PATH}")


if __name__ == "__main__":
    main()