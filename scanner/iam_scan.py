from datetime import datetime, timezone

import boto3


PROFILE = "CSPM-Administrator-831744285700"
REGION = "us-east-1"
ACCESS_KEY_MAX_AGE_DAYS = 90


def get_iam_client():
    session = boto3.Session(
        profile_name=PROFILE,
        region_name=REGION,
    )

    return session.client("iam")


def get_account_summary(iam):
    response = iam.get_account_summary()

    return response.get("SummaryMap", {})


def check_root_mfa(iam):
    summary = get_account_summary(iam)

    root_mfa_enabled = summary.get("AccountMFAEnabled", 0)

    if root_mfa_enabled == 1:
        return {
            "rule_id": "IAM-001",
            "title": "Root Account MFA",
            "status": "PASS",
            "severity": "INFO",
            "message": "Root account MFA is enabled.",
        }

    return {
        "rule_id": "IAM-001",
        "title": "Root Account MFA",
        "status": "FAIL",
        "severity": "HIGH",
        "message": "Root account MFA is not enabled.",
    }


def discover_users(iam):
    users = []

    paginator = iam.get_paginator("list_users")

    for page in paginator.paginate():
        users.extend(page.get("Users", []))

    return users


def get_user_access_keys(iam, user_name):
    response = iam.list_access_keys(
        UserName=user_name
    )

    return response.get("AccessKeyMetadata", [])


def check_access_key_age(iam):
    users = discover_users(iam)
    findings = []

    now = datetime.now(timezone.utc)

    for user in users:
        user_name = user["UserName"]
        access_keys = get_user_access_keys(iam, user_name)

        for access_key in access_keys:
            access_key_id = access_key["AccessKeyId"]
            status = access_key["Status"]
            created_at = access_key["CreateDate"]

            age_days = (now - created_at).days

            if (
                status == "Active"
                and age_days > ACCESS_KEY_MAX_AGE_DAYS
            ):
                findings.append(
                    {
                        "rule_id": "IAM-002",
                        "title": "Old Active Access Key",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "message": (
                            f"User '{user_name}' has active access key "
                            f"'{access_key_id}' that is "
                            f"{age_days} days old."
                        ),
                    }
                )

    if not findings:
        findings.append(
            {
                "rule_id": "IAM-002",
                "title": "Old Active Access Key",
                "status": "PASS",
                "severity": "INFO",
                "message": (
                    "No active IAM access keys older than "
                    f"{ACCESS_KEY_MAX_AGE_DAYS} days were found."
                ),
            }
        )

    return findings


def scan_iam(iam):
    findings = []

    findings.append(check_root_mfa(iam))
    findings.extend(check_access_key_age(iam))

    return findings


def print_findings(findings):
    print("\nCSPM IAM SECURITY SCAN")
    print("=====================")

    for finding in findings:
        print(
            f"{finding['rule_id']} | "
            f"{finding['status']} | "
            f"{finding['severity']} | "
            f"{finding['title']} | "
            f"{finding['message']}"
        )

    passed = sum(
        1
        for finding in findings
        if finding["status"] == "PASS"
    )

    failed = sum(
        1
        for finding in findings
        if finding["status"] == "FAIL"
    )

    print("\nIAM SCAN SUMMARY")
    print("----------------")
    print(f"Findings: {len(findings)}")
    print(f"Passed:   {passed}")
    print(f"Failed:   {failed}")


def main():
    iam = get_iam_client()

    findings = scan_iam(iam)

    print_findings(findings)


if __name__ == "__main__":
    main()