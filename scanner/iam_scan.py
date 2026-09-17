import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

from scanner.finding import Finding


PROFILE = "CSPM-Administrator-831744285700"
REGION = "us-east-1"

REPORT_PATH = Path("reports/iam_scan.json")

ACCESS_KEY_MAX_AGE_DAYS = 90
MIN_PASSWORD_LENGTH = 14


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

    root_mfa_enabled = summary.get(
        "AccountMFAEnabled",
        0,
    )

    if root_mfa_enabled == 1:
        return Finding(
            rule_id="IAM-001",
            resource="AWS Account",
            resource_type="IAM",
            status="PASS",
            severity="INFO",
            description="Root account MFA is enabled.",
            recommendation=(
                "Keep root account MFA enabled."
            ),
        )

    return Finding(
        rule_id="IAM-001",
        resource="AWS Account",
        resource_type="IAM",
        status="FAIL",
        severity="HIGH",
        description="Root account MFA is not enabled.",
        recommendation=(
            "Enable MFA on the AWS root account."
        ),
    )


def discover_users(iam):
    users = []

    paginator = iam.get_paginator(
        "list_users"
    )

    for page in paginator.paginate():
        users.extend(
            page.get("Users", [])
        )

    return users


def get_user_access_keys(iam, user_name):
    response = iam.list_access_keys(
        UserName=user_name
    )

    return response.get(
        "AccessKeyMetadata",
        []
    )


def check_access_key_age(iam):
    users = discover_users(iam)
    findings = []

    now = datetime.now(timezone.utc)

    for user in users:
        user_name = user["UserName"]

        access_keys = get_user_access_keys(
            iam,
            user_name,
        )

        for access_key in access_keys:
            access_key_id = access_key[
                "AccessKeyId"
            ]

            status = access_key[
                "Status"
            ]

            created_at = access_key[
                "CreateDate"
            ]

            age_days = (
                now - created_at
            ).days

            if (
                status == "Active"
                and age_days > ACCESS_KEY_MAX_AGE_DAYS
            ):
                findings.append(
                    Finding(
                        rule_id="IAM-002",
                        resource=user_name,
                        resource_type="IAM User",
                        status="FAIL",
                        severity="HIGH",
                        description=(
                            f"User '{user_name}' has active "
                            f"access key '{access_key_id}' "
                            f"that is {age_days} days old."
                        ),
                        recommendation=(
                            "Rotate or deactivate old IAM "
                            "access keys and use temporary "
                            "credentials where possible."
                        ),
                    )
                )

    if not findings:
        findings.append(
            Finding(
                rule_id="IAM-002",
                resource="IAM Users",
                resource_type="IAM",
                status="PASS",
                severity="INFO",
                description=(
                    "No active IAM access keys older than "
                    f"{ACCESS_KEY_MAX_AGE_DAYS} days were found."
                ),
                recommendation=(
                    "Continue rotating IAM access keys "
                    "regularly."
                ),
            )
        )

    return findings


def discover_roles(iam):
    roles = []

    paginator = iam.get_paginator(
        "list_roles"
    )

    for page in paginator.paginate():
        roles.extend(
            page.get("Roles", [])
        )

    return roles


def get_role_trust_policy(iam, role_name):
    response = iam.get_role(
        RoleName=role_name
    )

    encoded_policy = response[
        "Role"
    ][
        "AssumeRolePolicyDocument"
    ]

    if isinstance(
        encoded_policy,
        str,
    ):
        return json.loads(
            encoded_policy
        )

    return encoded_policy


def principal_contains_wildcard(principal):
    if principal == "*":
        return True

    if isinstance(
        principal,
        dict,
    ):
        for value in principal.values():
            if value == "*":
                return True

            if (
                isinstance(value, list)
                and "*" in value
            ):
                return True

    if isinstance(
        principal,
        list,
    ):
        return "*" in principal

    return False


def trust_policy_allows_wildcard(policy):
    statements = policy.get(
        "Statement",
        [],
    )

    if isinstance(
        statements,
        dict,
    ):
        statements = [statements]

    for statement in statements:
        principal = statement.get(
            "Principal"
        )

        if principal_contains_wildcard(
            principal
        ):
            return True

    return False


def check_role_trust_policies(iam):
    roles = discover_roles(iam)
    findings = []

    for role in roles:
        role_name = role["RoleName"]

        policy = get_role_trust_policy(
            iam,
            role_name,
        )

        if trust_policy_allows_wildcard(
            policy
        ):
            findings.append(
                Finding(
                    rule_id="IAM-003",
                    resource=role_name,
                    resource_type="IAM Role",
                    status="FAIL",
                    severity="HIGH",
                    description=(
                        f"Role '{role_name}' has a trust "
                        "policy containing a wildcard "
                        "principal."
                    ),
                    recommendation=(
                        "Restrict the role trust policy "
                        "to explicitly authorized AWS "
                        "principals."
                    ),
                )
            )

    if not findings:
        findings.append(
            Finding(
                rule_id="IAM-003",
                resource="IAM Roles",
                resource_type="IAM",
                status="PASS",
                severity="INFO",
                description=(
                    "No IAM roles with wildcard trust-policy "
                    "principals were found."
                ),
                recommendation=(
                    "Keep IAM role trust policies restricted "
                    "to authorized principals."
                ),
            )
        )

    return findings


def policy_document_has_full_admin_access(
    policy_document
):
    statements = policy_document.get(
        "Statement",
        [],
    )

    if isinstance(
        statements,
        dict,
    ):
        statements = [statements]

    for statement in statements:
        if statement.get(
            "Effect"
        ) != "Allow":
            continue

        action = statement.get(
            "Action"
        )

        resource = statement.get(
            "Resource"
        )

        action_is_wildcard = (
            action == "*"
            or (
                isinstance(
                    action,
                    list,
                )
                and "*" in action
            )
        )

        resource_is_wildcard = (
            resource == "*"
            or (
                isinstance(
                    resource,
                    list,
                )
                and "*" in resource
            )
        )

        if (
            action_is_wildcard
            and resource_is_wildcard
        ):
            return True

    return False


def get_attached_role_policies(
    iam,
    role_name,
):
    policies = []

    paginator = iam.get_paginator(
        "list_attached_role_policies"
    )

    for page in paginator.paginate(
        RoleName=role_name
    ):
        policies.extend(
            page.get(
                "AttachedPolicies",
                [],
            )
        )

    return policies


def get_policy_document(
    iam,
    policy_arn,
):
    response = iam.get_policy(
        PolicyArn=policy_arn
    )

    default_version_id = response[
        "Policy"
    ][
        "DefaultVersionId"
    ]

    version_response = iam.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=default_version_id,
    )

    document = version_response[
        "PolicyVersion"
    ][
        "Document"
    ]

    if isinstance(
        document,
        str,
    ):
        return json.loads(
            document
        )

    return document


def check_role_admin_policies(iam):
    roles = discover_roles(iam)
    findings = []

    for role in roles:
        role_name = role["RoleName"]

        policies = get_attached_role_policies(
            iam,
            role_name,
        )

        for policy in policies:
            policy_name = policy[
                "PolicyName"
            ]

            policy_arn = policy[
                "PolicyArn"
            ]

            document = get_policy_document(
                iam,
                policy_arn,
            )

            if policy_document_has_full_admin_access(
                document
            ):
                findings.append(
                    Finding(
                        rule_id="IAM-004",
                        resource=role_name,
                        resource_type="IAM Role",
                        status="FAIL",
                        severity="HIGH",
                        description=(
                            f"Role '{role_name}' has attached "
                            f"policy '{policy_name}' granting "
                            "Action '*' on Resource '*'."
                        ),
                        recommendation=(
                            "Apply least-privilege permissions "
                            "and avoid granting full administrative "
                            "access unless explicitly required."
                        ),
                    )
                )

    if not findings:
        findings.append(
            Finding(
                rule_id="IAM-004",
                resource="IAM Roles",
                resource_type="IAM",
                status="PASS",
                severity="INFO",
                description=(
                    "No attached IAM role policies granting "
                    "full administrative access were found."
                ),
                recommendation=(
                    "Continue following least-privilege "
                    "principles for IAM permissions."
                ),
            )
        )

    return findings


def check_password_policy(iam):
    try:
        response = iam.get_account_password_policy()

        policy = response.get(
            "PasswordPolicy",
            {}
        )

    except ClientError as error:
        error_code = error.response.get(
            "Error",
            {}
        ).get(
            "Code"
        )

        if error_code == "NoSuchEntity":
            return Finding(
                rule_id="IAM-005",
                resource="AWS Account",
                resource_type="IAM",
                status="FAIL",
                severity="MEDIUM",
                description=(
                    "No IAM account password policy "
                    "is configured."
                ),
                recommendation=(
                    "Configure an IAM account password "
                    "policy with strong password requirements."
                ),
            )

        raise

    issues = []

    minimum_length = policy.get(
        "MinimumPasswordLength",
        0,
    )

    if minimum_length < MIN_PASSWORD_LENGTH:
        issues.append(
            f"minimum password length is {minimum_length}"
        )

    if not policy.get(
        "RequireUppercaseCharacters",
        False,
    ):
        issues.append(
            "uppercase characters are not required"
        )

    if not policy.get(
        "RequireLowercaseCharacters",
        False,
    ):
        issues.append(
            "lowercase characters are not required"
        )

    if not policy.get(
        "RequireNumbers",
        False,
    ):
        issues.append(
            "numbers are not required"
        )

    if not policy.get(
        "RequireSymbols",
        False,
    ):
        issues.append(
            "symbols are not required"
        )

    if not policy.get(
        "PasswordReusePreventionEnabled",
        False,
    ):
        issues.append(
            "password reuse prevention is not enabled"
        )

    if not policy.get(
        "ExpirePasswords",
        False,
    ):
        issues.append(
            "password expiration is not enabled"
        )

    if issues:
        return Finding(
            rule_id="IAM-005",
            resource="AWS Account",
            resource_type="IAM",
            status="FAIL",
            severity="MEDIUM",
            description=(
                "IAM password policy does not meet the "
                "configured security requirements: "
                + "; ".join(issues)
                + "."
            ),
            recommendation=(
                "Configure the IAM account password policy "
                "to meet the required security settings."
            ),
        )

    return Finding(
        rule_id="IAM-005",
        resource="AWS Account",
        resource_type="IAM",
        status="PASS",
        severity="INFO",
        description=(
            "IAM account password policy meets the "
            "configured security requirements."
        ),
        recommendation=(
            "Keep the IAM account password policy "
            "configured with strong security requirements."
        ),
    )


def scan_iam(iam):
    findings = []

    findings.append(
        check_root_mfa(iam)
    )

    findings.extend(
        check_access_key_age(iam)
    )

    findings.extend(
        check_role_trust_policies(iam)
    )

    findings.extend(
        check_role_admin_policies(iam)
    )

    findings.append(
        check_password_policy(iam)
    )

    return findings


def save_report(findings):
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
        "resource_type": "IAM",
        "summary": {
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


def print_findings(findings):
    print("\nCSPM IAM SECURITY SCAN")
    print("=====================")

    for finding in findings:
        print(
            f"{finding.rule_id} | "
            f"{finding.status} | "
            f"{finding.severity} | "
            f"{finding.description}"
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

    severity_counts = Counter(
        finding.severity
        for finding in findings
    )

    print("\nIAM SCAN SUMMARY")
    print("----------------")
    print(f"Findings: {len(findings)}")
    print(f"Passed:   {passed}")
    print(f"Failed:   {failed}")

    print("\nSEVERITY SUMMARY")
    print("----------------")
    print(
        f"HIGH:   "
        f"{severity_counts.get('HIGH', 0)}"
    )
    print(
        f"MEDIUM: "
        f"{severity_counts.get('MEDIUM', 0)}"
    )
    print(
        f"LOW:    "
        f"{severity_counts.get('LOW', 0)}"
    )
    print(
        f"INFO:   "
        f"{severity_counts.get('INFO', 0)}"
    )

    print(
        f"\nReport: {REPORT_PATH}"
    )


def main():
    iam = get_iam_client()

    findings = scan_iam(iam)

    save_report(findings)

    print_findings(findings)


if __name__ == "__main__":
    main()