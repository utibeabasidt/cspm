import unittest
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from scanner.iam_scan import (
    check_access_key_age,
    check_password_policy,
    check_role_admin_policies,
    check_role_trust_policies,
    check_root_mfa,
    principal_contains_wildcard,
    trust_policy_allows_wildcard,
)


class TestIAMHelperFunctions(unittest.TestCase):

    def test_principal_contains_wildcard_string(self):
        self.assertTrue(
            principal_contains_wildcard("*")
        )

    def test_principal_contains_wildcard_dict(self):
        principal = {
            "AWS": "*"
        }

        self.assertTrue(
            principal_contains_wildcard(principal)
        )

    def test_principal_without_wildcard(self):
        principal = {
            "AWS": "arn:aws:iam::123456789012:root"
        }

        self.assertFalse(
            principal_contains_wildcard(principal)
        )

    def test_trust_policy_allows_wildcard(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRole",
                }
            ]
        }

        self.assertTrue(
            trust_policy_allows_wildcard(policy)
        )

    def test_trust_policy_rejects_specific_principal(self):
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:root"
                    },
                    "Action": "sts:AssumeRole",
                }
            ]
        }

        self.assertFalse(
            trust_policy_allows_wildcard(policy)
        )


class TestIAMChecks(unittest.TestCase):

    def test_root_mfa_enabled(self):
        iam = MagicMock()

        iam.get_account_summary.return_value = {
            "SummaryMap": {
                "AccountMFAEnabled": 1
            }
        }

        finding = check_root_mfa(iam)

        self.assertEqual(
            finding.status,
            "PASS"
        )

    def test_root_mfa_disabled(self):
        iam = MagicMock()

        iam.get_account_summary.return_value = {
            "SummaryMap": {
                "AccountMFAEnabled": 0
            }
        }

        finding = check_root_mfa(iam)

        self.assertEqual(
            finding.status,
            "FAIL"
        )

    def test_password_policy_missing(self):
        iam = MagicMock()

        error_response = {
            "Error": {
                "Code": "NoSuchEntity",
                "Message": "Password policy not found",
            }
        }

        iam.get_account_password_policy.side_effect = (
            ClientError(
                error_response,
                "GetAccountPasswordPolicy",
            )
        )

        finding = check_password_policy(iam)

        self.assertEqual(
            finding.status,
            "FAIL"
        )

    def test_password_policy_configured(self):
        iam = MagicMock()

        iam.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 14,
                "RequireSymbols": True,
                "RequireNumbers": True,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "PasswordReusePreventionEnabled": True,
                "ExpirePasswords": True,
            }
        }

        finding = check_password_policy(iam)

        self.assertEqual(
            finding.status,
            "PASS"
        )

    def test_access_key_age_with_no_users(self):
        iam = MagicMock()

        iam.get_paginator.return_value.paginate.return_value = [
            {
                "Users": []
            }
        ]

        findings = check_access_key_age(iam)

        self.assertIsInstance(
            findings,
            list
        )

        self.assertEqual(
            len(findings),
            1
        )

        self.assertEqual(
            findings[0].status,
            "PASS"
        )

    def test_role_trust_policy_without_roles(self):
        iam = MagicMock()

        iam.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": []
            }
        ]

        findings = check_role_trust_policies(iam)

        self.assertIsInstance(
            findings,
            list
        )

        self.assertEqual(
            len(findings),
            1
        )

        self.assertEqual(
            findings[0].status,
            "PASS"
        )

    def test_role_admin_policies_without_roles(self):
        iam = MagicMock()

        iam.get_paginator.return_value.paginate.return_value = [
            {
                "Roles": []
            }
        ]

        findings = check_role_admin_policies(iam)

        self.assertIsInstance(
            findings,
            list
        )

        self.assertEqual(
            len(findings),
            1
        )

        self.assertEqual(
            findings[0].status,
            "PASS"
        )


if __name__ == "__main__":
    unittest.main()