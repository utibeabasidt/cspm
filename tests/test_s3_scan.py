import unittest

from scanner.s3_scan import evaluate_public_access


class TestS3PublicAccess(unittest.TestCase):

    def test_all_public_access_settings_enabled(self):
        config = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }

        finding = evaluate_public_access(
            "test-bucket",
            config,
        )

        self.assertEqual(finding.status, "PASS")
        self.assertEqual(finding.severity, "INFO")

    def test_public_acl_block_disabled(self):
        config = {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }

        finding = evaluate_public_access(
            "test-bucket",
            config,
        )

        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, "HIGH")

    def test_public_policy_block_disabled(self):
        config = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True,
        }

        finding = evaluate_public_access(
            "test-bucket",
            config,
        )

        self.assertEqual(finding.status, "FAIL")

    def test_restrict_public_buckets_disabled(self):
        config = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": False,
        }

        finding = evaluate_public_access(
            "test-bucket",
            config,
        )

        self.assertEqual(finding.status, "FAIL")


if __name__ == "__main__":
    unittest.main()