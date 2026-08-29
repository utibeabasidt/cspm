import unittest

from rules.s3_public_access import S3PublicAccessRule


class TestS3PublicAccess(unittest.TestCase):

    def setUp(self):
        self.rule = S3PublicAccessRule()
        self.bucket = "test-bucket"

    def test_all_public_access_settings_enabled(self):
        config = {
            "public_access": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

        finding = self.rule.evaluate(
            self.bucket,
            config,
        )

        self.assertEqual(finding.rule_id, "S3-001")
        self.assertEqual(finding.status, "PASS")
        self.assertEqual(finding.severity, "INFO")

    def test_public_acl_block_disabled(self):
        config = {
            "public_access": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

        finding = self.rule.evaluate(
            self.bucket,
            config,
        )

        self.assertEqual(finding.rule_id, "S3-001")
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, "HIGH")

    def test_public_policy_block_disabled(self):
        config = {
            "public_access": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": True,
            }
        }

        finding = self.rule.evaluate(
            self.bucket,
            config,
        )

        self.assertEqual(finding.rule_id, "S3-001")
        self.assertEqual(finding.status, "FAIL")

    def test_restrict_public_buckets_disabled(self):
        config = {
            "public_access": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": False,
            }
        }

        finding = self.rule.evaluate(
            self.bucket,
            config,
        )

        self.assertEqual(finding.rule_id, "S3-001")
        self.assertEqual(finding.status, "FAIL")


if __name__ == "__main__":
    unittest.main()