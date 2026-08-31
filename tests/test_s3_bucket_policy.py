import unittest

from rules.s3_bucket_policy import S3BucketPolicyRule


class TestS3BucketPolicyRule(unittest.TestCase):

    def setUp(self):
        self.rule = S3BucketPolicyRule()
        self.bucket = "test-bucket"

    def test_public_policy_disabled(self):
        config = {
            "public_policy": False,
        }

        finding = self.rule.evaluate(
            self.bucket,
            config,
        )

        self.assertEqual(finding.rule_id, "S3-005")
        self.assertEqual(finding.status, "PASS")
        self.assertEqual(finding.severity, "INFO")

    def test_public_policy_enabled(self):
        config = {
            "public_policy": True,
        }

        finding = self.rule.evaluate(
            self.bucket,
            config,
        )

        self.assertEqual(finding.rule_id, "S3-005")
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, "HIGH")


if __name__ == "__main__":
    unittest.main()