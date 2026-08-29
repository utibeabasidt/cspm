import unittest

from rules.s3_versioning import S3VersioningRule


class TestS3VersioningRule(unittest.TestCase):

    def setUp(self):
        self.rule = S3VersioningRule()
        self.bucket = "test-bucket"

    def test_versioning_enabled(self):
        config = {
            "versioning_enabled": True,
        }

        finding = self.rule.evaluate(
            self.bucket,
            config,
        )

        self.assertEqual(finding.rule_id, "S3-003")
        self.assertEqual(finding.status, "PASS")
        self.assertEqual(finding.severity, "INFO")

    def test_versioning_disabled(self):
        config = {
            "versioning_enabled": False,
        }

        finding = self.rule.evaluate(
            self.bucket,
            config,
        )

        self.assertEqual(finding.rule_id, "S3-003")
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, "MEDIUM")


if __name__ == "__main__":
    unittest.main()