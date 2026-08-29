import unittest

from rules.s3_encryption import S3EncryptionRule


class TestS3EncryptionRule(unittest.TestCase):

    def setUp(self):
        self.rule = S3EncryptionRule()
        self.bucket = "test-bucket"

    def test_encryption_enabled(self):
        config = {
            "encryption_enabled": True,
        }

        finding = self.rule.evaluate(
            self.bucket,
            config,
        )

        self.assertEqual(finding.rule_id, "S3-002")
        self.assertEqual(finding.status, "PASS")
        self.assertEqual(finding.severity, "INFO")

    def test_encryption_disabled(self):
        config = {
            "encryption_enabled": False,
        }

        finding = self.rule.evaluate(
            self.bucket,
            config,
        )

        self.assertEqual(finding.rule_id, "S3-002")
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, "MEDIUM")


if __name__ == "__main__":
    unittest.main()