import unittest

from rules.s3_logging import S3LoggingRule


class TestS3LoggingRule(unittest.TestCase):

    def setUp(self):
        self.rule = S3LoggingRule()
        self.bucket = "test-bucket"

    def test_logging_enabled(self):
        config = {
            "logging_enabled": True,
        }

        finding = self.rule.evaluate(
            self.bucket,
            config,
        )

        self.assertEqual(finding.rule_id, "S3-004")
        self.assertEqual(finding.status, "PASS")
        self.assertEqual(finding.severity, "INFO")

    def test_logging_disabled(self):
        config = {
            "logging_enabled": False,
        }

        finding = self.rule.evaluate(
            self.bucket,
            config,
        )

        self.assertEqual(finding.rule_id, "S3-004")
        self.assertEqual(finding.status, "FAIL")
        self.assertEqual(finding.severity, "MEDIUM")


if __name__ == "__main__":
    unittest.main()