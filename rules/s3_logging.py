from scanner.finding import Finding
from scanner.rule import SecurityRule


class S3LoggingRule(SecurityRule):

    @property
    def rule_id(self):
        return "S3-004"

    @property
    def name(self):
        return "S3 Server Access Logging"

    def evaluate(self, resource, config):
        logging_enabled = config.get(
            "logging_enabled",
            False,
        )

        if logging_enabled:
            return Finding(
                rule_id=self.rule_id,
                resource=resource,
                resource_type="S3",
                status="PASS",
                severity="INFO",
                description=(
                    "S3 server access logging is enabled."
                ),
                recommendation=(
                    "Keep S3 server access logging enabled."
                ),
            )

        return Finding(
            rule_id=self.rule_id,
            resource=resource,
            resource_type="S3",
            status="FAIL",
            severity="MEDIUM",
            description=(
                "S3 server access logging is not enabled."
            ),
            recommendation=(
                "Enable server access logging for the S3 bucket."
            ),
        )