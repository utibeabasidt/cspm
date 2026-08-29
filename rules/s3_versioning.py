from scanner.finding import Finding
from scanner.rule import SecurityRule


class S3VersioningRule(SecurityRule):

    @property
    def rule_id(self):
        return "S3-003"

    @property
    def name(self):
        return "S3 Bucket Versioning"

    def evaluate(self, resource, config):
        versioning_enabled = config.get(
            "versioning_enabled",
            False,
        )

        if versioning_enabled:
            return Finding(
                rule_id=self.rule_id,
                resource=resource,
                resource_type="S3",
                status="PASS",
                severity="INFO",
                description=(
                    "S3 bucket versioning is enabled."
                ),
                recommendation=(
                    "Keep S3 bucket versioning enabled."
                ),
            )

        return Finding(
            rule_id=self.rule_id,
            resource=resource,
            resource_type="S3",
            status="FAIL",
            severity="MEDIUM",
            description=(
                "S3 bucket versioning is not enabled."
            ),
            recommendation=(
                "Enable versioning for the S3 bucket."
            ),
        )