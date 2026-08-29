from scanner.finding import Finding
from scanner.rule import SecurityRule


class S3EncryptionRule(SecurityRule):

    @property
    def rule_id(self):
        return "S3-002"

    @property
    def name(self):
        return "S3 Default Encryption"

    def evaluate(self, resource, config):
        encryption_enabled = config.get(
            "encryption_enabled",
            False,
        )

        if encryption_enabled:
            return Finding(
                rule_id=self.rule_id,
                resource=resource,
                resource_type="S3",
                status="PASS",
                severity="INFO",
                description=(
                    "S3 default encryption is enabled."
                ),
                recommendation=(
                    "Keep S3 default encryption enabled."
                ),
            )

        return Finding(
            rule_id=self.rule_id,
            resource=resource,
            resource_type="S3",
            status="FAIL",
            severity="MEDIUM",
            description=(
                "S3 default encryption is not enabled."
            ),
            recommendation=(
                "Enable default encryption for the S3 bucket."
            ),
        )