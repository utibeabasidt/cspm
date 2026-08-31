from scanner.finding import Finding
from scanner.rule import SecurityRule


class S3BucketPolicyRule(SecurityRule):

    @property
    def rule_id(self):
        return "S3-005"

    @property
    def name(self):
        return "S3 Bucket Policy Public Access"

    def evaluate(self, resource, config):
        public_policy = config.get(
            "public_policy",
            False,
        )

        if not public_policy:
            return Finding(
                rule_id=self.rule_id,
                resource=resource,
                resource_type="S3",
                status="PASS",
                severity="INFO",
                description=(
                    "S3 bucket policy does not allow public access."
                ),
                recommendation=(
                    "Keep the S3 bucket policy restricted "
                    "to authorized principals."
                ),
            )

        return Finding(
            rule_id=self.rule_id,
            resource=resource,
            resource_type="S3",
            status="FAIL",
            severity="HIGH",
            description=(
                "S3 bucket policy allows public access."
            ),
            recommendation=(
                "Remove public access from the S3 bucket policy."
            ),
        )