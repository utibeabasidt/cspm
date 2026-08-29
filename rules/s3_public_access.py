from scanner.finding import Finding
from scanner.rule import SecurityRule


class S3PublicAccessRule(SecurityRule):

    @property
    def rule_id(self):
        return "S3-001"

    @property
    def name(self):
        return "S3 Block Public Access"

    def evaluate(self, resource, config):
        public_access = config.get(
            "public_access",
            {},
        )

        checks = {
            "BlockPublicAcls": public_access.get(
                "BlockPublicAcls",
                False,
            ),
            "IgnorePublicAcls": public_access.get(
                "IgnorePublicAcls",
                False,
            ),
            "BlockPublicPolicy": public_access.get(
                "BlockPublicPolicy",
                False,
            ),
            "RestrictPublicBuckets": public_access.get(
                "RestrictPublicBuckets",
                False,
            ),
        }

        if all(checks.values()):
            return Finding(
                rule_id=self.rule_id,
                resource=resource,
                resource_type="S3",
                status="PASS",
                severity="INFO",
                description=(
                    "S3 Block Public Access is fully enabled."
                ),
                recommendation=(
                    "Keep all S3 Block Public Access settings enabled."
                ),
            )

        return Finding(
            rule_id=self.rule_id,
            resource=resource,
            resource_type="S3",
            status="FAIL",
            severity="HIGH",
            description=(
                "S3 Block Public Access is not fully enabled."
            ),
            recommendation=(
                "Enable all S3 Block Public Access settings."
            ),
        )