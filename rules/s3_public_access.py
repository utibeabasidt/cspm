from scanner.finding import Finding


RULE_ID = "S3-001"


def evaluate(bucket_name, config):
    """
    Evaluate whether all S3 Block Public Access
    settings are enabled.
    """

    checks = {
        "BlockPublicAcls": config.get("BlockPublicAcls", False),
        "IgnorePublicAcls": config.get("IgnorePublicAcls", False),
        "BlockPublicPolicy": config.get("BlockPublicPolicy", False),
        "RestrictPublicBuckets": config.get(
            "RestrictPublicBuckets", False
        ),
    }

    if all(checks.values()):
        return Finding(
            rule_id=RULE_ID,
            resource=bucket_name,
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
        rule_id=RULE_ID,
        resource=bucket_name,
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