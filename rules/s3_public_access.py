import boto3

PROFILE = "CSPM-Administrator-831744285700"
REGION = "us-east-1"
BUCKET_NAME = "cspm-lab-2026-utyszn"


def check_public_access():
    session = boto3.Session(
        profile_name=PROFILE,
        region_name=REGION,
    )

    s3 = session.client("s3")

    try:
        response = s3.get_public_access_block(
            Bucket=BUCKET_NAME
        )

        config = response["PublicAccessBlockConfiguration"]

        settings = [
            config.get("BlockPublicAcls", False),
            config.get("IgnorePublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False),
        ]

        if all(settings):
            return {
                "status": "PASS",
                "severity": "INFO",
                "resource": BUCKET_NAME,
                "finding": "S3 Block Public Access is fully enabled.",
            }

        return {
            "status": "FAIL",
            "severity": "HIGH",
            "resource": BUCKET_NAME,
            "finding": "S3 Block Public Access is not fully enabled.",
        }

    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        return {
            "status": "FAIL",
            "severity": "HIGH",
            "resource": BUCKET_NAME,
            "finding": "S3 Block Public Access configuration is missing.",
        }


if __name__ == "__main__":
    result = check_public_access()

    print("\nCSPM S3 SECURITY CHECK")
    print("----------------------")
    print(f"Resource: {result['resource']}")
    print(f"Status:   {result['status']}")
    print(f"Severity: {result['severity']}")
    print(f"Finding:  {result['finding']}")