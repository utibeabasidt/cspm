import boto3

PROFILE = "CSPM-Administrator-831744285700"
REGION = "us-east-1"


def discover_buckets():
    session = boto3.Session(
        profile_name=PROFILE,
        region_name=REGION,
    )

    s3 = session.client("s3")

    response = s3.list_buckets()

    buckets = []

    for bucket in response.get("Buckets", []):
        buckets.append({
            "name": bucket["Name"],
            "creation_date": bucket["CreationDate"],
        })

    return buckets


if __name__ == "__main__":
    buckets = discover_buckets()

    print("\nCSPM S3 RESOURCE DISCOVERY")
    print("--------------------------")

    if not buckets:
        print("No S3 buckets discovered.")
    else:
        for bucket in buckets:
            print(f"Bucket: {bucket['name']}")
            print(f"Created: {bucket['creation_date']}")
            print()