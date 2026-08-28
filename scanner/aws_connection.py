import boto3

PROFILE = "CSPM-Administrator-831744285700"
REGION = "us-east-1"

session = boto3.Session(
    profile_name=PROFILE,
    region_name=REGION,
)

sts = session.client("sts")

identity = sts.get_caller_identity()

print("AWS connection successful!")
print(f"Account: {identity['Account']}")
print(f"Identity: {identity['Arn']}")