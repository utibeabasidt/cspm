import boto3


PROFILE = "CSPM-Administrator-831744285700"
REGION = "us-east-1"


def get_iam_client():
    session = boto3.Session(
        profile_name=PROFILE,
        region_name=REGION,
    )

    return session.client("iam")


def discover_users(iam):
    users = []

    paginator = iam.get_paginator("list_users")

    for page in paginator.paginate():
        users.extend(page.get("Users", []))

    return users


def discover_roles(iam):
    roles = []

    paginator = iam.get_paginator("list_roles")

    for page in paginator.paginate():
        roles.extend(page.get("Roles", []))

    return roles


def discover_groups(iam):
    groups = []

    paginator = iam.get_paginator("list_groups")

    for page in paginator.paginate():
        groups.extend(page.get("Groups", []))

    return groups


def discover_iam(iam):
    return {
        "users": discover_users(iam),
        "roles": discover_roles(iam),
        "groups": discover_groups(iam),
    }


def print_summary(resources):
    users = resources["users"]
    roles = resources["roles"]
    groups = resources["groups"]

    print("\nCSPM IAM RESOURCE DISCOVERY")
    print("==========================")

    print(f"Users discovered:  {len(users)}")
    print(f"Roles discovered:  {len(roles)}")
    print(f"Groups discovered: {len(groups)}")

    print("\nUSERS")
    print("-----")

    if users:
        for user in users:
            print(f"- {user['UserName']}")
    else:
        print("- None")

    print("\nROLES")
    print("-----")

    if roles:
        for role in roles:
            print(f"- {role['RoleName']}")
    else:
        print("- None")

    print("\nGROUPS")
    print("------")

    if groups:
        for group in groups:
            print(f"- {group['GroupName']}")
    else:
        print("- None")


def main():
    iam = get_iam_client()

    resources = discover_iam(iam)

    print_summary(resources)


if __name__ == "__main__":
    main()