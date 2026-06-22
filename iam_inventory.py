import boto3
import json
import csv
import io
import os
import time
from datetime import datetime, timezone

def list_users(iam_client):
    users = []
    paginator = iam_client.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page['Users']:
            users.append({
                'UserName': user['UserName'],
                'UserId':   user['UserId'],
                'Arn':      user['Arn'],
                'Created':  str(user['CreateDate'])
            })
    return users



def list_roles(iam_client):
    roles = []
    paginator = iam_client.get_paginator('list_roles')
    for page in paginator.paginate():
        for role in page['Roles']:
            roles.append({
                'RoleName': role['RoleName'],
                'RoleId':   role['RoleId'],
                'Arn':      role['Arn'],
                'Created':  str(role['CreateDate'])
            })
    return roles

def list_attached_policies_with_documents(iam_client) -> list:
    """
    Collect every IAM managed policy (AWS-managed + customer-managed)
    that is attached to at least one user, role, or group.
    For each policy, also fetch the active policy document (the JSON
    that contains Action/Resource statements).

    Returns a list of dicts:
    [
      {
        'PolicyName':       'AdministratorAccess',
        'PolicyId':         'ANPA...',
        'Arn':              'arn:aws:iam::aws:policy/AdministratorAccess',
        'AttachedTo':       2,
        'DefaultVersionId': 'v1',
        'Document':         {   ← the actual policy JSON, already URL-decoded
            'Version': '2012-10-17',
            'Statement': [
                {'Effect': 'Allow', 'Action': '*', 'Resource': '*'}
            ]
        }
      },
      ...
    ]
    """
    policies = []

    # Scope='All' means both AWS-managed and customer-managed policies.
    # OnlyAttached=True skips policies nobody is using — no need to analyse them.
    paginator = iam_client.get_paginator('list_policies')
    for page in paginator.paginate(Scope='All', OnlyAttached=True):
        for policy in page['Policies']:

            # Fetch the active version document for this policy.
            # 'DefaultVersionId' is the version currently in effect, e.g. 'v1' or 'v3'.
            # get_policy_version() returns the document URL-encoded — boto3 decodes it for us.
            version_response = iam_client.get_policy_version(
                PolicyArn=policy['Arn'],
                VersionId=policy['DefaultVersionId']
            )

            # The document lives here in the response:
            # response['PolicyVersion']['Document'] → dict with 'Version' and 'Statement'
            document = version_response['PolicyVersion']['Document']

            policies.append({
                'PolicyName':       policy['PolicyName'],
                'PolicyId':         policy['PolicyId'],
                'Arn':              policy['Arn'],
                'AttachedTo':       policy['AttachmentCount'],
                'DefaultVersionId': policy['DefaultVersionId'],
                'Document':         document,
            })

    return policies


def get_credential_report(iam_client) -> list:
    """
    Fetch the IAM credential report and return it as a list of dicts.

    AWS may need a moment to generate the report if it doesn't exist yet.
    We call generate_credential_report() first, then get_credential_report()
    once it's ready.

    The report is returned as CSV bytes by AWS. We decode it and parse it
    into a list of dicts — one dict per IAM user row.

    Returns:
    [
      {
        'user':                        'alice',
        'arn':                         'arn:aws:iam::123456789012:user/alice',
        'password_enabled':            'true',    ← string, not bool
        'mfa_active':                  'false',   ← string, not bool
        'access_key_1_active':         'true',
        'access_key_1_last_used_date': '2024-01-15T10:00:00+00:00',
        'access_key_2_active':         'false',
        ...
      },
      ...
    ]

    Note: 'password_enabled' is 'not_supported' for the root account row.
    The root account row has user == '<root_account>' — handle separately.
    """

    # Step 1: Ask AWS to generate a fresh credential report.
    # This is async — AWS may return state 'STARTED' or 'INPROGRESS' before 'COMPLETE'.
    while True:
        response = iam_client.generate_credential_report()
        if response['State'] == 'COMPLETE':
            break
        # Report not ready yet — wait briefly and retry
        time.sleep(2)

    # Step 2: Download the report.
    # Content is a bytes object containing a CSV.
    report_response = iam_client.get_credential_report()
    csv_bytes = report_response['Content']             # bytes
    csv_text  = csv_bytes.decode('utf-8')              # decode to string

    # Step 3: Parse the CSV into a list of dicts.
    # csv.DictReader uses the first row as column headers automatically.
    reader = csv.DictReader(io.StringIO(csv_text))
    return list(reader)


def get_iam_inventory(role_arn):
    # Step 1: Assume the read-only role
    sts = boto3.client('sts')
    creds = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName='iam-inventory-session'
    )['Credentials']

    # Step 2: Build an IAM client using those temporary credentials
    iam = boto3.client(
        'iam',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken']
    )

    # Step 3: Run all three functions
    inventory = {
        'generated_at': str(datetime.now(timezone.utc)),
        'users':        list_users(iam),
        'roles':        list_roles(iam),
        'policies':     list_attached_policies_with_documents(iam),
	'credential_report': get_credential_report(iam)
    }

    # Step 4: Print a summary to the terminal
    print(f"Users:    {len(inventory['users'])}")
    print(f"Roles:    {len(inventory['roles'])}")
    print(f"Policies: {len(inventory['policies'])}")
    print(f"Credential report: {len(inventory['credential_report'])} rows")	

    return inventory


def save_json(inventory):
    filename = f"iam_inventory_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(inventory, f, indent=2, default=str)
    print(f"Saved: {filename}")

def save_csv(inventory):
    import csv
    for kind in ['users', 'roles', 'policies']:
        rows = inventory[kind]
        if not rows:
            continue
        with open(f'iam_{kind}.csv', 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        print(f"Saved: iam_{kind}.csv")


def collect_inventory(role_arn: str = os.environ.get('AUDIT_ROLE_ARN', '')) -> dict:
    """
    Public entry point for test_run_analyzer.py.

    Calls get_iam_inventory(), fetches the account ID via STS,
    and returns a dict with the key names analyzer.py expects:

    {
        'account_id':   "178701499493",
        'generated_at': "2025-...",
        'iam_users':    [ {UserName, UserId, Arn, Created}, ... ],
        'iam_roles':    [ {RoleName, RoleId, Arn, Created}, ... ],
        'iam_policies': [ {PolicyName, PolicyId, Arn, AttachedTo}, ... ],
    }
    """
    # Step 1: Assume the audit role and collect raw inventory
    raw = get_iam_inventory(role_arn)

    # Step 2: Fetch account ID using the *local* credentials (before role assumption).
    # get_caller_identity() requires zero IAM permissions — it always works.
    sts = boto3.client('sts')
    account_id = sts.get_caller_identity()['Account']

    # Step 3: Rename keys to the canonical names analyzer.py expects.
    # We keep 'generated_at' as-is since it's already correct.
    return {
        'account_id':   account_id,
        'generated_at': raw['generated_at'],
        'iam_users':    raw['users'],       # 'users' → 'iam_users'
        'iam_roles':    raw['roles'],       # 'roles' → 'iam_roles'
        'iam_policies': raw['policies'],    # 'policies' → 'iam_policies'
	'credential_report': raw['credential_report'], # 'credential_report' -> iam_credential_report',
    }


if __name__ == '__main__':
    ROLE_ARN = os.environ.get('AUDIT_ROLE_ARN')

    inventory = get_iam_inventory(ROLE_ARN)
    save_json(inventory)
    save_csv(inventory)
