import boto3
from botocore.exceptions import ClientError

# AWS clients
s3 = boto3.client('s3')
iam = boto3.client('iam')
ec2 = boto3.client('ec2')

# -----------------------------
# 1. Public S3 Buckets
# -----------------------------
def check_public_s3():
    findings = []
    buckets = s3.list_buckets().get('Buckets', [])

    for b in buckets:
        name = b['Name']
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get('Grants', []):
                if 'AllUsers' in str(grant):
                    findings.append(f"Public S3 bucket detected: {name}")
        except ClientError:
            continue

    return findings

# -----------------------------
# 2. MFA Check
# -----------------------------
def check_mfa_missing():
    findings = []
    users = iam.list_users().get('Users', [])

    for u in users:
        mfa = iam.list_mfa_devices(UserName=u['UserName'])
        if len(mfa.get('MFADevices', [])) == 0:
            findings.append(f"MFA missing for IAM user: {u['UserName']}")

    return findings

# -----------------------------
# 3. Access Keys
# -----------------------------
def check_access_keys():
    findings = []
    users = iam.list_users().get('Users', [])

    for u in users:
        keys = iam.list_access_keys(UserName=u['UserName']).get('AccessKeyMetadata', [])
        for k in keys:
            findings.append(f"Access key found for {u['UserName']}: {k['AccessKeyId']}")

    return findings

# -----------------------------
# 4. Security Groups Open 0.0.0.0/0
# -----------------------------
def check_open_sgs():
    findings = []
    groups = ec2.describe_security_groups().get('SecurityGroups', [])

    for g in groups:
        for perm in g.get('IpPermissions', []):
            for ip in perm.get('IpRanges', []):
                if ip.get('CidrIp') == '0.0.0.0/0':
                    findings.append(f"Open Security Group: {g['GroupName']}")

    return findings

# -----------------------------
# 5. EC2 Public IPs
# -----------------------------
def check_ec2_public():
    findings = []
    reservations = ec2.describe_instances().get('Reservations', [])

    for r in reservations:
        for i in r.get('Instances', []):
            if 'PublicIpAddress' in i:
                findings.append(f"Public EC2 instance: {i['InstanceId']}")

    return findings

# -----------------------------
# 6. Root Account Warning
# -----------------------------
def check_root_usage():
    return ["Ensure root account has MFA enabled and no access keys"]

# -----------------------------
# 7. Password Policy
# -----------------------------
def check_password_policy():
    findings = []
    try:
        policy = iam.get_account_password_policy()['PasswordPolicy']
        if policy.get('MinimumPasswordLength', 0) < 12:
            findings.append("Weak IAM password policy (length < 12)")
    except ClientError:
        findings.append("No IAM password policy configured")

    return findings

# -----------------------------
# MAIN SCANNER
# -----------------------------
def run_full_scan():
    return {
        "S3": check_public_s3(),
        "IAM MFA": check_mfa_missing(),
        "IAM Keys": check_access_keys(),
        "Security Groups": check_open_sgs(),
        "EC2": check_ec2_public(),
        "Root Account": check_root_usage(),
        "Password Policy": check_password_policy()
    }