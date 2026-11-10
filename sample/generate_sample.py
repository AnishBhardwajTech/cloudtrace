"""Generates sample/cloudtrail-incident.json: a fictional account compromise
written in the real CloudTrail log format, for demos and tests."""
import json, random, uuid
from datetime import datetime, timedelta, timezone

random.seed(7)
ACCOUNT = "111122223333"
ATTACKER = "185.220.101.47"
start = datetime(2026, 10, 14, 6, 0, tzinfo=timezone.utc)
records = []

def ident(user):
    if user == "root":
        return {"type": "Root", "principalId": ACCOUNT, "arn": f"arn:aws:iam::{ACCOUNT}:root", "accountId": ACCOUNT}
    if user.startswith("role:"):
        role, sess = user[5:].split("/")
        return {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{sess}", "accountId": ACCOUNT}
    return {"type": "IAMUser", "userName": user, "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}", "accountId": ACCOUNT}

def ev(t, user, name, source, ip, req=None, resp=None, error=None, extra=None, region="us-east-1"):
    r = {"eventVersion": "1.09", "userIdentity": ident(user), "eventTime": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
         "eventSource": source, "eventName": name, "awsRegion": region, "sourceIPAddress": ip,
         "userAgent": "aws-cli/2.17.0" if source != "signin.amazonaws.com" else "Mozilla/5.0",
         "requestParameters": req, "responseElements": resp, "eventID": str(uuid.UUID(int=random.getrandbits(128))),
         "eventType": "AwsConsoleSignIn" if name == "ConsoleLogin" else "AwsApiCall", "recipientAccountId": ACCOUNT}
    if error:
        r["errorCode"], r["errorMessage"] = error, "User is not authorized to perform this operation"
    if extra:
        r["additionalEventData"] = extra
    records.append(r)

# Normal background activity over the day
for i in range(60):
    t = start + timedelta(minutes=random.randint(0, 16 * 60))
    who, ip = random.choice([("alice", "203.0.113.10"), ("role:ci-deploy/github-actions", "140.82.112.4"), ("bob", "203.0.113.22")])
    name, src = random.choice([("DescribeInstances", "ec2.amazonaws.com"), ("ListBuckets", "s3.amazonaws.com"),
                               ("GetObject", "s3.amazonaws.com"), ("DescribeSecurityGroups", "ec2.amazonaws.com"),
                               ("GetCallerIdentity", "sts.amazonaws.com")])
    ev(t, who, name, src, ip)
ev(start + timedelta(hours=1), "alice", "ConsoleLogin", "signin.amazonaws.com", "203.0.113.10",
   resp={"ConsoleLogin": "Success"}, extra={"MFAUsed": "Yes"})

# 09:12 brute force against dev-jenkins
t = start + timedelta(hours=3, minutes=12)
for i in range(7):
    ev(t + timedelta(seconds=40 * i), "dev-jenkins", "ConsoleLogin", "signin.amazonaws.com", ATTACKER,
       resp={"ConsoleLogin": "Failure"}, error="Failed authentication", extra={"MFAUsed": "No"})
t += timedelta(minutes=6)
ev(t, "dev-jenkins", "ConsoleLogin", "signin.amazonaws.com", ATTACKER, resp={"ConsoleLogin": "Success"}, extra={"MFAUsed": "No"})

# Reconnaissance: lots of denied calls
for i, (name, src) in enumerate([("ListUsers", "iam.amazonaws.com"), ("ListRoles", "iam.amazonaws.com"),
                                 ("GetAccountAuthorizationDetails", "iam.amazonaws.com"), ("ListSecrets", "secretsmanager.amazonaws.com"),
                                 ("DescribeDBInstances", "rds.amazonaws.com"), ("ListKeys", "kms.amazonaws.com")] * 2):
    ev(t + timedelta(minutes=1, seconds=20 * i), "dev-jenkins", name, src, ATTACKER, error="AccessDenied")

# Privilege escalation
t += timedelta(minutes=8)
ev(t, "dev-jenkins", "AttachUserPolicy", "iam.amazonaws.com", ATTACKER,
   req={"userName": "dev-jenkins", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
ev(t + timedelta(minutes=1), "dev-jenkins", "CreateAccessKey", "iam.amazonaws.com", ATTACKER, req={"userName": "backup-admin"},
   resp={"accessKey": {"accessKeyId": "AKIAEXAMPLEBACKUP01", "status": "Active", "userName": "backup-admin"}})
ev(t + timedelta(minutes=2), "dev-jenkins", "CreateLoginProfile", "iam.amazonaws.com", ATTACKER, req={"userName": "backup-admin"})

# Defense evasion + persistence + exposure
t += timedelta(minutes=5)
ev(t, "dev-jenkins", "StopLogging", "cloudtrail.amazonaws.com", ATTACKER, req={"name": "org-trail"})
ev(t + timedelta(minutes=1), "dev-jenkins", "DeleteFlowLogs", "ec2.amazonaws.com", ATTACKER, req={"flowLogId": ["fl-0abc"]})
ev(t + timedelta(minutes=3), "dev-jenkins", "AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", ATTACKER,
   req={"groupId": "sg-0db1", "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}})
ev(t + timedelta(minutes=4), "dev-jenkins", "PutBucketPolicy", "s3.amazonaws.com", ATTACKER,
   req={"bucketName": "acme-customer-exports"})
for i in range(5):
    ev(t + timedelta(minutes=6, seconds=5 * i), "dev-jenkins", "GetObject", "s3.amazonaws.com", ATTACKER,
       req={"bucketName": "acme-customer-exports", "key": f"exports/2026-10/customers-{i}.csv"})

# Responder uses root to contain the incident (also flagged)
ev(start + timedelta(hours=5), "root", "ConsoleLogin", "signin.amazonaws.com", "198.51.100.5",
   resp={"ConsoleLogin": "Success"}, extra={"MFAUsed": "Yes"})
ev(start + timedelta(hours=5, minutes=3), "root", "DeleteAccessKey", "iam.amazonaws.com", "198.51.100.5",
   req={"userName": "backup-admin", "accessKeyId": "AKIAEXAMPLEBACKUP01"})
ev(start + timedelta(hours=5, minutes=5), "root", "StartLogging", "cloudtrail.amazonaws.com", "198.51.100.5", req={"name": "org-trail"})

records.sort(key=lambda r: r["eventTime"])
with open("sample/cloudtrail-incident.json", "w") as f:
    json.dump({"Records": records}, f, indent=1)
print(len(records), "records")
