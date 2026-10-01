# TryHackMe — The Over-Privileged User

**Path:** Defending AWS › Identity and Access Management
**Room:** The Over-Privileged User (≈30 min)
**Focus:** AWS IAM auditing, least privilege, group-based access, permissions boundaries, IAM Policy Simulator
**Tooling:** AWS CLI (from the TryHackMe AttackBox), IAM Policy Simulator

> This is a write-up of a guided TryHackMe lab run in a temporary AWS account provisioned by the platform. Account IDs shown in screenshots belong to that disposable lab environment.

---

## Contents

1. [Scenario](#scenario)
2. [Why it matters: Code Spaces (2014)](#why-it-matters-code-spaces-2014)
3. [Identification: auditing the user](#identification-auditing-the-user)
4. [Remediation: scoping Carl down](#remediation-scoping-carl-down)
5. [Building it securely](#building-it-securely)
6. [Analyst notes: what I'd tighten in production](#analyst-notes-what-id-tighten-in-production)
7. [Key takeaways](#key-takeaways)
8. [Command cheat sheet](#command-cheat-sheet)
9. [References](#references)

---

## Scenario

Carl, a new developer, needed AWS access. A busy admin attached full administrator rights directly to his IAM user and promised to "scope it later." Weeks passed and nobody did.

My role in the lab: act as the security analyst who audits IAM permissions, confirms the misconfiguration, remediates it with a least-privilege design, and validates the fix.

---

## Why it matters: Code Spaces (2014)

The room opens with the Code Spaces incident, a textbook example of what an over-privileged identity enables.

Code Spaces was a code-hosting company running on AWS. On 17 June 2014 it came under a DDoS attack, but that was a distraction: the attacker already had access to the AWS management console and demanded a ransom. When staff tried to regain control by changing passwords, the attacker had already created backdoor IAM logins, and responded by deleting EBS snapshots, S3 buckets, AMIs and EC2 instances. Within roughly 12 hours, production and most backups were gone, and the company announced it would shut down permanently.

**Root cause:** a compromised identity with unrestricted administrative access to the whole account. There were no permission boundaries, no explicit denies on destructive actions, no MFA on sensitive operations, and no alerting on IAM changes.

That is exactly the position Carl's account puts this environment in.

---

## Identification: auditing the user

All commands were run with the AWS CLI. I stored the account ID in a variable first to keep ARNs readable:

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo $ACCOUNT_ID
```

### 1. Enumerate IAM users

```bash
aws iam list-users \
  --query "Users[*].[UserName,CreateDate]" \
  --output table
```

![List users](screenshots/01-list-users.png)

Three identities: the lab operator user, `carl-the-dev` and `ci-deployer`.

### 2. Check Carl's managed policies and read the policy document

```bash
aws iam list-attached-user-policies --user-name carl-the-dev

aws iam get-policy-version \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/AWS201-DevCarlAdmin \
  --version-id v1
```

![Carl's attached policy and document](screenshots/02-carl-policy.png)

```json
{
  "Action": "*",
  "Resource": "*",
  "Effect": "Allow",
  "Sid": "OverPrivilegedAccess"
}
```

**Finding:** `Action: "*"` on `Resource: "*"` is full administrative access to every service and resource in the account, attached directly to a human user.

Reminder of how IAM evaluates a request: an **explicit Deny** always wins, then an **explicit Allow** grants access, and anything not allowed falls through to an **implicit Deny**. With a blanket Allow and no Denies anywhere, nothing stops Carl.

### 3. Read the user's tags for context

```bash
aws iam list-user-tags --user-name carl-the-dev
```

![Carl's tags](screenshots/03-carl-tags.png)

The tags tell the story on their own: `Role = Developer`, and a `Note` reading *"Temporary admin access - needs to be scoped down"*. Tags like this are useful audit evidence, since they document intended access versus actual access.

### 4. Check for inline policies and group membership

```bash
aws iam list-user-policies --user-name carl-the-dev     # inline policies
aws iam list-groups-for-user --user-name carl-the-dev   # group membership
```

Both returned empty lists. Inline policies are worth checking every time because they don't appear in `list-attached-user-policies`. No groups means permissions are managed per-user, which doesn't scale and is easy to lose track of.

### 5. Compare with a well-configured user: `ci-deployer`

```bash
aws iam list-groups-for-user --user-name ci-deployer
aws iam list-attached-user-policies --user-name ci-deployer
```

![ci-deployer groups and policies](screenshots/04-ci-deployer.png)

`ci-deployer` is a member of the `Deployers` group and has no policies attached directly to the user. Access comes from the group, which is the pattern Carl should follow.

### Findings summary

| # | Finding | Risk | Evidence |
|---|---------|------|----------|
| F1 | `AWS201-DevCarlAdmin` grants `*:*` to a developer | Critical | Policy document v1 |
| F2 | Admin policy attached directly to a human user | High | `list-attached-user-policies` |
| F3 | User not in any group; access managed ad hoc | Medium | `list-groups-for-user` |
| F4 | "Temporary" access never reviewed or revoked | Medium | `Note` tag on user |

With F1 alone, compromised credentials for Carl would let an attacker delete any S3 bucket, terminate EC2 instances, tamper with or delete CloudTrail logs, delete EBS snapshots and AMIs, change security groups and network controls, and read any secret in Secrets Manager. That is the Code Spaces scenario.

---

## Remediation: scoping Carl down

Approach:

1. Understand what Carl actually needs.
2. Remove the over-permissive policy.
3. Create a scoped, least-privilege policy.
4. Attach it through a group, not the user.
5. Verify.

### Requirements

As a developer, Carl needs to:

- Read and list objects in the `thm-app-data-<account-id>` S3 bucket
- Describe EC2 instances
- Read CloudWatch Logs for debugging

Everything else is out of scope.

### 1. Detach the admin policy

```bash
aws iam detach-user-policy \
  --user-name carl-the-dev \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/AWS201-DevCarlAdmin

aws iam list-attached-user-policies --user-name carl-the-dev
```

![Detach admin policy](screenshots/05-detach-policy.png)

Carl now has no policies, so every request ends in an implicit deny until the scoped access is in place.

### 2. Create the scoped policy (`AppAccess`)

```bash
aws iam create-policy \
  --policy-name AppAccess \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "S3AppBucketReadOnly",
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:ListBucket"],
        "Resource": [
          "arn:aws:s3:::thm-app-data-'"$ACCOUNT_ID"'",
          "arn:aws:s3:::thm-app-data-'"$ACCOUNT_ID"'/*"
        ]
      },
      {
        "Sid": "EC2DescribeOnly",
        "Effect": "Allow",
        "Action": [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs"
        ],
        "Resource": "*"
      },
      {
        "Sid": "CloudWatchLogsReadOnly",
        "Effect": "Allow",
        "Action": [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:GetLogEvents",
          "logs:FilterLogEvents"
        ],
        "Resource": "arn:aws:logs:us-east-1:'"$ACCOUNT_ID"':log-group:/aws/app/*"
      }
    ]
  }'
```

![Create AppAccess policy](screenshots/06-create-appaccess.png)

Design notes:

- **S3:** two resource ARNs are needed. `s3:ListBucket` applies to the bucket ARN; `s3:GetObject` applies to the object ARN (`bucket/*`).
- **EC2:** `Describe*` actions don't support resource-level restrictions, so `"Resource": "*"` is expected here and is read-only.
- **CloudWatch Logs:** scoped to the `/aws/app/` log group prefix in one region rather than every log group in the account.

### 3. Attach via a group

```bash
aws iam create-group --group-name Developers

aws iam attach-group-policy \
  --group-name Developers \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/AppAccess"

aws iam add-user-to-group --group-name Developers --user-name carl-the-dev
```

![Attach policy to group](screenshots/07-attach-group-policy.png)

### 4. Verify

```bash
aws iam list-groups-for-user --user-name carl-the-dev
aws iam list-attached-group-policies --group-name Developers
```

![Carl in Developers group](screenshots/08-verify-group.png)
![Developers group policy](screenshots/09-verify-group-policy.png)

### 5. Validate with the IAM Policy Simulator

```bash
POLICY_DOC=$(aws iam get-policy-version \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/AppAccess" \
  --version-id v1 \
  --query 'PolicyVersion.Document' --output json)

aws iam simulate-custom-policy \
  --policy-input-list "$POLICY_DOC" \
  --action-names "s3:ListBucket" "s3:GetObject" \
  --resource-arns "arn:aws:s3:::thm-app-data-${ACCOUNT_ID}" \
  --query "EvaluationResults[*].[EvalActionName,EvalDecision]" \
  --output table
```

Then a negative test with a destructive action:

```bash
aws iam simulate-custom-policy \
  --policy-input-list "$POLICY_DOC" \
  --action-names "s3:DeleteBucket" \
  --resource-arns "arn:aws:s3:::thm-app-data-${ACCOUNT_ID}" \
  --query "EvaluationResults[*].[EvalActionName,EvalDecision]" \
  --output table
```

![Policy simulation results](screenshots/10-policy-simulation.png)

| Action | Result |
|--------|--------|
| `s3:ListBucket` | allowed |
| `s3:GetObject` | allowed |
| `s3:DeleteBucket` | **implicitDeny** |

The required actions are allowed, and `DeleteBucket` is refused. Because nothing in `AppAccess` mentions it, the request falls through to an implicit deny. Negative testing like this is as important as positive testing: it proves the policy doesn't grant more than intended.

---

## Building it securely

Fixing Carl is reactive. The room then covers three principles for preventing the problem in the first place.

### 1. Group-based permission model

Define job functions as groups and manage access through membership. Joiners get added to a group; leavers and movers get removed. No per-user policy sprawl.

```bash
aws iam create-group --group-name Accounting
```

### 2. Least-privilege policies

The Accounting team needs read/write on the app bucket and nothing more:

```bash
aws iam create-policy \
  --policy-name AccountingPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "S3AppAccess",
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
        "Resource": [
          "arn:aws:s3:::thm-app-data-'"$ACCOUNT_ID"'",
          "arn:aws:s3:::thm-app-data-'"$ACCOUNT_ID"'/*"
        ]
      }
    ]
  }'

aws iam attach-group-policy \
  --group-name Accounting \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/AccountingPolicy"
```

<!-- Screenshot: add screenshots/11-accounting-group.png -->

### 3. Permissions boundaries as guardrails

A **permissions boundary** is a managed policy that sets the *maximum* permissions an IAM user or role can have. Even if someone later attaches a more permissive policy, the identity can only do what both the identity policies **and** the boundary allow.

```bash
aws iam create-policy \
  --policy-name CarlBoundary \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyCarlActions",
        "Effect": "Deny",
        "Action": [
          "s3:GetObject", "s3:PutObject", "s3:ListBucket",
          "s3:DeleteBucket", "s3:ListAllMyBuckets"
        ],
        "Resource": "*"
      }
    ]
  }'

aws iam put-user-permissions-boundary \
  --user-name carl-the-dev \
  --permissions-boundary "arn:aws:iam::${ACCOUNT_ID}:policy/CarlBoundary"

aws iam get-user --user-name carl-the-dev --query "User.PermissionsBoundary"
```

<!-- Screenshot: add screenshots/12-permissions-boundary.png -->

See the analyst notes below for an important caveat about how this particular boundary behaves.

---

## Analyst notes: what I'd tighten in production

The lab is intentionally simplified. These are the points I'd raise if this were a real review.

**1. A Deny-only permissions boundary locks the user out of everything.**
Effective permissions are the *intersection* of identity-based policies and the boundary. The lab's `CarlBoundary` contains only a `Deny` statement and no `Allow`, so the intersection is empty: Carl loses S3 access **and** his EC2 and CloudWatch Logs access too. A boundary is normally written as an Allow for the maximum permitted set, optionally with Denies for actions that must never be possible:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "MaxDeveloperPermissions",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket", "ec2:Describe*", "logs:Describe*", "logs:GetLogEvents", "logs:FilterLogEvents"],
      "Resource": "*"
    },
    {
      "Sid": "NeverAllowed",
      "Effect": "Deny",
      "Action": ["iam:*", "s3:DeleteBucket", "cloudtrail:StopLogging", "cloudtrail:DeleteTrail"],
      "Resource": "*"
    }
  ]
}
```

**2. Test the principal, not just the policy document.**
`simulate-custom-policy` evaluates a policy in isolation. `simulate-principal-policy` evaluates what's actually attached to Carl, including group policies, and the boundary can be supplied with `--permissions-boundary-policy-input-list` to test the combined effect:

```bash
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::${ACCOUNT_ID}:user/carl-the-dev" \
  --action-names "s3:GetObject" \
  --resource-arns "arn:aws:s3:::thm-app-data-${ACCOUNT_ID}/*" \
  --query "EvaluationResults[*].[EvalActionName,EvalDecision]" \
  --output table
```

**3. Match resource ARNs to the action being simulated.**
The lab simulates `s3:GetObject` against the bucket ARN. `GetObject` acts on objects, so a more accurate test uses `arn:aws:s3:::thm-app-data-<id>/*`, as above.

**4. Delete the old admin policy, don't just detach it.**
A detached `AWS201-DevCarlAdmin` still exists and can be re-attached by anyone with IAM permissions. Confirm nothing else uses it, then remove it:

```bash
aws iam list-entities-for-policy --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/AWS201-DevCarlAdmin
aws iam delete-policy --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/AWS201-DevCarlAdmin
```

**5. Controls outside the room's scope that would close the Code Spaces gap:**
MFA enforcement for console users, rotating or removing long-lived access keys (or moving humans to IAM Identity Center with short-lived credentials), CloudTrail with log file validation stored somewhere the account's own admins can't delete, alerts on IAM changes via EventBridge or GuardDuty, and IAM Access Analyzer to surface unused permissions over time.

---

## Key takeaways

- Never give human users standing administrative access. "Temporary" access needs an owner and an expiry.
- Attach permissions to groups (or roles), not individual users.
- Write policies from requirements: specific actions on specific resources.
- Use permissions boundaries as guardrails, and remember they intersect with identity policies.
- Validate with the Policy Simulator, including negative tests for actions that should be denied.
- Audit regularly: managed policies, inline policies, group membership, and tags.

---

## Command cheat sheet

| Purpose | Command |
|---------|---------|
| Current account ID | `aws sts get-caller-identity --query Account --output text` |
| List users | `aws iam list-users` |
| Managed policies on a user | `aws iam list-attached-user-policies --user-name <user>` |
| Inline policies on a user | `aws iam list-user-policies --user-name <user>` |
| Read a policy document | `aws iam get-policy-version --policy-arn <arn> --version-id v1` |
| User's groups | `aws iam list-groups-for-user --user-name <user>` |
| User tags | `aws iam list-user-tags --user-name <user>` |
| Detach from user | `aws iam detach-user-policy --user-name <user> --policy-arn <arn>` |
| Create group | `aws iam create-group --group-name <group>` |
| Attach to group | `aws iam attach-group-policy --group-name <group> --policy-arn <arn>` |
| Add user to group | `aws iam add-user-to-group --group-name <group> --user-name <user>` |
| Group policies | `aws iam list-attached-group-policies --group-name <group>` |
| Set boundary | `aws iam put-user-permissions-boundary --user-name <user> --permissions-boundary <arn>` |
| Simulate a policy | `aws iam simulate-custom-policy --policy-input-list <doc> --action-names <actions> --resource-arns <arns>` |
| Simulate a principal | `aws iam simulate-principal-policy --policy-source-arn <arn> --action-names <actions>` |

---

<details>
<summary>Room question answers (spoilers)</summary>

| Question | Answer |
|----------|--------|
| Initial attack type used against Code Spaces | DDoS |
| Misconfiguration that enabled the damage | Unrestricted administrative access on the compromised identity |
| Carl's role | Developer |
| ci-deployer's group | Deployers |
| S3 actions allowed in AppAccess | GetObject,ListBucket |
| Simulation result for `s3:DeleteBucket` | implicitDeny |
| Mechanism that caps an identity's maximum permissions | Permissions boundary |

</details>

---

## References

- TryHackMe — Defending AWS path, Identity and Access Management module
- Code Spaces incident: https://www.breaches.cloud/incidents/codespaces/
- AWS docs — Policy evaluation logic: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
- AWS docs — Permissions boundaries: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
- AWS docs — IAM Policy Simulator: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html

---

*Written by Shaistha Khanum · [LinkedIn](https://www.linkedin.com/in/shaistha-khanum-33b396a4/) · [Medium](https://medium.com/@shaika74) · [GitHub](https://github.com/shaistha74)*
