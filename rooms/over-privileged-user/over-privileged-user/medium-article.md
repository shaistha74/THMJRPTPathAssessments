# "We'll Scope It Later": Auditing and Fixing an Over-Privileged AWS IAM User

*A TryHackMe write-up: Defending AWS › Identity and Access Management › The Over-Privileged User*

---

Every cloud environment has a Carl.

Carl is a new developer who needs AWS access on his first week. The admin is busy, the ticket is urgent, and there's a policy called `AdministratorAccess` sitting right there. So Carl gets full admin, attached directly to his user, with a promise to "scope it later."

Later never comes.

This TryHackMe room puts you in the position of the security analyst who finds Carl's account weeks afterwards. The job: audit the permissions, prove the misconfiguration, replace it with least-privilege access, and design something that stops it happening again. I worked through it entirely with the AWS CLI, and this post walks through what I did, what I found, and a few things I'd do differently in a production environment.

*(Everything below ran in a disposable lab account provisioned by TryHackMe.)*

---

## Why one over-privileged user is a big deal

The room opens with the story of **Code Spaces**, and it's worth retelling because it's the whole argument in one incident.

Code Spaces was a code-hosting company built on AWS. In June 2014 it was hit by a DDoS attack, but the flood of traffic was cover. The attacker already had access to the company's AWS console and demanded a ransom. When staff changed passwords to lock them out, it was too late: the attacker had quietly created backup IAM logins. Seeing the recovery attempt, they started deleting things: EBS snapshots, S3 buckets, AMIs, EC2 instances.

Within about 12 hours, production data and most of the backups were gone. Code Spaces told its customers it could no longer operate and shut down for good.

The root cause wasn't a sophisticated exploit. It was a single identity that could do *anything* in the account, with no guardrails around it: no permission boundaries, no explicit denies on destructive actions, no MFA on sensitive operations, and no alerting when IAM changed.

Keep that in mind when you look at Carl's policy.

---

## Part 1: The audit

I started by saving the account ID to a variable so the ARNs stay readable:

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
```

Then listed the users:

```bash
aws iam list-users \
  --query "Users[*].[UserName,CreateDate]" \
  --output table
```

*[Screenshot: list-users output]*

Three identities: the lab operator, `carl-the-dev` and `ci-deployer`.

### Carl's policy

```bash
aws iam list-attached-user-policies --user-name carl-the-dev

aws iam get-policy-version \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/AWS201-DevCarlAdmin \
  --version-id v1
```

*[Screenshot: policy document]*

The document contains one statement:

```json
{
  "Action": "*",
  "Resource": "*",
  "Effect": "Allow",
  "Sid": "OverPrivilegedAccess"
}
```

Any action, on any resource. That's full admin.

A quick refresher on how IAM evaluates a request, because it explains why this is so dangerous. An explicit **Deny** always wins. If there's no Deny, an explicit **Allow** grants access. Anything left over is an **implicit Deny**. Carl has a blanket Allow and no Deny anywhere, so there is nothing between his credentials and every API in the account.

### The tags gave it away

```bash
aws iam list-user-tags --user-name carl-the-dev
```

*[Screenshot: user tags]*

Two tags stood out: `Role: Developer`, and a `Note` that literally says *"Temporary admin access - needs to be scoped down."* I like this detail because it's so realistic. The intent was documented; the follow-through wasn't. In a real audit, a tag like that is useful evidence of the gap between intended and actual access.

### Inline policies and groups

Two more checks that are easy to skip:

```bash
aws iam list-user-policies --user-name carl-the-dev     # inline policies
aws iam list-groups-for-user --user-name carl-the-dev   # group membership
```

Inline policies don't show up in the attached-policy list, so you always check separately. In this case there were none. Carl also wasn't in any group, meaning his access was managed on the user directly. That works for one person and becomes unmanageable at fifty.

### What good looks like

For contrast, the other user:

```bash
aws iam list-groups-for-user --user-name ci-deployer
aws iam list-attached-user-policies --user-name ci-deployer
```

*[Screenshot: ci-deployer]*

`ci-deployer` belongs to a `Deployers` group and has nothing attached directly to the user. All of its access comes through the group. That's the model Carl should be on.

### The verdict

If Carl's credentials leaked, an attacker could delete any S3 bucket, terminate EC2 instances, tamper with or delete CloudTrail logs, wipe EBS snapshots and AMIs, open up security groups, and read every secret in Secrets Manager. In other words, Code Spaces all over again.

---

## Part 2: Scoping Carl down

The remediation plan was simple: work out what Carl actually needs, remove the admin policy, write a scoped policy, attach it via a group, and verify.

Carl's real requirements as a developer:

- Read and list objects in the `thm-app-data-<account-id>` bucket
- Describe EC2 instances
- Read CloudWatch Logs for debugging

That's a long way from `*:*`.

### Remove the admin policy

```bash
aws iam detach-user-policy \
  --user-name carl-the-dev \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/AWS201-DevCarlAdmin
```

*[Screenshot: detach and verify]*

At this point Carl has no permissions at all. Every request hits the implicit deny.

### Write the scoped policy

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

*[Screenshot: create-policy]*

A few details worth noticing. The S3 statement needs *two* ARNs, because `ListBucket` acts on the bucket while `GetObject` acts on the objects inside it (`bucket/*`). The EC2 statement uses `"Resource": "*"`, which looks alarming but is expected: `Describe*` calls don't support resource-level restrictions, and they're read-only. The CloudWatch Logs statement is limited to one log-group prefix in one region rather than the whole account.

### Attach it through a group

```bash
aws iam create-group --group-name Developers

aws iam attach-group-policy \
  --group-name Developers \
  --policy-arn "arn:aws:iam::${ACCOUNT_ID}:policy/AppAccess"

aws iam add-user-to-group --group-name Developers --user-name carl-the-dev
```

*[Screenshot: group membership and group policy]*

### Prove it works, and prove it doesn't

The IAM Policy Simulator lets you test a policy without touching real resources. First the actions Carl should have:

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

Both came back **allowed**. Then the more interesting test, an action he should *not* have:

```bash
aws iam simulate-custom-policy \
  --policy-input-list "$POLICY_DOC" \
  --action-names "s3:DeleteBucket" \
  --resource-arns "arn:aws:s3:::thm-app-data-${ACCOUNT_ID}" \
  --query "EvaluationResults[*].[EvalActionName,EvalDecision]" \
  --output table
```

*[Screenshot: simulation results]*

`s3:DeleteBucket` → **implicitDeny**. Nothing in the policy mentions it, so it falls through to the default deny. I'd argue this negative test matters more than the positive one: it's the evidence that the new policy doesn't grant more than you meant it to.

---

## Part 3: Building it securely from the start

Fixing Carl is reactive. The last part of the room is about not needing to.

**Group-based access.** Define job functions as groups and manage people through membership. A new accountant joins, they go in the `Accounting` group. Someone leaves, they come out. No hand-crafted per-user policies to forget about.

**Least privilege from requirements.** The Accounting team needs read/write on the app bucket, so their policy grants `GetObject`, `PutObject` and `ListBucket` on that bucket and nothing else.

**Permissions boundaries as guardrails.** A permissions boundary is a managed policy that caps the *maximum* permissions a user or role can ever have. Even if someone later attaches an over-generous policy, the identity can only do what both its own policies *and* the boundary allow. It's the control that would have limited the damage at Code Spaces.

```bash
aws iam put-user-permissions-boundary \
  --user-name carl-the-dev \
  --permissions-boundary "arn:aws:iam::${ACCOUNT_ID}:policy/CarlBoundary"
```

---

## What I'd tighten in a real environment

The lab is deliberately simplified, which is right for teaching. A few things I'd flag if this were a real review:

**The lab's boundary locks Carl out entirely.** Effective permissions are the *intersection* of identity policies and the boundary. The room's `CarlBoundary` contains only a Deny statement and no Allow, so the intersection is empty. Carl doesn't just lose S3; he loses his EC2 and CloudWatch access too. A production boundary is normally an Allow listing the maximum permitted actions, plus Denies for things that must never happen (IAM changes, deleting buckets, stopping CloudTrail).

**Simulate the principal, not just the policy.** `simulate-custom-policy` tests a policy document in isolation. `simulate-principal-policy` tests what's actually attached to Carl, including group policies, and you can pass in the boundary to see the combined result.

**Match the ARN to the action.** The lab simulates `GetObject` against the bucket ARN. Since `GetObject` acts on objects, a more accurate test targets `bucket/*`.

**Delete the old policy.** Detaching `AWS201-DevCarlAdmin` isn't the same as removing it. It's still sitting there for anyone with IAM rights to re-attach. Check nothing else uses it, then delete it.

**The rest of the Code Spaces checklist.** MFA for console users, short-lived credentials for humans (IAM Identity Center rather than long-lived access keys), CloudTrail logs stored where account admins can't delete them, alerts on IAM changes, and IAM Access Analyzer to catch permissions nobody uses.

---

## Key takeaways

- "Temporary" admin access is permanent until someone owns removing it.
- Attach permissions to groups or roles, never directly to users.
- Build policies from requirements: specific actions on specific resources.
- Permissions boundaries set the ceiling, and they intersect with identity policies.
- Test that the right things are allowed, and that the wrong things are denied.
- Audit all of it regularly: managed policies, inline policies, groups, and tags.

The most useful thing about this room is how ordinary the misconfiguration is. Nobody was careless in an unusual way; an admin was just busy. That's precisely why it's worth auditing for.

---

*Full commands, screenshots and a CLI cheat sheet are on my GitHub: [github.com/shaistha74](https://github.com/shaistha74)*

*I'm Shaistha, a cybersecurity professional focused on IAM and cloud security. I write about hands-on labs and security practice here and on [LinkedIn](https://www.linkedin.com/in/shaistha-khanum-33b396a4/).*

*#AWS #CloudSecurity #IAM #TryHackMe #Cybersecurity #LeastPrivilege*
