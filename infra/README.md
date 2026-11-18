# AWS Level 2 reference scaffold

This directory is a Terraform reference only. It does not contain credentials and has not
been applied. It uses ECS/Fargate as the proportionate compute choice (see
`../docs/DECISIONS.md`).

## Prerequisites

- AWS account and organization-specific IAM privileges for VPC, ECS, RDS, S3, IAM,
  KMS, Secrets Manager, CloudWatch, ECR, Elastic Load Balancing, and Budgets
- Terraform >= 1.5
- An existing or separately configured remote state backend
- A globally unique S3 bucket name per environment
- An immutable ECR image digest for the API
- DNS, a public TLS certificate/ACM certificate, and an ALB HTTPS listener
- A database migration and secret-injection design
- Budget notification recipients; keep the list empty until approved

## Structure

Environment separation is represented by distinct `dev`, `staging`, and `prod` tfvars,
CIDR ranges, tags, resource names, and RDS settings. State must be isolated per
environment using separate backend keys/workspaces.

## Local validation

```bash
terraform -chdir=infra fmt -check -recursive
terraform -chdir=infra init -backend=false
terraform -chdir=infra validate
terraform -chdir=infra plan -var-file=environments/dev.tfvars
```

The plan command requires AWS provider credentials or a credential-free provider plan
only if configured; this repository does not provide or use credentials. Terraform
validation does not prove an AWS deployment is correct or safe.

## Exact deferred items

- Remote Terraform state, locking, state encryption policy, and backend bootstrap
- NAT topology hardening, VPC endpoints, flow logs, and private DNS
- ACM certificate, Route 53/DNS, HTTPS listener, WAF, and public ingress policy
- ECS service registration, autoscaling, deployment circuit breakers, rollback automation
- Application database URL and password injection, migration job, PostgreSQL RLS setup
- ECR repository lifecycle, image scanning, signing, promotion, and digest pinning
- S3 lifecycle/replication, retention governance policy approval, and access logs
- KMS key policies, cross-account access, and alias policies
- CloudWatch alarm SNS/paging actions, dashboards, SLOs, and log sampling
- Budget thresholds and approved email/SNS subscribers
- AWS Config, GuardDuty, Security Hub, CloudTrail organization trail, and audit storage
- EKS and Kubernetes manifests
- Multi-region active/passive or backup replication
