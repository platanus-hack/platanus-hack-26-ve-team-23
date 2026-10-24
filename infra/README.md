# infra

Infrastructure as code for the off-site archive of sealed batches
(ADR-0026). Optional: a Core without an archive keeps its record locally.

| Directory | What |
|---|---|
| `aws/` | OpenTofu (Terraform-compatible) module: S3 bucket with Object Lock in compliance mode, KMS key, TLS-only policy, lifecycle, and a put-only credential for the Core |
| `localstack/` | LocalStack for the demo, on a separate PC acting as the cloud |

## Demo: LocalStack on another PC

1. On the "cloud" PC (Docker installed):
   ```sh
   cd infra/localstack && docker compose up -d
   ```
2. From any machine with OpenTofu (or Terraform) that reaches that PC:
   ```sh
   cd infra/aws
   tofu init
   tofu apply -var localstack_endpoint=http://<cloud-pc>:4566
   tofu output -json core_environment
   ```
3. Start the Core with those values:
   ```sh
   ARCHIVE_ENDPOINT=http://<cloud-pc>:4566 ARCHIVE_REGION=us-east-1 \
   ARCHIVE_BUCKET=hawk-archive-team23 ARCHIVE_PREFIX=core \
   ARCHIVE_ACCESS_KEY=... ARCHIVE_SECRET_KEY=... just guardian
   ```
4. Every signed head uploads `core/batches/<first>-<last>.bin` and
   `core/heads/<seq>.json`. Check them:
   ```sh
   aws --endpoint-url http://<cloud-pc>:4566 s3 ls s3://hawk-archive-team23/core/ --recursive
   ```
   A delete of a locked object must fail.

## Real AWS

```sh
cd infra/aws && tofu init && tofu apply
```

Uses your AWS credentials; `bucket_name` must be globally unique. On AWS the
put-only credential, TLS-only policy and KMS key are all enforced.

## What this must never do

- Give the Core a credential that can read, list or delete.
- Store anything unsealed: the Core uploads only sealed batches and signed
  heads.
