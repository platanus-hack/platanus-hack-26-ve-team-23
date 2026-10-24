# infra

Optional cloud features (ADR-0026, ADR-0027). **HAWK runs 100% offline by
default**; any owner, personal or company, can switch these on:

- **Off-site archive** of sealed batches and signed heads, in a bucket with
  Object Lock in compliance mode (nobody can delete or overwrite during the
  retention period). Enabled on the Core with `ARCHIVE_*`.
- **Remote configuration as code**: the next signed configuration published
  as `config/latest.json`; the Core applies it only if it is the next link of
  its configuration chain and signed by the signer the owner authorised.
  Enabled with `CONFIG_REMOTE=1` and `CONFIG_*`.

| Directory | What |
|---|---|
| `aws/` | OpenTofu (Terraform-compatible) module with three targets: `aws`, `localstack`, `s3` (any S3-compatible store with Object Lock) |
| `render/` | Render Blueprint: the landing page (`misc/landing`, static site) and RustFS (S3-compatible, Object Lock) on a persistent disk |
| `localstack/` | LocalStack for a demo on another PC |

None of this has been applied yet from this repository (OpenTofu was not
installed on the development machine).

## Landing page on Render

The same Blueprint publishes `misc/landing` as the static site
`hawk-landing` (free plan, rebuilt only when `misc/landing` changes) at
`https://hawkeeper.xyz` (custom domain on `hawk-landing.onrender.com`;
DNS at Namecheap: `A @ 216.24.57.1`, `CNAME www hawk-landing.onrender.com`),
which is the URL in the landing's
install command. `install.sh` is served as `text/plain` so it can be read in
a browser before it is piped to `sh`. Its build runs
`misc/landing/fetch_downloads.py`, which needs the service variable
`GITHUB_TOKEN` (fine-grained, read-only Contents on this repository) to copy
the releases into `/downloads/` (ADR-0032). The landing is not part of HAWK: the
Core, the daemons and the app never contact it.

## Option A: Render (RustFS)

1. Render dashboard -> New -> Blueprint -> this repository, Blueprint path
   `infra/render/render.yaml`. Pin the RustFS image to 1.0.0-rc.1 or later.
2. Take the generated `RUSTFS_ACCESS_KEY` and `RUSTFS_SECRET_KEY` from the
   service's environment, and its URL (`https://<service>.onrender.com`).
3. Create the bucket with Object Lock:
   ```sh
   cd infra/aws && tofu init
   tofu apply -var target=s3 -var endpoint=https://<service>.onrender.com \
              -var access_key=<RUSTFS_ACCESS_KEY> -var secret_key=<RUSTFS_SECRET_KEY>
   ```
4. In RustFS, create a user for the Core with put-only on `core/*` and read on
   `config/latest.json`; do not give the Core the root keys outside a demo.

## Option B: LocalStack on another PC

```sh
cd infra/localstack && docker compose up -d                       # on the cloud PC
cd infra/aws && tofu init && tofu apply -var target=localstack -var endpoint=http://<pc>:4566
```

LocalStack's community edition does not enforce IAM.

## Option C: real AWS

```sh
cd infra/aws && tofu init && tofu apply
```

Creates the bucket (Object Lock, versioning, KMS, TLS-only, lifecycle) and a
credential for the Core that can only put under `core/` and read
`config/latest.json`.

## Start the Core with the archive

```sh
tofu output -json core_environment     # ARCHIVE_* and CONFIG_* values
ARCHIVE_ENDPOINT=... ARCHIVE_BUCKET=... ARCHIVE_ACCESS_KEY=... ARCHIVE_SECRET_KEY=... just guardian
```

Every signed head uploads `core/batches/<first>-<last>.bin` and
`core/heads/<seq>.json`.

## Configuration as code

1. Create the pipeline's signer once and keep the private key in its secret
   store:
   ```sh
   guardian config-keygen
   ```
2. The owner authorises it from the app by including its public key in a
   configuration (`enterprise_signer`), signed by the owner.
3. For each change, write the next `CoreConfig` (`version` = active + 1,
   `prev` = active hash; `guardian probe <core>` shows both), sign it and
   publish it:
   ```sh
   guardian config-sign signer.key next-config.json > signed.json
   tofu apply -var signed_config_file=signed.json   # plus your target variables
   ```
4. Start the Core with `CONFIG_REMOTE=1` and the `CONFIG_*` values. It polls
   every `CONFIG_POLL_SECS` (60 by default), applies the next link, and alerts
   on a rollback or a fork. Remote configurations cannot carry router secrets
   and cannot change the signer.

## What this must never do

- Give the Core a credential that can delete objects.
- Store anything unsealed: the Core uploads only sealed batches and signed
  heads; configurations carry no secrets.
- Make the cloud a requirement: if it is unreachable the Core keeps working
  with its own record and configuration.
