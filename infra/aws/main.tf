# Enterprise edition, optional (ADR-0026, ADR-0027): off-site archive of the
# Core's sealed batches and the store for its remote configuration.
#
# One module, three targets:
#   target = "aws"        real AWS: bucket, Object Lock, KMS, TLS-only policy,
#                         lifecycle, put-only and read-config credentials
#   target = "localstack" the demo PC running infra/localstack
#   target = "s3"         any S3-compatible store with Object Lock, such as
#                         RustFS on Render (infra/render): bucket + lock only
#
#   tofu init
#   tofu apply                                                   # AWS
#   tofu apply -var target=localstack -var endpoint=http://<pc>:4566
#   tofu apply -var target=s3 -var endpoint=https://<service>.onrender.com \
#              -var access_key=... -var secret_key=...           # Render

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "target" {
  type    = string
  default = "aws"
  validation {
    condition     = contains(["aws", "localstack", "s3"], var.target)
    error_message = "target must be aws, localstack or s3."
  }
}

variable "endpoint" {
  type        = string
  description = "S3 endpoint for localstack or s3 targets."
  default     = ""
}

variable "access_key" {
  type      = string
  default   = "test"
  sensitive = true
}

variable "secret_key" {
  type      = string
  default   = "test"
  sensitive = true
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "bucket_name" {
  type        = string
  description = "Globally unique on AWS."
  default     = "hawk-archive-team23"
}

variable "prefix" {
  type    = string
  default = "core"
}

variable "retention_days" {
  type        = number
  description = "Compliance-mode retention: no object can be deleted or overwritten before this."
  default     = 90
}

variable "signed_config_file" {
  type        = string
  description = "Optional: a SignedConfig from `guardian config-sign`, published as config/latest.json."
  default     = ""
}

locals {
  aws       = var.target == "aws"
  emulated  = var.target == "localstack"
  custom    = var.target != "aws"
  with_iam  = var.target != "s3" # AWS and LocalStack have KMS and IAM
}

provider "aws" {
  region = var.region

  access_key                  = local.custom ? var.access_key : null
  secret_key                  = local.custom ? var.secret_key : null
  skip_credentials_validation = local.custom
  skip_metadata_api_check     = local.custom
  skip_requesting_account_id  = local.custom
  skip_region_validation      = local.custom
  s3_use_path_style           = local.custom

  dynamic "endpoints" {
    for_each = local.custom ? [1] : []
    content {
      s3  = var.endpoint
      kms = var.endpoint
      iam = var.endpoint
      sts = var.endpoint
    }
  }
}

resource "aws_s3_bucket" "archive" {
  bucket              = var.bucket_name
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "archive" {
  bucket = aws_s3_bucket.archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.archive]
}

# ---- AWS and LocalStack only ---------------------------------------------

resource "aws_kms_key" "archive" {
  count               = local.with_iam ? 1 : 0
  description         = "HAWK archive (batches are already sealed to the owner; this is a second layer)"
  enable_key_rotation = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "archive" {
  count  = local.with_iam ? 1 : 0
  bucket = aws_s3_bucket.archive.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.archive[0].arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "archive" {
  count                   = local.with_iam ? 1 : 0
  bucket                  = aws_s3_bucket.archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_user" "core" {
  count = local.with_iam ? 1 : 0
  name  = "hawk-core"
}

# Put-only on the archive prefix; read-only on the configuration document.
resource "aws_iam_user_policy" "core" {
  count = local.with_iam ? 1 : 0
  name  = "archive-put-config-read"
  user  = aws_iam_user.core[0].name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.archive.arn}/${var.prefix}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.archive.arn}/config/latest.json"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Encrypt", "kms:Decrypt"]
        Resource = aws_kms_key.archive[0].arn
      },
    ]
  })
}

resource "aws_iam_access_key" "core" {
  count = local.with_iam ? 1 : 0
  user  = aws_iam_user.core[0].name
}

# ---- AWS only ------------------------------------------------------------

resource "aws_s3_bucket_lifecycle_configuration" "archive" {
  count  = local.aws ? 1 : 0
  bucket = aws_s3_bucket.archive.id
  rule {
    id     = "archive-class"
    status = "Enabled"
    filter {
      prefix = "${var.prefix}/"
    }
    transition {
      days          = 30
      storage_class = "GLACIER_IR"
    }
  }
}

resource "aws_s3_bucket_policy" "tls_only" {
  count  = local.aws ? 1 : 0
  bucket = aws_s3_bucket.archive.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "TlsOnly"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.archive.arn, "${aws_s3_bucket.archive.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# ---- Remote configuration (ADR-0027), optional ------------------------------

# Each apply with a new file writes a new, locked version of the object; the
# Core accepts it only if it is the next link of its configuration chain.
resource "aws_s3_object" "config_latest" {
  count        = var.signed_config_file != "" ? 1 : 0
  bucket       = aws_s3_bucket.archive.id
  key          = "config/latest.json"
  source       = var.signed_config_file
  etag         = filemd5(var.signed_config_file)
  content_type = "application/json"
  depends_on   = [aws_s3_bucket_object_lock_configuration.archive]
}

output "core_environment" {
  description = "Environment for the Core (ARCHIVE_* and CONFIG_*). On the s3 target, use credentials created in the store for the Core."
  sensitive   = true
  value = {
    ARCHIVE_ENDPOINT   = local.custom ? var.endpoint : "https://s3.${var.region}.amazonaws.com"
    ARCHIVE_REGION     = var.region
    ARCHIVE_BUCKET     = aws_s3_bucket.archive.bucket
    ARCHIVE_PREFIX     = var.prefix
    ARCHIVE_ACCESS_KEY = local.with_iam ? aws_iam_access_key.core[0].id : var.access_key
    ARCHIVE_SECRET_KEY = local.with_iam ? aws_iam_access_key.core[0].secret : var.secret_key
    CONFIG_REMOTE      = "1"
    CONFIG_KEY         = "config/latest.json"
    CONFIG_ACCESS_KEY  = local.with_iam ? aws_iam_access_key.core[0].id : var.access_key
    CONFIG_SECRET_KEY  = local.with_iam ? aws_iam_access_key.core[0].secret : var.secret_key
  }
}
