# Off-site archive of the Core's sealed batches (ADR-0026).
#
# A bucket with Object Lock in compliance mode (nobody, not even the account
# root, can delete or overwrite an object during the retention period), a
# dedicated KMS key, TLS-only access, and a credential that can only put
# objects under the Core's prefix.
#
# Real AWS:   tofu init && tofu apply
# LocalStack: tofu init && tofu apply -var localstack_endpoint=http://<pc>:4566

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
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
  description = "Compliance-mode retention: objects cannot be deleted or overwritten before this."
  default     = 90
}

variable "localstack_endpoint" {
  type        = string
  description = "Set to LocalStack's URL (for example http://192.168.88.40:4566) to target the demo PC instead of AWS."
  default     = ""
}

locals {
  local = var.localstack_endpoint != ""
}

provider "aws" {
  region = var.region

  # Only when targeting LocalStack: dummy credentials, path-style S3 and every
  # used service pointed at the emulator.
  access_key                  = local.local ? "test" : null
  secret_key                  = local.local ? "test" : null
  skip_credentials_validation = local.local
  skip_metadata_api_check     = local.local
  skip_requesting_account_id  = local.local
  s3_use_path_style           = local.local

  dynamic "endpoints" {
    for_each = local.local ? [1] : []
    content {
      s3  = var.localstack_endpoint
      kms = var.localstack_endpoint
      iam = var.localstack_endpoint
      sts = var.localstack_endpoint
    }
  }
}

resource "aws_kms_key" "archive" {
  description         = "HAWK archive (batches are already sealed to the owner; this is a second layer)"
  enable_key_rotation = true
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

resource "aws_s3_bucket_server_side_encryption_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.archive.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "archive" {
  bucket                  = aws_s3_bucket.archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id
  rule {
    id     = "archive-class"
    status = "Enabled"
    filter {}
    transition {
      days          = 30
      storage_class = "GLACIER_IR"
    }
  }
}

resource "aws_s3_bucket_policy" "archive" {
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
  # LocalStack is reached over plain HTTP in the demo, so the TLS-only policy
  # is applied on real AWS only.
  count = local.local ? 0 : 1
}

# The Core's credential: put objects under its prefix, nothing else. No read,
# no list, no delete. (Later: IAM Roles Anywhere, so no long-lived key on the Pi.)
resource "aws_iam_user" "core" {
  name = "hawk-core-archiver"
}

resource "aws_iam_user_policy" "core" {
  name = "put-only"
  user = aws_iam_user.core.name
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
        Action   = ["kms:GenerateDataKey", "kms:Encrypt"]
        Resource = aws_kms_key.archive.arn
      },
    ]
  })
}

resource "aws_iam_access_key" "core" {
  user = aws_iam_user.core.name
}

output "core_environment" {
  description = "Environment for the Core (ARCHIVE_*)."
  sensitive   = true
  value = {
    ARCHIVE_ENDPOINT   = local.local ? var.localstack_endpoint : "https://s3.${var.region}.amazonaws.com"
    ARCHIVE_REGION     = var.region
    ARCHIVE_BUCKET     = aws_s3_bucket.archive.bucket
    ARCHIVE_PREFIX     = var.prefix
    ARCHIVE_ACCESS_KEY = aws_iam_access_key.core.id
    ARCHIVE_SECRET_KEY = aws_iam_access_key.core.secret
  }
}
