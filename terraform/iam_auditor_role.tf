terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" { default = "ap-south-1" }
variable "auditor_principal_arn" {
  description = "ARN (IAM role) allowed to assume this role, e.g., management account role or GitHub OIDC role."
  type        = string
}

resource "aws_iam_role" "auditor" {
  name = "OrganizationAccountAccessRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { AWS = var.auditor_principal_arn },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "readonly" {
  name = "AuditorReadOnly"
  role = aws_iam_role.auditor.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = [
        "ec2:Describe*",
        "rds:Describe*",
        "lambda:List*",
        "lambda:Get*",
        "cloudwatch:GetMetricStatistics",
        "s3:ListAllMyBuckets",
        "s3:GetBucket*",
        "s3:ListBucket",
        "organizations:List*"
      ],
      Resource = "*"
    }]
  })
}

output "auditor_role_arn" { value = aws_iam_role.auditor.arn }
