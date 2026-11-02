terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
  # PREREQUISITE: the S3 state bucket `lanyard-terraform-state` and the
  # DynamoDB lock table `lanyard-terraform-locks` must be provisioned
  # out-of-band (manually or via a separate bootstrap stack) before
  # `terraform init` can succeed against this backend. They are not managed
  # by this configuration, so a fresh account will fail init until they exist.
  backend "s3" {
    bucket         = "lanyard-terraform-state"
    key            = "production/terraform.tfstate"
    region         = "ap-southeast-2"
    dynamodb_table = "lanyard-terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "lanyard"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}