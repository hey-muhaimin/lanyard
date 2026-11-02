variable "vpc_id" {
  description = "VPC where the ALB and instances live"
  type        = string
}

# NOTE: `vpc_cidr` is intentionally NOT declared here. It is already declared
# in variables.tf (default "10.0.0.0/16") and is reused by ops_alb_sg.tf.
# Redeclaring it here would be a duplicate variable definition error.

# Each subnet in this list must have a route to an Internet Gateway; an
# internet-facing ALB cannot be placed in private subnets.
variable "public_subnet_ids" {
  description = "List of public subnet IDs for the internet-facing ALB"
  type        = list(string)
}

variable "ec2_instance_ids" {
  description = "IDs of the EC2 instance(s) that run NGINX + the Go control‑plane."
  type        = list(string)
}

variable "acm_certificate_arn" {
  description = "ARN of an ACM certificate covering api.linkedqueue.cloud"
  type        = string
}

variable "ops_instance_security_group_id" {
  description = "Optional. Security group ID of the backend EC2 instance(s) running the control plane. When set, an ingress rule allowing TCP 8080 from the ALB security group is created. Leave empty to manage the instance SG out of band."
  type        = string
  default     = ""
}
