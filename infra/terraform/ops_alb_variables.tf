variable "vpc_id" {
  description = "VPC where the ALB and instances live"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of subnet IDs for the ALB (public subnets if you want internet‑facing)."
  type        = list(string)
}

variable "ec2_instance_ids" {
  description = "IDs of the EC2 instance(s) that run NGINX + the Go control‑plane."
  type        = list(string)
}

variable "acm_certificate_arn" {
  description = "ARN of an ACM certificate covering ops.linkedqueue.cloud"
  type        = string
}