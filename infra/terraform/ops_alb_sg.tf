resource "aws_security_group" "ops_alb_sg" {
  name        = "ops-alb-sg-${var.environment}"
  description = "Allow inbound HTTPS from the internet and scoped outbound to the EC2 instance."
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Scoped egress: the ALB only needs to reach backends inside the VPC.
  # The static console is served by CloudFront -> S3, so port 80 to the
  # instances is only needed while any legacy backend still listens there.
  egress {
    description = "HTTP to backends within the VPC CIDR"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Ops API (Go control plane) to backends within the VPC CIDR"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = var.tags
}

# OPTIONAL: backend instance security group.
#
# The instance SG MUST permit TCP 8080 from the ALB security group ONLY.
# Do not open 8080 to 0.0.0.0/0 or to the VPC CIDR generally: the control
# plane must only ever be reachable through the ALB.
#
# This rule is created only when ops_instance_security_group_id is set.
# The empty default leaves the instance SG untouched so this module never
# silently widens access on a security group it does not own.
resource "aws_security_group_rule" "allow_alb_to_instance" {
  count = var.ops_instance_security_group_id == "" ? 0 : 1

  type                     = "ingress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  security_group_id        = var.ops_instance_security_group_id
  source_security_group_id = aws_security_group.ops_alb_sg.id
  description              = "Allow ALB to reach the control-plane on port 8080"
}
