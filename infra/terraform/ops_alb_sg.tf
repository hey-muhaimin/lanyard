resource "aws_security_group" "ops_alb_sg" {
  name        = "ops-alb-sg-${var.environment}"
  description = "Allow inbound HTTPS from the internet and outbound to the EC2 instance."
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound (to instance on 80/8080)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}