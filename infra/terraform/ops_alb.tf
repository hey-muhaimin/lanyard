# -------------------------------------------------
# 1️⃣ ALB (Internet‑facing)
# -------------------------------------------------
resource "aws_lb" "ops_alb" {
  name               = "ops-alb-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.ops_alb_sg.id]
  # An internet-facing ALB must live in PUBLIC subnets (route to an IGW).
  subnets = var.public_subnet_ids

  enable_deletion_protection = true

  tags = var.tags
}

# -------------------------------------------------
# 2️⃣ Target group for the **Ops API** (control‑plane)
# -------------------------------------------------
resource "aws_lb_target_group" "ops_api_tg" {
  name        = "ops-api-tg-${var.environment}"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    path                = "/ops/health"
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
    matcher             = "200"
  }

  tags = var.tags
}

# -------------------------------------------------
# 3️⃣ Listener (HTTPS – you must have an ACM cert)
# -------------------------------------------------
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.ops_alb.arn
  port              = "443"
  protocol          = "HTTPS"

  ssl_policy      = "ELBSecurityPolicy-2023-04"
  certificate_arn = var.acm_certificate_arn

  # Fail closed: anything that does not match a rule below is a 404.
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Not Found"
      status_code  = "404"
    }
  }
}

# -------------------------------------------------
# 4️⃣ Listener rule – the **Ops API**
# -------------------------------------------------
# This single rule covers /ops/* and therefore /ops/auth/* as well; no
# separate auth rule is needed. The static console is served by
# CloudFront -> S3, so there is no static-asset rule on the ALB.
resource "aws_lb_listener_rule" "ops_api" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 20

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ops_api_tg.arn
  }

  condition {
    path_pattern {
      values = ["/ops/*"]
    }
  }
}

# -------------------------------------------------
# 5️⃣ Register the EC2 instance(s) with the API TG
# -------------------------------------------------
resource "aws_lb_target_group_attachment" "ops_api_instance" {
  count            = length(var.ec2_instance_ids)
  target_group_arn = aws_lb_target_group.ops_api_tg.arn
  target_id        = var.ec2_instance_ids[count.index]
  port             = 8080
}
