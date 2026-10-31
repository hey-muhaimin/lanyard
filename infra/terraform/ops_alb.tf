# -------------------------------------------------
# 1️⃣ ALB (Internet‑facing)
# -------------------------------------------------
resource "aws_lb" "ops_alb" {
  name               = "ops-alb-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.ops_alb_sg.id]
  subnets            = var.private_subnet_ids

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
# 3️⃣ (Optional) Target group for **static assets**
# -------------------------------------------------
resource "aws_lb_target_group" "ops_static_tg" {
  name        = "ops-static-tg-${var.environment}"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    path                = "/"
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
# 4️⃣ Listener (HTTPS – you must have an ACM cert)
# -------------------------------------------------
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.ops_alb.arn
  port              = "443"
  protocol          = "HTTPS"

  ssl_policy     = "ELBSecurityPolicy-2023-04"
  certificate_arn = var.acm_certificate_arn

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
# 5️⃣ Listener rule – static assets first
# -------------------------------------------------
resource "aws_lb_listener_rule" "static_assets" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ops_static_tg.arn
  }

  condition {
    path_pattern {
      values = ["/ops/_next/*", "/ops/static/*"]
    }
  }
}

# -------------------------------------------------
# 6️⃣ Listener rule – catch‑all for the **Ops API**
# -------------------------------------------------
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
# 7️⃣ Register the EC2 instance(s) with the TGs
# -------------------------------------------------
resource "aws_lb_target_group_attachment" "ops_api_instance" {
  count            = length(var.ec2_instance_ids)
  target_group_arn = aws_lb_target_group.ops_api_tg.arn
  target_id        = var.ec2_instance_ids[count.index]
  port             = 8080
}

resource "aws_lb_target_group_attachment" "ops_static_instance" {
  count            = length(var.ec2_instance_ids)
  target_group_arn = aws_lb_target_group.ops_static_tg.arn
  target_id        = var.ec2_instance_ids[count.index]
  port             = 80
}