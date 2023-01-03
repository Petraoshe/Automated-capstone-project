#create VPC
resource "aws_vpc" "motiva_vpc" {
  cidr_block       = var.vpc_cidr
  instance_tenancy = "default"

  tags = {
    Name = "motiva_vpc"
  }
}

#create public subnet 1
resource "aws_subnet" "motiva_pub_subnet1" {
  vpc_id            = aws_vpc.motiva_vpc.id
  cidr_block        = var.cidr_pub_sub1
  availability_zone = "eu-west-2a"

  tags = {
    Name = "motiva_pub_subnet1"
  }
}

#create public subnet 2
resource "aws_subnet" "motiva_pub_subnet2" {
  vpc_id            = aws_vpc.motiva_vpc.id
  cidr_block        = var.cidr_pub_sub2
  availability_zone = "eu-west-2b"

  tags = {
    Name = "motiva_pub_subnet2"
  }
}

#create private subnet 1
resource "aws_subnet" "motiva_prv_subnet1" {
  vpc_id            = aws_vpc.motiva_vpc.id
  cidr_block        = var.cidr_prv_sub1
  availability_zone = "eu-west-2a"

  tags = {
    Name = "motiva_prv_subnet1"
  }
}

#create private subnet 2
resource "aws_subnet" "motiva_prv_subnet2" {
  vpc_id            = aws_vpc.motiva_vpc.id
  cidr_block        = var.cidr_prv_sub2
  availability_zone = "eu-west-2b"

  tags = {
    Name = "motiva_prv_subnet2"
  }
}

#create internet gateway
resource "aws_internet_gateway" "motiva_gw" {
  vpc_id = aws_vpc.motiva_vpc.id

  tags = {
    Name = "motiva_gw"
  }
}

#create NAT gateway
resource "aws_nat_gateway" "motiva_nat" {
  allocation_id = aws_eip.motiva_eip.id
  subnet_id     = aws_subnet.motiva_pub_subnet1.id

  tags = {
    Name = "motiva_nat"
  }


}

#create eip for NAT gateway
resource "aws_eip" "motiva_eip" {
  vpc = true
}

#. create public route tables
resource "aws_route_table" "motiva_Pub_rtb" {
  vpc_id = aws_vpc.motiva_vpc.id

  route {
    cidr_block = var.rtb_pub_ciderblock
    gateway_id = aws_internet_gateway.motiva_gw.id
  }
  tags = {
    Name = "motiva_gw"
  }
}
# create private route tables
resource "aws_route_table" "motiva_prv_rtb" {
  vpc_id = aws_vpc.motiva_vpc.id

  route {
    cidr_block     = var.rtb_prv_ciderblock
    nat_gateway_id = aws_nat_gateway.motiva_nat.id
  }
  tags = {
    Name = "motiva_prv_rtb"
  }
}
# motiva route table association to public sn1
resource "aws_route_table_association" "motiva_pub_rt_association1" {
  subnet_id      = aws_subnet.motiva_pub_subnet1.id
  route_table_id = aws_route_table.motiva_Pub_rtb.id
}
# motiva route table association to public sn2
resource "aws_route_table_association" "motiva_pub_rt_association2" {
  subnet_id      = aws_subnet.motiva_pub_subnet2.id
  route_table_id = aws_route_table.motiva_Pub_rtb.id
}
# motiva route table association to private sn1
resource "aws_route_table_association" "motiva_prv_rt_association1" {
  subnet_id      = aws_subnet.motiva_prv_subnet1.id
  route_table_id = aws_route_table.motiva_prv_rtb.id
}
# motiva route table association to private sn2
resource "aws_route_table_association" "motiva_prv_rt_association2" {
  subnet_id      = aws_subnet.motiva_prv_subnet2.id
  route_table_id = aws_route_table.motiva_prv_rtb.id
}
#   # 14. create FRONTEND security groups
resource "aws_security_group" "motiva_fe_sg" {
  name        = "motiva_fe_sg"
  description = "inbound traffic"
  vpc_id      = aws_vpc.motiva_vpc.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SHH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]

  }

  tags = {
    Name = "motiva_fe_sg"
  }
}

# 16. create BACKEND Security group
resource "aws_security_group" "motiva_be_sg" {
  name        = "motiva_be_sg"
  description = "outbound traffic"
  vpc_id      = aws_vpc.motiva_vpc.id

  ingress {
    description = "From pubsn to DB"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]

  }
  tags = {
    Name = "motiva_be_sg"
  }
}


/* # create Subnet Groups for RDS
resource "aws_db_subnet_group" "motiva_sub_g" {
  name       = "motiva_sub_g"
  subnet_ids = [aws_subnet.motiva_prv_subnet1.id, aws_subnet.motiva_prv_subnet2.id]

  tags = {
    Name = "motiva_sub_g"
  }
}

# create RDS
resource "aws_db_instance" "motiva_rds" {
  db_subnet_group_name   = aws_db_subnet_group.motiva_sub_g.name
  allocated_storage      = 10
  identifier             = "motivadb"
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t2.micro"
  multi_az               = true
  db_name                = "motivadbname"
  username               = "motivauser"
  password               = var.db_password
  parameter_group_name   = "default.mysql5.7"
  skip_final_snapshot    = true
  vpc_security_group_ids = [aws_security_group.motiva_be_sg.id]
} */

#Create a keypair for EC2 access
resource "aws_key_pair" "pacaad" {
  key_name   = "pacaad"
  public_key = file(var.path-to-publickey)
}

#Create EC2 instance_word press
resource "aws_instance" "motiva_wordpress" {
  ami                         = var.ami_id
  instance_type               = "t2.micro"
  iam_instance_profile        = aws_iam_instance_profile.motiva_profile.name
  subnet_id                   = aws_subnet.motiva_pub_subnet1.id
  key_name                    = aws_key_pair.pacaad.key_name
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.motiva_fe_sg.id]

  /* user_data = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
sudo yum install httpd php-fpm php-mysqlnd mariadb-server -y
sudo systemctl start httpd
cd /var/www/html
sudo touch indextest.html
sudo yum install wget -y
sudo wget https://wordpress.org/wordpress-5.1.1.tar.gz
sudo tar -xzf wordpress-5.1.1.tar.gz
sudo cp -r wordpress/* /var/www/html/
sudo rm -rf wordpress
sudo rm -rf wordpress-5.1.1.tar.gz
sudo echo "This is a test file" >> indextest.html
sudo chmod -R 755 wp-content
sudo chown -R apache:apache wp-content
sudo wget https://s3.amazonaws.com/bucketforwordpresslab-donotdelete/htaccess.txt
sudo mv htaccess.txt .htaccess
cd /var/www/html && sudo mv wp-config-sample.php wp-config.php
sudo sed -i "s@define( 'DB_NAME', 'database_name_here' )@define( 'DB_NAME', 'motivadbname' )@g" /var/www/html/wp-config.php
sudo sed -i "s@define( 'DB_USER', 'username_here' )@define( 'DB_USER', 'motivauser' )@g" /var/www/html/wp-config.php
sudo sed -i "s@define( 'DB_PASSWORD', 'password_here' )@define( 'DB_PASSWORD', 'Set10Admin' )@g" /var/www/html/wp-config.php
sudo sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST', '"${aws_db_instance.motiva_rds.endpoint}"' )@g" /var/www/html/wp-config.php
chkconfig httpd on
sudo sed -i 's/enforcing/disabled/g' /etc/selinux/config /etc/selinux/config
sudo setenforce 0
sudo systemctl restart httpd
curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'
sudo yum install unzip -y
unzip awscliv2.zip
sudo ./aws/install
sudo aws s3 cp --recursive /var/www/html/ s3://code-set-10-bucket
sudo sed -i -e '15a* * * * * ec2-user /usr/local/bin/aws s3 sync --delete s3://code-set-10-bucket /var/www/html/' /etc/crontab
sudo sed -i -e '16a* * * * * ec2-user /usr/local/bin/aws s3 sync /var/www/html/wp-content/uploads/ s3://media-set-10-bucket' /etc/crontab
sudo setenforce 0

EOF */
  tags = {
    Name = "motiva_wordpress"
  }
}

#Create IAM role for EC2
resource "aws_iam_role" "motiva_role2" {
  name = "motiva_role2"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    tag-key = "tag-value"
  }
}

#attach s3 full access to iam role
resource "aws_iam_role_policy_attachment" "motiva-attach" {
  role       = aws_iam_role.motiva_role2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

#Create instance profile 
resource "aws_iam_instance_profile" "motiva_profile" {
  name = "motiva_profile"
  role = aws_iam_role.motiva_role2.name
}
#create s3 bucket for media
resource "aws_s3_bucket" "media-set-10-bucket" {
  bucket        = "media-set-10-bucket"
  force_destroy = true
  tags = {
    Name = "media-set-10-bucket"

  }
}

resource "aws_s3_bucket_acl" "motiva-media-acl" {
  bucket = aws_s3_bucket.media-set-10-bucket.id
  acl    = "public-read"
}
#create s3 bucket for code
resource "aws_s3_bucket" "code-set-10-bucket" {
  bucket        = "code-set-10-bucket"
  force_destroy = true
  tags = {
    Name = "code-set-10-bucket"

  }
}

resource "aws_s3_bucket_acl" "motiva-code-acl" {
  bucket = aws_s3_bucket.code-set-10-bucket.id
  acl    = "private"
}
#create s3 bucket policy for media bucket
resource "aws_s3_bucket_policy" "motiva-s3-policy" {
  bucket = aws_s3_bucket.media-set-10-bucket.id

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "PublicReadGetObject",
        "Effect" : "Allow",
        "Principal" = {

          AWS = "*"

        }
        "Action" : [
          "s3:*Object"
        ],
        "Resource" : [
          "arn:aws:s3:::media-set-10-bucket/*"
        ]
      }
    ]
  })
}

/* #Create cloudfront distribution

resource "aws_cloudfront_distribution" "Motiva_distribution" {
  origin {
    domain_name = aws_s3_bucket.media-set-10-bucket.bucket_regional_domain_name
    origin_id   = aws_s3_bucket.media-set-10-bucket.id


  }

  enabled             = true
  comment             = "Some comment"
  default_root_object = "2022/06/devops-tools.png"

  logging_config {
    include_cookies = false
    bucket          = "media-set-10-bucket.s3.amazonaws.com"
    prefix          = "myprefix"
  }

  #aliases = ["mysite.example.com", "yoursite.example.com"]

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = aws_s3_bucket.media-set-10-bucket.id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }


  price_class = "PriceClass_200"

  restrictions {
    geo_restriction {
      restriction_type = "none"
      #locations        = ["US", "CA", "GB", "DE"]
    }
  }

  tags = {
    Environment = "DevOps"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
} */


#Create AMI for Wordpress instance

resource "aws_ami_from_instance" "motiva_ami" {
  name               = "motiva_ami"
  source_instance_id = aws_instance.motiva_wordpress.id
}

#Create Target group for LB

resource "aws_lb_target_group" "wordpress-lb-tg" {
  name        = "wordpress-lb-tg"
  port        = 80
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = aws_vpc.motiva_vpc.id

  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 4
    timeout             = 60
    interval            = 90
    path                = "/indextest.html"
  }
}


#Create the TG association

resource "aws_lb_target_group_attachment" "motiva_lb_attachment" {
  target_group_arn = aws_lb_target_group.wordpress-lb-tg.arn
  target_id        = aws_instance.motiva_wordpress.id
  port             = 80
}
#create load balancer 
resource "aws_lb" "motiva-lb" {
  name               = "motiva-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.motiva_fe_sg.id]
  subnets = [aws_subnet.motiva_pub_subnet1.id,
  aws_subnet.motiva_pub_subnet2.id]
  enable_deletion_protection = false

  tags = {
    Name = "motiva-lb"
  }
}
#create load balancer listener
resource "aws_lb_listener" "motiva_lb_listener" {
  load_balancer_arn = aws_lb.motiva-lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wordpress-lb-tg.arn
  }
}

# create Launch configuration

resource "aws_launch_configuration" "motiva_lc" {
  name                        = "motiva_lc"
  image_id                    = aws_ami_from_instance.motiva_ami.id
  instance_type               = "t2.micro"
  iam_instance_profile        = aws_iam_instance_profile.motiva_profile.name
  key_name                    = aws_key_pair.pacaad.key_name
  associate_public_ip_address = true
  security_groups             = [aws_security_group.motiva_fe_sg.id]

  user_data = <<-EOF
  #!/bin/bash
  sudo setenforce 0
  sudo systemctl restart httpd
  EOF
}

# Create Autoscaling group
resource "aws_autoscaling_group" "motiva_asg" {
  name                      = "motiva_asg"
  max_size                  = 5
  min_size                  = 2
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 4
  force_delete              = true
  launch_configuration      = aws_launch_configuration.motiva_lc.name
  vpc_zone_identifier       = [aws_subnet.motiva_pub_subnet1.id, aws_subnet.motiva_pub_subnet2.id]
  target_group_arns         = [aws_lb_target_group.wordpress-lb-tg.arn]
  tag {
    key                 = "name"
    value               = "motiva_asg"
    propagate_at_launch = true
  }
}

# Create autoscaling policy

resource "aws_autoscaling_policy" "motiva_policy" {
  autoscaling_group_name = aws_autoscaling_group.motiva_asg.name
  name                   = "motiva_policy"
  policy_type            = "TargetTrackingScaling"
  # ... other configuration ...

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }

    target_value = 60.0
  }
}

/* # Add monitoring
# Create CloudWatch dashboard
resource "aws_cloudwatch_dashboard" "motiva-dashboard" {
  dashboard_name = "motiva-dashboard"

  dashboard_body = <<EOF
{
  "widgets": [
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          [
            "AWS/EC2",
            "CPUUtilization",
            "InstanceId",
            "${aws_instance.motiva_wordpress.id}"
          ]
        ],
        "period": 300,
        "stat": "Average",
        "region": "eu-west-2",
        "title": "wordpress Instance CPU Utilization"
      }
    },
    {
      "type": "text",
      "x": 0,
      "y": 7,
      "width": 3,
      "height": 3,
      "properties": {
        "markdown": "Hello world"
      }
    }
  ]
}
EOF
}

#Create sns topic
resource "aws_sns_topic" "motiva-sns" {
  name            = "motiva-sns"
  delivery_policy = <<EOF
{
  "http": {
    "defaultHealthyRetryPolicy": {
      "minDelayTarget": 20,
      "maxDelayTarget": 20,
      "numRetries": 3,
      "numMaxDelayRetries": 0,
      "numNoDelayRetries": 0,
      "numMinDelayRetries": 0,
      "backoffFunction": "linear"
    },
    "disableSubscriptionOverrides": false,
    "defaultThrottlePolicy": {
      "maxReceivesPerSecond": 1
    }
  }
}
EOF
  provisioner "local-exec" {
    command = "aws sns subscribe --topic-arn arn:aws:sns:eu-west-2:627874023416:motiva-sns --protocol email --notification-endpoint jikpe@cloudhight.com"
  }
}

#Create cloudwatch meric alarm CPUUtilization
resource "aws_cloudwatch_metric_alarm" "motiva-metric-status" {
  alarm_name                = "motiva-metric-status"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "2"
  metric_name               = "CPUUtilization"
  namespace                 = "AWS/EC2"
  period                    = "120"
  statistic                 = "Average"
  threshold                 = "60"
  alarm_description         = "This metric monitors ec2 cpu utilization"
  insufficient_data_actions = []
  alarm_actions             = [aws_sns_topic.motiva-sns.arn]
  ok_actions                = [aws_sns_topic.motiva-sns.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.motiva_asg.name
  }
}

#Create cloudwatch meric alarm for statusCheckfailed
resource "aws_cloudwatch_metric_alarm" "motiva-metric-cpu" {
  alarm_name                = "motiva-metric-cpu"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "2"
  metric_name               = "statusCheckFailed"
  namespace                 = "AWS/EC2"
  period                    = "120"
  statistic                 = "Average"
  threshold                 = "60"
  alarm_description         = "This metric monitors ec2 cpu utilization"
  insufficient_data_actions = []
  alarm_actions             = [aws_sns_topic.motiva-sns.arn]
  ok_actions                = [aws_sns_topic.motiva-sns.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.motiva_asg.name
  }
} */




