output "wordpress_ip" {
  value = aws_instance.motiva_wordpress.public_ip
}

/* output "Cloudfront_domain" {
  value = aws_cloudfront_distribution.Motiva_distribution.domain_name
} */

output "lb_dns" {
  value = aws_lb.motiva-lb.dns_name
}

output "AMI_number" {
  value = aws_ami_from_instance.motiva_ami.id
}
