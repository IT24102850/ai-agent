output "ecs_cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "ecs_service_name" {
  value = aws_ecs_service.api.name
}

output "load_balancer_dns" {
  value = aws_lb.this.dns_name
}

output "rds_address" {
  value = aws_db_instance.this.address
}

output "object_store_bucket" {
  value = aws_s3_bucket.reports.id
}

output "kms_key_arn" {
  value = aws_kms_key.platform.arn
}
