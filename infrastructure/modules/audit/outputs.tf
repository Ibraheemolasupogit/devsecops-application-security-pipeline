output "cloudtrail_name" {
  value = aws_cloudtrail.management.name
}
output "cloudtrail_bucket_name" {
  value = aws_s3_bucket.cloudtrail.id
}
