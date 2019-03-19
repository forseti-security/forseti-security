resource "google_project_service" "redis-service-api" {
  project   = "${var.gcp_project}"
  service   = "redis.googleapis.com"
}

resource "google_redis_instance" "redis" {
  name           = "redis"
  memory_size_gb = 1
  depends_on     = ["google_project_service.redis-service-api"]
}
