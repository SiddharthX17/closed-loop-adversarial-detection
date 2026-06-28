variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for Cloud Run service and Secret Manager"
  type        = string
  default     = "asia-south1"
}

variable "service_name" {
  description = "Cloud Run service name"
  type        = string
  default     = "adversarial-detection-pipeline"
}

variable "container_image" {
  description = "Full image path, e.g. us-central1-docker.pkg.dev/PROJECT_ID/REPO/IMAGE:TAG"
  type = string
}

variable "min_instances" {
  description = "Cloud Run min instance count"
  type        = number
  default     = 0
}

variable "max_instances" {
  description = "Cloud Run max instance count."
  type        = number
  default     = 1
}
