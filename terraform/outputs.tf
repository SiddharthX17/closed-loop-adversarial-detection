output "service_url" {
  description = "Live URL of the deployed Cloud Run service — hit /health here"
  value       = google_cloud_run_v2_service.pipeline_service.uri
}

output "service_account_email" {
  description = "Pipeline's runtime service account — useful for debugging IAM issues"
  value       = google_service_account.pipeline_sa.email
}

output "anthropic_secret_id" {
  description = "Secret Manager resource ID for ANTHROPIC_API_KEY"
  value       = google_secret_manager_secret.anthropic_api_key.secret_id
}

output "github_token_secret_id" {
  description = "Secret Manager resource ID for GITHUB_TOKEN"
  value       = google_secret_manager_secret.github_token.secret_id
}
