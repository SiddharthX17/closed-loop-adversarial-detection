terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# -----------------------------------------------------------------------------
# Service Account — dedicated identity for the pipeline, minimum permissions.
# Only needs: read access to its own two secrets. Nothing else.
# (No GCS, no Firestore — both dropped from scope.)
# -----------------------------------------------------------------------------
resource "google_service_account" "pipeline_sa" {
  account_id   = "adversarial-detection-pipeline"
  display_name = "Closed-Loop Adversarial Detection Pipeline"
  description  = "Runtime identity for the Cloud Run service. Scoped to Secret Manager read-only."
}

# -----------------------------------------------------------------------------
# Secrets — values are NOT set here. Terraform creates the secret containers;
# task 4.09 populates the actual versions via `gcloud secrets versions add`
# or the console, so secret values never touch Terraform state in plaintext
# beyond what's passed in as -var (which itself should come from env vars,
# never a committed .tfvars file).
# -----------------------------------------------------------------------------
resource "google_secret_manager_secret" "anthropic_api_key" {
  secret_id = "ANTHROPIC_API_KEY"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "github_token" {
  secret_id = "GITHUB_TOKEN"

  replication {
    auto {}
  }
}

# Two app-level auth secrets — NOT GCP IAM. Cloud Run's own IAM invoker
# check (the public_access binding below) is enforced at the whole-service
# level and can't be scoped per-path, so the /run vs /health+/results
# distinction is implemented in app.py instead, via these two values.
resource "google_secret_manager_secret" "pipeline_run_secret" {
  secret_id = "PIPELINE_RUN_SECRET"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "pipeline_viewer_secret" {
  secret_id = "PIPELINE_VIEWER_SECRET"

  replication {
    auto {}
  }
}
# Initial secret VERSIONS are deliberately NOT created here. Populating them
# via Terraform would write the plaintext value into terraform.tfstate
# permanently — sensitive=true only hides it from CLI/log output, not from
# the state file itself. Instead, the secret CONTAINERS above are created
# empty, and you populate the actual value via `gcloud secrets versions add`
# after this first apply (see task 4.09 notes). Secret values never touch
# Terraform state this way.

# -----------------------------------------------------------------------------
# IAM — grant the pipeline SA read access to each secret, nothing broader.
# -----------------------------------------------------------------------------
resource "google_secret_manager_secret_iam_member" "anthropic_key_access" {
  secret_id = google_secret_manager_secret.anthropic_api_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.pipeline_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "github_token_access" {
  secret_id = google_secret_manager_secret.github_token.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.pipeline_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "run_secret_access" {
  secret_id = google_secret_manager_secret.pipeline_run_secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.pipeline_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "viewer_secret_access" {
  secret_id = google_secret_manager_secret.pipeline_viewer_secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.pipeline_sa.email}"
}

# -----------------------------------------------------------------------------
# Cloud Run Service — hosts the FastAPI app. Single resource, no Job, no
# Scheduler (deferred per Phase 4 scoping decision).
#
# Secrets are mounted as env vars via secret refs, NOT passed as plain
# Terraform variables into container env — the secret value never appears
# in the Cloud Run service's own config, only a reference to the secret.
# -----------------------------------------------------------------------------
resource "google_cloud_run_v2_service" "pipeline_service" {
  name     = var.service_name
  location = var.region

  template {
    service_account = google_service_account.pipeline_sa.email

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    containers {
      image = var.container_image

      resources {
        limits = {
          # Pipeline does LLM calls + light pySigma/sqlite3 work — no heavy
          # compute since sentence-transformers/torch is gone. 1 CPU / 1Gi
          # should be plenty; bump only if you see OOM in Cloud Run logs.
          cpu    = "1"
          memory = "1Gi"
        }
      }

      env {
        name  = "GITHUB_REPO"
        value = "SiddharthX17/closed-loop-adversarial-detection"
      }

      env {
        name = "ANTHROPIC_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.anthropic_api_key.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "GITHUB_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.github_token.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "PIPELINE_RUN_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.pipeline_run_secret.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "PIPELINE_VIEWER_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.pipeline_viewer_secret.secret_id
            version = "latest"
          }
        }
      }
    }

    # Pipeline runs can take a while (LLM calls + defender retries).
    # Cloud Run v2 service timeout — default is 300s, this raises it for
    # the /run endpoint's worst case (multiple iterations, retries).
    timeout = "900s"
  }

  depends_on = [
    google_secret_manager_secret_iam_member.anthropic_key_access,
    google_secret_manager_secret_iam_member.github_token_access,
    google_secret_manager_secret_iam_member.run_secret_access,
    google_secret_manager_secret_iam_member.viewer_secret_access,
  ]
}

# -----------------------------------------------------------------------------
# Allows the service to be reached without a GCP identity token — actual
# access control now happens at the app layer via the two shared secrets
# above, not GCP IAM. Removing this binding would require a Google identity
# token on EVERY request (no path-level carve-out is possible at this layer),
# which would also lock out /health for anyone without GCP credentials.
# -----------------------------------------------------------------------------
resource "google_cloud_run_v2_service_iam_member" "public_access" {
  name     = google_cloud_run_v2_service.pipeline_service.name
  location = google_cloud_run_v2_service.pipeline_service.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}
