terraform {
  required_version = ">= 1.7.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

data "google_project" "current" {
  project_id = var.project_id
}

locals {
  runner_job     = "reaper-runner"
  dispatcher_job = "reaper-dispatcher"
}

resource "google_project_service" "run" {
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "kms" {
  service            = "cloudkms.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "secretmanager" {
  service            = "secretmanager.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "scheduler" {
  service            = "cloudscheduler.googleapis.com"
  disable_on_destroy = false
}

resource "google_service_account" "dispatcher" {
  account_id   = "reaper-dispatcher"
  display_name = "REAPER Cloud Run dispatcher"
}

resource "google_service_account" "runner" {
  account_id   = "reaper-runner"
  display_name = "REAPER Cloud Run runner"
}

resource "google_service_account" "scheduler" {
  account_id   = "reaper-scheduler"
  display_name = "REAPER dispatcher scheduler"
}

resource "google_kms_key_ring" "reaper" {
  name       = "reaper"
  location   = var.region
  depends_on = [google_project_service.kms]
}

resource "google_kms_crypto_key" "scope_signing" {
  name     = "authorization-scope"
  key_ring = google_kms_key_ring.reaper.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_ED25519"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "dispatcher_signer" {
  crypto_key_id = google_kms_crypto_key.scope_signing.id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.dispatcher.email}"
}

resource "google_secret_manager_secret" "dispatcher_database_url" {
  secret_id = "reaper-dispatcher-database-url"
  replication {
    auto {}
  }
  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret" "runner_trusted_scope_keys" {
  secret_id = "reaper-runner-trusted-scope-keys"
  replication {
    auto {}
  }
  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret" "runner_database_url" {
  secret_id = "reaper-runner-database-url"
  replication {
    auto {}
  }
  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret_iam_member" "dispatcher_database" {
  secret_id = google_secret_manager_secret.dispatcher_database_url.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.dispatcher.email}"
}

resource "google_secret_manager_secret_iam_member" "runner_trust" {
  secret_id = google_secret_manager_secret.runner_trusted_scope_keys.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runner.email}"
}

resource "google_secret_manager_secret_iam_member" "runner_database" {
  secret_id = google_secret_manager_secret.runner_database_url.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runner.email}"
}

resource "google_cloud_run_v2_job" "runner" {
  name                = local.runner_job
  location            = var.region
  deletion_protection = var.deletion_protection

  template {
    task_count = 1

    template {
      service_account = google_service_account.runner.email
      max_retries     = 0
      timeout         = "1900s"

      dynamic "vpc_access" {
        for_each = var.network_egress_enforced ? [1] : []

        content {
          egress = "ALL_TRAFFIC"
          network_interfaces {
            network    = google_compute_network.execution[0].name
            subnetwork = google_compute_subnetwork.execution[0].name
            tags       = ["reaper-execution"]
          }
        }
      }

      volumes {
        name = "runner-trust"
        secret {
          secret = google_secret_manager_secret.runner_trusted_scope_keys.secret_id
          items {
            version = "latest"
            path    = "trusted-scope-keys.json"
          }
        }
      }

      containers {
        image   = var.runner_image
        command = ["node"]
        args    = ["/app/platform/dist/cloud-run-entry.js"]

        volume_mounts {
          name       = "runner-trust"
          mount_path = "/var/run/reaper-trust"
        }

        resources {
          limits = {
            cpu    = "1"
            memory = "512Mi"
          }
        }

        env {
          name  = "REAPER_CLOUD_RUN_RESOURCE_ENFORCED"
          value = "1"
        }

        env {
          name  = "REAPER_CLOUD_RUN_NETWORK_ENFORCED"
          value = var.network_egress_enforced ? "1" : "0"
        }

        env {
          name = "REAPER_PLATFORM_DATABASE_URL"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.runner_database_url.secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition = !var.network_egress_enforced || (
        length(var.allowed_runner_target_cidrs) > 0 &&
        length(var.allowed_runner_database_cidrs) > 0 &&
        length(var.authorized_runner_origins) > 0
      )
      error_message = "REAPER commercial runner egress requires explicit target HTTPS and PostgreSQL /32 destination lists."
    }
  }

  depends_on = [
    google_project_service.run,
    google_secret_manager_secret_iam_member.runner_database,
    google_secret_manager_secret_iam_member.runner_trust,
    google_compute_firewall.runner_deny_all,
    google_compute_firewall.runner_target_https,
    google_compute_firewall.runner_postgres,
    google_compute_router_nat.execution,
  ]
}

resource "google_cloud_run_v2_job" "dispatcher" {
  name                = local.dispatcher_job
  location            = var.region
  deletion_protection = var.deletion_protection

  template {
    task_count = 1

    template {
      service_account = google_service_account.dispatcher.email
      max_retries     = 0
      timeout         = "300s"

      containers {
        image   = var.runner_image
        command = ["node"]
        args    = ["/app/platform/dist/cloud-dispatcher.js"]

        resources {
          limits = {
            cpu    = "1"
            memory = "512Mi"
          }
        }

        env {
          name  = "REAPER_GCP_PROJECT_ID"
          value = var.project_id
        }

        env {
          name  = "REAPER_GCP_REGION"
          value = var.region
        }

        env {
          name  = "REAPER_GCP_RUNNER_JOB"
          value = google_cloud_run_v2_job.runner.name
        }

        env {
          name  = "REAPER_CLOUD_AUTHORIZED_ORIGINS"
          value = jsonencode(var.authorized_runner_origins)
        }

        env {
          name  = "REAPER_GCP_KMS_KEY_VERSION"
          value = "${google_kms_crypto_key.scope_signing.id}/cryptoKeyVersions/1"
        }

        env {
          name  = "REAPER_GCP_KMS_KEY_ID"
          value = "gcp-kms-authorization-scope-v1"
        }

        env {
          name  = "REAPER_PLATFORM_CONFIG_ROOT"
          value = "/app/platform/config"
        }

        env {
          name = "REAPER_PLATFORM_DATABASE_URL"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.dispatcher_database_url.secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }

  depends_on = [
    google_project_service.run,
    google_kms_crypto_key_iam_member.dispatcher_signer,
    google_secret_manager_secret_iam_member.dispatcher_database,
  ]
}

resource "google_cloud_run_v2_job_iam_member" "dispatcher_can_execute_runner" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.runner.name
  role     = "roles/run.jobsExecutorWithOverrides"
  member   = "serviceAccount:${google_service_account.dispatcher.email}"
}

resource "google_cloud_run_v2_job_iam_member" "scheduler_can_execute_dispatcher" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.dispatcher.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler.email}"
}

resource "google_service_account_iam_member" "scheduler_token_creator" {
  service_account_id = google_service_account.scheduler.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloudscheduler.iam.gserviceaccount.com"
}

resource "google_cloud_scheduler_job" "dispatcher" {
  name             = "reaper-dispatcher"
  region           = var.scheduler_region
  schedule         = var.dispatch_schedule
  time_zone        = "Etc/UTC"
  attempt_deadline = "180s"

  retry_config {
    retry_count = 0
  }

  http_target {
    http_method = "POST"
    uri         = "https://run.googleapis.com/v2/projects/${var.project_id}/locations/${var.region}/jobs/${google_cloud_run_v2_job.dispatcher.name}:run"
    body        = base64encode("{}")

    headers = {
      "Content-Type" = "application/json"
    }

    oauth_token {
      service_account_email = google_service_account.scheduler.email
    }
  }

  depends_on = [
    google_project_service.scheduler,
    google_cloud_run_v2_job_iam_member.scheduler_can_execute_dispatcher,
    google_service_account_iam_member.scheduler_token_creator,
  ]
}
