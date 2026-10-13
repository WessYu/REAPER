output "runner_job" {
  value = google_cloud_run_v2_job.runner.name
}

output "dispatcher_job" {
  value = google_cloud_run_v2_job.dispatcher.name
}

output "dispatcher_service_account" {
  value = google_service_account.dispatcher.email
}

output "runner_service_account" {
  value = google_service_account.runner.email
}

output "kms_key_version" {
  value = "${google_kms_crypto_key.scope_signing.id}/cryptoKeyVersions/1"
}

output "dispatcher_database_secret" {
  value = google_secret_manager_secret.dispatcher_database_url.secret_id
}

output "runner_database_secret" {
  value = google_secret_manager_secret.runner_database_url.secret_id
}
