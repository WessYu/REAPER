variable "project_id" {
  type        = string
  description = "Google Cloud project that owns REAPER managed execution."
}

variable "region" {
  type        = string
  description = "Cloud Run and KMS region."
  default     = "southamerica-east1"
}

variable "scheduler_region" {
  type        = string
  description = "Cloud Scheduler region."
  default     = "southamerica-east1"
}

variable "runner_image" {
  type        = string
  description = "Immutable Artifact Registry image reference for the REAPER platform image."
}

variable "dispatch_schedule" {
  type        = string
  description = "Cloud Scheduler cron expression used to drain pending jobs."
  default     = "* * * * *"
}

variable "network_egress_enforced" {
  type        = bool
  description = "Set true only after runner egress is enforced outside the application. Strict mode fails closed while false."
  default     = false
}

variable "deletion_protection" {
  type        = bool
  description = "Protect Cloud Run jobs from accidental deletion."
  default     = false
}
