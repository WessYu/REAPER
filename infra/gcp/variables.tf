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

variable "runner_subnet_cidr" {
  type        = string
  description = "IPv4 subnet used exclusively by the Cloud Run execution network."
  default     = "10.92.0.0/24"

  validation {
    condition     = can(cidrhost(var.runner_subnet_cidr, 0))
    error_message = "runner_subnet_cidr must be a valid IPv4 subnet."
  }
}

variable "allowed_runner_target_cidrs" {
  type        = list(string)
  description = "Explicitly approved public IPv4 /32 addresses of authorized HTTPS assessment targets."
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.allowed_runner_target_cidrs :
      can(cidrhost(cidr, 0)) && can(regex("^[0-9.]+/32$", cidr))
    ]) && length(var.allowed_runner_target_cidrs) <= 10
    error_message = "Target egress entries must be at most ten exact IPv4 /32 CIDRs."
  }
}

variable "allowed_runner_database_cidrs" {
  type        = list(string)
  description = "Reviewed IPv4 /32 addresses for the durable PostgreSQL database, TCP 5432 only."
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.allowed_runner_database_cidrs :
      can(cidrhost(cidr, 0)) && can(regex("^[0-9.]+/32$", cidr))
    ]) && length(var.allowed_runner_database_cidrs) <= 5
    error_message = "Database egress entries must be at most five exact IPv4 /32 CIDRs."
  }
}

variable "authorized_runner_origins" {
  type        = list(string)
  description = "Explicitly authorized exact HTTPS hostname origins approved by a human operator for this pilot."
  default     = []

  validation {
    condition = length(var.authorized_runner_origins) <= 20 && alltrue([
      for origin in var.authorized_runner_origins :
      can(regex("^https://[a-z0-9][a-z0-9.-]*[a-z0-9]$", origin))
    ])
    error_message = "Authorized runner origins must be exact lowercase HTTPS host origins without paths, credentials, ports or query strings."
  }
}

variable "scope_signing_key_version" {
  type        = number
  description = "Reviewed Cloud KMS Ed25519 signing key version number. Rotate only with the runner trust registry updated first."
  default     = 1

  validation {
    condition     = var.scope_signing_key_version >= 1 && var.scope_signing_key_version == floor(var.scope_signing_key_version)
    error_message = "scope_signing_key_version must be a positive integer."
  }
}

variable "scope_signing_key_id" {
  type        = string
  description = "Distinct trusted key id for the selected KMS version. Never reuse a key id after rotation."
  default     = "gcp-kms-authorization-scope-v1"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]{1,100}$", var.scope_signing_key_id))
    error_message = "scope_signing_key_id must be a valid bounded identifier."
  }
}
