# Private execution network. Nothing is provisioned until egress is explicitly enabled.
# The runner is the only workload tagged for these firewall rules.
resource "google_project_service" "compute" {
  service            = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_compute_network" "execution" {
  count                   = var.network_egress_enforced ? 1 : 0
  name                    = "reaper-execution"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.compute]
}

resource "google_compute_subnetwork" "execution" {
  count                    = var.network_egress_enforced ? 1 : 0
  name                     = "reaper-execution"
  network                  = google_compute_network.execution[0].id
  region                   = var.region
  ip_cidr_range            = var.runner_subnet_cidr
  private_ip_google_access = true
}

# DENY takes precedence over implicit VPC egress allow. More specific ALLOW
# rules below have numerically lower priority than this deny rule.
resource "google_compute_firewall" "runner_deny_all" {
  count              = var.network_egress_enforced ? 1 : 0
  name               = "reaper-runner-egress-deny"
  network            = google_compute_network.execution[0].name
  direction          = "EGRESS"
  priority           = 1000
  target_tags        = ["reaper-execution"]
  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }
}

# A commercial pilot authorizes one or more literal destination IPs.
# DNS names do not weaken the firewall: new addresses require a reviewed apply.
resource "google_compute_firewall" "runner_target_https" {
  count              = var.network_egress_enforced ? 1 : 0
  name               = "reaper-runner-target-https"
  network            = google_compute_network.execution[0].name
  direction          = "EGRESS"
  priority           = 900
  target_tags        = ["reaper-execution"]
  destination_ranges = var.allowed_runner_target_cidrs

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

# The durable state database is NOT an assessment target. Its IP is separately
# reviewed and only PostgreSQL traffic is permitted through this rule.
resource "google_compute_firewall" "runner_postgres" {
  count              = var.network_egress_enforced ? 1 : 0
  name               = "reaper-runner-state-postgres"
  network            = google_compute_network.execution[0].name
  direction          = "EGRESS"
  priority           = 900
  target_tags        = ["reaper-execution"]
  destination_ranges = var.allowed_runner_database_cidrs

  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }
}

# Cloud Run Direct VPC egress needs Cloud NAT for approved public IPv4
# destinations. NAT does not override firewall deny/allow rules.
resource "google_compute_router" "execution" {
  count   = var.network_egress_enforced ? 1 : 0
  name    = "reaper-execution-router"
  network = google_compute_network.execution[0].name
  region  = var.region
}

resource "google_compute_router_nat" "execution" {
  count                              = var.network_egress_enforced ? 1 : 0
  name                               = "reaper-execution-nat"
  router                             = google_compute_router.execution[0].name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.execution[0].id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }
}
