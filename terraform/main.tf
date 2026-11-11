/*
 * syzygy on GKE Autopilot via Terraform.
 *
 *   - Enables GKE Autopilot (hardened by default: Workload Identity,
 *     shielded nodes, secure boot, private nodes optional)
 *   - Deploys syzygy via the Helm chart in ../helm/syzygy
 *   - Exposes via a regional L7 HTTPS LB + managed certificate
 *
 * This is a minimal, opinionated example; adapt to your project/host.
 */

terraform {
  required_version = ">= 1.5"
  required_providers {
    google   = { source = "hashicorp/google";   version = ">= 5.0" }
    kubernetes = { source = "hashicorp/kubernetes"; version = ">= 2.23" }
    helm     = { source = "hashicorp/helm";     version = ">= 2.11" }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

/* ---------- GKE Autopilot ---------- */

resource "google_container_cluster" "syzygy" {
  name             = "syzygy"
  location         = var.region
  enable_autopilot = true
  release_channel  { channel = "REGULAR" }
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
  private_cluster_config {
    enable_private_nodes = false
    master_ipv4_cidr_block = "172.16.0.0/28"
  }
  ip_allocation_policy { cluster_secondary_range_name = "" }
}

data "google_client_config" "default" {}

/* ---------- K8s / Helm provider bootstrapping ---------- */

provider "kubernetes" {
  host  = "https://${google_container_cluster.syzygy.endpoint}"
  token = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(
    google_container_cluster.syzygy.master_auth[0].cluster_ca_certificate
  )
}

provider "helm" {
  kubernetes {
    host  = "https://${google_container_cluster.syzygy.endpoint}"
    token = data.google_client_config.default.access_token
    cluster_ca_certificate = base64decode(
      google_container_cluster.syzygy.master_auth[0].cluster_ca_certificate
    )
  }
}

/* ---------- Namespace + secret (TLS) ---------- */

resource "kubernetes_namespace" "syzygy" {
  metadata { name = "syzygy" }
}

resource "kubernetes_secret" "tls" {
  metadata { name = "syzygy-tls"; namespace = kubernetes_namespace.syzygy.id }
  type = "kubernetes.io/tls"
  data = {
    "tls.crt" = filebase64(var.tls_cert_path)
    "tls.key" = filebase64(var.tls_key_path)
  }
}

/* ---------- syzygy Helm release ---------- */

resource "helm_release" "syzygy" {
  name       = "syzygy"
  namespace  = kubernetes_namespace.syzygy.id
  chart      = "${path.module}/../helm/syzygy"
  depends_on = [kubernetes_secret.tls]
  values = [yamlencode({
    replicaCount = 3
    tls = { secretName = "syzygy-tls" }
    resources = {
      requests = { cpu = "50m",  memory = "64Mi"  }
      limits   = { cpu = "500m", memory = "256Mi" }
    }
    networkPolicy = { enabled = true }
  })]
}
