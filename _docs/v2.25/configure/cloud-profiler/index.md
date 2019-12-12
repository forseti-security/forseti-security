---
title: Cloud Profiler
order: 600
---

# {{ page.title }}

[Cloud Profiler](https://cloud.google.com/profiler/) is a statistical, low-overhead flame graph profiler on GCP that continuously gathers CPU usage and memory-allocation information from your Forseti application, helping you identify 
the parts of the application consuming the most resources and providing a more complete picture of the application's performance.

---

## Setting up

In your `main.tf` file, set the `cloud_profiler_enabled` variable in the Forseti Terraform module to `true`:

```
module "forseti" {
  source                   = "terraform-google-modules/forseti/google"
  project_id               = "PROJECT_ID"
  org_id                   = "ORG_ID"
  domain                   = "DOMAIN"
  
  ...
  
  cloud_profiler_enabled   = true
}
```

Apply the Terraform module.

```
terraform apply
```

## Permissions & Installations

The following steps are taken by Terraform to enable Cloud Profiler:

1. Install pip package `google-cloud-profiler`.
1. Assign `Stackdriver Profiler Agent` (`roles/cloudprofiler.agent`) to Forseti Server service account.
1. Enable `cloudprofiler.googleapis.com` API on Forseti project.

## Outputs

The Cloud Profiler interface displays a flame graph and a provides a set of controls to analyze the collected data.

In your GCP console, navigate to Stackdriver and click on Profiler to view the data.

For an in-depth instruction on how to use the interface, refer to the official Cloud Profiler 
[documentation](https://cloud.google.com/profiler/docs/using-profiler).

## Disabling Cloud Profiler

*Important:* Once you have completed an analysis of your Forseti application, we recommend that you disable the Cloud Profiler.

In your `main.tf` file, set the `cloud_profiler_enabled` variable in the Forseti Terraform module to `false`:

```
module "forseti" {
  source                   = "terraform-google-modules/forseti/google"
  project_id               = "PROJECT_ID"
  org_id                   = "ORG_ID"
  domain                   = "DOMAIN"
  
  ...
  
  cloud_profiler_enabled   = false
}
```

Apply the Terraform module.

```
terraform apply
```
