---
title: Default Policies
order: 502
---

# {{ page.title }}

Forseti Real Time Enforcer comes with default policies for specific Google Cloud Platform (GCP) resources. 

This page lists the current resources and policies that are provided by Forseti Real Time Enforcer.

---

## Cloud Storage
   * Enable logging
   * Enable versioning
   * Remove allUsers/allAuthenticatedUsers from bucket IAM policy

## Cloud SQL
   * Enable automated backups
   * Enable require SSL for all connections
   * Remove 0.0.0.0/0 from the list of permitted IPs

## BigQuery
   * Remove alUsers/allAuthenticatedUsers from dataset IAM policy