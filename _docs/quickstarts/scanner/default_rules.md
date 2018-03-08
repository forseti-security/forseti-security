---
title: Default Rules
order: 106
---

# {{ page.title }}

Forseti Scanner has default rules that create a [violation]({% link _docs/quickstarts/scanner/policy-violations.md %}) when their conditions are met.

* BigQuery
  * Datasets should not be public.
  * Datasets should not be accessible by users who's email address matches `@gmail.com`.
  * Datasets should not be accessible by groups who's email address matches `@gmail.com`.

* Blacklist
  * The IP address of any GCP instances should not be listed on the [emergingthreats](https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt) website

* Cloud Storage (legacy ACL policies)
  * Buckets ACLs should not be publicly accessible (`AllUsers`).
  * Buckets ACLs should not be accessible by any authenticated user (`AllAuthenticatedUsers`).
 
* Cloud SQL
  * Cloud SQL instances should not allow access from anywhere (authorized networks).
  * Cloud SQL instances should not allow access over SSL from anywhere (authorized networks).
 
* G Suite Groups
  * Your company users (@domain.tld) and all gmail users are allowed to be members of your G Suite groups.
 
* Cloud IAM policies
  * Only Cloud IAM user and group members in my domain may be granted the role `Organization Admin`.

* Cloud Identity Aware Proxy (IAP) bypass access
  * Forbid any IAP bypasses on all resources in my organization, when IAP is enabled.
  * Allow direct access from debug IPs and internal monitoring hosts.

* Kubernetes Engine (KE)
  * Only allow the following supported versions
    * For major version 1.6, the minor version has to be at least 13-gke.1
    * For major version 1.7, the minor version has to be at least 11-gke.1
    * For major version 1.8, the minor version has to be at least 4-gke.1
    * For major version 1.9, any minor version is allowed