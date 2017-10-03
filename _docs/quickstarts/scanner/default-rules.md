---
title: Default Rules
order: 106
---

# {{ page.title }}

Forseti Scanner is preconfigured with some default rules. When any of these rules' conditions are met, 
Scanner will create a [violation]({% link _docs/quickstarts/scanner/policy-violations.md %}).

* BigQuery
  * Datasets should not be public.
  * Datasets should not be accessible by users who are @gmail.com.
  * Datasets should not be accessible by groups who are @gmail.com.
 
* Cloud Storage
  * Buckets should not be publicly accessible (“AllUsers”).
  * Buckets should not be accessible by any authenticated user (“AllAuthenticatedUsers”).
 
* Cloud SQL
  * Cloud SQL instances should not allow access from anywhere (authorized networks).
  * Cloud SQL instances should not allow access over SSL from anywhere (authorized networks).
 
* G Suite Groups
  * My company users (@domain.tld) and all gmail users are allowed to be members of my G Suite groups.
 
* IAM policies
  * Only IAM user and group members in my domain may be granted the role `Organization Admin`.
  * Service accounts should not be granted the role `Folder Admin`.
 
* IAP bypass access
  * Forbid any IAP bypasses on all resources in my organization, when IAP is enabled.
  * Allow direct access from debug IPs and internal monitoring hosts.
