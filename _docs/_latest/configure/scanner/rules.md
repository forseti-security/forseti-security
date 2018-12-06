---
title: Defining Rules
order: 301
---

# {{ page.title }}

Forseti Scanner can be configured with rules that create a violation when their
conditions are met. Violations can be configured by configuring a
[notifier]({% link _docs/latest/configure/notifier/index.md %}).

---

## Defining custom rules

You can find some starter rules in the
[rules](https://github.com/GoogleCloudPlatform/forseti-security/tree/stable/rules)
directory. When you make changes to the rule files, upload them to your
Forseti bucket under `forseti-server-xxxx/rules/` or copy them to the `rules_path`
listed in `forseti_server_conf.yaml`. Each rule has a page in the left
navigation with a detailed description and configuration example.

## Default Rules

### BigQuery
  * Datasets should not be public.
  * Datasets should not be accessible by users who's email address matches `@gmail.com`.
  * Datasets should not be accessible by groups who's email address matches `*@googlegroups.com`.

### Blacklist
  * The IP address of any GCP instances should not be listed on
  the [emergingthreats](https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt) website.

### Cloud Storage (legacy ACL policies)
  * Buckets ACLs should not be publicly accessible (`AllUsers`).
  * Buckets ACLs should not be accessible by any authenticated user (`AllAuthenticatedUsers`).

### Cloud SQL
  * Cloud SQL instances should not allow access from anywhere (authorized networks).
  * Cloud SQL instances should not allow access over SSL from anywhere (authorized networks).

### G Suite
  * Your company users (@domain.tld) and all gmail users are allowed to be members of your G Suite
  groups.

### Cloud Identity and Access Management (Cloud IAM) policies
  * Only Cloud IAM users and group members in my domain may be granted the role `Organization Admin`.

### Cloud Identity-Aware Proxy (Cloud IAP) bypass access
  * Forbid any Cloud IAP bypasses on all resources in my organization, when Cloud IAP is enabled.
  * Allow direct access from debug IPs and internal monitoring hosts.

### Firewall
  * Prevent allow all ingress (used to detect allow ingress to all policies)

### Kubernetes Engine Version
  * Only allow the following supported versions:
    * For major version 1.8, the minor version must be at least 12-gke.1
    * For major version 1.9, the minor version must be at least 7-gke.1
    * For major version 1.10, the minor version must be at least 2-gke.1
    * For major version 1.11, any minor version is allowed

### Service Account Key
  * User-managed service account keys should not be older than the date and time you specify.

