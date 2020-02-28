---
title: Default Rules
order: 302
---

# {{ page.title }}

Forseti Scanner has default rules that create a
[violation]({% link _docs/latest/use/cli/scanner.md %}) when their conditions are met.
This page describes the default rules for specific Google Cloud Platform (GCP) products and
resources.

---

## Audit logging
  * All the operations that read and write user provided data should be logged
    for the specified service on all the projects, and for all the GCP users 
    except for the users you specify.
  
## BigQuery
  * Datasets should not be public.
  * Datasets should not be accessible by users who's email address matches `@gmail.com`.
  * Datasets should not be accessible by groups who's email address matches `*@googlegroups.com`.

## Blacklist
  * The IP address of any GCP instances should not be listed on
  the [emergingthreats](https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt) website.

## Cloud SQL
  * Cloud SQL instances should not allow access from anywhere (authorized networks).
  * Cloud SQL instances should not allow access over SSL from anywhere (authorized networks).
  
## Cloud Storage (legacy ACL policies)
  * Buckets ACLs should not be publicly accessible (`AllUsers`).
  * Buckets ACLs should not be accessible by any authenticated user (`AllAuthenticatedUsers`).

## Cloud Identity and Access Management (Cloud IAM) policies
  * Only Cloud IAM users and group members in my domain may be granted the role `Organization Admin`.

## Cloud Identity-Aware Proxy (Cloud IAP) bypass access
  * Forbid any Cloud IAP bypasses on all resources in my organization, when Cloud IAP is enabled.
  * Allow direct access from debug IPs and internal monitoring hosts.

## Enabled APIs
  * Only supported APIs should be enabled for all projects.
  
## External Project Access
  * Find any users in your org that may have access to projects outside of your allowed org or folder.
  
## Firewall
  * Prevent allow all ingress (used to detect allow ingress to all policies)

## Forwarding
  * Unauthorized external traffic should be directed to the target instance 
  based on the IP address, IP protocol and port/port range specified.
  
## Group
  * Your company users (@domain.tld) and all gmail users are allowed to be members of your G Suite
  groups.
  
## Group Settings
  * Only allow the following supported settings for groups with IAM policies:
    * A user from outside of the organization can never join the group.
    * Invitation is required to join.
    * Managers can invite people to join the group.
    * Managers can add people to the group.
    * Managers can leave the group.
  
## Instance Network Interface
  * Ensure instances with external IPs are only running on whitelisted networks.
  * Ensure instances are only running on networks created in allowed projects.
  
## KMS
  * Crypto keys with the following config should be rotated in 100 days.
    * algorithm: GOOGLE_SYMMETRIC_ENCRYPTION
    * protection_level: SOFTWARE
    * purpose: ENCRYPT_DECRYPT
    * state: ENABLED
    
## Kubernetes Engine Version
  * Only allow the following supported versions:
    * For major version 1.8, the minor version must be at least 12-gke.1
    * For major version 1.9, the minor version must be at least 7-gke.1
    * For major version 1.10, the minor version must be at least 2-gke.1
    * For major version 1.11, any minor version is allowed
    
## Lien
  * All projects in the specified organization should have liens to block
    the project's deletion.
    
## Location
  * Buckets in the specified organization must be in the US.
  * Buckets in the specified organization must not be in Europe.       
  
## Log Sink
  * Ensures all projects have specified log sinks.
  * Ensures destination and filter specified matches that of log sink's. 
  
## Resource
  * Resource trees should have a match in the Forseti inventory.

## Retention
  * All buckets and big tables in the organization should be deleted or 
    overwritten in the retention period specified.
  
## Role
  * Custom role granted to the projects should have the permissions you specify.

## Service Account Key
  * User-managed service account keys should not be older than the date and time you specify.
