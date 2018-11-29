---
title: Cloud Audit Logging Rules
order: 310 
---

# {{ page.title }}

## Description

You can configure Cloud Audit Logging to save Admin Activity and Data Access for
Google Cloud Platform (GCP) services. The audit log configurations for a project,
folder, or organization specify which logs should be saved, along with members who
are exempted from having their accesses logged. The audit logging scanner detects
if any projects are missing a required audit log, or have extra exempted members.

For examples of how to define scanner rules for Cloud Audit Logging, see the
[`audit_logging_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/audit_logging_rules.yaml)
rule file.

## Rule definition

```yaml
rules:
  - name: sample audit logging rule for data access logging
    resource:
      - type: project
        resource_ids:
          - '*'
    service: 'storage.googleapis.com'
    log_types:
      - 'DATA_READ'
      - 'DATA_WRITE'
    allowed_exemptions:
      - 'user:user1@MYDOMAIN.com'
      - 'user:user2@MYDOMAIN.com'
 ```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `resource`
  * `type`
    * **Description**: The type of the resource.
    * **Valid values**: One of `organization`, `folder` or `project`.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: String, you can use `*` to match for all.

* `service`
  * **Description**: The service on which logs must be enabled. The special value of `allServices` denotes audit logs for all services.
  * **Valid values**: String.
  * **Example values**: `allServices`, `storage.googleapis.com`

* `log_types`
  * **Description**: The required log types.
  * **Valid values**: One of `ADMIN_READ`, `DATA_READ` or `DATA_WRITE`.

* `allowed_exemptions`
  * **Description**: Optional, a list of allowed exemptions in the audit logs for this service.
  * **Valid values**: String.
  * **Example values**: `user:user1@MYDOMAIN.com`
