---
title: Cloud SQL Network Rule
order: 325 
---

# {{ page.title }}

## Description

Cloud SQL instances can be configured to grant external networks access. The
Cloud SQL scanner supports a blacklist mode, to ensure unauthorized users don't
gain access to your Cloud SQL instances.

For examples of how to define scanner rules for your Cloud SQL instances, see
the
[`cloudsql_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/cloudsql_rules.yaml)
rule file.

## Rule definition

```yaml
rules:
  - name: sample Cloud SQL rule to search for publicly exposed instances
    instance_name: '*'
    authorized_networks: '0.0.0.0/0'
    ssl_enabled: 'False'
    resource:
      - type: organization
        resource_ids:
          - YOUR_ORG_ID / YOUR_PROJECT_ID
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

* `instance_name`
  * **Description**: The Cloud SQL instance to which you want to apply the rule.
  * **Valid values**: String, you can use `*` to match for all.

* `authorized_networks`
  * **Description**: The allowed network.
  * **Valid values**: String.
  * **Example values**: `0.0.0.0/0`

* `ssl_enabled`
  * **Description**: Whether SSL should be enabled.
  * **Valid values**: One of `true` or `false`.
