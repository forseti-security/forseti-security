---
title: Google Kubernetes Engine Version Rules
order: 346 
---

# {{ page.title }}

## Description

Kubernetes Engine clusters running on older versions can be exposed to security
vulnerabilities, or lack of support. The KE version scanner can ensure your
Kubernetes Engine clusters are running safe and supported versions.

For examples of how to define scanner rules for your Kubernetes Engine versions, see the
[`ke_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/ke_rules.yaml)
file.

## Rule definition

```yaml
rules:
  - name: Nodepool version not patched for critical security vulnerabilities
    resource:
      - type: organization
        resource_ids:
          - '*'
    check_serverconfig_valid_node_versions: false
    check_serverconfig_valid_master_versions: false
    allowed_nodepool_versions:
      - major: '1.6'
        minor: '13-gke.1'
        operator: '>='
      - major: '1.7'
        minor: '11-gke.1'
        operator: '>='
      - major: '1.8'
        minor: '4-gke.1'
        operator: '>='
      - major: '1.9'
        operator: '>='
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

* `check_serverconfig_valid_node_versions`
  * **Description**: If true, will raise a violation for any node pool running a version
  that is not listed as supported for the zone the cluster is running in.
  * **Valid values**: One of `true` or `false`.

* `check_serverconfig_valid_master_versions`
  * **Description**: If true, will raise a violation for any cluster running an out of
  date master version. New clusters can only be created with a supported master version.
  * **Valid values**: One of `true` or `false`.

* `allowed_nodepool_versions`
  * **Description**: Optional, if not included all versions are allowed.
  The list of rules for what versions are allowed on nodes.
    * `major`
      * **Description**: The major version that is allowed.
      * **Valid values**: String.
      * **Example values**: `1.6`, `1.7`, `1.8`

    * `minor`
      * **Description**: Optional, the minor version that is allowed. If not included, all minor
      versions are allowed.
      * **Valid values**: String.
      * **Example values**: `11-gke.1`, `12-gke.1`

    * `operator`
      * **Description**: Optional, defaults to =, can be one of (=, >, <, >=, <=). The operator
      determines how the current version compares with the allowed version. If a minor version is
      not included, the operator applies to major version. Otherwise it applies to minor versions
      within a single major version.
      * **Valid values**: String.
      * **Example values**: `>=`
