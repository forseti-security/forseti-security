---
title: Enabled APIs Rules
order: 330 
---

# {{ page.title }}

## Description

The Enabled APIs scanner detects if a project has appropriate APIs enabled. It
supports whitelisting supported APIs, blacklisting unsupported APIs, and
specifying required APIs that must be enabled.

For examples of how to define scanner rules for Enabled APIs, see the
[`enabled_apis_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/enabled_apis_rules.yaml)
rule file.

## Rule definition

```yaml
rules:
  - name: sample enabled APIs whitelist rule
    mode: whitelist
    resource:
      - type: project
        resource_ids:
          - '*'
    services:
      - 'bigquery-json.googleapis.com'
      - 'compute.googleapis.com'
      - 'logging.googleapis.com'
      - 'monitoring.googleapis.com'
      - 'pubsub.googleapis.com'
      - 'storage-api.googleapis.com'
      - 'storage-component.googleapis.com'
 ```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `mode`
  * **Description**: The mode of the rule.
  * **Valid values**: One of `whitelist`, `blacklist` or `required`.
  * **Note**:
    * `whitelist`: Allow only the APIs listed in `services`.
    * `blacklist`: Block the APIs listed in `services`.
    * `required`: All APIs listed in `services` must be enabled.

* `resource`
  * `type`
    * **Description**: The type of the resource.
    * **Valid values**: One of `organization`, `folder` or `project`.

  * `applies_to`
    * **Description**: What resources to apply the rule to.
    * **Valid values**: One of `self`, `children` or `self_and_children`.
    * **Note**:
      * `self`: Allow the members defined.
      * `children`: Block the members defined.
      * `self_and_children`: The rule applies to the specified resource and its child resources.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: String, you can use `*` to match for all.

* `services`
  * **Description**: The list of services to whitelist/blacklist/require.
  * **Valid values**: String.
  * **Example values**: `bigquery-json.googleapis.com`, `logging.googleapis.com`
