---
title: Resource Location Rules
order: 375 
---

# {{ page.title }}

## Description

Allow customers to ensure their resources are located only in the intended
locations. Set guards around locations as part of automated project deployment.

For examples of how to define scanner rules for location, see the
[`location_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/location_rules.yaml)
rule file.

## Rule definition

```yaml
rules:
  - name: All buckets in organization must be in the US.
    mode: whitelist
    resource:
      - type: organization
        resource_ids:
          - org-1
    applies_to:
      - type: 'bucket'
        resource_ids: '*'
    locations:
      - 'us*'
 - name: All buckets in organization must not be in EU.
    mode: blacklist
    resource:
      - type: organization
        resource_ids:
          - org-1
    applies_to:
      - type: 'bucket'
        resource_ids: '*'
    locations:
      - 'eu*'
```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `mode`
  * **Description**: The mode of the rule.
  * **Valid values**: One of `blacklist` or `whitelist`.

* `resource`
  * `type`
    * **Description**: The type of the resource the applies_to resources belong to.
    * **Valid values**: One of `organization`, `folder` or `project`.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: List of strings.

* `applies_to`
  * `type`
    * **Description**: The type of resource to apply the rule to.
    * **Valid values**: Currently only supports `bucket`.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: List of strings. A single wildcard string is also accepted.

* `locations`:
  * **Description**: A list of resource locations.
  * **Value values**: String. Supports wildcards.
  * **Note**:
    * Due to differences in capitalization among resource locations, all resources locations will be lower cased before being matched.
    * Due to differences in region (europe-west1) vs multi regional (EU) naming, we recommend writing rules that can cover both (e.g. eu* instead of europe*).
