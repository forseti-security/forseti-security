---
title: Google Cloud Storage Bucket Retention Rules
order: 341 
---

# {{ page.title }}

## Description

TODO: Provide an overview

## Rule definition

```yaml
rules:
  - name: All buckets in the organization should have a retention policy for 100 to 200 days.
    applies_to:
      - bucket
    resource:
      - type: organization
        resource_ids:
          - "123456789012"
    minimum_retention: 100 # days
    maximum_retention: 200 # days
```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.
  
* `applies_to`
  * `type`
    * **Description**: The type of resource to apply the rule to.
    * **Valid values**: String, Currently only supports `bucket`.

* `resource`
  * `type`
    * **Description**: The type of the resource.
    * **Valid values**: One of `organization`, `folder`, `project`
      or `bucket`.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: String.

* `minimum_retention`
  * **Description**: The minimum number of days to remain data.
    Remove this entry if it is not needed.
  * **Valid values**: Integer, number of days.

* `maximum_retention`
  * **Description**: The maximum number of days for which your data
    can be retained. Remove this entry if it is not needed.
  * **Valid values**: Integer, number of days.

    *Tip*: The rule must include a minimum_retention, maximum_retention or both.
