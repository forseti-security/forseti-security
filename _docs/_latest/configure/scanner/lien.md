---
title: Resource Lien Rules
order: 365 
---

# {{ page.title }}

## Description

Allow customers to ensure projects do not get deleted, by ensuring Liens for 
their projects exist and are configured correctly.

For examples of how to define scanner rules for lien, see the
[`lien_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/lien_rules.yaml)
rule file.

## Rule definition

```yaml
rules:
- name: Require project deletion liens for all projects in the organization.
  mode: required
  resource:
  - resource_ids:
    - org-1
    type: organization
  restrictions:
  - resourcemanager.projects.delete
```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `mode`
  * **Description**: The mode of the rule.
  * **Valid values**: Currently only supports `required`.

* `resource`
  * `type`
    * **Description**: The type of the resource.
    * **Valid values**: One of `organization`, `folder` or `project`.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: String.

* `restrictions`
  * **Description**: A list of restrictions to check for.
  * **Valid values**: Currently only supports `resourcemanager.projects.delete`.
