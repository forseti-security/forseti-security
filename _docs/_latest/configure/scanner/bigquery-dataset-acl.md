---
title: BigQuery Dataset ACL Rules
order: 305 
---

# {{ page.title }}

## Description

BigQuery datasets have access properties that can publicly expose your datasets.
The BigQuery scanner supports a blacklist mode to ensure unauthorized users
don't gain access to your datasets.

For examples of how to define scanner rules for your BigQuery datasets, see the
[`bigquery_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/bigquery_rules.yaml)
rule file.

## Rule definition

BigQuery scanner rules can be blacklists or whitelists, for example:

```yaml
rules:
  - name: sample BigQuery rule to search for public datasets
    mode: blacklist
    resource:
      - type: organization
        resource_ids:
          - YOUR_ORG_ID / YOUR_PROJECT_ID
    dataset_ids: ['*']
    bindings:
      - role: '*'
        members:
          - special_group: 'allAuthenticatedUsers'
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

* `dataset_ids`
  * **Description**: List of BigQuery datasets to which you want to apply the rule.
  * **Valid values**: String, you can use `*` to match for all.

* `bindings`
  * **Description**: The BigQuery ACL rule bindings to bind members to a role.
    * `role`
      * **Description**: A [BigQuery ACL role](https://cloud.google.com/storage/docs/access-control/lists).
      * **Valid values**: One of `OWNER`, `WRITER` or `READER`.
    * `members`
      * **Description**: A list of members. You can also use an empty list. Only a single field must be set per member.
        * `domain` 
          * **Description**: Domain.
          *  **Valid values**: String.
        * `group_email`
          * **Description**: Group email.
          * **Valid values**: String.
        * `user_email`
          * **Description**: User email.
          * **Valid values**: String.
        * `special_group`
          * **Description**: Special group.
          * **Valid values**: String.

* `special_group`
  * **Description**: The special group. ***DEPRECATED, please use bindings instead.***
  * **Valid values**: String, you can use `*` to match for all.

* `domain`
  * **Description**: Domain. ***DEPRECATED, please use bindings instead.***
  * **Valid values**: String, you can use `*` to match for all.

* `role`
  * **Description**: Role. ***DEPRECATED, please use bindings instead.***
  * **Valid values**: One of `OWNER`, `WRITER` or `READER`.

* `group_email`
  * **Description**: Group email. ***DEPRECATED, please use bindings instead.***
  * **Valid values**: String, you can use `*` to match for all.

* `user_email`
  * **Description**: User email. ***DEPRECATED, please use bindings instead.***
  * **Valid values**: String, you can use `*` to match for all.

The BigQuery Scanner rules specify entities that are allowed or not allowed 
(depending on mode) to access your datasets. 
For blacklists, when you set a value of `*` for `special_group`, `user_email`,
`domain`, or `group_email`, the Scanner checks to make sure that no entities that 
have the field set can access your datasets. If you specify any other value, the 
Scanner only checks to make sure that the entity you specified doesn't have access.
For whitelists, the specified entity specifies who has access to your datasets.
Any entity that does not match a whitelist binding will be marked as a violation.
