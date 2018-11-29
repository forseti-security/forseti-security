---
title: Service Account Key Rules
order: 385 
---

# {{ page.title }}

## Description

It's best to periodically rotate your user-managed service account
keys, in case the keys get compromised without your knowledge. With the
service account key scanner, you can define the max age at which your service
account keys should be rotated. The scanner will then find any key that is older
than the max age.

For examples of how to define scanner rules for your service account keys, see the
[`service_account_key_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/service_account_key_rules.yaml)
file.

## Rule definitions

 ```yaml
 rules:
  # The max allowed age of user managed service account keys (in days)
  - name: Service account keys not rotated
    resource:
      - type: organization
        resource_ids:
          - '*'
    max_age: 100 # days
 ```

* `name`
  * **Description**: The name of the rule
  * **Valid values**: String.

* `type`
  * **Description**: The type of the resource this rule applies to.
  * **Valid values**: String, one of `organization`, `folder` or `project`.

* `resource_ids`
  * **Description**: The id of the resource this rule applies to.
  * **Valid values**: String, you can use `*` to match for all.

* `max_age`
  * **Description**: The maximum number of days at which your service account keys can exist before rotation is required.
  * **Valid values**: String, number of days.
