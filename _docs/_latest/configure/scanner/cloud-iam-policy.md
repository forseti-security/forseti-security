---
title: Cloud IAM Policy Rules
order: 315 
---

# {{ page.title }}

## Description

This section describes rules for Cloud Identity and Access Management (Cloud IAM).

Cloud IAM policies directly grant access on GCP. To ensure only authorized
members and permissions are granted in Cloud IAM policies, IAM policy scanner
supports the following:

* Whitelist, blacklist, and required modes.
* Define if the scope of the rule inherits from parents or just self.
* Access to specific organization, folder, project or bucket resource types.

For examples of how to define scanner rules for Cloud IAM policies, see the
[`iam_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/iam_rules.yaml)
rule file.

## Rule definition

Forseti Scanner recognizes the following rule grammar in YAML or JSON:

```yaml
rules:
  - name: $rule_name
    mode: $rule_mode
    resource:
      - type: $resource_type
        applies_to: $applies_to
        resource_ids:
          - $resource_id1
          - $resource_id2
          - ...
    inherit_from_parents: $inherit_from
    bindings:
      - role: $role_name
        members:
          - $member1
          - $member2
          ...
```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `mode`
  * **Description**: The mode of the rule.
  * **Valid values**: One of `whitelist`, `blacklist` or `required`.
  * **Note**:
    * `whitelist`: Allow the members defined.
    * `blacklist`: Block the members defined.
    * `required`: Defined members with the specified roles must be found in policy.

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

* `inherit_from_parents`
  * **Description**: A boolean that defines whether a specified resource inherits ancestor rules.
  * **Valid values**: One of `true` or `false`.

* `bindings`
  * **Description**: The
  [Policy Bindings](https://cloud.google.com/iam/reference/rest/v1/Policy#binding) to audit.
    * `role`
      * **Description**: A [Cloud IAM role](https://cloud.google.com/compute/docs/access/iam).
      * **Valid values**: String.
      * **Example values**: `roles/editor`, `roles/viewer`
    * `members`
      * **Description**: A list of Cloud IAM members. You can also use wildcards.
      * **Valid values**: String.
      * **Example values**: `serviceAccount:*@*gserviceaccount.com` (all service accounts) or
        `user:*@company.com` (anyone with an identity at company.com).
