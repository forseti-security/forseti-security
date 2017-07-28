---
title: Defining Rules for Forseti Scanner
order: 105
---
#  {{ page.title }}

This page describes how to define rules for Forseti Scanner.

## Defining custom rules

By default, the DM template includes a rules.yaml file that allows service
accounts on the organization and its children Cloud IAM policies. To define
custom rules, edit your `rules.yaml` and then upload to your `SCANNER_BUCKET`.
The `forseti_instance.py` template defaults to `gs://SCANNER_BUCKET/rules`.
If you've stored `rules.yaml` in a different location, make sure to update the
template. You'll need to replace every instance of `rules/rules.yaml` with the
appropriate path.

## Defining Cloud IAM policy rules

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

  - `rules`: a sequence of rules.
  - `mode`: a string of one of the following values:
    - `whitelist`: allow the members defined.
    - `blacklist`: block the members defined
    - `required`: defined members with the specified roles must be found in
    policy.
  - `resource_type`: a string of one of the following values:
    - `organization`
    - `folder` (coming soon)
    - `project`
  - `applies_to`: a string of one of the following values:
    - `self`: the rule only applies to the specified resource
    - `children`: the rule only applies to the child resources of the specified
    resource.
    - `self_and_children`: the rule applies to the specified resource and its
    child resources.
  - `inherit_from_parents`: a true or false boolean that defines whether a
  specified resource inherits ancestor rules.
  - `role_name`: a [Cloud IAM role](https://cloud.google.com/compute/docs/access/iam)
  such as `roles/editor` or `roles/viewer`.
    - You can also use wildcards, such as `roles/*`. Refer to samples or the
    unit tests directory for examples.
  - `members`: a list of Cloud IAM members, such as `username@company.com`.
  You can also use wildcards, such as `serviceAccount:@.gserviceaccount.com`
  (any service accounts).

## What's next

  - Learn more about
  [Cloud IAM Policy](https://cloud.google.com/iam/reference/rest/v1/Policy)
  including user types.
