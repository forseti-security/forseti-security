---
title: Defining Rules
order: 103
---
# {{ page.title }}
This page describes how to define rules for Forseti Scanner.

## Defining custom rules

You can find some starter rules in the [rules](https://github.com/GoogleCloudPlatform/forseti-security/tree/dev/rules) 
directory. When you make changes to the rule files, upload them to your 
Forseti bucket or copy them to the `rules_path` (found in `forseti_conf.yaml`).

## Cloud IAM policy rules

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

- **rules**: a sequence of rules.
- **mode**: a string of one of the following values:
  - **whitelist**: allow the members defined.
  - **blacklist**: block the members defined
  - **required**: defined members with the specified roles must be found in
    policy.
- **resource_type**: a string of one of the following values:
  - **organization**
  - **folder** (coming soon)
  - **project**
- **applies_to**: a string of one of the following values:
  - **self**: the rule only applies to the specified resource
  - **children**: the rule only applies to the child resources of the
    specified resource.
  - **self_and_children**: the rule applies to the specified resource and its
    child resources.
- **inherit_from_parents**: a true or false boolean that defines whether a
  specified resource inherits ancestor rules.
- **role_name**: a
  [Cloud IAM role](https://cloud.google.com/compute/docs/access/iam) such as
  **roles/editor** or **roles/viewer**.
  - You can also use wildcards, such as **roles/***. Refer to samples or the
    unit tests directory for examples.
- **members**: a list of Cloud IAM members, such as **username@company.com**. You
  can also use wildcards, such as **serviceAccount:@.gserviceaccount.com** (any
  service accounts).

## Google Groups rules

```yaml
- name: Allow my company users and gmail users to be in my company groups.
  group_email: my_customer
  mode: whitelist
  conditions:
    - member_email: '@MYDOMAIN.com'
    - member_email: '@gmail.com'
```

## GCS bucket ACL rules

```yaml
rules:
  - name: sample bucket acls rule to search for public buckets
    bucket: '*'
    entity: AllUsers
    email: '*'
    domain: '*'
    role: '*'
    resource:
        - resource_ids:
          - YOUR_ORG_ID / YOUR_PROJECT_ID
```

 - **name**: The description of your rule.
 - **bucket**: The bucket name you want to audit.
 - **entity**: The [ACL entity](https://cloud.google.com/storage/docs/access-control/lists) holding the bucket permissions.
 - **email**: The email of the entity.
 - **domain**: The domain of the entity.
 - **role**: The access permission of the entity.
 - **resource**: The resource under which the bucket resides.

For more information, refer to the [BucketAccessControls](https://cloud.google.com/storage/docs/json_api/v1/objectAccessControls#resource) documentation.

## Cloud SQL rules

Coming soon.

## BigQuery rules

Coming soon.

## Forwarding rules

Coming soon.

## IAP rules

Coming soon.

## What's next

-   Learn more about
    [Cloud IAM Policy](https://cloud.google.com/iam/reference/rest/v1/Policy)
    including user types.
