---
title: Google Cloud Storage Bucket ACL Rules
order: 340 
---

# {{ page.title }}

## Description

Cloud Storage buckets have ACLs that can grant public access to your
Cloud Storage bucket and objects. The bucket scanner supports a blacklist mode,
to ensure unauthorized users don't gain access to your Cloud Storage bucket.

For examples of how to define scanner rules for your Cloud Storage buckets, see the
[`bucket_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/bucket_rules.yaml) rule file.

## Rule definition

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

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `resource`
  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: String, you can use `*` to match for all.

* `bucket`
  * **Description**: The bucket name you want to audit.
  * **Valid values**: String, you can use `*` to match for all.

* `entity`
  * **Description**: The [ACL entity](https://cloud.google.com/storage/docs/access-control/lists) that holds the bucket permissions.
  * **Valid values**: String.
  * **Example values**: `AllUsers`

* `email`
  * **Description**: The email of the entity.
  * **Valid values**: String, you can use `*` to match for all.

* `domain`
  * **Description**: The domain of the entity.
  * **Valid values**: String, you can use `*` to match for all.

* `role`
  * **Description**: The access permission of the entity.
  * **Valid values**: String, you can use `*` to match for all.

For more information, refer to the
[BucketAccessControls](https://cloud.google.com/storage/docs/json_api/v1/objectAccessControls#resource)
documentation.
