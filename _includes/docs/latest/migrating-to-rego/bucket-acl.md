## Bucket ACL

**Description:** Cloud Storage buckets have ACLs that can grant public access 
to your Cloud Storage bucket and objects. The bucket scanner supports a 
blacklist mode, to ensure unauthorized users don’t gain access to your 
Cloud Storage bucket.

{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [bucket_rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/bucket_rules.yaml) | [gcp_storage_bucket_world_readable_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_storage_bucket_world_readable_v1.yaml) | [storage_blacklist_public.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/storage_blacklist_public.yaml)

### Rego constraint asset type

This Rego constraint scans IAM policies for the following CAI asset types:

- storage.googleapis.com/Bucket

### Rego constraint properties

This Rego constraint can check for `allUsers` and `allAuthenticatedUsers` 
without defining specific properties in the constraint.

### Python scanner to Rego constraint sample

The following Python scanner rules utilize the Bucket ACL scanner to search 
for any public buckets in an organization with ID `123456`.

`bucket_rules.yaml`:
```
rules:
 - name: Bucket acls rule to search for public buckets
    bucket: '*'
    entity: allUsers
    email: '*'
    domain: '*'
    role: '*'
    resource:
        - resource_ids:
          - organizations/123456
  - name: Bucket acls rule to search for exposed buckets
    bucket: '*'
    entity: allAuthenticatedUsers
    email: '*'
    domain: '*'
    role: '*'
    resource:
        - resource_ids:
          - organizations/123456

```

Add the Rego constraint template 
[gcp_storage_bucket_world_readable_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_storage_bucket_world_readable_v1.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`storage_blacklist_public.yaml`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPStorageBucketWorldReadableConstraintV1
metadata:
  name: blacklist_public_users
spec:
  match:
    target: [“organizations/123456”]
  parameters: {}
```
