## IAM Policy
**Description:** Cloud IAM policies directly grant access on GCP. To ensure 
only authorized members and permissions are granted in Cloud IAM policies, 
IAM policy scanner supports the following:
- Whitelist, blacklist, and required modes.

{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [iam_rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/iam_rules.yaml) | [gcp_iam_allowed_bindings_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_iam_allowed_bindings_v1.yaml)<br>[gcp_iam_required_bindings_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_iam_required_bindings_v1.yaml) | [iam_allowed_roles.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/iam_allowed_roles.yaml)<br>[iam_restrict_gmail.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/iam_restrict_gmail.yaml)<br>[iam_blacklist_role.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/iam_blacklist_role.yaml)<br>[iam_blacklist_service_account_creator_role.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/iam_blacklist_service_account_creator_role.yaml)<br>[iam_blacklist_public.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/iam_blacklist_public.yaml)<br>[iam_restrict_role.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/iam_restrict_role.yaml)<br>[iam_required_roles.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/iam_required_roles.yaml)

### Rego constraint asset type

This Rego constraint can scan IAM policies for any CAI asset type with bindings. You can define the asset type(s) to look for in the constraint itself.

E.g.
- cloudresourcemanager.googleapis.com/Project

### Rego constraint properties

[gcp_iam_allowed_bindings_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_iam_allowed_bindings_v1.yaml) 

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| mode | metadata.spec.parameters.mode
| resource.resource_ids | metadata.spec.match.target
| bindings.role | metadata.spec.parameters.role
| bindings.members | metadata.spec.parameters.members

[gcp_iam_required_bindings_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_iam_required_bindings_v1.yaml)


{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| mode | metadata.spec.parameters.mode
| resource.resource_ids | metadata.spec.match.target
| bindings.role | metadata.spec.parameters.role
| bindings.members | metadata.spec.parameters.members

### Python scanner to Rego constraint sample

The following Python scanner rules utilizes the IAM Policy scanner to:
- Allow only IAM members in `my-cool-domai.comn` to be an OrgAdmin in organization with ID 123456.
- Prevent public users from having access to buckets via IAM in organization with ID 123456.

`iam_policy_rules.yaml`:
```
 rules:
  - name: Allow only IAM members in my domain to be an OrgAdmin
    mode: whitelist
    resource:
      - type: organization
        applies_to: self
        resource_ids:
          - '*'
    inherit_from_parents: true
    bindings:
      - role: roles/resourcemanager.organizationAdmin
        members:
          - user:*@my-cool-domain.com
          - group:*@my-cool-domain.com

  - name: Prevent public users from having access to buckets via IAM
    mode: blacklist
    resource:
      - type: bucket
        applies_to: self
        resource_ids:
          - '*'
    inherit_from_parents: true
    bindings:
      - role: '*'
        members:
          - allUsers

```

Add the Rego constraint template 
[gcp_iam_allowed_bindings_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_iam_allowed_bindings_v1.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`iam_whitelist_domain.yaml`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPIAMAllowedBindingsConstraintV1
metadata:
  name: whitelist_domain
spec:
  severity: high
  match:
    target: ["organizations/123456"]
  parameters:
    mode: whitelist
    role: “roles/resourcemanager.organizationAdmin”
    members:
    - "user:*@my-cool-domain.com"
    - “group:*@my-cool-domain.com”
```

`iam_blacklist_public.yaml`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPIAMAllowedBindingsConstraintV1
metadata:
  name: blacklist_all_users
spec:
  severity: high
  match:
    target: ["organizations/123456"]
  parameters:
    mode: blacklist
    assetType: “storage.googleapis.com/Bucket”
    role: "roles/*"
    members:
    - "allUsers"
    - "allAuthenticatedUsers"
```
