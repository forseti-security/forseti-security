## Role

**Description:** Control permissions that are actually in IAM roles - ensure 
that custom IAM roles do not have more permissions than they should to 
prevent access.

{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [role_rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/role_rules.yaml) | [gcp_iam_custom_role_permissions_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_iam_custom_role_permissions_v1.yaml) | [iam_allowed_roles.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/iam_custom_role_permissions.yaml)

### Rego constraint asset type

This Rego constraint can scan the following CAI asset type:

- iam.googleapis.com/Role

### Rego constraint properties

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| role_name | metadata.spec.parameters.title
| permissions | metadata.spec.parameters.permissions
| resource.resource_ids | metadata.spec.match.target


### Python scanner to Rego constraint sample

The following Python scanner rule utilizes the Role scanner to search for 
the ‘BigqueryViewer’ role to ensure that there are only the permissions defined. 

`role_rules.yaml`:
```
  - name: "The role BigqueryViewer contains exactly the following 3 permissions"
     role_name: "BigqueryViewer"
     permissions:
     - "bigquery.datasets.get"
     - "bigquery.tables.get"
     - "bigquery.tables.list"
     resource:
     - type: project
       resource_ids: ['*']

```

#### Rego sample constraint

Add the Rego constraint template 
[gcp_iam_custom_role_permissions_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_iam_custom_role_permissions_v1.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`iam_custom_role_permissions.yaml`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPIAMCustomRolePermissionsConstraintV1
metadata:
  name: allowlist-role-permissions
  annotations:
    description: Bigquery Viewer role must only have specific permissions
spec:
  severity: high
  parameters:
    mode: allowlist
    title: "Bigquery Viewer"
    permissions:
     - "bigquery.datasets.get"
     - "bigquery.tables.get"
     - "bigquery.tables.list"
```
