## BigQuery Dataset ACL

**Description:** BigQuery datasets have access properties that can publicly 
expose your datasets. The BigQuery scanner supports blacklist and whitelist 
modes to ensure unauthorized users don’t gain access to your datasets, and only 
authorized users can gain access.

{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [bigquery_rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/bigquery_rules.yaml) | [gcp_iam_allowed_bindings_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_iam_allowed_bindings_v1.yaml) | [iam_blacklist_public.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/iam_blacklist_public.yaml)

### Rego constraint asset type

This Rego constraint can scan IAM policies for any CAI asset type with bindings. 
You can define the asset type(s) to look for in the constraint itself.

E.g.
- bigquery.googleapis.com/Dataset
- storage.googleapis.com/Bucket

### Rego constraint properties

This Rego constraint utilizes the following properties:

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| mode | metadata.spec.parameters.mode
| resource.resource_ids | metadata.spec.match.target
| dataset_ids | metadata.spec.parameters.assetNames
| bindings.role | metadata.spec.parameters.role
| bindings.members | metadata.spec.parameters.members


### Python scanner to Rego constraint sample

The following Python scanner rule utilizes the BigQuery Dataset ACL scanner to 
search for any datasets in an organization with ID `123456` that are accessible 
by groups with `googlegroups.com` addresses.

`bigquery_rules.yaml`:
```
 - name: BigQuery rule to search for datasets accessible by groups with googlegroups.com addresses
    mode: blacklist
    resource:
      - type: organization
        resource_ids:
          - 123456
    dataset_ids: ['*']
    bindings:
      - role: '*'
        members:
        - group_email: '*@googlegroups.com'

```

Rego sample constraint:

Add the Rego constraint template 
[gcp_iam_allowed_bindings_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_iam_allowed_bindings_v1.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`bigquery_rules_iam_blacklist_googlegroups.yaml`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPIAMAllowedBindingsConstraintV1
metadata:
  name: bigquery_rules_iam_blacklist_googlegroups
spec:
  match:
    target: [“organizations/123456”]
  parameters:
    mode: “blacklist”
    assetType: “bigquery.googleapis.com/Dataset”
    role: "roles/*"
    members:
    - "group:*@googlegroups.com"
```
