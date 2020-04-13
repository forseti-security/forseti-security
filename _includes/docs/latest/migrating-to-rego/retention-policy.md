## Retention Policy

**Description:** Allow customers to ensure the retention policies on their 
resources are set as intended.

{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [retention_rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/retention_rules.yaml) | [gcp_storage_bucket_retention_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_storage_bucket_retention_v1.yaml)<br>[gcp_bigquery_table_retention_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_bigquery_table_retention_v1.yaml) | [storage_bucket_retention.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/storage_bucket_retention.yaml)<br>[bigquery_table_retention.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/bigquery_table_retention.yaml)

### Rego constraint asset type

[gcp_storage_bucket_retention_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_storage_bucket_retention_v1.yaml) scans for the following CAI asset types:

- storage.googleapis.com/Bucket

[gcp_bigquery_table_retention_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_bigquery_table_retention_v1.yaml) scans for the following CAI asset types:

- bigquery.googleapis.com/Table

### Rego constraint properties

[gcp_storage_bucket_retention_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_storage_bucket_retention_v1.yaml)

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| resource.resource_ids | metadata.spec.match.target
| minimum_retention | metadata.spec.parameters.minimum_retention_days
| maximmum_retention | metadata.spec.parameters.maximum_retention_days

[gcp_bigquery_table_retention_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_bigquery_table_retention_v1.yaml) 

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| resource.resource_ids | metadata.spec.match.target
| minimum_retention | metadata.spec.parameters.minimum_retention_days
| maximum_retention | metadata.spec.parameters.maximum_retention_days


### Python scanner to Rego constraint sample

The following Python scanner rule utilizes the Retention Policy scanner to 
require all buckets in organization with ID 123456 to have a retention shorter 
than 730 days.

`retention_rules.yaml`:
```
  - name: Buckets in Organization must have a retention shorter than 730 days.
     applies_to:
       - bucket
     resource:
       - type: organization
         resource_ids:
           - "1234556"
     maximum_retention: 730

```

Add the Rego constraint template 
[gcp_storage_bucket_retention_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_storage_bucket_retention_v1.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`storage_bucket_retention.yaml`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPStorageBucketRetentionConstraintV1
metadata:
  name: storage_bucket_maximum_retention
spec:
  severity: high
  match:
    target: ["organizations/123456"]
  parameters:
    maximum_retention_days: 730
    exemptions: []
```
