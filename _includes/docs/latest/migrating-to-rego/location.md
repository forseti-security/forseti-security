## Location

**Description:** Allow customers to ensure their resources are located only in 
the intended locations. Set guards around locations as part of automated project 
deployment.

{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [location_rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/location_rules.yaml) | [gcp_storage_location_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_storage_location_v1.yaml)<br><br>[gcp_sql_location_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_sql_location_v1.yaml)<br><br>[gcp_bq_dataset_location_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_bq_dataset_location_v1.yaml)<br><br>[gcp_gke_cluster_location_v2.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_gke_cluster_location_v2.yaml)<br><br>[gcp_compute_zone_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_compute_zone_v1.yaml) | [storage_location.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/storage_location.yaml)<br><br>[sql_location.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/sql_location.yaml)<br><br>[bq_dataset_location.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/bq_dataset_location.yaml)<br><br>[gke_cluster_location.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/gke_cluster_location.yaml)<br><br>[compute_zone.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/compute_zone.yaml)

### Rego constraint asset type

[gcp_storage_location_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_storage_location_v1.yaml) scans for the following CAI asset types:

- storage.googleapis.com/Bucket

[gcp_sql_location_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_sql_location_v1.yaml) scans for the following CAI asset types:

- sqladmin.googleapis.com/Instance

[gcp_bq_dataset_location_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_bq_dataset_location_v1.yaml) scans for the following CAI asset types:

- bigquery.googleapis.com/Dataset

[gcp_gke_cluster_location_v2.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_gke_cluster_location_v2.yaml) scans for the following CAI asset types:

- container.googleapis.com/Cluster

[gcp_compute_zone_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_compute_zone_v1.yaml) scans for the following CAI asset types:

- compute.googleapis.com/Instance
- compute.googleapis.com/Disk

### Rego constraint properties

[gcp_storage_location_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_storage_location_v1.yaml)

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| mode | metadata.spec.parameters.mode
| resource.resource_ids | metadata.spec.match.target
| locations | metadata.spec.parameters.locations

[gcp_sql_location_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_sql_location_v1.yaml)

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name
| metadata.name
| mode
| metadata.spec.parameters.mode
| resource.resource_ids
| metadata.spec.match.target
| locations
| metadata.spec.parameters.locations

[gcp_bq_dataset_location_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_bq_dataset_location_v1.yaml)

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| mode | metadata.spec.parameters.mode
| resource.resource_ids | metadata.spec.match.target
| locations | metadata.spec.parameters.locations

[gcp_gke_cluster_location_v2.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_gke_cluster_location_v2.yaml) 

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| mode | metadata.spec.parameters.mode
| resource.resource_ids | metadata.spec.match.target
| locations | metadata.spec.parameters.locations

[gcp_compute_zone_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_compute_zone_v1.yaml) 

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| mode | metadata.spec.parameters.mode
| resource.resource_ids | metadata.spec.match.target
| locations | metadata.spec.parameters.zones

### Python scanner to Rego constraint sample

The following Python scanner rule utilizes the Location scanner to ensure that 
all buckets in organization with ID 123456 are NOT be in EU.

`location_rules.yaml`:
```
- name: All buckets in organization must not be in EU.
  mode: blacklist
  resource:
   - type: organization
     resource_ids:
       - ${org_id}
  applies_to:
   - type: 'bucket'
     resource_ids:
       - '*'
  locations:
   - 'eu*'

```

Add the Rego constraint template 
[gcp_storage_location_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_storage_location_v1.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`storage_location_eu_denylist.yaml`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPStorageLocationConstraintV1
metadata:
  name: denylist_bucket_eu_location
spec:
  severity: high
  match:
    target: ["organizations/123456*"]
  parameters:
    mode: "denylist"
    locations:
    - europe-north1
    - europe-west1
    - europe-west2
    - europe-west3
    - europe-west4
    - europe-west6
    exemptions: []
```
