## Kubernetes Engine Version

**Description:** Kubernetes Engine clusters running on older versions can be 
exposed to security vulnerabilities, or lack of support. The KE version scanner 
can ensure your Kubernetes Engine clusters are running safe and supported 
versions.

{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [ke_rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/ke_rules.yaml) | [gcp_gke_cluster_version_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_gke_cluster_version_v1.yaml) | [gke_cluster_version.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/gke_cluster_version.yaml)

### Rego constraint asset type

This Rego constraint scans IAM policies for the following CAI asset types:

- container.googleapis.com/Cluster

### Rego constraint properties


{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| resource.resource_ids | metadata.spec.match.target
| allowed_nodepool_versions | metadata.spec.parameters.versions


### Python scanner to Rego constraint sample

The following Python scanner rule utilizes the Kubernetes Engine Version 
scanner to allow only specific nodepool versions.

`ke_rules.yaml`:
```
 - name: Nodepool version not patched for critical security vulnerabilities
    resource:
      - type: organization
        resource_ids:
          - '*'
    check_serverconfig_valid_node_versions: false
    check_serverconfig_valid_master_versions: false
    allowed_nodepool_versions:
        # Note: We must use = here because using >= will also allow earlier
        # versions of 11-gke.* and 12-gke.* (e.g. 11-gke.1) which might have
        # the vulnerabilities.
      - major: '1.8'
        minor: '10-gke.2'
        operator: '='
      - major: '1.9'
        minor: '6-gke.2'
        operator: '='

```

Add the Rego constraint template 
[gcp_gke_cluster_version_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_gke_cluster_version_v1.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`gke_allowlist_nodepool_versions.yaml`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GKEClusterVersionConstraintV1
metadata:
  name: gke-cluster-version
spec:
  severity: high
  match:
    target: ["organization/*"]
  parameters:
    mode: "allowlist"
    version_type: "master"
    versions:
      - 1.8.10-gke.2
      - 1.9.6-gke.2
    exemptions: []
```
