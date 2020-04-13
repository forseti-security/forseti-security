## Kubernetes Engine

**Description:** Kubernetes Engine clusters have a wide-variety of options. 
You might want to have standards so your clusters are deployed in a uniform 
fashion. Some of the options can introduce unnecessary security risks. 
The KE scanner allows you to write rules that check arbitrary cluster properties 
for violations. It supports the following features:

- Any cluster property can be checked in a rule by providing a JMESPath expression that extracts the right fields.
See http://jmespath.org/ for a tutorial and detailed specifications.
- Rules can be whitelists or blacklists.

{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [ke_scanner_rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/ke_scanner_rules.yaml) | [gcp_resource_value_pattern_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_resource_value_pattern_v1.yaml) | [gke_enable_logging.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/gke_enable_logging.yaml)

### Rego constraint asset type

This Rego constraint can scan for any CAI asset type. You can define the asset 
type(s) to look for in the constraint itself.

E.g.
- container.googleapis.com/Cluster
- bigquery.googleapis.com/Dataset
- storage.googleapis.com/Bucket


### Rego constraint properties

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| resource.type | metadata.spec.parameters.asset_types
| resource.resource_ids | metadata.spec.match.target
| key | metadata.spec.parameters.field_name
| mode | metadata.spec.parameters.mode
| values | metadata.spec.parameters.pattern

### Python scanner to Rego constraint sample

The following Python scanner rule utilizes the Kubernetes Engine scanner to 
require that all logging is enabled in Kubernetes clusters.

`ke_scanner.yaml`:
```
 - name: logging should be enabled
    resource:
      - type: project
        resource_ids:
          - '*'
    key: loggingService
    mode: whitelist
    values:
      - logging.googleapis.com

```

#### Rego sample constraint

Add the Rego constraint template 
[gcp_resource_value_pattern_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_resource_value_pattern_v1.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`gke_enable_logging.yaml`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPResourceValuePatternConstraintV1
metadata:
  name: gke-cluster-enable-logging
spec:
  severity: high
  match:
    target: ["organizations/123456"]
  parameters:
    mode: allowlist
    asset_types:
        - "container.googleapis.com/Cluster"
    field_name: "loggingService"
    pattern: "logging.googleapis.com"
```
