## Enabled APIs

**Description:** The Enabled APIs scanner detects if a project has appropriate 
APIs enabled. It supports allowlisting supported APIs, denylisting unsupported 
APIs, and specifying required APIs that must be enabled.

{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [enabled_apis_rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/enabled_apis_rules.yaml) | [gcp_serviceusage_allowed_services_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_serviceusage_allowed_services_v1.yaml) | [serviceusage_allow_basic_apis.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/serviceusage_allow_basic_apis.yaml)<br><br>[serviceusage_deny_apis.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/serviceusage_deny_apis.yaml)

### Rego constraint asset type

This Rego constraint scans for the following CAI asset types:

- serviceusage.googleapis.com/Service

### Rego constraint properties

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| mode | metadata.spec.parameters.mode
| resource.resource_ids | metadata.spec.match.target
| services | metadata.spec.parameters.services

### Python scanner to Rego constraint sample

The following Python scanner rule utilizes the Enabled APIs scanner to search 
for any APIs that are not listed in the allowed services defined.

`enabled_apis_rules.yaml`:
```
   - name: Example Enabled APIs allowlist
     mode: whitelist
     resource:
       - type: project
         resource_ids:
           - '*'
     services:
       - 'bigquery.googleapis.com'
       - 'clouddebugger.googleapis.com'
       - 'cloudtrace.googleapis.com'
       - 'compute.googleapis.com'
       - 'container.googleapis.com'
       - 'containerregistry.googleapis.com'
       - 'deploymentmanager.googleapis.com'
       - 'language.googleapis.com'
       - 'logging.googleapis.com'
       - 'monitoring.googleapis.com'
       - 'pubsub.googleapis.com'
       - 'replicapool.googleapis.com'
       - 'replicapoolupdater.googleapis.com'
       - 'resourceviews.googleapis.com'
       - 'servicemanagement.googleapis.com'
       - 'serviceusage.googleapis.com'
       - 'sql-component.googleapis.com'
       - 'storage-api.googleapis.com'
       - 'storage-component.googleapis.com'
       - 'translate.googleapis.com'

```

Add the Rego constraint template 
[gcp_serviceusage_allowed_services_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_serviceusage_allowed_services_v1.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`serviceusage_allow_apis.yaml`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPServiceUsageConstraintV1
metadata:
  name: allow_apis
spec:
  severity: high
  match:
    target: ["organization/123456"]
  parameters:
    mode: allow
    services:
     - 'bigquery.googleapis.com'
     - 'clouddebugger.googleapis.com'
     - 'cloudtrace.googleapis.com'
     - 'compute.googleapis.com'
     - 'container.googleapis.com'
     - 'containerregistry.googleapis.com'
     - 'deploymentmanager.googleapis.com'
     - 'language.googleapis.com'
     - 'logging.googleapis.com'
     - 'monitoring.googleapis.com'
     - 'pubsub.googleapis.com'
     - 'replicapool.googleapis.com'
     - 'replicapoolupdater.googleapis.com'
     - 'resourceviews.googleapis.com'
     - 'servicemanagement.googleapis.com'
     - 'serviceusage.googleapis.com'
     - 'sql-component.googleapis.com'
     - 'storage-api.googleapis.com'
     - 'storage-component.googleapis.com'
     - 'translate.googleapis.com'
```
