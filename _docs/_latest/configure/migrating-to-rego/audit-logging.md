## Audit Logging

**Description:** You can configure Cloud Audit Logging to save Admin Activity 
and Data Access for Google Cloud Platform (GCP) services. The audit log 
configurations for a project, folder, or organization specify which logs should 
be saved, along with members who are exempted from having their accesses logged. 
The audit logging scanner detects if any projects are missing a required audit 
log, or have extra exempted members.


{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [audit_logging_rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/audit_logging_rules.yaml) |
| [gcp_iam_audit_log.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_iam_audit_log.yaml) |
| [iam_audit_log.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/iam_audit_log.yaml) |

### Rego constraint asset type

This Rego constraint scans IAM policies for the following CAI asset types:

- cloudresourcemanager.googleapis.com/Organization
- cloudresourcemanager.googleapis.com/Folder
- cloudresourcemanager.googleapis.com/Project

### Rego constraint properties

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name |
| resource.resource_ids | metadata.spec.match.target |
| service | metadata.spec.parameters.services |
| log_types | metadata.spec.parameters.log_types |
| allowed_exemptions | metadata.spec.parameters.allowed_exemptions |


### Python scanner to Rego constraint sample

The following Python scanner rule utilizes the Audit Logging scanner to require all logging (log_types) for the Compute service (compute.googleapis.com) in two projects (`proj-1`, `proj-2`), with two exempted members (`user:user1@org.com`, `user:user12@org.com`).

`audit_logging_rules.yaml`:
```
  - name: 'Require all logging for compute, with exemptions.'
     resource:
       - type: project
         resource_ids:
           - 'proj-1'
           - 'proj-2'
     service: 'compute.googleapis.com'
     log_types:
       - 'ADMIN_READ'
       - 'DATA_READ'
       - 'DATA_WRITE'
     allowed_exemptions:
       - 'user:user1@org.com'
       - 'user:user2@org.com'

```

Rego sample constraint:

Add the Rego constraint template 
[gcp_iam_audit_log.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_iam_audit_log.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`iam_audit_log_data_read_write_exemptions.yaml`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPIAMAuditLogConstraintV1
metadata:
  name: audit_log_data_read_write_exemptions
spec:
  match:
    target: [“**/projects/proj-1”, “**/projects/proj-2”]
  parameters:
    services: [“compute.googleapis.com”]
    log_types: [“ADMIN_READ”, “DATA_READ”, “DATA_WRITE”]
    exemptions: [“user:user1@org.com”, “user:user2@org.com”]
```

