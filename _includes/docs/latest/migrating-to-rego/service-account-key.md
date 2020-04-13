## Service Account Key

**Description:** It’s best to periodically rotate your user-managed service 
account keys, in case the keys get compromised without your knowledge. With 
the service account key scanner, you can define the max age at which your 
service account keys should be rotated. The scanner will then find any key 
that is older than the max age.

{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [service_account_key_rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/service_account_key_rules.yaml) | [gcp_iam_restrict_service_account_key_age_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_iam_restrict_service_account_key_age_v1.yaml) | [gcp_iam_restrict_service_account_key_age.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/gcp_iam_restrict_service_account_key_age.yaml)

### Rego constraint asset type

This Rego constraint scans IAM policies for the following CAI asset types:

- iam.googleapis.com/ServiceAccountKey

### Rego constraint properties

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| resource.resource_ids | metadata.spec.match.target
| max_age | metadata.spec.parameters.max_age


### Python scanner to Rego constraint sample

The following Python scanner rules utilize the Service Account Key scanner to
define the max age at which the Service Account Keys should be rotated.

`service_account_key_rules.yaml`:
```

rules:
  # The max allowed age of user managed service account keys (in days)
  - name: Service account keys not rotated
    resource:
      - type: organization
        resource_ids:
          - '*'
    max_age: 100 # days
```

Add the Rego constraint template 
[gcp_iam_restrict_service_account_key_age_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_iam_restrict_service_account_key_age_v1.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`gcp_iam_restrict_service_account_key_age.yaml`:

```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPIAMRestrictServiceAccountKeyAgeConstraintV1
metadata:
  name: iam-restrict-service-account-key-age-ninety-days
  annotations:
    # This constraint is not certified by CIS.
    bundles.validator.forsetisecurity.org/cis-v1.1: 1.06
spec:
  severity: high
  parameters:
      max_age: 2160h
```
