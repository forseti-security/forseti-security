## KMS

**Description:** You can configure the KMS scanner to alert if the enabled 
cryptographic keys in the organization are not rotated within the time 
specified. You can also check if the algorithm, protection level and purpose 
of the cryptographic key is correctly configured.

{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [kms_rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/kms_rules.yaml) | [gcp_cmek_settings_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_cmek_settings_v1.yaml) | [cmek_settings.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/cmek_settings.yaml)<br><br>[cmek_rotation_100_days.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/cmek_rotation_100_days.yaml)<br><br>[cmek_rotation.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/cmek_rotation.yaml)

### Rego constraint asset type

This Rego constraint scans IAM policies for the following CAI asset types:

- cloudkms.googleapis.com/CryptoKey

### Rego constraint properties

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| resource.resource_ids | metadata.spec.match.target
| key.rotation_period | metadata.spec.parameters.rotation_period
| key.algorithms | metadata.spec.parameters.algorithms
| key.protection_level | metadata.spec.parameters.protection_level
| key.purpose | metadata.spec.parameters.purpose

### Python scanner to Rego constraint sample

The following Python scanner rule utilizes the KMS scanner to require the 
cryptographic keys in the organization to be rotated within the time specified 
(rotation_period), and to ensure that algorithm, protection level 
(protection_level) and purpose are correctly configured.

`kms_rules.yaml`:

```
rules:
  - name: All crypto keys with following config should be rotated in 100 days
    mode: whitelist
    resource:
      - type: organization
        resource_ids:
          - '*'
    key:
       -  rotation_period: 100 #days
         algorithms:
         - GOOGLE_SYMMETRIC_ENCRYPTION
         protection_level: SOFTWARE
         purpose:
         - ENCRYPT_DECRYPT
```

Add the Rego constraint template 
[gcp_cmek_settings_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_cmek_settings_v1.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`cmek_settings.yaml`:

```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPCMEKRotationConstraintV1
metadata:
  name: cmek_rotation_one_hundred_days
spec:
  severity: high
  match:
    target: ["organization/*"]
  parameters:
    period: 2400h
    algorithm: GOOGLE_SYMMETRIC_ENCRYPTION
    purpose: ENCRYPT_DECRYPT
    protection_level: SOFTWARE
```
