## Cloud SQL

**Description:** Cloud SQL instances can be configured to grant external 
networks access. The Cloud SQL scanner supports a blacklist mode, to ensure 
unauthorized users don’t gain access to your Cloud SQL instances.

{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [cloudsql_rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/cloudsql_rules.yaml) | [gcp_sql_ssl_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_sql_ssl_v1.yaml)<br>[gcp_sql_allowed_authorized_networks_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_sql_allowed_authorized_networks_v1.yaml)<br>[gcp_sql_public_ip_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_sql_public_ip_v1.yaml) | [sql_ssl.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/sql_ssl.yaml)<br>[sql_allowed_authorized_networks.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/sql_allowed_authorized_networks.yaml)<br>[sql_public_ip.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/sql_public_ip.yaml) 


### Rego constraint asset type

The Rego constraints scan IAM policies for the following CAI asset types:

- sqladmin.googleapis.com/Instance

### Rego constraint properties

[gcp_sql_ssl_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_sql_ssl_v1.yaml) 
constraint checks that all SQL instances have required SSL without defining 
specific properties to the constraint.

[gcp_sql_public_ip_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_sql_public_ip_v1.yaml) 
constraint checks that all SQL instances do not have public IPs.

[gcp_sql_allowed_authorized_networks_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_sql_allowed_authorized_networks_v1.yaml)

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| resource.resource_ids | metadata.spec.match.target
| authorized_networks | metadata.spec.parameters.authorized_networks

### Python scanner to Rego constraint sample

The following Python scanner rules utilize the Cloud SQL scanner to search for 
publicly exposed Cloud SQL instances where SSL is enabled in organization with 
ID `123456`.

`cloudsql_rules.yaml`:
```
name: Cloud SQL rule to search for publicly exposed instances (SSL enabled)
    instance_name: '*'
    authorized_networks: '0.0.0.0/0'
    ssl_enabled: 'True'
    resource:
      - type: organization
        resource_ids:
          - ${org_id}

```

#### Rego sample constraints

Add the Rego constraint template [gcp_sql_allowed_authorized_networks_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_sql_allowed_authorized_networks_v1.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`require_sql_ssl.yaml`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPSQLSSLConstraintV1
metadata:
  name: require_sql_ssl
spec:
  match:
    target: [“organizations/123456”]
  severity: high
  parameters: {}
```

Add the Rego constraint template [gcp_sql_public_ip_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_sql_public_ip_v1.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`prevent_public_ip_sql.yaml`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPSQLPublicIpConstraintV1
metadata:
  name: prevent_public_ip_sql
spec:
  match:
    target: [“organizations/123456”]
  severity: high
  parameters: {}
```
