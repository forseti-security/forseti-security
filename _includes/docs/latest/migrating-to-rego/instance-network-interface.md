## Instance Network Interface

**Description:** VM instances with external IP addresses expose your 
environment to an additional attack surface area. The instance network 
interface scanner audits all of your VM instances in your environment, 
and determines if any VMs with external IP addresses are outside of the 
trusted networks.

{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [instance_network_interface_<br>rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/instance_network_interface_rules.yaml) | [gcp_compute_allowed_networks.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_compute_allowed_networks.yaml) | [compute_allowed_networks.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/compute_allowed_networks.yaml)

### Rego constraint asset type

This Rego constraint scans IAM policies for the following CAI asset types:

- compute.googleapis.com/Instance

### Rego constraint properties

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| project | metadata.spec.match.target
| whitelist | metadata.spec.parameters.allowed

### Python scanner to Rego constraint sample

The following Python scanner rule utilizes the Instance Network Interface 
scanner to ensure instances with external IPs are only running on allowlisted 
networks and instances are only running on networks created in allowed projects 
(using XPN)

`instance_network_interface_rules.yaml`:
```
- name: all networks covered in allowlist
  project: '*'
  network: '*'
  is_external_network: True
  whitelist:
    project-1:
     - network-1
    project-2:
     - network-2
     - network-2-2
    project-3:
     - network-3

```

Add the Rego constraint template 
[gcp_compute_allowed_networks.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_compute_allowed_networks.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`gcp_compute_allowed_networks.yaml`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPComputeAllowedNetworksConstraintV2
metadata:
  name: allowed-networks
spec:
  severity: high
  match:
    gcp:
      target: ["organizations/123456"]
  parameters:
      allowed:
         - https://www.googleapis.com/compute/v1/projects/project-1/global/networks/network-1
         - https://www.googleapis.com/compute/v1/projects/project-2/global/networks/network-2
         - https://www.googleapis.com/compute/v1/projects/project-2/global/networks/network-2-2
         - https://www.googleapis.com/compute/v1/projects/project-3/global/networks/network-3
```
