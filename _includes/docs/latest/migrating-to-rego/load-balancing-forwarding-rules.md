## Load Balancer Forwarding Rules

**Description:** You can configure load balancer forwarding rules to direct 
unauthorized external traffic to your target instances. The forwarding rule 
scanner supports a whitelist mode, to ensure each forwarding rule only directs 
to the intended target instances.

{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [forwarding_rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/forwarding_rules.yaml) | [gcp_lb_forwarding_rules_whitelist.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_lb_forwarding_rules_whitelist.yaml)<br>[gcp_glb_external_ip_access_constraint_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_glb_external_ip_access_constraint_v1.yaml) | [gcp_lb_forwarding_rules_whitelist.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/gcp_lb_forwarding_rules_whitelist.yaml)<br>[gcp_glb_external_ip.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/gcp_glb_external_ip.yaml)

### Rego constraint asset type

The Rego constraints scan for the following CAI asset types:

- compute.googleapis.com/ForwardingRule
- compute.googleapis.com/GlobalForwardingRule

### Rego constraint properties

[gcp_lb_forwarding_rules_whitelist.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_lb_forwarding_rules_whitelist.yaml)

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| name | metadata.name
| target | metadata.spec.parameters.target
| mode | metadata.spec.parameters.whitelist
| load_balancing_scheme | metadata.spec.parameters.load_balancing_scheme
| ip_protocol | metadata.spec.parameters.ip_protocol
| ip_address | metadata.spec.parameters.ip_address


### Python scanner to Rego constraint sample

The following Python scanner rules utilize the Load Balancer Forwarding Rules 
scanner to only allow UDP load balancers for external VPN.
`forwarding_rules.yaml`:
```
  - name: UDP LB for External VPN
    target: https://www.googleapis.com/compute/v1/projects/THEPROJECT/regions/us-central1/THELB/FWD_RULE_NAME
    mode: whitelist
    load_balancing_scheme: EXTERNAL
    port_range: 4500-4500
    ip_protocol: UDP
    ip_address: "198.51.100.99"

```

Add the Rego constraint template 
[gcp_lb_forwarding_rules_whitelist.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_lb_forwarding_rules_whitelist.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`gcp_lb_forwarding_rule_whitelist`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPLBForwardingRuleWhitelistConstraintV1
metadata:
  name: gcp_lb_forwarding_rule_whitelist
spec:
  severity: high
  parameters:
    whitelist:
     - target: https://www.googleapis.com/compute/v1/projects/THEPROJECT/regions/us-central1/THELB/FWD_RULE_NAME
       load_balancing_scheme: EXTERNAL
       port_range: 4500-4500
       ip_protocol: UDP
       ip_address: "198.51.100.99"
```
