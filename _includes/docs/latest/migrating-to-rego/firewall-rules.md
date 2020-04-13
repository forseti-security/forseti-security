## Firewall Rules

**Description:** Network firewall rules protect your network & organization by 
only allowing desired traffic into and out of your network. The firewall rules 
scanner can ensure that all your network’s firewalls are properly configured.

{: .table .table-striped}
| Python Scanner | Rego Constraint Template | Constraint Sample
| ------------- | ------------- | -----------------
| [firewall_rules.yaml](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/firewall_rules.yaml) | [https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_restricted_firewall_rules_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_restricted_firewall_rules_v1.yaml) | [restrict_fw_rules_generic.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/restrict_fw_rules_generic.yaml)<br>[restrict_fw_rules_world_open.yaml](https://github.com/forseti-security/policy-library/blob/master/samples/restrict_fw_rules_world_open.yaml)

### Rego constraint asset type

This Rego constraint scans for the following CAI asset types:

- compute.googleapis.com/Firewall

### Rego constraint properties

{: .table .table-striped}
| Python Scanner field | Rego Constraint field
| ------------- | -------------
| rule_id | metadata.name
| mode | metadata.spec.parameters.mode
| direction | metadata.spec.parameters.rules.direction
| allowed | metadata.spec.parameters.rules.rule_type
| denied | metadata.spec.parameters.rules.rule_type
| allowed.IPProtocol | metadata.spec.parameters.rules.protocol
| allowed.ports | metadata.spec.parameters.rules.port
| denied.IPProtocol | metadata.spec.parameters.rules.protocol
| denied.ports | metadata.spec.parameters.rules.ports
| sourceRanges | metadata.spec.parameters.rules.source_ranges
| sourceServiceAccounts | metadata.spec.parameters.rules.source_service_accounts
| sourceTags | metadata.spec.parameters.rules.source_tags
| destinationRanges | metadata.spec.parameters.rules.target_ranges
| targetServiceAccounts | metadata.spec.parameters.rules.target_service_accounts
| targetTags | metadata.spec.parameters.rules.target_tags

### Python scanner to Rego constraint sample

The following Python scanner rules utilize the Firewall Rules scanner to search 
for policies that allow ingress and expose every port.

`firewall_rules.yaml`:
```
 - rule_id: 'prevent_allow_all_ingress'
    description: Detect allow ingress to all policies
    mode: blacklist
    match_policies:
      - direction: ingress
        allowed: ['*']
    verify_policies:
      - allowed:
        - IPProtocol: 'all'

  - rule_id: 'disallow_all_ports'
    description: Don't allow policies that expose every port
    mode: blacklist
    match_policies:
      - direction: ingress
        allowed: ['*']
    verify_policies:
      - allowed:
        - IPProtocol: 'tcp'
          ports:
            - 'all'
      - allowed:
        - IPProtocol: 'udp'
          ports:
            - 'all'

```

Rego sample constraint:

Add the Rego constraint template 
[https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_restricted_firewall_rules_v1.yaml](https://github.com/forseti-security/policy-library/blob/master/policies/templates/gcp_restricted_firewall_rules_v1.yaml) 
in your `policies/templates/`directory.

Create a new yaml file in your `policies/constraints/`directory with the following:

`restrict_firewall_rules.yamll`:
```
apiVersion: constraints.gatekeeper.sh/v1alpha1
kind: GCPRestrictedFirewallRulesConstraintV1
metadata:
  name: restrict-firewall-rule-deny-ingress
spec:
  severity: high
  match:
    target: ["organizations/123456"]
  parameters:
    mode: “denylist”
    rules:
      - direction: "INGRESS"
        rule_type: "allowed"
        protocol: "all"
     - direction: “INGRESS”
       rule_type: "allowed"
       protocol: “tcp”
       port: “all”
     - direction: “INGRESS”
       rule_type: "allowed"
       protocol: “udp”
       port: “all”
```
