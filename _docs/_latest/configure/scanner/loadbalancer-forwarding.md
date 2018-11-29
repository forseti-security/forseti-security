---
title: Load Balancer Forwarding Rules
order: 370 
---

# {{ page.title }}

## Description

You can configure load balancer forwarding rules to direct unauthorized external
traffic to your target instances. The forwarding rule scanner supports a
whitelist mode, to ensure each forwarding rule only directs to the intended
target instances.

For examples of how to define scanner rules for your forwarding rules, see the
[`forwarding_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/forwarding_rules.yaml)
rule file.

## Rule definition

```yaml
rules:
  - name: Rule Name Example
    target: Forwarding Rule Target Example
    mode: whitelist
    load_balancing_scheme: EXTERNAL
    ip_protocol: ESP
    ip_address: "198.51.100.46"
```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `target`
  * **Description**: The URL of the target resource to receive the matched traffic.
  * **Valid values**: String.

* `mode`
  * **Description**: The mode of the rule.
  * **Valid values**: Current only support `whitelist` mode.
  * **Note**:
    * `whitelist`: Ensure each forwarding rule only directs to the intended target instance.

* `load_balancing_scheme`
  * **Description**: What the ForwardingRule will be used for.
  * **Valid values**: One of `INTERNAL` or `EXTERNAL`.

* `ip_protocol`
  * **Description**: The IP protocol to which this rule applies.
  * **Valid values**: One of `TCP`, `UDP`, `ESP`, `AH`, `SCTP`, or `ICMP`.

* `ip_address`
  * **Description**: The IP address for which this forwarding rule serves.
  * **Valid values**: String.
  * **Example values**: `198.51.100.46`

To learn more, see the
[ForwardingRules](https://cloud.google.com/compute/docs/reference/latest/forwardingRules)
documentation.
