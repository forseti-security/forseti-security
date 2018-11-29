---
title: Cloud IAP Rules
order: 320 
---

# {{ page.title }}

## Description

Cloud Identity-Aware Proxy (Cloud IAP) enforces access control at the network
edge, inside the load balancer. If traffic can get directly to the VM, Cloud IAP
is unable to enforce its access control. The IAP scanner ensures that firewall
rules are properly configured and prevents the introduction of other network
paths that bypass the normal load balancer to instance flow.

For examples of how to define scanner rules for Cloud IAP, see the
[`iap_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/iap_rules.yaml)
rule file.

## Rule definition

```yaml
rules:
  # custom rules
  - name: Allow direct access from debug IPs and internal monitoring hosts
    resource:
      - type: organization
        applies_to: self_and_children
        resource_ids:
          - YOUR_ORG_ID
    inherit_from_parents: true
    allowed_direct_access_sources: '10.*,monitoring-instance-tag'
```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `mode`
  * **Description**: The mode of the rule.
  * **Valid values**: One of `whitelist`, `blacklist` or `required`.
  * **Note**:
    * `whitelist`: Allow the members defined.
    * `blacklist`: Block the members defined.
    * `required`: Defined members with the specified roles must be found in policy.

* `resource`
  * `type`
    * **Description**: The type of the resource.
    * **Valid values**: One of `organization`, `folder` or `project`.

  * `applies_to`
    * **Description**: What resources to apply the rule to.
    * **Valid values**: One of `self`, `children` or `self_and_children`.
    * **Note**:
      * `self`: Allow the members defined.
      * `children`: Block the members defined.
      * `self_and_children`: The rule applies to the specified resource and its child resources.

  * `resource_ids`
    * **Description**: A list of one or more resource ids to match.
    * **Valid values**: String, you can use `*` to match for all.

* `inherit_from_parents`
  * **Description**: A boolean that defines whether a specified resource inherits ancestor rules.
  * **Valid values**: One of `true` or `false`.

* `allowed_direct_access_sources`
  * **Description**:  Comma-separated list of globs that are matched against the IP ranges and tags in your
  firewall rules that allow access to services in your GCP environment.
  * **Valid values**: String.
  * **Example values**: `10.*,monitoring-instance-tag`
