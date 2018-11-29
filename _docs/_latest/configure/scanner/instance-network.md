---
title: Instance Network Interface Rules
order: 355 
---

# {{ page.title }}

## Description

VM instances with external IP addresses expose your environment to an
additional attack surface area. The instance network interface scanner audits
all of your VM instances in your environment, and determines if any VMs with
external IP addresses are outside of the trusted networks.

For examples of how to define scanner rules for network interfaces, see the
[`instance_network_interface_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/instance_network_interface_rules.yaml)
rule file.

## Rule definition

```yaml
rules:
  # This rule helps with:
  # #1 Ensure instances with external IPs are only running
  # on whitelisted networks
  # #2 Ensure instances are only running on networks created in allowed
  # projects (using XPN)
  - name: all networks covered in whitelist
    project: '*'
    network: '*'
    is_external_network: True
    # this would be a custom list of your networks/projects.
    whitelist:
       project-1:
        - network-1
       project-2:
        - network-2
        - network-2-2
       project-3:
        - network-3
```

* `name`
  * **Description**: The name of the rule.
  * **Valid values**: String.

* `project`
  * **Description**: Project id.
  * **Valid values**: String, you can use `*` to match for all.

* `network`
  * **Description**: Network.
  * **Valid values**: String, you can use `*` to match for all.

* `whitelist`
  * **Description**: The whitelist describes which projects and networks for which VM
  instances can have external IPs.
  * **Valid values**: project/networks pairs.
  * **Example values**: The following values would specify that VM instances in
  project_01’s network_01 can have external IP addresses:

    ```yaml
    project_01:
    - network_01
    ```
