---
title: IP Address Blacklist Rules
order: 360 
---

# {{ page.title }}

## Description

Virtual Machine (VM) instances that have external IP addresses can communicate
with the outside world. If they are compromised, they could appear in various
blacklists and could be known as malicious, such as for sending spam,
hosting Command & Control servers, and so on. The blacklist scanner audits
all of the VM instances in your environment and determines if any VMs
with external IP addresses are on a specific blacklist you've configured.

For examples of how to define scanner rules, see the
[`blacklist_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/rules/blacklist_rules.yaml) rule file.

## Rule definition

```yaml
rules:
  - blacklist: Emerging Threat blacklist
    url: https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
```

* **blacklist**: The name of your blacklist.
* **url**: URL that contains a list of IPs to check against.
