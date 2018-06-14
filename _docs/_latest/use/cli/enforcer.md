---
title: Enforcer
order: 107
---

# {{ page.title }}

This page describes how to get started with Forseti Enforcer. Enforcer
compares policy files that define the desired state of a resource
against the current state of the resource. If it finds any differences in
policy, Enforcer makes changes using Google Cloud APIs.

Enforcer code currently supports Compute Engine firewall rules.
Additional enforcement endpoints are in development.

---

## Before you begin

Forseti Enforcer requires write permissions for the resources that it manages.
When you setup Forseti using the installer, a service account is created and
granted write access to update firewalls on any project in your organization.

If you did not use the installer, you did not enable enforcer during
installation, or you want to run enforcer on a different instance than the
Forseti server, then you need to grant the service account used by enforcer
the following permissions:

* The Compute Security Admin role on all projects that it will enforce, or on
  the folder(s) or organization parenting the projects.
* The cloud-platform or compute API scope on the instance that's running
  Forseti Enforcer.

## Using Forseti Enforcer

To use Forseti Enforcer, you'll define policies in a JSON formatted rule list,
and then run the `forseti_enforcer` tool referencing a local or Cloud Storage
policy file.

Forseti Enforcer policy files are JSON formatted rule lists that apply to a
project. Each rule must include all required fields, based on the rule
direction. To learn more, refer to the
[Compute Engine Firewall](https://cloud.google.com/vpc/docs/firewalls#gcp_firewall_rule_summary_table)
documentation.

If a rule does not include a network name, then it's applied to all networks
configured on the project. The network name is prepended to the rule name.

The following is an example firewall policy (which can be applied by enforcer)
that only allows:
  * SSH from anywhere
  * HTTP(S) traffic from both load balancer and health checker to VM instances
  * Internal tcp, udp, and icmp traffic between VMs

  ```json
  [{
        "sourceRanges": ["0.0.0.0/0"],
        "description": "Allow SSH from anywhere",
        "direction": "INGRESS",
        "allowed": [
            {
                "IPProtocol": "tcp",
                "ports": ["22"]
            }
        ],
        "name": "allow-ssh"
   },
   {
        "sourceRanges": ["130.211.0.0/22", "35.191.0.0/16"],
        "description": "Allow traffic from load balancer and health checks to reach VM instances",
        "direction": "INGRESS",
        "allowed": [
            {
                "IPProtocol": "tcp",
                "ports": ["80","443"]
            }
        ],
        "name": "allow-health-check"
   },
   {
        "sourceRanges": ["10.0.0.0/8"],
        "description": "Allow internal only",
        "direction": "INGRESS",
        "allowed": [
            {
                "IPProtocol": "tcp",
                "ports": ["0-65535"]
            },
            {
                "IPProtocol": "udp",
                "ports": ["0-65535"]
            },
            {
                "IPProtocol": "icmp"
            }
        ],
        "name": "allow-internal"
  }]
  ```

### Running Enforcer

#### Use a local policy file

To run Forseti Enforcer with a local policy file, run the following command on
the server instance:

  ```bash
  forseti_enforcer --enforce_project PROJECT_ID \
    --policy_file path/to/policy.json
  ```

#### Use a Cloud Storage policy file

To run Forseti Enforcer with a policy file stored in Cloud Storage,
such as `gs://my-project-id/firewall-policies/default.json`, run the following
command on the server instance:

  ```bash
  forseti_enforcer --enforce_project PROJECT_ID \
    --policy_file gs://my-project-id/firewall-policies/default.json
  ```
