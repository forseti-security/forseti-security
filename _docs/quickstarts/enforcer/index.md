---
title: Enforcer Quickstart
order: 201
---
# {{ page.title }}

This quickstart describes how to get started with Forseti Enforcer. Forseti
Enforcer compares policy files that define the desired state of a resource
against the current state of the resource. If it finds any differences in
policy, Forseti Enforcer makes changes using Google Cloud APIs.

Forseti Enforcer code currently supports Compute Engine firewall rules.
Additional enforcement endpoints are in development.

## Before you begin

Forseti Enforcer requires write permissions for the resources that it manages.
If you use the default Compute Engine service account, the account must have
the following permissions:

  - Permissions to update the Compute API for the projects it enforces.
  - The Compute Security Admin role in your organization's Cloud IAM settings.
  - Access to the Compute API scope on the instance that's running Forseti
  Enforcer.

You'll also need the project ID of the resource you want to enforce.

## Defining policies

Forseti Enforcer policy files are JSON formatted rule lists that apply to a
project. Each rule must contain a name, sourceRanges or sourceTags, and one or
more allowed protocols. To learn more, refer to the
[Compute Engine Firewall](https://cloud.google.com/compute/docs/reference/latest/firewalls)
documentation.

If a rule doesn't include a network name, then it's applied to all networks
configured on the project. The network name is prepended to the rule name.

Following is an example rule that allows SSH from anywhere:

````
{
    "sourceRanges": ["0.0.0.0/0"],
    "description": "Allow SSH from anywhere",
    "allowed": [
        {
            "IPProtocol": "tcp",
            "ports": ["22"]
        }
    ],
    "name": "allow-ssh"
}
````

## Running Forseti Enforcer

### Use a local policy file

To run Forseti Enforcer with a local policy file, run the following command:

````
forseti_enforcer --enforce_project PROJECT_ID \
    --policy_file path/to/policy.json
````

### Use a Google Cloud Storage policy file

To run Forseti Enforcer with a policy file stored in Google Cloud Storage,
such as `gs://my-project-id/firewall-policies/default.json`, run the following
command:

````
forseti_enforcer --enforce_project PROJECT_ID \
    --policy_file gs://my-project-id/firewall-policies/default.json
````
