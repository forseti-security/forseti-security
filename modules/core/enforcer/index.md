---
permalink: /modules/core/enforcer/
---
# Enforcer
The Forseti enforcer compares policy files defining the desired state of a
resource against the current state of the resource. Any required changes are
made using the Google Cloud APIs.

The enforcer code currently supports Compute Engine firewall rules. Additional
enforcement endpoints are under development.

## Running the enforcer

* The enforcer job requires write permissions for the resources that it manages.
  If using the default Compute Engine service account, the account must have
  permissions to update the Compute API for the project(s) being enforced. The
  account should be granted the Compute Security Admin role in your organization
  IAM settings. It must also be granted access to the compute API scope on the
  instance that is running enforcer.

* Before running the enforcer, make sure you've installed the forseti-security
  package. See the [README](/README.md) in the top-level directory of this repo.

* Update gcloud (the following gcloud commands have been tested with version
  1.3.8):

```sh
$ gcloud components update
```

* Set your gcloud environment to use this project. To create a new environment
  configuration:

```sh
$ gcloud init
```

* To see all the available commandline flags for the enforcer, run:

```sh
$ forseti_enforcer --helpfull
```

To run the enforcer with a local policy file:

```sh
$ forseti_enforcer --enforce_project <project_id> \
    --policy_file path/to/policy.json
```

To run the enforcer with a policy file stored in GCS, e.g.
`gs://my-project-id/firewall-policies/default.json`:

```sh
$ forseti_enforcer --enforce_project <project_id> \
    --policy_file gs://my-project-id/firewall-policies/default.json
```

The result of the enforcement will be output to stdout.

## Defining policies

The policy files are json formatted lists of rules to apply to a project. Each
rule must contain a name, sourceRanges or sourceTags, and one or more allowed
protocols. The [Compute API](https://cloud.google.com/compute/docs/reference/latest/firewalls)
documentation has more details.

If no network name is listed, then the rule will be applied to all networks
configured on the project. The network name will be prepended to the rule name.

Example rule:
```json

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

```

If this rule is used in a policy file, it needs to be wrapped in a list.
See [default_allow_policy.json].

[default_allow_policy.json]: samples/default_allow_policy.json
