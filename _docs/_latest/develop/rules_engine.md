---
title: Rules Engine
order: 104
---
# {{ page.title }}

The *rules engine* checks data (e.g. IAM policy, firewall rule) against
some user-defined rules. The current version of Forseti Security supports rule checking
for the following resources:

* Organizations
* Folders
* Projects
* GCS bucket ACLs
* BigQuery dataset ACLs
* Load balancer rules
* Cloud SQL authorized networks

See the [rules](https://github.com/GoogleCloudPlatform/forseti-security/tree/dev/rules) 
directory for examples.

## IamRulesEngine Overview

With the `IamRulesEngine`, Forseti Scanner integrates with Forseti Inventory to
get IAM policy data for organizations, folders, and projects and audits the policies 
against the user-defined rules. `IamRulesEngine` uses the organization resources' hierarchy, so
rules can "roll up" to resource parents. For example, a project under an
organization can look for rules for that project and for its parent
organization.

If a policy binding violates a rule, the `IamRulesEngine` reports a rule violation.
The rule violations get dumped to a CSV in a GCS bucket as well as to a table in Cloud SQL.

## Creating your own rules engine

The base rules engine class
`google.cloud.security.scanner.audit.BaseRulesEngine` contains some generic
methods for loading rules files in YAML or JSON format. Because Google Cloud
Platform (GCP) resources have different kinds of data that can be checked for 
whether they are secureliy configured, you'll need to design the rule checking 
according to the kind of data that needs to be audited.

To design a rules engine, follow the guidelines below:

1.  Create another rules engine class that inherits from `BaseRulesEngine`.
1.  Implement `BaseRulesEngine.build_rule_book()` and
    `BaseRulesEngine.find_policy_violations()`.
    *   The rule book is a data structure that provides a way to compare a rule
        with a policy.
    *   The `find_policy_violations()` method searches the rule book and
        compares the policy against the rule (if found) in the book.
1.  Create a new scanner and add the necessary scanner mappings and configurations.

Refer to `scanner.py` for an example of how the `IamRulesEngine` works with the 
other Forseti scanners.
