---
title: Rules Engine
order: 104
---
# {{ page.title }}

The *rules engine* uses a rules file or *rule book* to check policies against
defined rules. The current version of Forseti Security supports rule checking
for the following resources:

*   Organizations
*   Projects

For example rule files, see the `samples/` directory.

## `IamRulesEngine` Overview

With the `IamRulesEngine`, Forseti Scanner integrates with Forseti Inventory to
get IAM policy data for organizations and projects and runs it against the rule
definitions. `IamRulesEngine` uses the organization resources' hierarchy, so
rules can "roll up" to resource parents. For example, a project under an
organization can look for rules for that project and for its parent
organization.

The `IamRulesEngine` breaks up an IAM policy by policy binding. If a policy
binding violates a rule in its rule book, it reports a rule violation. The
runner script (`scanner.py`) stores the rule violations in a CSV file.

## Creating your own rules engine

The base rules engine class
`google.cloud.security.scanner.audit.BaseRulesEngine` contains some generic
methods for loading rules files in YAML or JSON format. Because Google Cloud
Platform (GCP) resources have different kinds of policies—like project and
firewall policies—you'll need to design rule checking based on the resource
policies you want to audit.

To design a rules engine, follow the guidelines below:

1.  Create another rules engine class that inherits from `BaseRulesEngine`.
1.  Implement `BaseRulesEngine.build_rule_book()` and
    `BaseRulesEngine.find_policy_violations()`.
    *   The rule book is a data structure that provides a way to compare a rule
        with a policy.
    *   The `find_policy_violations()` method searches the rule book and
        compares the policy against the rule (if found) in the book.
1.  Create or reuse the runner script to instantiate and run your rules engine,
    such as `scanner.py`.

Refer to `scanner.py` for an example of how the `IamRulesEngine` works with
Forseti Inventory.
