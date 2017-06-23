---
title: Rules Engine
order: 103
---
# {{ page.title }}

The "rules engine" takes in a rules file (see the `samples/` directory for
examples) and methodically checks policies against the rules. The current
version of Forseti Security supports rule checking for the following resources:

* Organizations
* Projects

# High level overview of `IamRulesEngine`

With the `IamRulesEngine`, Forseti Scanner integrates with Forseti Inventory
to get IAM policy data for organizations and projects and runs it against the
rule definitions. `IamRulesEngine` was designed with the organization
resources' hierarchy in mind, so rules can "roll up" to the resource ancestors
(e.g. a project under some org can look for both the rules for that project as
well as for that org).

The `IamRulesEngine` breaks up an IAM policy by policy binding. If a policy
binding violates a rule in its "rule book", it will report a rule violation. In
the runner script (`scanner.py`), the rule violations are collected into a CSV
file.

# Creating your own rules engine

There's a base rules engine class,
`google.cloud.security.scanner.audit.BaseRulesEngine`, that contains some
generic methods for loading rules files in either yaml or json format. Because
Google Cloud Platform resources have different kinds of policies (e.g. a
project policy is different from a firewall policy), there will be some work
involved to design rule checking, depending on what resource policies you're
auditing.

The general design for a rules engine would be:

1. Create another rules engine class that inherits from `BaseRulesEngine`.
2. Implement `BaseRulesEngine.build_rule_book()` and
`BaseRulesEngine.find_policy_violations()`.
   * The rule book is a data structure that provides a way to lookup a rule
   for comparison with a policy.
   * The `find_policy_violations()` method searches the rule book and compares
   the policy against the rule (if found) in the book.
3. Create or reuse the runner script to instantiate your rules engine and run
it. (e.g. `scanner.py`)

Refer to `scanner.py` for an example of how the `IamRulesEngine` works in
conjunction with Forseti Inventory.
