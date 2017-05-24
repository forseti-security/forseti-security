---
permalink: /modules/core/scanner/rules/
---
# Defining IAM policy rules
The Forseti Scanner recognizes the following rule grammar (either in YAML or JSON):

```yaml
rules:
  - name: $rule_name
    mode: $rule_mode
    resource:
      - type: $resource_type
        applies_to: $applies_to
        resource_ids:
          - $resource_id1
          - $resource_id2
          - ...
    inherit_from_parents: $inherit_from
    bindings:
      - role: $role_name
        members:
          - $member1
          - $member2
          ...
```

`rules` is a sequence of rules.

`mode` is string of one of the following values:
 * "whitelist" - allow the members defined
 * "blacklist" - block the members defined
 * "required' - these members with these roles must be found in the policy

`resource_type` is a string of one of the following values:
 * "organization"
 * "folder" (coming soon)
 * "project"

`applies_to` is a string of one of the following values:
 * "self" - the rule only applies to the specified resource
 * "children" - the rule only applies to the child resources of this resource
 * "self_and_children" - the rule applies to all

`inherit_from_parents` is a boolean, either true or false, that tells whether the resource being checked should look in its inheritance hierarchy and apply the ancestor rules.

`role_name` is one of the [IAM roles](https://cloud.google.com/compute/docs/access/iam) e.g. "roles/editor" or "roles/viewer". Roles can also be wildcarded, e.g. roles/*. Refer to the samples or the unit tests directory for examples.

In the members list, specify IAM members, e.g. user:someone@company.com. You can also use wildcards on the member name, e.g. serviceAccount:*@*.gserviceaccount.com ("any service accounts").

More information about IAM users types can be found in the [policy documentation](https://cloud.google.com/iam/reference/rest/v1/Policy).

# Defining Google Groups rules
Coming soon.

# Defining GCS bucket rules
Coming soon.
