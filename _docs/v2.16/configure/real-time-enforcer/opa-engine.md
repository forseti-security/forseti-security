---
title: Open Policy Agent
order: 503
---

# {{ page.title }}

The [Open Policy Agent (OPA)](https://www.openpolicyagent.org/docs/) engine evaluates policy against resources 
using an OPA server. Policies need to be namespaced properly for the OPA Engine to locate them, and 
evaluate policy properly. All remediation is implemented in OPA's policy language, Rego.

OPA policies are pulled from Cloud Storage and loaded into OPA when the `forseti-enforcer` VM boots.

## For Developers

OPA policies should be namespaced as `<resource.type()>.policy.<policy_name>`. 

For example, the `gcp.GcpSqlInstance` resource has a type of `gcp.sqladmin.instances`, so a policy requiring backups 
to be enabled might be namespaced `gcp.sqladmin.instances.policy.backups`. 

The policy should implement the following rules:

`valid`: Returns true if the provided resource adheres to the policy

`remediate`: Returns the input resource altered to adhere to the policy

For each `resource.type()` you also need to define a policies rule and a violations rule. 
This allows the OPA engine to query all violations for a given resource type in a single API call. 

```
package gcp.sqladmin.instances

policies [policy_name] {
    policy := data.gcp.sqladmin.instances.policy[policy_name]
}

violations [policy_name] {
    policy := data.gcp.sqladmin.instances.policy[policy_name]
    policy.valid != true
}
```

For more information on how to write OPA policies, refer to the official 
OPA guide [here](https://www.openpolicyagent.org/docs/how-do-i-write-policies.html).
