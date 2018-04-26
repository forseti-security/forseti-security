---
title: Explain
order: 000
---
# {{ page.title }}

This guide describes how to configure Explain for Forseti Security.

Explain helps you understand the Cloud Identity and Access Management
(Cloud IAM) policies that affect your Google Cloud Platform (GCP) resources.
It can enumerate access by resource or member, answer why a principal has access 
to a certain resource, or offer possible strategies for how to grant a specific 
resource.

## Running Explain

Before you start using Explain, you'll first select the data model you
want to use.

To review the hierarchy of commands and explore Explain functionality, use
`–help`.

### Creating a data model

Data model is built using the inventory data we created through the Forseti Inventory service.

Instructions on how to run Forseti Inventory can be found [here]({% link _docs/latest/use/inventory.md %}).

Once you have the inventory ready, retrieve the inventory_index_id and use it to create the data model as follows:

```bash
$ forseti model create --inventory_index_id <INVENTORY_INDEX_ID> <MODEL_NAME>
```

### Listing all the data model

```bash
$ forseti model list
```

### Selecting a data model

```bash
$ forseti model use <MODEL_NAME>
```

### Querying the data model through Explain

Following are some example commands you can run to query the data model.

#### Listing all resources in the data model

```bash
$ forseti explainer list_resources
```

Filter the results and list resources only in a folder

```bash
$ forseti-client-XXXX-vm> forseti explainer list_resources --prefix organization/1234567890/folder/folder-name
```

#### List all members in the data model

```bash
$ forseti-client-XXXX-vm> forseti explainer list_members
```

Filter the results and list members with a prefix match

```bash
$ forseti-client-XXXX-vm> forseti explainer list_members --prefix test
```

#### List all roles in the data model

```bash
$ forseti-client-XXXX-vm> forseti explainer list_roles
```

Filter the results by prefix

```bash
$ forseti-client-XXXX-vm> forseti explainer list_roles --prefix roles/
```

Returned results will contain only predefined roles

Common filters include the following:

`--prefix 'roles/iam'` returns results that only contain predefined roles related to Cloud IAM

`--prefix 'organizations'` returns results that only contain custom roles defined on the organization level

#### List permissions contained in a role/roles in the data model

```bash
$ forseti-client-XXXX-vm> forseti explainer list_permissions --roles <ROLE1> <ROLE2>
```

For example:
```bash
$ forseti-client-XXXX-vm> forseti explainer list_permissions --roles roles/iam.roleAdmin roles/resourcemanager.projectMover
```
The above query will list permissions contained in `roles/iam.roleAdmin` and `roles/resourcemanager.projectMover`


```bash
$ forseti-client-XXXX-vm> forseti explainer list_permissions --role_prefixes roles/iam
```
The above query will list permissions in each predefined roles related to Cloud IAM individually

#### Get policies on a resource

```bash
$ forseti-client-XXXX-vm> forseti explainer get_policy <RESOURCE_NAME>
```
Example values for `<RESOURCE_NAME>` are the `project/<PROJECT_ID>` and `organization/<ORGANIZATION_ID>`.

Important note: Cloud SQL Instance have slightly different syntax.
For Cloud SQL Instance the syntax is of the format `cloudsqlinstance/project_id:cloudsqlinstance_name`

For example:
```bash
$ forseti-client-XXXX-vm> forseti explainer get_policy cloudsqlinstance/sample-project-123:my-sql-instance
```

#### Test if a member has permission on a resource, or if a tuple <resource, permission, member> is granted

```bash
$ forseti-client-XXXX-vm> forseti explainer check_policy <RESOURCE_NAME> <PERMISSION_NAME> <MEMEBER_NAME>
```

For example:

```bash
$ forseti-client-XXXX-vm> forseti explainer check_policy organizations/1234567890 iam.roles.get user/user1@gmail.com
```

The above query returns True or False to indicate if the  member has permission on the resource.

#### List all resources that can be accessed by a member by a direct binding

```bash
$ forseti-client-XXXX-vm> forseti explainer access_by_member user/<USER_NAME>
```
By default, resource_expansion is not performed. For example, `user/foo` has `roles/owner` on the `organization/1234567890` and no other policies. 

Without resource expansion, a command like the one above will only show `organization/1234567890`

To enable resource expansion pass in the argument `--expand_resource true`

Example:
```
$ forseti-client-XXXX-vm> forseti explainer access_by_member user/<USER_NAME> --expand_resource true
```

Forseti will perform resource expansion and list all resources accessible by `user/<USER_NAME>` through a direct or indirect binding. 
With resource expansion enabled, the example above will return `organizations/1234567890` and all folders/projects/vms/... in it.

To constrain the result to a certain type of permission

```
$ forseti-client-XXXX-vm> forseti explainer access_by_member user/<USER_NAME> iam.roles.get
```

The above query will list all resources that can be accessed by the member with a binding of `iam.roles.get`

#### List all members that can access a resource by a direct binding

```
$ forseti-client-XXXX-vm> forseti explainer access_by_resource <RESOURCE_NAME>
```

Similar to `access_by_member` command, group expansion is not performed by default.

For example, `group/bar` has `roles/owner` on the `organization/1234567890` and no other policies. Without group expansion, the following example will only show `group/bar`.

```
$ forseti-client-XXXX-vm> forseti explainer access_by_resource organizations/1234567890
```

To enable group expansion pass in the `--expand_group` argument

```
$ forseti-client-XXXX-vm> forseti explainer access_by_resource <RESOURCE_NAME> --expand_group true 
```

Forseti will perform group expansion and list all members that can access the resource even if the access is granted because a member is in a group.

With group expansion enabled, the example above will list `group/bar` and `user/foo` if `user/foo` is a member in `group/bar`.

To constrain the result to a certain type of permission, pass in the permission

```
$ forseti-client-XXXX-vm> forseti explainer access_by_resource <RESOURCE_NAME> <PERMISSION> 
```


#### Access member or resource by permission

You can specify a permission, such as `p`, and list `<members, resource, role>` pairs that have a relation.

For instance a that role contains permission p and member has permission p on resource.

```
$ forseti-client-XXXX-vm> forseti explainer access_by_authz --permission iam.serviceAccounts.get
...
Member member1
Member member2
Resource resource1
Role roles/owner
...
```

These results mean that resource `resource1` has a policy to grant `roles/owner` to `member1` and `member2`

With `access_by_authz` you can also specify role instead of permission 

```
# With G Suite Group expansion
$ forseti-client-XXXX-vm> forseti explainer access_by_authz --expand_group

# With resource expansion.
$ forseti-client-XXXX-vm> forseti explainer access_by_authz --expand_resource
```

#### Understand why a member has a permission to a resource

```
$ forseti-client-XXXX-vm> forseti explainer why_granted <MEMBER_NAME> <RESOURCE_NAME> --permission <PERMISSION_NAME>
```

Example values for `<MEMBER_NAME>`, `user/user1@gmail.com`, `serviceAccount/service1@domain.com`

#### Understand why a member doesn’t have a permission on a resource

```
$ forseti-client-XXXX-vm> forseti explainer why_denied <MEMBER_NAME> <RESOURCE_NAME> --permission <PERMISSION_NAME>
```

The result will list any potential bindings to add.

```
strategies { 
    bindings { 
        member: "member_foo " 
        resource: "resource_bar_parent" 
        role: "roles/baz_role" 
    } 
    overgranting: 1
}
strategies { 
    bindings { 
        member: "group_foo_parent " 
        resource: "resource_bar"
        role: "roles/baz_role" 
    }
    overgranting: 1
}
strategies { 
    bindings { 
        member: "member_foo" 
        resource: "resource_bar" 
        role: "roles/baz_role" 
    } 
}
...
```

This binding doesn't work directly on the target member and resource. Instead, the binding applies to groups that contain the target member or resources that contain the target resource. In the example above, overgranting equals 1 to indicate that the binding could grant unnecessary privileges.


## What's next

- Read more about [the concepts of data model]({% link _docs/latest/concepts/models.md %}).
- Learn about the [complete list of functionalities]({% link _docs/latest/use/cli.md %}) available in Explain.
