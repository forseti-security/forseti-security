---
title: Explain
order: 105
---
# {{ page.title }}

This guide describes how to configure Explain for Forseti Security.

Explain helps you understand the Cloud Identity and Access Management
(Cloud IAM) policies that affect your Google Cloud Platform (GCP) resources.
It can enumerate access by resource or member, answer why a principal has access
to a certain resource, or offer possible strategies for how to grant access
to a specific resource.

---

## Before you begin

To run Explain, you'll need the following:

* Data collected by [Inventory]({% link _docs/v2.14/use/cli/inventory.md %})

## Running Explain

Before you start using Explain, you'll first create and select the data model you
want to use.

To review the hierarchy of commands and explore Explain functionality, use
`–help`.

### Creating a data model

Get the `inventory_index_id` and use it to create the data model by running
the following command:

```bash
forseti model create --inventory_index_id <INVENTORY_INDEX_ID> <MODEL_NAME>
```

### Selecting a data model

Select the data model you created by running the following command:

```bash
forseti model use <MODEL_NAME>
```

### Using Explain to query the data model

Following are some example commands you can run to query the data model.

### List resources in the data model

```bash
forseti explainer list_resources
```

You can also filter the results and list resources only in a folder:

```bash
forseti explainer list_resources --prefix organization/1234567890/folder/folder-name
```

### List all members in the data model

```bash
forseti explainer list_members
```

You can also filter the results and list members with a prefix match:

```bash
forseti explainer list_members --prefix test
```

### List all roles in the data model

```bash
forseti explainer list_roles
```

You can also filter the results by prefix:

```bash
forseti explainer list_roles --prefix roles/
```
Returned results will contain only predefined roles.

Common filters include the following:

`--prefix 'roles/iam'` returns results that only contain predefined roles related to Cloud IAM.

`--prefix 'organizations'` returns results that only contain custom roles defined on the
organization level.

### List permissions

The following command lists the permissions contained by roles in the data model:

```bash
forseti explainer list_permissions --roles <ROLE1> <ROLE2>
```

For example, the following query lists permissions contained in `roles/iam.roleAdmin` and
`roles/resourcemanager.projectMover`:

```bash
forseti explainer list_permissions --roles roles/iam.roleAdmin roles/resourcemanager.projectMover
```

The following query lists individual permissions in each predefined Cloud IAM role:

```bash
forseti explainer list_permissions --role_prefixes roles/iam
```

### Get policies on a resource

```bash
forseti explainer get_policy <RESOURCE_NAME>
```
Example values for `<RESOURCE_NAME>` are the `project/<PROJECT_ID>` and
`organization/<ORGANIZATION_ID>`.

### Test permissions

```bash
forseti explainer check_policy <RESOURCE_NAME> <PERMISSION_NAME> <MEMEBER_NAME>
```

For example, the following query returns True or False to indicate if the member has permissions
on the resource:

```bash
forseti explainer check_policy organizations/1234567890 iam.roles.get user/user1@gmail.com
```

### List member access
The following command lists all resources that can be accessed by a member by a direct binding:

```bash
forseti explainer access_by_member user/<USER_NAME>
```

By default, resource_expansion is not performed. For example, `user/foo` has `roles/owner` on the
`organization/1234567890` and no other policies. The above command will only show
`organization/1234567890`.

To enable resource expansion, pass in the argument `--expand_resource`. Forseti will perform
resource expansion and list all resources that can be accessed by `user/<USER_NAME>` through a
direct or indirect binding.

```bash
forseti explainer access_by_member user/<USER_NAME> --expand_resource
```

With resource expansion enabled, the example above will return `organizations/1234567890` and all
folders, projects, VMs, and other resources in it.

To constrain the result to a certain type of permission, use the following command:

```bash
forseti explainer access_by_member user/<USER_NAME> iam.roles.get
```

The above query will list all resources that can be accessed by the member with a binding of
`iam.roles.get`.

### List resource permissions

The following command lists all members that can access a resource by a direct binding:

```bash
forseti explainer access_by_resource <RESOURCE_NAME>
```

Similar to the `access_by_member` command, group expansion is not performed by default. For
example, `group/bar` has `roles/owner` on the `organization/1234567890` and no other policies.
Without group expansion, the following example will only return `group/bar`:

```bash
forseti explainer access_by_resource organizations/1234567890
```

To enable group expansion, pass in the `--expand_groups` argument. Forseti will perform group
expansion and list all members that can access the resource, even if the access is granted because a member is in a group.

```bash
forseti explainer access_by_resource <RESOURCE_NAME> --expand_groups
```

With group expansion enabled, the example above will list `group/bar` and `user/foo` if `user/foo`
is a member in `group/bar`.

To constrain the result to a certain type of permission, pass in the permission:

```bash
forseti explainer access_by_resource <RESOURCE_NAME> <PERMISSION>
```

### Access member or resource by permission

You can specify a permission, such as `iam.serviceAccounts.get`, and list all the
`<members, resource, role>` that have a relation.

The tuple `<members, resource, role>` contains the members with a role that contains permission
`iam.serviceAccounts.get` on the resource.

```bash
forseti explainer access_by_authz --permission iam.serviceAccounts.get

...
Member member1
Member member2
Resource resource1
Role roles/owner
...

```

These results mean that resource `resource1` has a policy to grant `roles/owner` to `member1` and `member2`

With `access_by_authz` you can also specify a role instead of a permission:

```bash
# With G Suite Group expansion
forseti explainer access_by_authz --permission iam.serviceAccounts.get --expand_group

# With resource expansion.
forseti explainer access_by_authz --permission iam.serviceAccounts.get --expand_resource
```

### View permission source
Understand why a member has a permission to a resource:

```bash
forseti explainer why_granted <MEMBER_NAME> <RESOURCE_NAME> --permission <PERMISSION_NAME>
```

Example values for `<MEMBER_NAME>` are `user/user1@gmail.com` or `serviceAccount/service1@domain.com`

The result displays all bindings that grant the permission you specified.
For each binding `<resource, role, [member1, member2]>`, Forseti returns
how the resource hierarchy links to your target resource, and how a group
in the binding links to your target member.

In the following example, user `user/abc@gmail.com` has permission
`iam.serviceAccounts.get` on resource `my-project-123` because the user
has the role `roles/iam.securityReviewer` on resource
`organization/1234567890`. Member `user/abc@gmail.com` also has a
membership in group `group/my-group-123@gmail.com`.

```
forseti explainer why_granted user/abc@gmail.com project/my-project-123 --permission iam.serviceAccounts.get
bindings {
  member: "user/abc@gmail.com"
  resource: "organization/1234567890"
  role: "roles/iam.securityReviewer"
}
memberships {
  member: "user/abc@gmail.com"
  parents: "group/my-group-123@gmail.com"
}
resource_ancestors: "project/my-project-123"
resource_ancestors: "organization/1234567890"
```

### Grant a member permission to a resource

```bash
forseti explainer why_denied <MEMBER_NAME> <RESOURCE_NAME> --permission <PERMISSION_NAME>
```

The result will list any potential bindings you can add to grant the required permission. The
following example result shows that to access resource `resource_bar`, user `member_foo` needs
role `roles/baz_role` on the resource or its parent. The result also shows that the user gets the
role if you add them to the group `group_foo_parent`, which already has the required permission.

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

In the example above, overgranting equals 1 to indicate a binding that could grant unnecessary
privileges. This means that the binding doesn't work directly on the target member and resource. Instead, the binding applies to groups that contain the target member, or resources that contain the target resource.

## What's next

* Read more about [data model concepts]({% link _docs/v2.14/concepts/models.md %}).
