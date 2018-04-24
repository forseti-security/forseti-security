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

##### Listing all resources in the data model

```bash
$ forseti explainer list_resources
```

#### Filter the results and list resources only in a folder

```bash
$ forseti-client-XXXX-vm> forseti explainer list_resources --prefix organization/1234567890/folder/folder-name
```

#### List all members in the data model

```bash
$ forseti-client-XXXX-vm> forseti explainer list_members
```

#### Filter the results and list members with a prefix match

```bash
$ forseti-client-XXXX-vm> forseti explainer list_members --prefix test
```

#### List all roles in the data model

```bash
$ forseti-client-XXXX-vm> forseti explainer list_roles
```

#### Filter the results by prefix

```bash
$ forseti-client-XXXX-vm> forseti explainer list_roles --prefix roles/

# Returned results will contain only predefined roles
# Common filters include the following:
#--prefix 'roles/iam' returns results that only contain predefined roles related to Cloud IAM
#--prefix 'organizations' returns results that only contain custom roles defined on the organization level
```

#### List permissions contained in a role/roles in the data model

```bash
$ forseti-client-XXXX-vm> forseti explainer list_permissions --roles <ROLE1> <ROLE2>

# Example:
# List permissions contained in roles/iam.roleAdmin and roles/resourcemanager.projectMover
# forseti-client-XXXX-vm> forseti explainer list_permissions --roles roles/iam.roleAdmin roles/resourcemanager.projectMover
```

#### List permissions in each predefined roles related to Cloud IAM individually

```bash
$ forseti-client-XXXX-vm> forseti explainer list_permissions --role_prefixes roles/iam
```

#### Get policies on a resource

```bash
$ forseti-client-XXXX-vm> forseti explainer get_policy <RESOURCE_NAME>

# Example values for <RESOURCE_NAME> are the project/<PROJECT_ID> and organization/<ORGANIZATION_ID>.

# Important note: Cloud SQL Instance have slightly different syntax
# For Cloud SQL Instance the syntax is of the format cloudsqlinstance/project_id:cloudsqlinstance_name 
# Example:
# forseti-client-XXXX-vm> forseti explainer get_policy cloudsqlinstance/sample-project-123:my-sql-instance
```

#### Test if a member has permission on a resource, or if a tuple <resource, permission, member> is granted

```bash
$ forseti-client-XXXX-vm> forseti explainer check_policy <RESOURCE_NAME> <PERMISSION_NAME> <MEMEBER_NAME>

# Example:
# forseti-client-XXXX-vm> forseti explainer check_policy organizations/1234567890 iam.roles.get user/user1@gmail.com
# The above query returns True or False to indicate if the  member has permission on the resource.
```

#### List all resources that can be accessed by a member by a direct binding

```bash
$ forseti-client-XXXX-vm> forseti explainer access_by_member user/<USER_NAME>

# By default, resource_expansion is not performed. For example, user/foo has roles/owner on the organization/1234567890 and no other policies. 
# Without resource_expansion, a command like the one below will only show 'organization/1234567890'
# To enable resource expansion pass in the argument --expand_resource true
# Example:
# forseti-client-XXXX-vm> forseti explainer access_by_member user/<USER_NAME> --expand_resource true
# Forseti will perform resource expansion and list all resources accessible by 'user/<USER_NAME>' through a direct or indirect binding. With resource expansion enabled, the example above will return 'organizations/1234567890' and all folders/projects/vms/... in it.
```

#### To constrain the result to a certain type of permission

```bash
$ forseti-client-XXXX-vm> forseti explainer access_by_member user/<USER_NAME> iam.roles.get

# List all resources that can be accessed by the member with a binding of 'iam.roles.get'
```

#### List all members that can access a resource by a direct binding

```bash
$ forseti-client-XXXX-vm> forseti explainer access_by_resource <RESOURCE_NAME>
```

#### Get policies on a resource

```bash
$ forseti-client-XXXX-vm> forseti explainer get_policy <RESOURCE_NAME>

```

#### Get policies on a resource

```bash
$ forseti-client-XXXX-vm> forseti explainer get_policy <RESOURCE_NAME>

```

#### Get policies on a resource

```bash
$ forseti-client-XXXX-vm> forseti explainer get_policy <RESOURCE_NAME>

```
## What's next

- Read more about [the concepts of data model]({% link _docs/latest/concepts/models.md %}).
- Learn about the [complete list of functionalities]({% link _docs/latest/use/cli.md %}) available in Explain.
