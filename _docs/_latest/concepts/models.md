---
title: Models
order: 100
---

# {{ page.title }}

Starting with version 2.0, Forseti introduces the use of data models.

The data model is an additional pool of data that is relational in nature,
and is created from the flat json data in inventory, that's captured from GCP
API responses. With the relational data, we can more easily see the
relationships and the inheritances between resources, as well as being able
to query for them.  One example is see all the accesses that a service account
may have, across all the projects.

Another important concept to keep in mind is that the data models are not meant
to be persistent. The data models need to be created before use, and then
destroyed after use. So, before you want to use Explain, you will need to
create your own set of data model, and then delete them after finish using
Explain.

Also important, the Scanner and Explainer components depend on the data models
as the data source, i.e. it is a pre-requiste for the data models to be
created successfully, before the Scanner or the Explainer can be used.

## Tables

Each set of data models are stored in its own set of tables, which are tied
to each other by specific relationships.  At any given time, multiple set
of tables can exist, either created by the cron job, or by other users.

### binding_members

This table contains information about a the member name, and an binging id
of what it's bound to in the `bindings` table.

### bindings

This table contains information about the the binding id for a resource,
and a role.

Thus by combining this with `binding_members` table, we can see what
resources that a member has access to, and with which roles.

### group_in_group

This table contains information about how groups are nested in other groups.
Each row contains a group and its parent group.  If a group is not nested,
then it will not be in this table.

### group_members

This table contains information about groups, and the members in the group
(both users and other groups).

### members

This table contains information about members, the types of resources they are,
and their names.

### permissions

This table is a listing of all the permissions on GCP.

### roles

This table is a listing of all the roles on GCP, title, stage, description,
whether it's custom role or not.

### role_permissions

This table contains information on the roles and the permissions of that role.

By combining the `binding_members`, `bindings`, `roles`, and `role_permissions`
tables, we can see who has what permissions on what resources.

### resources
This table contains the details of each resource, such as `full_name`,
its parents, and raw gcp data.  This is the table that the various scanners use
to do all the scannings.
