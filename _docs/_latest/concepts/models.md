---
title: Models
order: 003
---

# {{ page.title }}

Starting with version 2.0, Forseti introduces the use of data models.

The data model is an additional pool of data that is relational in nature,
and is created from the flat json data in inventory. With the relational data, Forseti 
can more easily understand the entire relationship, including inheritance between resources. Models
allow for easier querying against the entire computed policy.

Another important concept to keep in mind is that the data models are not meant
to be persistent. Before using Scanner or Explain a data model must be created. Once you're done 
using the model it should be deleted.

Both Scanner and Explain depend on the data models being present, therefore creating a valid data 
model prior to using Scanner or Explain is **required**.

---

## How data models are stored

Data models are stored in its own set of tables, which are named with the
`<model_handle>_<table_name>` and are tied to each other by specific relationships.  At any given
time, multiple set of tables can exist, either created by the cron job, or by other users. The
table sets are listed in the `models` table.  

### The `binding_members` table

This table is a join table that connects `members` table with the `bindings` table, thus making it
possible to know what resources each member can access.

### The `bindings` table

This table contains information about what resource and what role are associated for a
`binding_id`. By combining this with `binding_members` table, we can see who has access to what
resources, and with which roles.

### The `group_in_group` table

This table contains information about how groups are nested in other groups.
Each row contains a group and its parent group.

If a group is not nested, then it will not be in this table.

### The `group_members` table

This table contains information about groups, and the members in the group
(both users and other groups).

### The `members` table

This table contains information about members, the types of resources they are,
and their names.

### The `permissions` table

This table is a listing of all the permissions on GCP.

### The `roles` table

This table is a listing of all the roles on GCP, title, stage, description,
and whether it's custom role or not.

### The `role_permissions` table

This table contains information on the roles and the permissions of that role.

By combining the `binding_members`, `bindings`, `roles`, and `role_permissions` tables, we can see
who has what permissions on what resources.

### The `resources` table
This table contains the details of each resource (e.g., `full_name`, its parents, and raw GCP data).
This table allows Scanner to perform its auditing.
