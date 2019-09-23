---
title: Models
order: 003
---

# {{ page.title }}

Starting with version 2.0, Forseti introduces the use of data models.

The data model is an additional pool of relational data that is created
from the flat JSON data in Inventory. With the relational data, Forseti
can more easily understand the entire relationship, including inheritance
between resources. Models allow for easier querying against the entire
computed policy.

Scanner and Explain depend on a data model, so you **must** create a valid
data model before you use Scanner or Explain. Note that data models aren't
meant to be persistent, so when you're finished using a model, you should delete it.

---

## How data models are stored

Data models are stored in their own set of tables with a naming convention of
`<model_handle>_<table_name>`, and are tied to each other by specific relationships.
Multiple sets of tables can exist, either created by the cron job, or by other users.
The table sets are listed in the `models` table.

### The `binding_members` table

This table is a join table that connects the `members` table with the `bindings` table,
so you can know what resources each member can access.

### The `bindings` table

This table contains information about what resource and roles are associated for a
`binding_id`. You can combine this with the binding_members table to see who has access to
resources, and with which roles.

### The `group_in_group` table

This table contains information about how groups are nested in other groups.
Each row contains a group and its parent group. If a group isn't nested, it won't
be in this table.

### The `group_members` table

This table contains information about groups, and the members in the group, including
users and other groups.

### The `members` table

This table contains information about members, the types of resources they are,
and their names.

### The `permissions` table

This table is a listing of all the permissions on Google Cloud Platform (GCP).

### The `roles` table

This table is a listing of all the roles on GCP, including title, stage, description,
and whether it's a custom role.

### The `role_permissions` table

This table contains information on the roles and the permissions of that role.

You can combine the `binding_members`, `bindings`, `roles`, and
`role_permissions` tables to see who has what permissions on which resources.

### The `resources` table
This table contains the details of each resource, like the full_name, its
parents, and raw GCP data. This table allows Scanner to perform its auditing.
