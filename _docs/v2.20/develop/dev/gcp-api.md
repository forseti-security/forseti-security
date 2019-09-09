---
title: GCP API
order: 103
---

# {{ page.title }}

This page describes how to add a new Google Cloud Platform (GCP) API
client that will allow Forseti to interact with GCP.

---

## Before you begin

Before you write a new API client, note that GCP APIs have the following
common methods:

* `list`
* `get`
* `create`
* `update`
* `delete`

Instead of writing redundant methods for each API client, you can write them
once as Mixin classes, and then re-use them in each API client.

* Learn more about [Mixin patterns](https://www.ianlewis.org/en/mixins-and-python).
* View the currently available [Mixins in Forseti]({% link _docs/v2.20/develop/reference/google.cloud.forseti.common.gcp_api.html %}).

## Overview

To add a new foo GCP API client, you'll complete the following tasks:

1. Define the API name & versions to be added.
1. Create a new foo API client file.
1. Create `FooClient` class to provide the entry point to the GCP API
method. `FooClient` contains `FooRepositoryClient`.
1. Create `FooRepositoryClient` class, and define the property method for the
bar resource that you want to interact with the GCP API. `FooRepositoryClient`
contains `_FooBarRepository`.
1. Create a `\_FooBarRepository` class, to install the base GCP API
functionalities (building requests, authentication, Mixin classes).
1. Use the new API client.

For a self-contained example, see [cloudsql.py]({% link _docs/v2.20/develop/reference/_modules/google/cloud/forseti/common/gcp_api/cloudsql.html %}).
The example below provides a code walkthrough of this file.

### Step 1: Define the API name & versions

Edit [google/cloud/forseti/common/gcp_api/_supported_apis.py](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/google/cloud/forseti/common/gcp_api/_supported_apis.py) to
add a new entry for the API and the versions that can be used in the
`SUPPORTED_APIS` map. For more information, see the available
[APIs provided by GCP](https://cloud.google.com/apis/docs/overview).

```python
SUPPORTED_APIS = {
    'bigquery': {
        'default_version': 'v2',
        'supported_versions': ['v2']
    },
    'cloudresourcemanager': {
        'default_version': 'v1',
        'supported_versions': ['v1', 'v2']
    },
    'foo': {
        'default_version': 'v1',
        'supported_versions': ['v1', 'beta']
    },
    'sqladmin': {
        'default_version': 'v1beta4',
        'supported_versions': ['v1beta4']
    },
}
```

### Step 2: Create a new API client file

Create a new foo API client file called `foo.py` in
[google/cloud/forseti/common/gcp_api]({% link _docs/v2.20/develop/reference/google.cloud.forseti.common.gcp_api.html %})
package.

### Step 3: Create a new class for the GCP API method

In this step, you'll edit [google/cloud/forseti/common/gcp_api/cloudsql.py]({% link _docs/v2.20/develop/reference/_modules/google/cloud/forseti/common/gcp_api/cloudsql.html %})
to create a new class to provide the entry point to the GCP API method.

1. Create `FooClient` class in `foo.py`.
1. Initialize with the allowed quota and `FooRepositoryClient` that you'll
create in the next section to define the property method.
1. If the repository client has property `instances`, create a
`get_(repository_client_property)s`, for example `get_instances()`. In the example
below, the repository has list Mixin, which will invoke the actual GCP API call.

```python
class CloudsqlClient(object):
    """CloudSQL Client."""

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            **kwargs (dict): The kwargs.
        """
        max_calls, quota_period = api_helpers.get_ratelimiter_config(
            global_configs, 'sqladmin')

        self.repository = CloudSqlRepositoryClient(
            quota_max_calls=max_calls,
            quota_period=quota_period,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_instances(self, project_id):
        """Gets all CloudSQL instances for a project.

        Args:
            project_id (int): The project id for a GCP project.

        Returns:
            list: A list of database Instance resource dicts for a project_id.
            https://cloud.google.com/sql/docs/mysql/admin-api/v1beta4/instances
        """

        paged_results = self.repository.instances.list(project_id)
        flattened_results = api_helpers.flatten_list_results(
            paged_results, 'items')
        LOGGER.debug('Getting all the cloudsql instances of a project,'
                     ' project_id = %s, flattened_results = %s',
                      project_id, flattened_results)
        return flattened_results
```

### Step 4: Create a new class and define the property method

Edit [google/cloud/forseti/common/gcp_api/cloudsql.py]({% link _docs/v2.20/develop/reference/_modules/google/cloud/forseti/common/gcp_api/cloudsql.html %})
to create a new class and define the property method:

1. Create a `FooRepositoryClient` class in `foo.py`.
1. Inherit from the `BaseRepositoryClient`.
1. Initialize it with quota parameters.
1. Define the property method named after the `bar` resource we want to interact
with, such as `bar()`. This property method will initialize a `\_FooBarRepository`
class that you'll create in the next section to install the base GCP API functionalities
(building requests, authentication, and API methods).

In this example, `bar` is `instances`.

```python
class CloudSqlRepositoryClient(_base_repository.BaseRepositoryClient):
    """Cloud SQL Admin API Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=1.0,
                 use_rate_limiter=True):
        """Constructor.

        Args:
            quota_max_calls (int): Allowed requests per <quota_period> for the
                API.
            quota_period (float): The time period to track requests over.
            use_rate_limiter (bool): Set to false to disable the use of a rate
                limiter for this service.
        """
        if not quota_max_calls:
            use_rate_limiter = False

        self._instances = None

        super(CloudSqlRepositoryClient, self).__init__(
            'sqladmin', versions=['v1beta4'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    @property
    def instances(self):
        """Returns a _CloudSqlInstancesRepository instance."""
        if not self._instances:
            self._instances = self._init_repository(
                _CloudSqlInstancesRepository)
        return self._instances
```

### Step 5: Create a new class for GCP API functionalities

In this step, you'll edit [google/cloud/forseti/common/gcp_api/cloudsql.py]({% link _docs/v2.20/develop/reference/_modules/google/cloud/forseti/common/gcp_api/cloudsql.html %}) to create a new class to install the GCP API functionalities.

1. Create a `\_FooBarRepository` class in `foo.py`.
1. Make it inherit the base `GCPRepository` and the appropriate GCP API method
Mixins. In this example, the Mixin is for `list`.

This will install the base GCP API functionalities for building requests,
authentication, and the API methods.

```python
class _CloudSqlInstancesRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of CloudSql Instances repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_CloudSqlInstancesRepository, self).__init__(
            component='instances', **kwargs)
```

### Step 6: Use the new API client

To use the new API client, initialize the GCP API client and call the resource method:

```
self.foo_api_client = foo.FooClient(configs)
self.foo_api_client.get_foos(project_id)
```
