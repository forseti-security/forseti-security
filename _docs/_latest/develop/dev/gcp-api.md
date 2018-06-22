---
title: GCP API
order: 103
---

# {{ page.title }}

This page describes how to add a new GCP API client, which will allow
Forseti to interact with GCP.

---

Before writing a new API client, it's important to note that GCP APIs have
common methods:

* list
* get
* create
* update
* delete

Instead of writing these methods separately and repeatedly for all the
different API clients, they can be written once as mixin classes, and then
inherited by each API client. This makes it easy and quick to add new API
clients, without having to rewrite these common methods for every API clients.

You can [learn more about the mixin pattern here](https://www.ianlewis.org/en/mixins-and-python).

You can see the currently available [mixins in Forseti here](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/google/cloud/forseti/common/gcp_api/repository_mixins.py).

## Main Steps

The main steps to add a new foo API client are:

1. Define the API name & versions to be added
1. Create a new foo API client file
1. Create a FooClient class to provide the entry point to the GCP API method
1. Create a FooRepositoryClient class, and define the property method for the resource that you want to interact with the GCP API
1. Create a \_FooBarRepository class, to install the base GCP API functionalities (building requests, authentication, mixin classes)
1. Use the new API client

A good example to look at, that is small, complete, and self-contained would be
[cloudsql.py](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/google/cloud/forseti/common/gcp_api/cloudsql.py).
We will use it for the code-walk below.

## Define the API name & versions to be added

Add a new entry for the API and the versions that can be used in the
`SUPPORTED_APIS` map.

[google/cloud/forseti/common/gcp_api/_supported_apis.py](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/google/cloud/forseti/common/gcp_api/_supported_apis.py)

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

## Create a new foo API client file

Create a new foo API client file called foo.py in
[google/cloud/forseti/common/gcp_api](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/google/cloud/forseti/common/gcp_api)
package.

## Create a FooClient class to provide the entry point to the GCP API method

1. Create FooClient class in foo.py.
1. Initialize with the allowed quota and FooRepositoryClient.
1. Create a get_foos(), which will invoke the actual GCP API
call.

[google/cloud/forseti/common/gcp_api/cloudsql.py](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/google/cloud/forseti/common/gcp_api/cloudsql.py)

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

## Create a FooRepositoryClient class, and define the property method

1. Create a FooRepositoryClient class in foo.py.
1. Make it inherit the `BaseRepositoryClient`.
1. Initialize it with quota parameters.
1. Define the property method named after the bar resource we want to interact
with, e.g. bar(). This property method will initialize a \_FooBarRepository
class, which will install the base GCP API functionalities (building requests,
authentication, and API methods).

[google/cloud/forseti/common/gcp_api/cloudsql.py](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/google/cloud/forseti/common/gcp_api/cloudsql.py)

In this example, bar is ```instances```.

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

## Create a \_FooBarRepository class, to install the base GCP API functionalities

1. Create a \_FooBarRepository class in foo.py.
1. Make it inherit the base `GCPRepository` and the appropriate GCP API method
mixins.  In this example, the mixin for list.
1. This will install the base GCP API functionalities for building requests,
authentication, and the API methods.

[google/cloud/forseti/common/gcp_api/cloudsql.py](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/google/cloud/forseti/common/gcp_api/cloudsql.py)

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

## Use the new API client

With everything in place, the new API client can be used by initializing
the GCP API client, and call the resource method.

```
self.foo_api_client = foo.FooClient(configs)
self.foo_api_client.get_foos(project_id)
```
