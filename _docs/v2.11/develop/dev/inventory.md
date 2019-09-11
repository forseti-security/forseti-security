---
title: Inventory
order: 102
---

# {{ page.title }}

This page describes how to update Forseti Inventory to collect and store new
data types, and import it into a data model.

---

To add a new type of Inventory data, you'll complete the following tasks:

1. Check that the API client exists
1. Create an iterator to retrieve the data with the API client
1. Add the iterator to Inventory factories to make it available for crawling
1. Add the Inventory data to a data model

The following guide demonstrates these steps as a walkthrough of 
[PR #883](https://github.com/forseti-security/forseti-security/pull/883),
which adds Compute Engine Image data to Inventory and a data model.

## Step 1: Check the API client

To check if the API client to retrieve the data already exists, look at the
`SUPPORTED_APIS` map in [_supported_apis.py](https://github.com/forseti-security/forseti-security/blob/master/google/cloud/forseti/common/gcp_api/_supported_apis.py).
If the API client isn't there, you will have to add it. For a self-contained example,
see [cloud_sql.py]({% link _docs/v2.11/develop/reference/_modules/google/cloud/forseti/common/gcp_api/cloudsql.html %}).

## Step 2: Create an iterator

Edit
[google/cloud/forseti/services/inventory/base/gcp.py]({% link _docs/v2.11/develop/reference/_modules/google/cloud/forseti/services/inventory/base/gcp.html %})
to create `iter_foo()` that will call the API client to retrieve the data.

```python
    @create_lazy('compute', _create_compute)
    def iter_images(self, projectid):
        """Image Iterator from Compte Engine API call

        Yields:
            dict: Generator of image resources
        """
        for image in self.compute.get_images(projectid):
            yield image
```

Edit
[google/cloud/forseti/services/inventory/base/resources.py]({% link _docs/v2.11/develop/reference/_modules/google/cloud/forseti/services/inventory/base/resources.html %})
to create `FooIterator` to call the `iter_foo()`, and cast the result for storage
in Inventory.

```python
    class ImageIterator(ResourceIterator):
        def iter(self):
            gcp = self.client
            if (self.resource.enumerable() and
                   self.resource.compute_api_enabled(gcp)):
                for data in gcp.iter_images(
                        projectid=self.resource['projectId']):
                    yield FACTORIES['image'].create_new(data)
```

To complete the casting, edit
[google/cloud/forseti/services/inventory/base/resources.py]({% link _docs/v2.11/develop/reference/_modules/google/cloud/forseti/services/inventory/base/resources.html %})
to create a resource class for foo. This allows you to access the `id` and `type`.
If the resource doesn't have a provided `id`, you'll have to synthesize one. For
details to create a synthetic key, see an existing `key()` in `resources.py`
where other existing resource attributes are hashed.


```python
    class Image(Resource):
        def key(self):
            return self['id']

        def type(self):
            return 'image'
```

## Step 3: Add the iterator to Inventory factories

Edit
[google/cloud/forseti/services/inventory/base/resources.py]({% link _docs/v2.11/develop/reference/_modules/google/cloud/forseti/services/inventory/base/resources.html %})
to create `ResourceFactory` for `foo`, and link the `FooIterator` to the parent resource.

```python
    FACTORIES = {
        'project': ResourceFactory({
            'dependsOn': ['organization', 'folder'],
            'cls': Project,
            'contains': [
                ImageIterator,
                FirewallIterator,
                NetworkIterator,
                SubnetworkIterator,
            ]}),
       'image': ResourceFactory({
            'dependsOn': ['project'],
            'cls': Image,
            'contains': [
                ]}),
    }
```

## Step 4: Add the Inventory data to a data model

This step assumes that you're working with a simple resource that
will go into the resource data model table. If you want to convert
the Inventory data into a more complicated data model, email
[discuss@forsetisecurity.org](mailto:discuss@forsetisecurity.org) for
help.

1. Edit
[google/cloud/forseti/services/model/importer/importer.py]({% link _docs/v2.11/develop/reference/_modules/google/cloud/forseti/services/model/importer/importer.html %})
to add `foo` into `gcp_type_list`.
    ```python
        def run(self):
            """Runs the import.

            Raises:
                NotImplementedError: If the importer encounters an unknown
                    inventory type.
            """
            gcp_type_list = [
                'organization',
                'folder',
                'project',
                'image',
            ]
    ```
1. Edit
[google/cloud/forseti/services/model/importer/importer.py]({% link _docs/v2.11/develop/reference/_modules/google/cloud/forseti/services/model/importer/importer.html %})
to create `_convert_foo()` to store the Inventory data in a data model.
    ```python
        def _convert_image(self, image):
            """Convert a image to a database object.

             Args:
                image (object): Image to store.
            """
            data = image.get_data()
            parent, full_res_name, type_name = self._full_resource_name(
                image)
            self.session.add(
                self.dao.TBL_RESOURCE(
                    full_name=full_res_name,
                    type_name=type_name,
                    name=image.get_key(),
                    type=image.get_type(),
                    display_name=data.get('displayName', ''),
                    email=data.get('email', ''),
                    data=image.get_data_raw(),
                    parent=parent))
    ```
1. Edit
[google/cloud/forseti/services/model/importer/importer.py]({% link _docs/v2.11/develop/reference/_modules/google/cloud/forseti/services/model/importer/importer.html %})
to connect `foo` with the `_convert_foo()` in the `handlers` map in
`_store_resource()`.
    ```python
        handlers = {
            'organization': (None,
                             self._convert_organization,
                             None),
            'folder': (None,
                       self._convert_folder,
                       None),
            'project': (None,
                        self._convert_project,
                        None),
            'image': (None,
                      self._convert_image,
                      None),
        }
    ```
Your new data type is now added to Inventory and a new data model.
