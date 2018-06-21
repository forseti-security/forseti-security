---
title: Inventory
order: 102
---

# {{ page.title }}

This page describes how to update Forseti Inventory to collect and store new
data types, as well as importing it into data model.

---

The main steps to add a new type of Inventory data are:
1. Check API client exists
1. Create iterator to retrieve the data with the API client
1. Add the iterator to Inventory factories to make it available for crawling
1. Add the Inventory data to data model

To see how these steps actually works, we will do a code-walk of
[PR #883](https://github.com/GoogleCloudPlatform/forseti-security/pull/883),
which adds Compute Image data to Inventory and data model.

## Check API clients exists

Look in [_supported_apis.py](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/google/cloud/forseti/common/gcp_api/_supported_apis.py), if the API client to retrieve the data already exists.
If the API client is not found, you will have to add it. See [cloud_sql.py](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/google/cloud/forseti/common/gcp_api/cloudsql.py)
for a small and self-contained example.

## Create iterator to retrieve the data with the API client

Create iter_xyz() that will call the API client to retrieve the data.

```
google/cloud/forseti/services/inventory/base/gcp.py

    @create_lazy('compute', _create_compute)
    def iter_images(self, projectid):
        """Image Iterator from gcp API call

        Yields:
            dict: Generator of image resources
        """
        for image in self.compute.get_images(projectid):
            yield image
```

Create XYZIterator to call the iter_xyz(), and cast the result for storage
in Inventory.

```
google/cloud/forseti/services/inventory/base/resources.py

    class ImageIterator(ResourceIterator):
        def iter(self):
            gcp = self.client
            if (self.resource.enumerable() and
                   self.resource.compute_api_enabled(gcp)):
                for data in gcp.iter_images(
                        projectid=self.resource['projectId']):
                    yield FACTORIES['image'].create_new(data)
```

In order to do the casting, we need to create a resource class for xyz. This
allows us to access the `id` and `type`. If the resource has no provided `id`,
we must synthesize our own.  See other existing `key()`, to see how to create
a synthetic key.

```
google/cloud/forseti/services/inventory/base/resources.py

    class Image(Resource):
        def key(self):
            return self['id']

        def type(self):
            return 'image'
```

## Add the iterator to Inventory factories to make it available for crawling

Create ResourceFactory for xyz, and link the XYZIterator to the parent resource.

```
google/cloud/forseti/services/inventory/base/resources.py

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

## Add the Inventory data to data model

Assumption here is that this is a simple resource, and will go into the
resource data model table. If you need to convert the Inventory data into
more complicated data model, please email `discuss@forsetisecurity.org` for
further assistance.

Add xyz into `gcp_type_list`, and create `_convert_xyz()` to store the inventory
data into data model. Connect xyz with the `_convert_xyz()` in the h`andlers`
map in `_store_resource()`.

```
google/cloud/forseti/services/model/importer/importer.py

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

```
google/cloud/forseti/services/model/importer/importer.py

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

```
google/cloud/forseti/services/model/importer/importer.py

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
