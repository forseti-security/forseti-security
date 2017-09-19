# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Pipeline to load appengine applications into Inventory."""

from google.cloud.security.common.data_access import project_dao as proj_dao
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory.pipelines import base_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadAppenginePipeline(base_pipeline.BasePipeline):
    """Load all AppEngine applications for all projects."""

    RESOURCE_NAME = 'appengine'
    SERVICES_RESOURCE_NAME = 'appengine_services'
    VERSIONS_RESOURCE_NAME = 'appengine_versions'
    INSTANCES_RESOURCE_NAME = 'appengine_instances'


    # pylint: disable=too-many-locals, too-many-nested-blocks
    def _retrieve(self):
        """Retrieve AppEngine applications from GCP.

        Get all the projects in the current snapshot and retrieve the
        AppEngine applications for each.

        Returns:
            dict: Mapping projects with their AppEngine applications:
            {project_id: application}
        """
        projects = (
            proj_dao
            .ProjectDao(self.global_configs)
            .get_projects(self.cycle_timestamp))
        apps = {}
        loadable_services = []
        loadable_versions = []
        loadable_instances = []
        for project in projects:
            app = self.safe_api_call('get_app', project.id)
            if app:
                apps[project.id] = app

                services = self.safe_api_call(
                    'list_services', project.id)
                if services:
                    for service in services:
                        app_id = app.get('id')
                        service_id = service.get('id')
                        loadable_services.append(
                            {'project_id': project.id,
                             'app_id': app_id,
                             'service_id': service_id,
                             'service': parser.json_stringify(service)})

                        versions = self.safe_api_call(
                            'list_versions', project.id, service_id)
                        if versions:
                            for version in versions:
                                version_id = version.get('id')
                                loadable_versions.append(
                                    {'project_id': project.id,
                                     'app_id': app_id,
                                     'service_id': service_id,
                                     'version_id': version_id,
                                     'version': parser.json_stringify(version)})

                                instances = self.safe_api_call(
                                    'list_instances', project.id,
                                    service_id, version_id)
                                if instances:
                                    for instance in instances:
                                        instance_id = instance.get('id')
                                        parser.json_stringify(instance)
                                        loadable_instances.append(
                                            {'project_id': project.id,
                                             'app_id': app_id,
                                             'service_id': service_id,
                                             'version_id': version_id,
                                             'instance_id': instance_id,
                                             'instance':
                                                 parser.json_stringify(
                                                     instance)})
        return apps, loadable_services, loadable_versions, loadable_instances
    # pylint: enable=too-many-locals, too-many-nested-blocks

    def _transform(self, resource_from_api):
        """Create an iterator of AppEngine applications to load into database.

        Args:
            resource_from_api (dict): AppEngine applications, keyed by
                project id, from GCP API.

        Yields:
            iterator: AppEngine applications in a dict.
        """
        for project_id, app in resource_from_api.iteritems():
            yield {'project_id': project_id,
                   'name': app.get('name'),
                   'app_id': app.get('id'),
                   'dispatch_rules': parser.json_stringify(
                       app.get('dispatchRules', [])),
                   'auth_domain': app.get('authDomain'),
                   'location_id': app.get('locationId'),
                   'code_bucket': app.get('codeBucket'),
                   'default_cookie_expiration': app.get(
                       'defaultCookieExpiration'),
                   'serving_status': app.get('servingStatus'),
                   'default_hostname': app.get('defaultHostname'),
                   'default_bucket': app.get('defaultBucket'),
                   'iap': parser.json_stringify(app.get('iap', {})),
                   'gcr_domain': app.get('gcrDomain'),
                   'raw_application': parser.json_stringify(app)}

    def run(self):
        """Run the pipeline."""
        apps, loadable_services, loadable_versions, loadable_instances = (
            self._retrieve())

        if apps:
            loadable_apps = self._transform(apps)
            self._load(self.RESOURCE_NAME, loadable_apps)
            # TODO: Make _get_loaded_count() support multiple resources
            # in a single pipeline.  This will be resolved when tackling
            # Inventory v2.
            self._load(self.SERVICES_RESOURCE_NAME, loadable_services)
            self._load(self.VERSIONS_RESOURCE_NAME, loadable_versions)
            self._load(self.INSTANCES_RESOURCE_NAME, loadable_instances)

        self._get_loaded_count()
