# Copyright 2017 Google Inc.
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

"""Creates a Cloud SQL database template for forseti_inventory."""


def GenerateConfig(context):
    """Generate configuration."""

    resources = []
    for instance in context.properties.get('instances'):
        resources.append({
            'name': instance,
            'type': 'sqladmin.v1beta4.database',
            'properties': {
                'name': instance,
                'project': context.env['project'],
                'instance': '$(ref.cloudsql-instance.name)'
            },
            'metadata': {
                'dependsOn':['cloudsql-instance'],
            }
        })

    return {'resources': resources}
