# Copyright 2018 The Forseti Security Authors. All rights reserved.
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
"""Location data to be used in the unit tests."""

from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.scanner.audit import location_rules_engine


ORGANIZATION = organization.Organization(
    '234',
    display_name='Organization 234',
    full_name='organization/234/',
    data='fake_org_data_234',
)

PROJECT = project.Project(
    'p1',
    project_number=11223344,
    display_name='Project with lien',
    parent=ORGANIZATION,
    full_name='organization/234/project/p1/',
    data='fake_project_data_2341',
)

_BUCKET_JSON = """{
    "id": "p1-bucket1",
    "parent": "projects/p1",
    "location": "EUROPE-WEST1"
}
"""

BUCKET = resource_util.create_resource_from_json(
    'bucket', PROJECT, _BUCKET_JSON)

_CLOUD_SQL_INSTANCE_JSON = """{
    "databaseVersion": "MYSQL_5_7",
    "instanceType": "CLOUD_SQL_INSTANCE",
    "kind": "sql#instance",
    "name": "p1-cloudsqlinstance1",
    "project": "p1",
    "region": "europe-west1",
    "gceZone": "europe-west1-a"
}
"""

CLOUD_SQL_INSTANCE = resource_util.create_resource_from_json(
    'cloudsqlinstance', PROJECT, _CLOUD_SQL_INSTANCE_JSON)

_CLUSTER_JSON = """{
    "name": "p1-cluster1",
    "locations": ["europe-west1-a"]
}
"""

CLUSTER = resource_util.create_resource_from_json(
    'kubernetes_cluster', PROJECT, _CLUSTER_JSON)

_DATASET_JSON = """{
    "datasetReference": {
        "datasetId": "p1-d1",
        "projectId": "p1"
    },
    "id": "p1:p1-d1",
    "kind": "bigquery#dataset",
    "location": "EU"
}
"""

DATASET = resource_util.create_resource_from_json(
    'dataset', PROJECT, _DATASET_JSON)

_GCE_INSTANCE_JSON = """{
    "id": "p1-instance1",
    "selfLink": "https://www.googleapis.com/compute/v1/projects/p1/zones/europe-west1-a/instances/p1-instance1"
}"""

GCE_INSTANCE = resource_util.create_resource_from_json(
    'instance', PROJECT, _GCE_INSTANCE_JSON)

def build_violations(res):
    """Build an expected violation.

    Args:
        res (Resource): resource to create violation from.

    Returns:
        RuleViolation: The violation.
    """
    return [location_rules_engine.RuleViolation(
        resource_id=res.id,
        resource_name=res.display_name,
        resource_type=res.type,
        full_name=res.full_name,
        rule_index=0,
        rule_name='Location test rule',
        violation_type='LOCATION_VIOLATION',
        violation_data=str(res.locations),
        resource_data=res.data,
    )]
