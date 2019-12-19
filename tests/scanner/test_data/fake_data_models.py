# Copyright 2019 The Forseti Security Authors. All rights reserved.
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

"""Fake Config Validator data models."""

ALL_ENABLED = {
    'scanners': [
        {'name': 'config_validator', 'enabled': True}
    ]
}

ALL_DISABLED = {'scanners': []}

NONEXISTENT_DATA_MODEL_ENABLED = {
    'scanners': [
        {'name': 'config_validator', 'enabled': True},
        {'name': 'non_existent', 'enabled': True}
    ]
}

FAKE_NON_CAI_RESOURCE = {
    "data_type": "resource",
    "primary_key": "lien/p123",
    "resource":
    {
        "_sa_instance_state": "<sqlalchemy.orm.state.InstanceState object at 0x10c5094d0>",
        "full_name": "folder/folder-1/project/project-2/lien/p123/",
        "cai_resource_name": "",
        "parent_type_name": "project/project-2",
        "type": "lien",
        "display_name": "liens/p123",
        "data": """{
            "createTime": "2019-07-29T19:19:32.856Z",
            "name": "liens/p123",
            "origin": "xpn.googleapis.com",
            "parent": "projects/123",
            "reason": "This lien is added to prevent the deletion of this shared VPC host project. This project should be disabled as a shared VPC host before it is deleted, otherwise it can cause networking outages in attached service projects.",
            "restrictions": [
              "resourcemanager.projects.delete"
            ]
        }""",
        "cai_resource_type": "",
        "type_name": "lien/p123",
        "name": "p123",
        "policy_update_counter": 0,
        "parent": "<Resource(full_name=folder/folder-1/project/project-2/, name=project-2 type=project)>"
    },
    "resource_type": "lien"
}

EXPECTED_NON_CAI_RESOURCE = {
    "data_type": "resource",
    "primary_key": "lien/p123",
    "resource":
    {
        "_sa_instance_state": "<sqlalchemy.orm.state.InstanceState object at 0x10c5094d0>",
        "full_name": "folder/folder-1/project/project-2/lien/p123/",
        "cai_resource_name": "//cloudresourcemanager.googleapis.com/Lien/lien/p123",
        "parent_type_name": "project/project-2",
        "type": "lien",
        "display_name": "liens/p123",
        "data": """{
            "createTime": "2019-07-29T19:19:32.856Z",
            "name": "liens/p123",
            "origin": "xpn.googleapis.com",
            "parent": "projects/123",
            "reason": "This lien is added to prevent the deletion of this shared VPC host project. This project should be disabled as a shared VPC host before it is deleted, otherwise it can cause networking outages in attached service projects.",
            "restrictions": [
              "resourcemanager.projects.delete"
            ]
        }""",
        "cai_resource_type": "cloudresourcemanager.googleapis.com/Lien",
        "type_name": "lien/p123",
        "name": "p123",
        "policy_update_counter": 0,
        "parent": "<Resource(full_name=folder/folder-1/project/project-2/, name=project-2 type=project)>"
    },
    "resource_type": "lien"
}
