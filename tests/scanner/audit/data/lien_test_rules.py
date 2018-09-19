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

"""Lien rules to use in the unit tests."""

_base = """
rules:
  - name: Lien test rule
    mode: required
    restrictions: [resourcemanager.projects.delete]
"""

ALL_PROJECTS = _base + """
    resource:
      - type: project
        resource_ids: [*]
"""

INAPPLICABLE_PROJECT = _base + """
    resource:
      - type: project
        resource_ids: [dne]
"""
