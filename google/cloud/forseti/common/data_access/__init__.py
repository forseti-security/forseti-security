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

"""Forseti APIs and Utilities for Data Access."""

# The database schema version needs to change any time the database schema
# is extended or changed. Adding a new table, or additional fields
# to an existing table, should increment the minor number of the version.
# Modifying any table in a non-backwards compatible way needs to increment
# the major number.

# pylint: disable=invalid-name
# TODO: Look at improving the naming so we don't have need the pylint disable.
db_schema_version = '2.0'

# Change log
# Version 1.0:
#   * Added table snapshot_cycles.
#   * Added table projects
#   * Added table project_iam_policies
#   * Added table raw_project_iam_policies
#
# Version 2.0:
#   * Added table folder_iam_policies
#   * Added table raw_folder_iam_policies
#
# Version x.y:
#   * ...
