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

"""Provides the load data sql for resources."""

from google.cloud.security.common.data_access import csv_writer
from google.cloud.security.common.data_access.sql_queries import load_data


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-return-type-doc


FIELDNAME_MAP = csv_writer.CSV_FIELDNAME_MAP

def provide_load_data_sql(resource_name, csv_filename, snapshot_table_name):
    """Provide the load data sql for projects.

    Args:
        resource_name (str): String of the resource's name.
        csv_filename (str): String of the csv filename; full path included.
        snapshot_table_name (str): String of the snapshot table name.

    Returns:
        String of the load data sql statement for projects.
    """
    fieldname = FIELDNAME_MAP[resource_name]
    return load_data.LOAD_DATA.format(
        csv_filename, snapshot_table_name,
        (','.join(fieldname)))
