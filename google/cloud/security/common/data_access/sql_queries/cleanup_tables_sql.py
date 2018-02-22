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
#
#
"""SQL queries for management of inventory tables."""

RESOURCE_NAME = 'cleanup_tables'

SELECT_SNAPSHOT_TABLES_OLDER_THAN = """
    SELECT tables.TABLE_NAME 'table'
    from information_schema.tables as tables
    inner join snapshot_cycles as snap
    ON snap.start_time < DATE_SUB(NOW(), INTERVAL %s DAY)
    AND tables.TABLE_NAME LIKE CONCAT('%%', snap.cycle_timestamp)
    WHERE tables.TABLE_SCHEMA = %s;
"""

DROP_TABLE = "DROP TABLE {0}"
