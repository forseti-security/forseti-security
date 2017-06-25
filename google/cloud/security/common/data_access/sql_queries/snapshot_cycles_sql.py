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
#
#
"""SQL queries for Snapshot Cycles tables."""

RESOURCE_NAME = 'snapshot_cycles'

CREATE_TABLE = """
    CREATE TABLE `snapshot_cycles` (
        `id` bigint(20) NOT NULL AUTO_INCREMENT,
        `start_time` datetime DEFAULT NULL,
        `complete_time` datetime DEFAULT NULL,
        `status` enum('SUCCESS','RUNNING','FAILURE',
                      'PARTIAL_SUCCESS','TIMEOUT') DEFAULT NULL,
        `schema_version` varchar(255) DEFAULT NULL,
        `cycle_timestamp` varchar(255) DEFAULT NULL,
         PRIMARY KEY (`id`),
         UNIQUE KEY `cycle_timestamp_UNIQUE` (`cycle_timestamp`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

SELECT_SNAPSHOT_CYCLES_TABLE = """
    SELECT TABLE_NAME from information_schema.tables
    WHERE TABLE_NAME = 'snapshot_cycles' 
    AND TABLE_SCHEMA in (
        SELECT DATABASE()
        );"""

INSERT_CYCLE = """
    INSERT INTO snapshot_cycles
    (cycle_timestamp, start_time, status, schema_version)
    VALUES (%s, %s, %s, %s);
"""

UPDATE_CYCLE = """
    UPDATE snapshot_cycles
    SET status=%s, complete_time=%s
    WHERE cycle_timestamp=%s;
"""
