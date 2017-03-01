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

"""Writes the csv files for upload to Cloud SQL."""

import csv
import logging
import os
import tempfile

from google.cloud.security.common.data_access.errors import CSVFileError
from google.cloud.security.common.util.log_util import LogUtil


LOGGER = LogUtil.setup_logging(__name__)

ORG_IAM_POLICIES_FIELDNAME = [
   'org_id',
   'role',
   'member_type',
   'member_name',
   'member_domain'
]


POLICY_VIOLATION_FIELDNAMES = [
    'resource_id',
    'resource_type',
    'rule_index',
    'rule_name',
    'violation_type',
    'role',
    'member'
]

PROJECTS_FIELDNAME = [
   'project_number',
   'project_id',
   'project_name',
   'lifecycle_state',
   'parent_type',
   'parent_id',
   'raw_project',
   'create_time'
]

PROJECT_IAM_POLICIES_FIELDNAME = [
   'project_number',
   'role',
   'member_type',
   'member_name',
   'member_domain'
]

RAW_ORG_IAM_POLICIES_FIELDNAME = [
   'org_id',
   'iam_policy'
]

RAW_PROJECT_IAM_POLICIES_FIELDNAME = [
   'project_number',
   'iam_policy'
]

CSV_FIELDNAME_MAP = {
    'org_iam_policies': ORG_IAM_POLICIES_FIELDNAME,
    'policy_violations': POLICY_VIOLATION_FIELDNAMES,
    'projects': PROJECTS_FIELDNAME,
    'project_iam_policies': PROJECT_IAM_POLICIES_FIELDNAME,
    'raw_org_iam_policies': RAW_ORG_IAM_POLICIES_FIELDNAME,
    'raw_project_iam_policies': RAW_PROJECT_IAM_POLICIES_FIELDNAME,
}


def write_csv(resource_name, data, write_header=False):
    """Start the csv writing flow.

    Args:
        resource_name: String of the resource name.
        data: An iterable of data to be written to csv.
        write_header: If True, write the header in the csv file.

    Returns:
       String of the csv filename; full path included.
    """
    csv_file = tempfile.NamedTemporaryFile(delete=False)
    try:
        writer = csv.DictWriter(csv_file, doublequote=False, escapechar='\\',
                                quoting=csv.QUOTE_NONE,
                                fieldnames=CSV_FIELDNAME_MAP[resource_name])
        if write_header:
            writer.writeheader()

        for i in data:
            writer.writerow(i)
        return csv_file.name
    except (IOError, OSError, csv.Error) as e:
        raise CSVFileError(resource_name, e)
    finally:
        csv_file.close()
