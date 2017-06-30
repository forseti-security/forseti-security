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

"""Map for the rule engine names to rule engine classes."""

from google.cloud.security.scanner.audit.iam_rules_engine import IamRulesEngine
# pylint: disable=line-too-long
from google.cloud.security.scanner.audit.bigquery_rules_engine import BigqueryRulesEngine
from google.cloud.security.scanner.audit.buckets_rules_engine import BucketsRulesEngine
from google.cloud.security.scanner.audit.cloudsql_rules_engine import CloudSqlRulesEngine
# pylint: enable=line-too-long


ENGINE_TO_DATA_MAP = {
    'IamRulesEngine': IamRulesEngine,
    'BigqueryRulesEngine': BigqueryRulesEngine,
    'BucketsRulesEngine': BucketsRulesEngine,
    'CloudSqlRulesEngine': CloudSqlRulesEngine,
}
