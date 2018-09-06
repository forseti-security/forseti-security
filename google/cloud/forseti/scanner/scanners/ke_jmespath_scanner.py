# Copyright 2017 The Forseti Security Authors. All rights reserved.
# Copyright 2018 Ross Vandegrift. All rights reserved.
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

"""Scanner for the KE jmespath rules engine."""

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import ke_jmespath_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner

LOGGER = logger.get_logger(__name__)


class KeJmespathScanner(base_scanner.KeBaseScanner):
    """Implement scanning for arbitrary jmespath expressions.

    This scanner allows the user to write rules that extract arbitrary
    values from a KE cluster's JSON representation, and match them
    against a given list of values.  The values can be treated as a
    whitelist or a blacklist.

    """
    _scanner_name = 'jmespath'
    _rules_engine_cls = ke_jmespath_rules_engine.KeJmespathRulesEngine
