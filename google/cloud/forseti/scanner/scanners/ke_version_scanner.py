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

"""Scanner for the KE version rules engine.

Check if the version of running KE clusters and nodes are allowed.

"""

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import ke_version_rules_engine
from google.cloud.forseti.scanner.scanners import ke_base_scanner

LOGGER = logger.get_logger(__name__)

KeVersionScannerBase = ke_base_scanner.ke_scanner_factory(
    'version',
    ke_version_rules_engine.KeVersionRulesEngine,
)


class KeVersionScanner(KeVersionScannerBase):
    """Scanner class for KE version rules."""
