# Copyright 2020 The Forseti Security Authors. All rights reserved.
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

"""External Project Access Scanner test"""

import pytest
import re
from endtoend_tests.helpers.forseti_cli import ForsetiCli


class TestExternalProjectAccessScanner:
    """External Project Access Scanner test

    Run the external project access scanner and verify the scanner completes
    without error.
    """

    @pytest.mark.e2e
    @pytest.mark.scanner
    @pytest.mark.server
    def test_external_project_access_scanner(self, forseti_cli: ForsetiCli,
                                             forseti_model_readonly):
        model_name, _, _ = forseti_model_readonly
        forseti_cli.model_use(model_name=model_name)

        result = forseti_cli.run_external_project_access_scanner()

        assert result.returncode == 0
        assert re.search('Running ExternalProjectAccessScanner',
                         str(result.stdout))
        assert re.search('Scan completed!', str(result.stdout))
