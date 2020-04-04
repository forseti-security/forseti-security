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

"""Model end-to-end tests"""

import pytest
import re
from endtoend_tests.helpers.forseti_cli import ForsetiCli


class TestModel:
    """Model tests

    Execute the basic model functionality such as: create, get, use, etc.
    """

    @pytest.mark.client
    @pytest.mark.e2e
    @pytest.mark.model
    def test_model_use(self, forseti_cli: ForsetiCli, forseti_model_readonly):
        # Arrange
        model_name, handle, _ = forseti_model_readonly

        # Act
        forseti_cli.model_use(model_name)
        result = forseti_cli.config_show()

        # Assert
        assert re.search(fr'{handle}', str(result.stdout))
